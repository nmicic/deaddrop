// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/slot"
	"github.com/nmicic/deaddrop/internal/wire"
)

// encryptForBucket seals plaintext using the derivations for the
// given minute bucket b (h = b / 60). Returns the URL path
// component (/svcHex/slotHex) and the full wire body
// (version || nonce || ct || tag). Recv-side mirror of Send.
func encryptForBucket(t *testing.T, b uint64, plaintext []byte) (path string, body []byte) {
	t.Helper()
	h := b / 60
	serviceID, err := slot.ServiceID(testDeploySecret, h)
	if err != nil {
		t.Fatalf("ServiceID: %v", err)
	}
	slotKey, err := slot.SlotKey(testPSK, testPairID)
	if err != nil {
		t.Fatalf("SlotKey: %v", err)
	}
	slotID, err := slot.SlotID(slotKey, b, 0)
	if err != nil {
		t.Fatalf("SlotID: %v", err)
	}
	aeadKey, err := slot.AEADKey(testPSK, testPairID, serviceID, slotID, wire.VersionPlainB)
	if err != nil {
		t.Fatalf("AEADKey: %v", err)
	}
	nonce := make([]byte, crypto.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ad := make([]byte, 0, slot.ServiceIDSize+slot.SlotIDSize+1)
	ad = append(ad, serviceID...)
	ad = append(ad, slotID...)
	ad = append(ad, wire.VersionPlainB)
	ct, err := crypto.Seal(aeadKey, nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	body = append(body, wire.VersionPlainB)
	body = append(body, nonce...)
	body = append(body, ct...)
	path = "/" + hex.EncodeToString(serviceID) + "/" + hex.EncodeToString(slotID)
	return
}

// bucketEntry is one row in bucketRelay's dispatch table.
type bucketEntry struct {
	status int
	body   []byte
}

// bucketRelay serves one status+body per configured URL path, or 404
// for any unconfigured path. Lets tests control which probe step
// gets which response.
func bucketRelay(t *testing.T, entries map[string]bucketEntry) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e, ok := entries[r.URL.Path]; ok {
			w.WriteHeader(e.status)
			_, _ = w.Write(e.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newRecvCfg builds a default RecvConfig rooted at srv.URL and using
// testClock. Tests that need a different clock copy this and
// override .Clock.
func newRecvCfg(srv *httptest.Server) client.RecvConfig {
	return client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: srv.URL,
		HTTPClient:   srv.Client(),
		Clock:        testClock,
	}
}

func assertRecvError(t *testing.T, err error, wantCode int) {
	t.Helper()
	var re *client.RecvError
	if !errors.As(err, &re) {
		t.Fatalf("want *RecvError, got %T: %v", err, err)
	}
	if re.Code != wantCode {
		t.Fatalf("code = %d, want %d (detail=%q)", re.Code, wantCode, re.Detail)
	}
}

// 1. TestRecv_HappyPath — message in the current bucket, first probe
// succeeds. Returned plaintext matches.
func TestRecv_HappyPath(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	plaintext := []byte("recv-happy")
	path, body := encryptForBucket(t, bNow, plaintext)
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: body},
	})

	got, err := client.Recv(newRecvCfg(srv))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// 2. TestRecv_ProbeSecondBucket — 404 on bNow, 200 on bNow-1.
func TestRecv_ProbeSecondBucket(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	plaintext := []byte("found-in-prev-minute")
	path, body := encryptForBucket(t, bNow-1, plaintext)
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: body},
	})

	got, err := client.Recv(newRecvCfg(srv))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// 3. TestRecv_ProbeThirdBucket — 404 on bNow and bNow-1, 200 on bNow-2.
func TestRecv_ProbeThirdBucket(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	plaintext := []byte("found-in-oldest-bucket")
	path, body := encryptForBucket(t, bNow-2, plaintext)
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: body},
	})

	got, err := client.Recv(newRecvCfg(srv))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

// 4. TestRecv_AllNotFound — every probe 404 → NotFound.
func TestRecv_AllNotFound(t *testing.T) {
	srv := bucketRelay(t, nil) // all paths 404
	_, err := client.Recv(newRecvCfg(srv))
	assertRecvError(t, err, exitcode.NotFound)
}

// 5. TestRecv_Auth401 — 401 on first probe → Auth (hard stop).
func TestRecv_Auth401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	cfg := newRecvCfg(srv)
	_, err := client.Recv(cfg)
	assertRecvError(t, err, exitcode.Auth)
}

// 6. TestRecv_Overloaded503 — 503 → RelayOverloaded (hard stop).
func TestRecv_Overloaded503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	_, err := client.Recv(newRecvCfg(srv))
	assertRecvError(t, err, exitcode.RelayOverloaded)
}

// 7. TestRecv_NetworkError — closed-port URL → RelayUnreachable.
func TestRecv_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	cfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: url,
		HTTPClient:   &http.Client{Timeout: 2 * time.Second},
		Clock:        testClock,
	}
	_, err := client.Recv(cfg)
	assertRecvError(t, err, exitcode.RelayUnreachable)
}

// 8. TestRecv_BadVersion — 200 body[0]=0x00 (reserved) → CryptoLocal
// with detail mentioning "version" (AEAD never attempted).
func TestRecv_BadVersion(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	// Use a path that matches the first probe so the relay returns
	// the tampered body; the exact slot derivations don't matter
	// because the version check fires before AEAD.
	path, _ := encryptForBucket(t, bNow, []byte("ignored"))
	bad := make([]byte, 1+crypto.NonceSize+crypto.TagSize+4)
	bad[0] = 0x00 // reserved
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: bad},
	})

	_, err := client.Recv(newRecvCfg(srv))
	var re *client.RecvError
	if !errors.As(err, &re) {
		t.Fatalf("want *RecvError, got %T: %v", err, err)
	}
	if re.Code != exitcode.CryptoLocal {
		t.Fatalf("code = %d, want %d", re.Code, exitcode.CryptoLocal)
	}
	if !strings.Contains(re.Detail, "version") {
		t.Fatalf("detail = %q, want to mention \"version\"", re.Detail)
	}
}

// 9. TestRecv_DecryptCorrupt — flip a byte in the ciphertext → Open
// fails → CryptoLocal with opaque detail "decrypt failed".
func TestRecv_DecryptCorrupt(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	path, body := encryptForBucket(t, bNow, []byte("original-plaintext"))
	// Ciphertext starts at body[1+NonceSize]; flip the first ct byte.
	corrupt := append([]byte{}, body...)
	corrupt[1+crypto.NonceSize] ^= 0xFF
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: corrupt},
	})
	_, err := client.Recv(newRecvCfg(srv))
	var re *client.RecvError
	if !errors.As(err, &re) {
		t.Fatalf("want *RecvError, got %T: %v", err, err)
	}
	if re.Code != exitcode.CryptoLocal {
		t.Fatalf("code = %d, want %d", re.Code, exitcode.CryptoLocal)
	}
	if re.Detail != "decrypt failed" {
		t.Fatalf("detail = %q, want \"decrypt failed\" (no oracle)", re.Detail)
	}
}

// 10. TestRecv_UnexpectedStatus — 500 → RelayUnreachable (catch-all).
func TestRecv_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	_, err := client.Recv(newRecvCfg(srv))
	assertRecvError(t, err, exitcode.RelayUnreachable)
}

// 11. TestRecv_HourBoundary — AC-ROLL-03. Sender encrypts at b=29999
// (h=499); receiver probes b=30001 (h=500), 30000 (h=500), 29999
// (h=499). The 3rd probe must use h=499 (per-bucket hour) or the
// derived service_id will not match the sender's.
func TestRecv_HourBoundary(t *testing.T) {
	senderClock := func() time.Time { return time.Unix(1_800_000-1, 0).UTC() }
	receiverClock := func() time.Time { return time.Unix(1_800_000+61, 0).UTC() }

	bSend := uint64(senderClock().Unix()) / 60
	if bSend != 29999 {
		t.Fatalf("sanity: bSend=%d, want 29999", bSend)
	}
	bRecv := uint64(receiverClock().Unix()) / 60
	if bRecv != 30001 {
		t.Fatalf("sanity: bRecv=%d, want 30001", bRecv)
	}

	plaintext := []byte("boundary-crossing")
	path, body := encryptForBucket(t, bSend, plaintext)
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: body},
	})

	cfg := newRecvCfg(srv)
	cfg.Clock = receiverClock
	got, err := client.Recv(cfg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch across hour boundary")
	}
}

// 12. TestRecv_BodyTooShort — 200 with 10-byte body (valid version
// at body[0], rest random). 10 < 1+24+16 → exit 10 with detail
// mentioning "body too short".
func TestRecv_BodyTooShort(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	path, _ := encryptForBucket(t, bNow, []byte("ignored"))
	short := []byte{wire.VersionPlainB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	srv := bucketRelay(t, map[string]bucketEntry{
		path: {status: http.StatusOK, body: short},
	})
	_, err := client.Recv(newRecvCfg(srv))
	var re *client.RecvError
	if !errors.As(err, &re) {
		t.Fatalf("want *RecvError, got %T: %v", err, err)
	}
	if re.Code != exitcode.CryptoLocal {
		t.Fatalf("code = %d, want %d", re.Code, exitcode.CryptoLocal)
	}
	if !strings.Contains(re.Detail, "body too short") {
		t.Fatalf("detail = %q, want \"body too short\"", re.Detail)
	}
}

// 13. TestRecv_RateLimit429 — 429 → RelayOverloaded (same class as 503).
func TestRecv_RateLimit429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	_, err := client.Recv(newRecvCfg(srv))
	assertRecvError(t, err, exitcode.RelayOverloaded)
}

// 14. TestRecv_NoWriteTokenOnGET — D-45: GET MUST NOT carry the
// X-DeadDrop-Write header. The relay records the header value on every
// probe; after the recv loop completes (either with a hit or all-404),
// the recorded value MUST be empty for every observed probe.
func TestRecv_NoWriteTokenOnGET(t *testing.T) {
	bNow := uint64(testClock().Unix()) / 60
	plaintext := []byte("no-write-token-on-get")
	path, body := encryptForBucket(t, bNow, plaintext)

	var observed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = append(observed, r.Header.Get("X-DeadDrop-Write"))
		if r.URL.Path == path {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	got, err := client.Recv(newRecvCfg(srv))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
	if len(observed) == 0 {
		t.Fatalf("relay observed zero probes; expected ≥ 1")
	}
	for i, h := range observed {
		if h != "" {
			t.Errorf("probe[%d]: X-DeadDrop-Write = %q, want empty (D-45)", i, h)
		}
	}
}

// Keep io imported (used by helpers above). Placed to make intent
// explicit.
var _ = io.Discard
