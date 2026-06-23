// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"bytes"
	"crypto/sha256"
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

// Deterministic test inputs. All tests use the same shape so the
// exact wire-body bytes are reproducible across runs.
var (
	testPSK          = bytes.Repeat([]byte{0x02}, 32)
	testPairID       = bytes.Repeat([]byte{0x03}, 8)
	testDeploySecret = bytes.Repeat([]byte{0x01}, 32)
	testWriteToken   = "test-write-token-32-bytes-long!!"
)

// testClock returns a fixed time — Unix 1_800_000_000 (2027-01-15 UTC)
// — so h and b buckets are stable across the whole suite and a
// -race -count=10 run cannot flake on a minute rollover.
func testClock() time.Time { return time.Unix(1_800_000_000, 0).UTC() }

// newCfg builds a SendConfig rooted at srv.URL. Callers mutate fields
// (e.g. RelayBaseURL for TestSend_NetworkError) after the return.
func newCfg(srv *httptest.Server) client.SendConfig {
	return client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: srv.URL,
		HTTPClient:   srv.Client(),
		Clock:        testClock,
	}
}

// captureRelay stands up an httptest server that records the first
// request it receives. fn can inspect w/r directly and is responsible
// for writing the status code.
type captured struct {
	method   string
	path     string
	headers  http.Header
	body     []byte
	received bool
}

func captureRelay(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	cap := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.headers = r.Header.Clone()
		cap.body, _ = io.ReadAll(r.Body)
		cap.received = true
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// 1. TestSend_HappyPath — 201 round-trip with full field inspection.
func TestSend_HappyPath(t *testing.T) {
	srv, cap := captureRelay(t, http.StatusCreated)
	cfg := newCfg(srv)

	plaintext := []byte("hello-send-test")
	deleteToken, err := client.Send(cfg, plaintext)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(deleteToken) != 32 {
		t.Fatalf("delete token len = %d, want 32", len(deleteToken))
	}

	// Path = /{svc_hex32}/{slot_hex32}.
	parts := strings.Split(cap.path, "/")
	if len(parts) != 3 || len(parts[1]) != 32 || len(parts[2]) != 32 {
		t.Fatalf("path = %q, want /{32-hex}/{32-hex}", cap.path)
	}

	if got := cap.headers.Get("X-DeadDrop-Write"); got != testWriteToken {
		t.Fatalf("X-DeadDrop-Write = %q, want %q", got, testWriteToken)
	}
	if got := cap.headers.Get("X-DeadDrop-Delete-Hash"); len(got) != 64 {
		t.Fatalf("X-DeadDrop-Delete-Hash len = %d, want 64 (hex of 32-byte hash)", len(got))
	}

	if cap.body[0] != wire.VersionPlainB {
		t.Fatalf("body[0] = 0x%02x, want 0x01", cap.body[0])
	}
	if len(cap.body) < 1+crypto.NonceSize+crypto.TagSize {
		t.Fatalf("body too short: %d bytes", len(cap.body))
	}

	// Full round-trip: re-derive the AEAD key and decrypt the body.
	h := uint64(testClock().Unix()) / 3600
	b := uint64(testClock().Unix()) / 60
	svcID, err := slot.ServiceID(testDeploySecret, h)
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
	aeadKey, err := slot.AEADKey(testPSK, testPairID, svcID, slotID, wire.VersionPlainB)
	if err != nil {
		t.Fatalf("AEADKey: %v", err)
	}
	nonce := cap.body[1 : 1+crypto.NonceSize]
	ct := cap.body[1+crypto.NonceSize:]
	ad := append(append(append([]byte{}, svcID...), slotID...), wire.VersionPlainB)
	pt, err := crypto.Open(aeadKey, nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func assertSendError(t *testing.T, err error, wantCode int) {
	t.Helper()
	var se *client.SendError
	if !errors.As(err, &se) {
		t.Fatalf("want *SendError, got %T: %v", err, err)
	}
	if se.Code != wantCode {
		t.Fatalf("code = %d, want %d (detail=%q)", se.Code, wantCode, se.Detail)
	}
}

// 2. TestSend_WrongWriteToken — relay 401 → Auth.
func TestSend_WrongWriteToken(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusUnauthorized)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.Auth)
}

// 3. TestSend_Collision409 — relay 409 → Collision.
func TestSend_Collision409(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusConflict)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.Collision)
}

// 4. TestSend_TooLarge413 — relay 413 → SizeCap.
func TestSend_TooLarge413(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusRequestEntityTooLarge)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.SizeCap)
}

// 5. TestSend_Overloaded503 — relay 503 → RelayOverloaded.
func TestSend_Overloaded503(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusServiceUnavailable)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.RelayOverloaded)
}

// 6. TestSend_RateLimit429 — relay 429 → RelayOverloaded (same class).
func TestSend_RateLimit429(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusTooManyRequests)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.RelayOverloaded)
}

// 7. TestSend_NetworkError — point at a closed port. net.DialTCP to an
// unused loopback port fails with "connection refused", which surfaces
// as a client.Do error.
func TestSend_NetworkError(t *testing.T) {
	// Start + immediately stop a server to borrow its bound port.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	cfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: url,
		HTTPClient:   &http.Client{Timeout: 2 * time.Second},
		Clock:        testClock,
	}
	_, err := client.Send(cfg, []byte("x"))
	assertSendError(t, err, exitcode.RelayUnreachable)
}

// 8. TestSend_BodyStructure — the prompt's canonical body-layout
// check with a fixed clock: verify version, nonce length, and that
// re-deriving + Open yields the original plaintext.
func TestSend_BodyStructure(t *testing.T) {
	srv, cap := captureRelay(t, http.StatusCreated)
	plaintext := []byte("structural-check")
	if _, err := client.Send(newCfg(srv), plaintext); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if cap.body[0] != wire.VersionPlainB {
		t.Fatalf("version byte = 0x%02x, want 0x01", cap.body[0])
	}
	if len(cap.body) < 1+crypto.NonceSize+crypto.TagSize {
		t.Fatalf("body too short: %d", len(cap.body))
	}
	// Re-derive and decrypt.
	h := uint64(testClock().Unix()) / 3600
	b := uint64(testClock().Unix()) / 60
	svcID, _ := slot.ServiceID(testDeploySecret, h)
	slotKey, _ := slot.SlotKey(testPSK, testPairID)
	slotID, _ := slot.SlotID(slotKey, b, 0)
	aeadKey, _ := slot.AEADKey(testPSK, testPairID, svcID, slotID, wire.VersionPlainB)
	nonce := cap.body[1 : 1+crypto.NonceSize]
	ct := cap.body[1+crypto.NonceSize:]
	ad := append(append(append([]byte{}, svcID...), slotID...), wire.VersionPlainB)
	pt, err := crypto.Open(aeadKey, nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip plaintext mismatch")
	}
}

// 9. TestSend_ADBinding — decrypting the captured body with a tampered
// AD (flip a service_id byte) must fail. Exercises D-27 binding.
func TestSend_ADBinding(t *testing.T) {
	srv, cap := captureRelay(t, http.StatusCreated)
	if _, err := client.Send(newCfg(srv), []byte("ad-bind")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	h := uint64(testClock().Unix()) / 3600
	b := uint64(testClock().Unix()) / 60
	svcID, _ := slot.ServiceID(testDeploySecret, h)
	slotKey, _ := slot.SlotKey(testPSK, testPairID)
	slotID, _ := slot.SlotID(slotKey, b, 0)
	aeadKey, _ := slot.AEADKey(testPSK, testPairID, svcID, slotID, wire.VersionPlainB)
	nonce := cap.body[1 : 1+crypto.NonceSize]
	ct := cap.body[1+crypto.NonceSize:]
	// Flip a bit in the svc_id component of the AD.
	tamperedAD := append([]byte{}, svcID...)
	tamperedAD[0] ^= 0x01
	tamperedAD = append(tamperedAD, slotID...)
	tamperedAD = append(tamperedAD, wire.VersionPlainB)
	_, err := crypto.Open(aeadKey, nonce, ct, tamperedAD)
	if !errors.Is(err, crypto.ErrOpen) {
		t.Fatalf("tampered AD: want ErrOpen, got %v", err)
	}
}

// 10. TestSend_DeleteHashCorrect — the header value is exactly
// hex(sha256(deleteToken returned to caller)).
func TestSend_DeleteHashCorrect(t *testing.T) {
	srv, cap := captureRelay(t, http.StatusCreated)
	deleteToken, err := client.Send(newCfg(srv), []byte("hash"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := sha256.Sum256(deleteToken)
	got := cap.headers.Get("X-DeadDrop-Delete-Hash")
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("delete-hash mismatch:\n  header: %s\n  want:   %s",
			got, hex.EncodeToString(want[:]))
	}
}

// 11. TestSend_UnexpectedStatus — 500 falls through to the catch-all
// branch → RelayUnreachable. Exercises the "other 4xx/5xx" path
// (same branch handles 404 for POST).
func TestSend_UnexpectedStatus(t *testing.T) {
	srv, _ := captureRelay(t, http.StatusInternalServerError)
	_, err := client.Send(newCfg(srv), []byte("x"))
	assertSendError(t, err, exitcode.RelayUnreachable)
}
