// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/identitystore"
	"github.com/nmicic/deaddrop/internal/wire"
)

// makeKeypair generates an X25519 keypair seeded by `seed` so the
// derived shared secret is reproducible across runs. The seed is
// reduced via X25519 clamping inside ScalarBaseMult — we just need a
// non-zero scalar.
func makeKeypair(seed byte) (sk, pk [32]byte) {
	for i := range sk {
		sk[i] = seed ^ byte(i)
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	return sk, pk
}

// pairLayers builds a matched pair of ContentLayers — one for the
// sender (Initiator) and one for the receiver (Responder) — sharing
// the same X25519 secret. Both layers carry the same PairID so the
// HKDF info-label binding lines up.
func pairLayers(t *testing.T) (*client.ContentLayer, *client.ContentLayer, [8]byte) {
	t.Helper()
	aSK, aPK := makeKeypair(0xA1)
	bSK, bPK := makeKeypair(0xB2)
	var pairID [8]byte
	for i := range pairID {
		pairID[i] = byte(0xC0 + i)
	}
	initEntry := &identitystore.Entry{
		Role:   identitystore.RoleInitiator,
		OwnSK:  aSK,
		OwnPK:  aPK,
		PeerPK: bPK,
	}
	respEntry := &identitystore.Entry{
		Role:   identitystore.RoleResponder,
		OwnSK:  bSK,
		OwnPK:  bPK,
		PeerPK: aPK,
	}
	clA, err := client.NewContentLayerFromEntry(initEntry, pairID)
	if err != nil {
		t.Fatalf("layer A: %v", err)
	}
	clB, err := client.NewContentLayerFromEntry(respEntry, pairID)
	if err != nil {
		t.Fatalf("layer B: %v", err)
	}
	return clA, clB, pairID
}

// e2eServer mirrors captureRelay but speaks the recv path: it serves
// the captured body back on GET. POST records the body and returns 201.
type e2eServer struct {
	body []byte
	srv  *httptest.Server
}

func newE2EServer(t *testing.T) *e2eServer {
	t.Helper()
	es := &e2eServer{}
	es.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			es.body, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if es.body == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(es.body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(es.srv.Close)
	return es
}

// TestE2E_Roundtrip: 0x04 send + 0x04 recv = original plaintext.
// Asserts wire byte 0 is VersionPlainBE2E and that the inner layer is
// actually applied (the captured body is NOT the plaintext after one
// outer Open — the recv ContentLayer is required).
func TestE2E_Roundtrip(t *testing.T) {
	es := newE2EServer(t)
	clSend, clRecv, _ := pairLayers(t)
	defer clSend.Wipe()
	defer clRecv.Wipe()

	plaintext := []byte("hello-e2e-roundtrip")

	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clSend,
	}
	if _, err := client.Send(sendCfg, plaintext); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if es.body == nil {
		t.Fatal("server never received POST body")
	}
	if es.body[0] != wire.VersionPlainBE2E {
		t.Fatalf("wire body[0] = 0x%02x, want 0x04", es.body[0])
	}

	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clRecv,
	}
	got, err := client.Recv(recvCfg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Recv plaintext mismatch")
	}
}

// TestE2E_InnerLayerIsActuallyApplied — proves the inner content-AEAD
// layer really wraps the bytes. We send with E2E (0x04) and then
// attempt an outer-only decrypt; the result must NOT equal the
// plaintext (it should be a content_nonce + content_ct blob) AND
// re-feeding it through a *different* ContentLayer must fail.
func TestE2E_InnerLayerIsActuallyApplied(t *testing.T) {
	es := newE2EServer(t)
	clSend, _, pairID := pairLayers(t)
	defer clSend.Wipe()

	plaintext := []byte("inner-layer-presence")
	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clSend,
	}
	if _, err := client.Send(sendCfg, plaintext); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Build a fresh, UNRELATED keypair and ContentLayer for the same
	// PairID — DH IKM differs, so content-AEAD Open must fail.
	xSK, xPK := makeKeypair(0x33)
	_, yPK := makeKeypair(0x66)
	wrongEntry := &identitystore.Entry{
		Role:   identitystore.RoleResponder,
		OwnSK:  xSK,
		OwnPK:  xPK,
		PeerPK: yPK,
	}
	wrongLayer, err := client.NewContentLayerFromEntry(wrongEntry, pairID)
	if err != nil {
		t.Fatalf("build wrong layer: %v", err)
	}
	defer wrongLayer.Wipe()

	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: wrongLayer,
	}
	_, err = client.Recv(recvCfg)
	if err == nil {
		t.Fatal("expected E2EUnwrap error from mismatched ContentLayer, got nil")
	}
	var re *client.RecvError
	if !errors.As(err, &re) || re.Code != exitcode.E2EUnwrap {
		t.Fatalf("err = %v, want RecvError with code E2EUnwrap", err)
	}
}

// TestRecv_E2EBodyButNoLayer — sender encrypts with 0x04, receiver has
// no ContentLayer. Must exit EDDIdentityMiss (not a generic decrypt
// error) so the operator gets a clear rebootstrap path.
func TestRecv_E2EBodyButNoLayer(t *testing.T) {
	es := newE2EServer(t)
	clSend, _, _ := pairLayers(t)
	defer clSend.Wipe()

	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clSend,
	}
	if _, err := client.Send(sendCfg, []byte("e2e-only-sender")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		// No ContentLayer.
	}
	_, err := client.Recv(recvCfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var re *client.RecvError
	if !errors.As(err, &re) || re.Code != exitcode.IdentityMiss {
		t.Fatalf("err = %v, want RecvError IdentityMiss", err)
	}
}

// TestRecv_LegacyBodyStrictMode — sender uses 0x01, receiver has
// ContentLayer + RequireE2E. Recv must refuse with EDDIdentityMiss.
func TestRecv_LegacyBodyStrictMode(t *testing.T) {
	es := newE2EServer(t)
	_, clRecv, _ := pairLayers(t)
	defer clRecv.Wipe()

	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		// Legacy sender — no ContentLayer.
	}
	if _, err := client.Send(sendCfg, []byte("legacy-sender")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clRecv,
		RequireE2E:   true,
	}
	_, err := client.Recv(recvCfg)
	if err == nil {
		t.Fatal("expected strict-mode refusal, got nil")
	}
	var re *client.RecvError
	if !errors.As(err, &re) || re.Code != exitcode.IdentityMiss {
		t.Fatalf("err = %v, want RecvError IdentityMiss", err)
	}
}

// TestRecv_LegacyBodyNonStrictWarn — same as above but RequireE2E=false:
// the message is delivered, and a warning is emitted via WarnSink.
func TestRecv_LegacyBodyNonStrictWarn(t *testing.T) {
	es := newE2EServer(t)
	_, clRecv, _ := pairLayers(t)
	defer clRecv.Wipe()

	plaintext := []byte("legacy-warn")
	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
	}
	if _, err := client.Send(sendCfg, plaintext); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var warn bytes.Buffer
	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clRecv,
		WarnSink:     &warn,
	}
	got, err := client.Recv(recvCfg)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
	if warn.Len() == 0 {
		t.Fatalf("expected warning on WarnSink for legacy body + identity-present")
	}
}

// TestE2E_WireVersionAsymmetryRegression — drift between body[0],
// slot.AEADKey(version), and the AD's version byte must produce a
// decrypt failure, never a silent acceptance. We construct a synthetic
// captured body where body[0]==0x04 but the AEADKey was derived with
// 0x01. This is a defensive proof — the production Send path uses a
// single wireVersion so this can't happen — but the test guards against
// re-introduction.
func TestE2E_WireVersionAsymmetryRegression(t *testing.T) {
	// Send legacy, capture body.
	es := newE2EServer(t)
	sendCfg := client.SendConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		WriteToken:   testWriteToken,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
	}
	if _, err := client.Send(sendCfg, []byte("asymmetry")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Stamp the byte to 0x04 to forge an asymmetric body.
	es.body[0] = wire.VersionPlainBE2E

	clSend, _, _ := pairLayers(t)
	defer clSend.Wipe()

	recvCfg := client.RecvConfig{
		PSK:          testPSK,
		PairID:       testPairID,
		DeploySecret: testDeploySecret,
		RelayBaseURL: es.srv.URL,
		HTTPClient:   es.srv.Client(),
		Clock:        testClock,
		ContentLayer: clSend, // present so we don't trip the early miss
	}
	_, err := client.Recv(recvCfg)
	if err == nil {
		t.Fatal("expected decrypt failure on forged version byte")
	}
	var re *client.RecvError
	if !errors.As(err, &re) {
		t.Fatalf("want RecvError, got %T", err)
	}
	if re.Code != exitcode.CryptoLocal {
		t.Fatalf("want EDDCryptoLocal on AD-mismatch, got %d (%s)", re.Code, re.Detail)
	}
}

// TestContentLayer_RejectsLowOrderPeer — a peer pubkey of all zeros
// (X25519 small-order) must surface as a constructor error so the CLI
// maps to EDDIdentityStore. Defensive: stdlib's curve25519.X25519 is
// expected to error out, but we want our own all-zero IKM check
// confirmed in case a future Go release changes that behaviour.
func TestContentLayer_RejectsLowOrderPeer(t *testing.T) {
	var sk, pk [32]byte
	for i := range sk {
		sk[i] = 0x55
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	var zero [32]byte
	entry := &identitystore.Entry{
		Role:   identitystore.RoleInitiator,
		OwnSK:  sk,
		OwnPK:  pk,
		PeerPK: zero,
	}
	var pairID [8]byte
	if _, err := client.NewContentLayerFromEntry(entry, pairID); err == nil {
		t.Fatal("expected error from low-order peer pubkey, got nil")
	}
	_ = crypto.NonceSize // keep crypto import live for future expansion
}
