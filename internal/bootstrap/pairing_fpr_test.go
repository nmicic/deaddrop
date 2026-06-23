// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func fprInputs() (psk [32]byte, pairID [8]byte, iPK, rPK [32]byte) {
	for i := range psk {
		psk[i] = 0x01
	}
	for i := range pairID {
		pairID[i] = 0x02
	}
	for i := range iPK {
		iPK[i] = 0x03
	}
	for i := range rPK {
		rPK[i] = 0x04
	}
	return
}

func TestPairingFingerprint_Canonical(t *testing.T) {
	psk, pairID, iPK, rPK := fprInputs()

	fpr1, err := PairingFingerprint(psk, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}
	if len(fpr1) != PairingFPRSize {
		t.Fatalf("len = %d, want %d", len(fpr1), PairingFPRSize)
	}

	fpr2, err := PairingFingerprint(psk, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fpr1, fpr2) {
		t.Fatal("not deterministic")
	}
}

func TestPairingFingerprint_Binding(t *testing.T) {
	psk, pairID, iPK, rPK := fprInputs()

	base, err := PairingFingerprint(psk, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}

	// vary PSK
	var psk2 [32]byte
	copy(psk2[:], psk[:])
	psk2[0] = 0xFF
	fpr, err := PairingFingerprint(psk2, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fpr, base) {
		t.Error("PSK variation produced same FPR")
	}

	// vary pairID
	var pid2 [8]byte
	copy(pid2[:], pairID[:])
	pid2[0] = 0xFF
	fpr, err = PairingFingerprint(psk, pid2, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fpr, base) {
		t.Error("pairID variation produced same FPR")
	}

	// vary initiatorPK
	var iPK2 [32]byte
	copy(iPK2[:], iPK[:])
	iPK2[0] = 0xFF
	fpr, err = PairingFingerprint(psk, pairID, iPK2, rPK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fpr, base) {
		t.Error("initiatorPK variation produced same FPR")
	}

	// vary responderPK
	var rPK2 [32]byte
	copy(rPK2[:], rPK[:])
	rPK2[0] = 0xFF
	fpr, err = PairingFingerprint(psk, pairID, iPK, rPK2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fpr, base) {
		t.Error("responderPK variation produced same FPR")
	}

	// pubkey order variation
	fpr, err = PairingFingerprint(psk, pairID, rPK, iPK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fpr, base) {
		t.Error("pubkey-order swap produced same FPR")
	}
}

func TestFormatPairingFPR_Groups(t *testing.T) {
	fpr := make([]byte, PairingFPRSize)
	for i := range fpr {
		fpr[i] = byte(i * 17)
	}
	s := FormatPairingFPR(fpr)

	if strings.Count(s, " ") != 4 {
		t.Fatalf("expected 4 spaces, got %d in %q", strings.Count(s, " "), s)
	}
	groups := strings.Split(s, " ")
	wantLens := []int{6, 6, 6, 6, 8}
	for i, g := range groups {
		if len(g) != wantLens[i] {
			t.Errorf("group %d: len=%d, want %d", i, len(g), wantLens[i])
		}
		if _, err := hex.DecodeString(g); err != nil {
			t.Errorf("group %d: not valid hex: %q", i, g)
		}
	}
}

func TestFormatPairingFPR_PanicOnBadInput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for 15-byte input")
		}
	}()
	FormatPairingFPR(make([]byte, 15))
}

// TestPairingFingerprint_CrossRoleSymmetry — D-67 reconstruction:
// given an identity entry stored on EITHER side, the side reconstructs
// (initiatorPK, responderPK) from (Role, OwnPK, PeerPK) and the
// resulting fingerprints must agree byte-for-byte.
func TestPairingFingerprint_CrossRoleSymmetry(t *testing.T) {
	psk, pairID, iPK, rPK := fprInputs()

	// Initiator's stored entry: OwnPK=iPK, PeerPK=rPK, Role=Initiator.
	// Reconstruction: initPK=OwnPK, respPK=PeerPK.
	fprFromInitiator, err := PairingFingerprint(psk, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}

	// Responder's stored entry: OwnPK=rPK, PeerPK=iPK, Role=Responder.
	// Reconstruction: initPK=PeerPK, respPK=OwnPK — same final tuple.
	respOwnPK := rPK
	respPeerPK := iPK
	fprFromResponder, err := PairingFingerprint(psk, pairID, respPeerPK, respOwnPK)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fprFromInitiator, fprFromResponder) {
		t.Fatalf("cross-role fingerprints disagree: initiator=%x responder=%x",
			fprFromInitiator, fprFromResponder)
	}
}

func TestPairingFingerprint_GoldenVector(t *testing.T) {
	psk, pairID, iPK, rPK := fprInputs()
	fpr, err := PairingFingerprint(psk, pairID, iPK, rPK)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(fpr)
	want := "4bde68274f6b160fddb3baaec2ecf687"
	if got != want {
		t.Fatalf("golden vector mismatch: got %s, want %s", got, want)
	}
}
