// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/slot"
)

func testDeploySecret() []byte {
	ds := make([]byte, 32)
	for i := range ds {
		ds[i] = byte(i + 1)
	}
	return ds
}

func testServiceID(t *testing.T) []byte {
	t.Helper()
	sid, err := slot.ServiceID(testDeploySecret(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func testLeg12Setup(t *testing.T, passphrase string, direction byte) (legKey, serviceID, slotID []byte) {
	t.Helper()
	pk := DerivePassphraseKey([]byte(passphrase))
	legKey, err := LegKey(pk, direction)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := LegSlotKey(pk, direction)
	if err != nil {
		t.Fatal(err)
	}
	serviceID = testServiceID(t)
	slotID, err = LegSlotID(sk, 6000)
	if err != nil {
		t.Fatal(err)
	}
	return legKey, serviceID, slotID
}

func sealLeg12Raw(legKey, serviceID, slotID []byte, direction byte, plaintext []byte) ([]byte, error) {
	ad := leg12AD(serviceID, slotID, direction)
	nonce := make([]byte, Leg12NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(legKey, nonce, plaintext, ad)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 1+len(nonce)+len(ct))
	body = append(body, Leg12Version)
	body = append(body, nonce...)
	body = append(body, ct...)
	return body, nil
}

func assertLeg12Error(t *testing.T, err error, wantCode int, wantDetail string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var le *Leg12Error
	if !errors.As(err, &le) {
		t.Fatalf("expected *Leg12Error, got %T: %v", err, err)
	}
	if le.Code != wantCode {
		t.Errorf("error code: got %d, want %d", le.Code, wantCode)
	}
	if le.Detail != wantDetail {
		t.Errorf("error detail: got %q, want %q", le.Detail, wantDetail)
	}
}

func TestSealOpen_Leg1_RoundTrip(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, body)
	if err != nil {
		t.Fatal(err)
	}
	if got != pk {
		t.Fatal("round-trip pubkey mismatch")
	}
}

func TestSealOpen_Leg2_RoundTrip(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirResponderToInitiator)

	body, err := SealLeg12(legKey, serviceID, slotID, DirResponderToInitiator, pk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenLeg12(legKey, serviceID, slotID, DirResponderToInitiator, body)
	if err != nil {
		t.Fatal(err)
	}
	if got != pk {
		t.Fatal("round-trip pubkey mismatch")
	}
}

func TestOpenLeg12_WrongVersion(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 0x01
	_, err = OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.CryptoLocal, "version mismatch")
}

func TestOpenLeg12_BodyTooShort(t *testing.T) {
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)
	_, err := OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, make([]byte, 10))
	assertLeg12Error(t, err, exitcode.CryptoLocal, "body too short")
}

func TestOpenLeg12_WrongPassphrase(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKeyA, serviceID, slotID := testLeg12Setup(t, "passphrase-A", DirInitiatorToResponder)

	body, err := SealLeg12(legKeyA, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}

	legKeyB, _, _ := testLeg12Setup(t, "passphrase-B", DirInitiatorToResponder)
	_, err = OpenLeg12(legKeyB, serviceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestOpenLeg12_WrongDirection(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenLeg12(legKey, serviceID, slotID, DirResponderToInitiator, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestOpenLeg12_ReservedDirection(t *testing.T) {
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)
	body := make([]byte, Leg12BodySize)
	body[0] = Leg12Version
	for _, d := range []byte{0x02, 0x03, 0x10, 0x7F, 0x80, 0xFF} {
		_, err := OpenLeg12(legKey, serviceID, slotID, d, body)
		assertLeg12Error(t, err, exitcode.CryptoLocal, "reserved-direction-codepoint")
	}
}

func TestOpenLeg12_CorruptCiphertext(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}
	body[30] ^= 0xff
	_, err = OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestOpenLeg12_WrongServiceID(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceIDA, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceIDA, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}

	serviceIDB, _ := slot.ServiceID(testDeploySecret(), 200)
	_, err = OpenLeg12(legKey, serviceIDB, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestOpenLeg12_WrongSlotID(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotIDA := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotIDA, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}

	ppk := DerivePassphraseKey([]byte("test-passphrase"))
	sk, _ := LegSlotKey(ppk, DirInitiatorToResponder)
	slotIDB, _ := LegSlotID(sk, 7000)
	_, err = OpenLeg12(legKey, serviceID, slotIDB, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestOpenLeg12_LowOrderPubkey(t *testing.T) {
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := sealLeg12Raw(legKey, serviceID, slotID, DirInitiatorToResponder, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "pubkey-invalid")
}

func TestOpenLeg12_ShortBody_FromShortPlaintext(t *testing.T) {
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := sealLeg12Raw(legKey, serviceID, slotID, DirInitiatorToResponder, make([]byte, 31))
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.CryptoLocal, "body too short")
}

func TestOpenLeg12_ADBinding(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}

	altServiceID, _ := slot.ServiceID(testDeploySecret(), 999)
	_, err = OpenLeg12(legKey, altServiceID, slotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")

	ppk := DerivePassphraseKey([]byte("test-passphrase"))
	sk, _ := LegSlotKey(ppk, DirInitiatorToResponder)
	altSlotID, _ := LegSlotID(sk, 9999)
	_, err = OpenLeg12(legKey, serviceID, altSlotID, DirInitiatorToResponder, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")

	_, err = OpenLeg12(legKey, serviceID, slotID, DirResponderToInitiator, body)
	assertLeg12Error(t, err, exitcode.BootstrapAuth, "aead open failed")
}

func TestSealLeg12_BodySize(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	body, err := SealLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 73 {
		t.Fatalf("body size: got %d, want 73", len(body))
	}
}

func TestOpenLeg12_Fuzz10k(t *testing.T) {
	legKey, serviceID, slotID := testLeg12Setup(t, "test-passphrase", DirInitiatorToResponder)

	for i := 0; i < 10_000; i++ {
		n := i % 201
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		_, err := OpenLeg12(legKey, serviceID, slotID, DirInitiatorToResponder, buf)
		if err == nil {
			t.Fatalf("iteration %d: expected error for random input of length %d", i, n)
		}
	}
}

func TestLeg12_ADLayout(t *testing.T) {
	serviceID, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	slotID, _ := hex.DecodeString("1112131415161718191a1b1c1d1e1f20")

	ad := leg12AD(serviceID, slotID, DirInitiatorToResponder)

	if len(ad) != 39 {
		t.Fatalf("AD length: got %d, want 39", len(ad))
	}
	if !bytes.Equal(ad[0:16], serviceID) {
		t.Error("AD[0:16] != serviceID")
	}
	if !bytes.Equal(ad[16:32], slotID) {
		t.Error("AD[16:32] != slotID")
	}
	if ad[32] != 0x02 {
		t.Errorf("AD[32] = %#02x, want 0x02", ad[32])
	}
	if ad[33] != 0x00 {
		t.Errorf("AD[33] = %#02x, want 0x00", ad[33])
	}

	ad2 := leg12AD(serviceID, slotID, DirResponderToInitiator)
	if ad2[33] != 0x01 {
		t.Errorf("AD[33] for DirResponderToInitiator = %#02x, want 0x01", ad2[33])
	}

	if !bytes.Equal(ad[34:39], []byte("leg12")) {
		t.Errorf("AD[34:39] = %q, want %q", ad[34:39], "leg12")
	}
}
