// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/slot"
)

func assertLeg3Error(t *testing.T, err error, wantCode int, wantDetail string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var le *Leg3Error
	if !errors.As(err, &le) {
		t.Fatalf("expected *Leg3Error, got %T: %v", err, err)
	}
	if le.Code != wantCode {
		t.Errorf("error code: got %d, want %d", le.Code, wantCode)
	}
	if le.Detail != wantDetail {
		t.Errorf("error detail: got %q, want %q", le.Detail, wantDetail)
	}
}

func deriveSK(pattern byte) [32]byte {
	var sk [32]byte
	for i := range sk {
		sk[i] = pattern + byte(i)
	}
	return sk
}

func pkFrom(sk [32]byte) [32]byte {
	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk
}

type leg3Keys struct {
	skI, pkI [32]byte
	skR, pkR [32]byte
	ephSK    [32]byte
	ephPK    [32]byte
}

func newLeg3Keys(t *testing.T) leg3Keys {
	t.Helper()
	var k leg3Keys
	var err error
	k.skI, k.pkI, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	k.skR, k.pkR, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	k.ephSK, k.ephPK, err = GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Test 1
func TestGenerateEphemeral(t *testing.T) {
	sk1, pk1, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	var zero [32]byte
	if pk1 == zero {
		t.Fatal("ephemeral pk is zero")
	}
	if IsLowOrderPoint(pk1) {
		t.Fatal("ephemeral pk is low-order")
	}
	if sk1 == zero {
		t.Fatal("ephemeral sk is zero")
	}
	sk2, pk2, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	if pk1 == pk2 {
		t.Fatal("two calls produced identical ephemeral pk (randomness?)")
	}
	if sk1 == sk2 {
		t.Fatal("two calls produced identical ephemeral sk (randomness?)")
	}
}

// Test 2
func TestLeg3SlotRoot_OrderMatters(t *testing.T) {
	_, pkA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, pkB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r1, err := Leg3SlotRoot(pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Leg3SlotRoot(pkB, pkA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(r1, r2) {
		t.Fatal("Leg3SlotRoot is symmetric in its args; expected order to matter")
	}
}

// Test 3
func TestLeg3SlotRoot_Deterministic(t *testing.T) {
	_, pkA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, pkB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r1, err := Leg3SlotRoot(pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Leg3SlotRoot(pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1, r2) {
		t.Fatal("Leg3SlotRoot not deterministic")
	}
}

// Test 4
func TestLeg3SlotID_DelegatesToSlotID(t *testing.T) {
	_, pkA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, pkB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root, err := Leg3SlotRoot(pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	b := uint64(123456)
	got, err := Leg3SlotID(root, b)
	if err != nil {
		t.Fatal(err)
	}
	want, err := slot.SlotID(root, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Leg3SlotID != slot.SlotID(..,0): got %x, want %x", got, want)
	}
}

// Test 5
func TestDeriveBodyKey_RoundTrip(t *testing.T) {
	k := newLeg3Keys(t)
	senderKey, err := DeriveBodyKey(k.ephSK, k.pkI, k.skR, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	receiverKey, err := DeriveBodyKeyFromEphPK(k.ephPK, k.pkR, k.skI, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(senderKey, receiverKey) {
		t.Fatalf("sender/receiver body keys differ:\n  sender   = %x\n  receiver = %x", senderKey, receiverKey)
	}
}

// Test 6
func TestDeriveBodyKey_DifferentEphemeral(t *testing.T) {
	k := newLeg3Keys(t)
	key1, err := DeriveBodyKey(k.ephSK, k.pkI, k.skR, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	ephSK2, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveBodyKey(ephSK2, k.pkI, k.skR, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("body key did not change with a different ephemeral keypair")
	}
}

// Test 7
func TestDeriveBodyKeyFromEphPK_ZeroDH_EphOnly(t *testing.T) {
	k := newLeg3Keys(t)
	var zeroEphPK [32]byte
	_, err := DeriveBodyKeyFromEphPK(zeroEphPK, k.pkR, k.skI, k.pkI, k.pkR)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "dh-zero")
}

// Test 8
func TestDeriveBodyKeyFromEphPK_ZeroDH_StaticOnly(t *testing.T) {
	k := newLeg3Keys(t)
	var zeroPeerPK [32]byte
	_, err := DeriveBodyKeyFromEphPK(k.ephPK, zeroPeerPK, k.skI, k.pkI, k.pkR)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "dh-zero")
}

// Test 8b — frozen on first run; do not modify without regenerating.
const knownVectorBodyKeyHex = "8a7ca703b5c4cdf0dce47c66247d21c02446127b97c93f4e705bfac7e4043da1"

func TestDeriveBodyKey_KnownVector(t *testing.T) {
	ephSK := deriveSK(0x01)
	skI := deriveSK(0x21)
	skR := deriveSK(0x41)
	pkI := pkFrom(skI)
	pkR := pkFrom(skR)

	got, err := DeriveBodyKey(ephSK, pkI, skR, pkI, pkR)
	if err != nil {
		t.Fatal(err)
	}
	gotHex := hex.EncodeToString(got)
	if gotHex != knownVectorBodyKeyHex {
		t.Fatalf("body_key mismatch:\n  got  %s\n  want %s", gotHex, knownVectorBodyKeyHex)
	}
}

// Test 8c
func TestDeriveBodyKey_InfoPubkeyOrderMatters(t *testing.T) {
	k := newLeg3Keys(t)
	keyAB, err := DeriveBodyKey(k.ephSK, k.pkI, k.skR, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	keyBA, err := DeriveBodyKey(k.ephSK, k.pkI, k.skR, k.pkR, k.pkI)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyAB, keyBA) {
		t.Fatal("DeriveBodyKey is symmetric in initiator/responder info args; expected order to matter")
	}
}

// Test 8d
func TestDeriveBodyKey_ZeroDH_Combined(t *testing.T) {
	k := newLeg3Keys(t)
	var zeroPeerPK [32]byte
	_, err := DeriveBodyKey(k.ephSK, zeroPeerPK, k.skR, k.pkI, k.pkR)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "dh-zero")
}

func testLeg3SenderKey(t *testing.T, k leg3Keys) []byte {
	t.Helper()
	bk, err := DeriveBodyKey(k.ephSK, k.pkI, k.skR, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	return bk
}

func testLeg3ReceiverKey(t *testing.T, k leg3Keys) []byte {
	t.Helper()
	bk, err := DeriveBodyKeyFromEphPK(k.ephPK, k.pkR, k.skI, k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	return bk
}

func testLeg3Slot(t *testing.T, k leg3Keys) []byte {
	t.Helper()
	root, err := Leg3SlotRoot(k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := Leg3SlotID(root, 6000)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// Test 9
func TestSealOpen_Leg3_RoundTrip(t *testing.T) {
	k := newLeg3Keys(t)
	senderKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	for i := range pairID {
		pairID[i] = byte(0xA0 + i)
	}
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		t.Fatal(err)
	}

	body, err := SealLeg3(senderKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}

	receiverKey := testLeg3ReceiverKey(t, k)
	gotPairID, gotPSK, err := OpenLeg3(receiverKey, serviceID, slotID, k.ephPK, body)
	if err != nil {
		t.Fatal(err)
	}
	if gotPairID != pairID {
		t.Fatalf("pair_id mismatch: got %x, want %x", gotPairID, pairID)
	}
	if gotPSK != psk {
		t.Fatalf("psk mismatch: got %x, want %x", gotPSK, psk)
	}
}

// Test 10
func TestOpenLeg3_WrongVersion(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 0x02
	_, _, err = OpenLeg3(bodyKey, serviceID, slotID, k.ephPK, body)
	assertLeg3Error(t, err, exitcode.CryptoLocal, "version mismatch")
}

// Test 11
func TestOpenLeg3_BodyTooShort(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	_, _, err := OpenLeg3(bodyKey, serviceID, slotID, k.ephPK, make([]byte, 10))
	assertLeg3Error(t, err, exitcode.CryptoLocal, "body too short")
}

// Test 12
func TestOpenLeg3_WrongBodyKey(t *testing.T) {
	k := newLeg3Keys(t)
	senderKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(senderKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}

	// A different keypair set → a different body key.
	k2 := newLeg3Keys(t)
	wrongKey := testLeg3SenderKey(t, k2)
	_, _, err = OpenLeg3(wrongKey, serviceID, slotID, k.ephPK, body)
	var le *Leg3Error
	if !errors.As(err, &le) {
		t.Fatalf("expected *Leg3Error, got %T: %v", err, err)
	}
	if le.Code != exitcode.BootstrapMITM {
		t.Errorf("error code: got %d, want %d", le.Code, exitcode.BootstrapMITM)
	}
}

// Test 13
func TestOpenLeg3_CorruptCiphertext(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext region (bytes 57..113).
	body[70] ^= 0xff
	_, _, err = OpenLeg3(bodyKey, serviceID, slotID, k.ephPK, body)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "aead open failed")
}

// Test 14
func TestOpenLeg3_WrongServiceID(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceIDA := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceIDA, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}
	serviceIDB, err := slot.ServiceID(testDeploySecret(), 200)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = OpenLeg3(bodyKey, serviceIDB, slotID, k.ephPK, body)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "aead open failed")
}

// Test 15
func TestOpenLeg3_WrongSlotID(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotIDA := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceID, slotIDA, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}
	root, err := Leg3SlotRoot(k.pkI, k.pkR)
	if err != nil {
		t.Fatal(err)
	}
	slotIDB, err := Leg3SlotID(root, 7000)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = OpenLeg3(bodyKey, serviceID, slotIDB, k.ephPK, body)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "aead open failed")
}

// Test 16
func TestOpenLeg3_EphPKMismatch(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}

	_, otherEphPK, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = OpenLeg3(bodyKey, serviceID, slotID, otherEphPK, body)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "eph-pk-mismatch")
}

// Test 16b
func TestOpenLeg3_EphPKLowOrder(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	// Build a 113-byte body with version=0x03 and ephPK=all-zero (low-order).
	body := make([]byte, Leg3BodySize)
	body[0] = Leg3Version
	// body[1:33] = all-zero (already zeroed by make)
	// remaining bytes also zero — AEAD would fail, but step 3a fires first.

	var zeroEph [32]byte
	_, _, err := OpenLeg3(bodyKey, serviceID, slotID, zeroEph, body)
	assertLeg3Error(t, err, exitcode.BootstrapMITM, "eph-pk-invalid")
}

// Test 17
func TestSealLeg3_BodySize(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	var pairID [8]byte
	var psk [32]byte
	body, err := SealLeg3(bodyKey, serviceID, slotID, k.ephPK, pairID, psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 113 {
		t.Fatalf("body size: got %d, want 113", len(body))
	}
}

// Test 18
func TestLeg3_ADLayout(t *testing.T) {
	serviceID, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	slotID, _ := hex.DecodeString("1112131415161718191a1b1c1d1e1f20")
	var ephPK [32]byte
	for i := range ephPK {
		ephPK[i] = byte(0x30 + i)
	}

	ad := leg3AD(serviceID, slotID, ephPK)

	if len(ad) != 69 {
		t.Fatalf("AD length: got %d, want 69", len(ad))
	}
	if !bytes.Equal(ad[0:16], serviceID) {
		t.Error("AD[0:16] != serviceID")
	}
	if !bytes.Equal(ad[16:32], slotID) {
		t.Error("AD[16:32] != slotID")
	}
	if ad[32] != 0x03 {
		t.Errorf("AD[32] = %#02x, want 0x03", ad[32])
	}
	if !bytes.Equal(ad[33:65], ephPK[:]) {
		t.Errorf("AD[33:65] != ephPK")
	}
	if !bytes.Equal(ad[65:69], []byte("leg3")) {
		t.Errorf("AD[65:69] = %q, want %q", ad[65:69], "leg3")
	}
}

// Test 19
func TestOpenLeg3_Fuzz10k(t *testing.T) {
	k := newLeg3Keys(t)
	bodyKey := testLeg3SenderKey(t, k)
	serviceID := testServiceID(t)
	slotID := testLeg3Slot(t, k)

	for i := 0; i < 10_000; i++ {
		n := i % 201
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		_, _, err := OpenLeg3(bodyKey, serviceID, slotID, k.ephPK, buf)
		if err == nil {
			t.Fatalf("iteration %d: expected error for random input of length %d", i, n)
		}
	}
}
