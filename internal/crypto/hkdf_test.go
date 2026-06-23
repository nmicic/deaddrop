// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nmicic/deaddrop/internal/crypto"
)

// hkdfAEADKeyFixture is the ad_binding.json fixture, re-embedded here so
// the HKDF test can pull the canonical aead_key_hex without importing
// state from aead_test.go (keeping test files independently readable).
//
//go:embed testdata/aead/ad_binding.json
var hkdfAEADKeyFixture []byte

// canonicalAEADKeyCase extracts the "canonical" case from the embedded
// ad_binding fixture.
func canonicalAEADKeyCase(t *testing.T) (aeadKeyHex, aadHex string) {
	t.Helper()
	var vf vectorFile
	if err := json.Unmarshal(hkdfAEADKeyFixture, &vf); err != nil {
		t.Fatalf("unmarshal ad_binding: %v", err)
	}
	for _, c := range vf.Cases {
		if c.Name == "canonical" {
			return c.Inputs.AEADKeyHex, c.Inputs.AADHex
		}
	}
	t.Fatalf("canonical case not found")
	return "", ""
}

// TestDeriveKey_AEADKey derives aead_key via the exact formula from
// SPEC_DRAFT_B_capsule.md §2 and asserts byte equality with the
// canonical value carried in ad_binding.json.
//
// Formula:
//
//	aead_key = HKDF-SHA256(
//	    secret = PSK,
//	    salt   = slot_id_bytes(16),
//	    info   = "deaddrop-v1-B" || pair_id(8) || service_id_bytes(16) || version(1),
//	    length = 32,
//	)
//
// PSK (0x02×32) and pair_id (0x03×8) are the canonical test inputs
// published in testdata/derive/slot_key.json. service_id,
// slot_id, and version are the first 16, next 16, and final byte of the
// 33-byte canonical AD in ad_binding.json.
func TestDeriveKey_AEADKey(t *testing.T) {
	aeadKeyHex, aadHex := canonicalAEADKeyCase(t)
	aad, err := hex.DecodeString(aadHex)
	if err != nil {
		t.Fatalf("decode aad_hex: %v", err)
	}
	if len(aad) != 33 {
		t.Fatalf("canonical AD length: got %d, want 33", len(aad))
	}
	want, err := hex.DecodeString(aeadKeyHex)
	if err != nil {
		t.Fatalf("decode aead_key_hex: %v", err)
	}

	serviceID := aad[0:16]
	slotID := aad[16:32]
	version := aad[32:33]

	psk := bytes.Repeat([]byte{0x02}, 32)
	pairID := bytes.Repeat([]byte{0x03}, 8)

	info := make([]byte, 0, 13+len(pairID)+len(serviceID)+len(version))
	info = append(info, []byte("deaddrop-v1-B")...)
	info = append(info, pairID...)
	info = append(info, serviceID...)
	info = append(info, version...)
	if len(info) != 38 {
		t.Fatalf("info length: got %d, want 38", len(info))
	}

	got, err := crypto.DeriveKey(psk, slotID, info, 32)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aead_key mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestDeriveKey_EmptySalt confirms that nil and empty salts are accepted
// (RFC 5869 §2.2: substitute HashLen zero bytes).
func TestDeriveKey_EmptySalt(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	info := []byte("test")

	nilOut, err := crypto.DeriveKey(secret, nil, info, 32)
	if err != nil {
		t.Fatalf("DeriveKey(nil salt): %v", err)
	}
	if len(nilOut) != 32 {
		t.Fatalf("nil-salt length: got %d, want 32", len(nilOut))
	}

	emptyOut, err := crypto.DeriveKey(secret, []byte{}, info, 32)
	if err != nil {
		t.Fatalf("DeriveKey(empty salt): %v", err)
	}
	if !bytes.Equal(nilOut, emptyOut) {
		t.Fatalf("nil and empty salt must produce identical output")
	}
}

// TestDeriveKey_ZeroLength rejects length <= 0 with ErrHKDFLength.
func TestDeriveKey_ZeroLength(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)

	for _, n := range []int{0, -1, -32} {
		n := n
		_, err := crypto.DeriveKey(secret, nil, nil, n)
		if !errors.Is(err, crypto.ErrHKDFLength) {
			t.Errorf("DeriveKey(length=%d): want ErrHKDFLength, got %v", n, err)
		}
	}
}

// TestDeriveKey_Deterministic verifies identical inputs yield identical
// outputs across two independent calls.
func TestDeriveKey_Deterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	salt := bytes.Repeat([]byte{0x22}, 16)
	info := []byte("deaddrop-deterministic-test")

	a, err := crypto.DeriveKey(secret, salt, info, 64)
	if err != nil {
		t.Fatalf("DeriveKey a: %v", err)
	}
	b, err := crypto.DeriveKey(secret, salt, info, 64)
	if err != nil {
		t.Fatalf("DeriveKey b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("DeriveKey not deterministic")
	}
}
