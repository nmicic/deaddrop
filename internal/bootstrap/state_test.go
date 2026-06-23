// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/nmicic/deaddrop/internal/slot"
)

func TestBootstrapSalt(t *testing.T) {
	h := sha256.Sum256([]byte("deaddrop-bootstrap-v1"))
	var want [16]byte
	copy(want[:], h[:16])
	got := BootstrapSalt()
	if got != want {
		t.Fatalf("BootstrapSalt mismatch: got %x, want %x", got, want)
	}
}

func TestDerivePassphraseKey(t *testing.T) {
	k1 := DerivePassphraseKey([]byte("test-passphrase"))
	if len(k1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(k1))
	}
	k2 := DerivePassphraseKey([]byte("test-passphrase"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("DerivePassphraseKey not deterministic")
	}
	k3 := DerivePassphraseKey([]byte("other-passphrase"))
	if bytes.Equal(k1, k3) {
		t.Fatal("different passphrases produced same key")
	}
}

func TestDerivePassphraseKey_KnownVector(t *testing.T) {
	got := DerivePassphraseKey([]byte("deaddrop-bootstrap-test-vector"))
	want, _ := hex.DecodeString("26b4826078f0fdad77ffbb002140413d58d1a8c578d34ceeb9d800eeb7be3ff0")
	if !bytes.Equal(got, want) {
		t.Fatalf("known vector mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func TestGenerateIdentity(t *testing.T) {
	sk1, pk1, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if pk1 == [32]byte{} {
		t.Fatal("pubkey is zero")
	}
	if IsLowOrderPoint(pk1) {
		t.Fatal("pubkey is low-order")
	}
	_ = sk1

	_, pk2, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity second call: %v", err)
	}
	if pk1 == pk2 {
		t.Fatal("two calls produced identical keys")
	}
}

func TestIsLowOrderPoint_AllFourteen(t *testing.T) {
	if len(lowOrderPoints) != 14 {
		t.Fatalf("expected 14 low-order points, got %d", len(lowOrderPoints))
	}
	for i, pt := range lowOrderPoints {
		if !IsLowOrderPoint(pt) {
			t.Errorf("point %d (%x) not detected as low-order", i, pt)
		}
	}
}

func TestIsLowOrderPoint_ValidKey(t *testing.T) {
	_, pk, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if IsLowOrderPoint(pk) {
		t.Fatal("valid key falsely detected as low-order")
	}
}

func TestIsLowOrderPoint_Order8Verification(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	bigA := big.NewInt(486662)

	order8Canonical := [][32]byte{lowOrderPoints[10], lowOrderPoints[12]}

	for idx, pt := range order8Canonical {
		cleaned := pt
		cleaned[31] &= 0x7f

		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = cleaned[31-i]
		}
		u := new(big.Int).SetBytes(rev)

		u2 := new(big.Int).Mul(u, u)
		u2.Mod(u2, p)
		u3 := new(big.Int).Mul(u2, u)
		u3.Mod(u3, p)
		au2 := new(big.Int).Mul(bigA, u2)
		au2.Mod(au2, p)
		rhs := new(big.Int).Add(u3, au2)
		rhs.Add(rhs, u)
		rhs.Mod(rhs, p)
		exp := new(big.Int).Sub(p, big.NewInt(1))
		exp.Rsh(exp, 1)
		euler := new(big.Int).Exp(rhs, exp, p)
		if euler.Cmp(big.NewInt(1)) != 0 && rhs.Sign() != 0 {
			t.Errorf("order-8 point %d: u^3+Au^2+u is not a QR mod p (not on curve)", idx)
		}

		for _, variant := range [][32]byte{pt, lowOrderPoints[10+idx*2+1]} {
			for s := 0; s < 3; s++ {
				var scalar, dst [32]byte
				scalar[3] = byte(s + 1)
				scalar[1] = byte(idx + 1)
				// Intentionally uses ScalarMult (not X25519): this test asserts the
				// low-order-point all-zeroes behavior that ScalarMult exhibits.
				curve25519.ScalarMult(&dst, &scalar, &variant) //nolint:staticcheck // SA1019: low-order zeroing is the property under test
				if dst != ([32]byte{}) {
					t.Errorf("order-8 point %d variant %x: X25519 result not zero for scalar %d", idx, variant[31], s)
				}
			}
		}
	}
}

func TestLegKey_DirectionDiffers(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-passphrase"))
	defer zeroize(pk)

	k0, err := LegKey(pk, 0x00)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := LegKey(pk, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k0, k1) {
		t.Fatal("leg keys for different directions are identical")
	}
}

func TestLegSlotKey_DirectionDiffers(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-passphrase"))
	defer zeroize(pk)

	k0, err := LegSlotKey(pk, 0x00)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := LegSlotKey(pk, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k0, k1) {
		t.Fatal("slot keys for different directions are identical")
	}
}

func TestLegKey_LegSlotKey_DomainSeparation(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-passphrase"))
	defer zeroize(pk)

	legK, err := LegKey(pk, 0x00)
	if err != nil {
		t.Fatal(err)
	}
	slotK, err := LegSlotKey(pk, 0x00)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legK, slotK) {
		t.Fatal("LegKey and LegSlotKey produced same output for same direction")
	}
}

func TestLegSlotID_DelegatesToSlotID(t *testing.T) {
	pk := DerivePassphraseKey([]byte("test-passphrase"))
	defer zeroize(pk)

	sk, err := LegSlotKey(pk, 0x00)
	if err != nil {
		t.Fatal(err)
	}
	var b uint64 = 12345
	got, err := LegSlotID(sk, b)
	if err != nil {
		t.Fatal(err)
	}
	want, err := slot.SlotID(sk, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("LegSlotID does not match slot.SlotID with attempt=0")
	}
}

func TestState_Zeroize(t *testing.T) {
	s := &State{
		IdentitySK:    [32]byte{1, 2, 3},
		IdentityPK:    [32]byte{4, 5, 6},
		PeerPK:        [32]byte{7, 8, 9},
		PassphraseKey: []byte{10, 11, 12, 13},
	}
	s.Zeroize()
	if s.IdentitySK != ([32]byte{}) {
		t.Error("IdentitySK not zeroed")
	}
	if s.PeerPK != ([32]byte{}) {
		t.Error("PeerPK not zeroed")
	}
	for _, b := range s.PassphraseKey {
		if b != 0 {
			t.Error("PassphraseKey not zeroed")
			break
		}
	}
}

// TestState_ZeroizeBootstrap_LeavesIdentity asserts the D-65 split:
// ZeroizeBootstrap clears PassphraseKey only, never the identity
// fields. CLI callers rely on this so FinishBootstrap can still see
// IdentitySK / IdentityPK / PeerPK after the leg work finished.
func TestState_ZeroizeBootstrap_LeavesIdentity(t *testing.T) {
	s := &State{
		IdentitySK:    [32]byte{1, 2, 3},
		IdentityPK:    [32]byte{4, 5, 6},
		PeerPK:        [32]byte{7, 8, 9},
		PassphraseKey: []byte{10, 11, 12, 13},
	}
	s.ZeroizeBootstrap()
	for _, b := range s.PassphraseKey {
		if b != 0 {
			t.Error("PassphraseKey not zeroed by ZeroizeBootstrap")
			break
		}
	}
	if s.IdentitySK == ([32]byte{}) {
		t.Error("IdentitySK was unexpectedly cleared by ZeroizeBootstrap")
	}
	if s.IdentityPK == ([32]byte{}) {
		t.Error("IdentityPK was unexpectedly cleared by ZeroizeBootstrap")
	}
	if s.PeerPK == ([32]byte{}) {
		t.Error("PeerPK was unexpectedly cleared by ZeroizeBootstrap")
	}
}

// TestState_ZeroizeIdentity_ClearsAllFields asserts the asymmetry
// fix: IdentityPK is now cleared (the original Zeroize left it).
func TestState_ZeroizeIdentity_ClearsAllFields(t *testing.T) {
	s := &State{
		IdentitySK: [32]byte{1, 2, 3},
		IdentityPK: [32]byte{4, 5, 6},
		PeerPK:     [32]byte{7, 8, 9},
	}
	s.ZeroizeIdentity()
	if s.IdentitySK != ([32]byte{}) {
		t.Error("IdentitySK not zeroed")
	}
	if s.IdentityPK != ([32]byte{}) {
		t.Error("IdentityPK not zeroed (D-65 asymmetry fix regressed)")
	}
	if s.PeerPK != ([32]byte{}) {
		t.Error("PeerPK not zeroed")
	}
}
