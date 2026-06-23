// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package capsule_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
)

// Shared fixed-shape test inputs. Deterministic so each run is
// reproducible without touching crypto/rand for test inputs.
var (
	testPassphrase = []byte("deaddrop-capsule-test")
	testPSK        = bytes.Repeat([]byte{0x42}, capsule.PSKSize)
	testPairID     = bytes.Repeat([]byte{0x17}, capsule.PairIDSize)
)

// cachedCapsuleOnce / cachedCapsule / cachedCapsuleErr back the
// shared "a valid capsule wrapped under testPassphrase" fixture.
// Argon2id at the default §1.1 profile (128 MiB / t=3 / p=4) is
// expensive; caching one wrap across every test and every -count
// repetition keeps `make test -race -count=10` bounded.
var (
	cachedCapsuleOnce sync.Once
	cachedCapsule     []byte
	cachedCapsuleErr  error
)

// validCapsuleCopy returns a fresh copy of the shared wrapped capsule.
// Tests are free to mutate the returned slice.
func validCapsuleCopy(t *testing.T) []byte {
	t.Helper()
	cachedCapsuleOnce.Do(func() {
		cachedCapsule, cachedCapsuleErr = capsule.Wrap(
			testPassphrase, testPSK, testPairID,
		)
	})
	if cachedCapsuleErr != nil {
		t.Fatalf("setup Wrap: %v", cachedCapsuleErr)
	}
	out := make([]byte, len(cachedCapsule))
	copy(out, cachedCapsule)
	return out
}

// synthCapsule builds a 109-byte capsule with valid magic, version,
// and the §1.1 default argon2_params — but with zero salt / nonce /
// wrap_ct / wrap_tag. Sufficient for tests whose rejection path
// (magic / version / size / param validation) short-circuits before
// Argon2id runs. Cheap — no crypto.
func synthCapsule() []byte {
	c := make([]byte, capsule.CapsuleSize)
	copy(c[capsule.OffsetMagic:], []byte(capsule.Magic))
	c[capsule.OffsetVersion] = capsule.Version
	base := capsule.OffsetArgon2Params
	c[base+0] = capsule.DefaultKDFVersion
	c[base+1] = capsule.DefaultMCostLog2
	c[base+2] = capsule.DefaultTCost
	c[base+3] = capsule.DefaultPCost
	c[base+4] = capsule.DefaultKeyLen
	c[base+5] = capsule.DefaultSaltLen
	// params[6..7] (reserved) and all other fields left zero.
	return c
}

// TestWrap_Unwrap_RoundTrip — wrap then unwrap with the same
// passphrase; PSK and pair_id must round-trip byte-identically.
func TestWrap_Unwrap_RoundTrip(t *testing.T) {
	c := validCapsuleCopy(t)
	psk, pairID, err := capsule.Unwrap(testPassphrase, c)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(psk, testPSK) {
		t.Fatalf("PSK mismatch")
	}
	if !bytes.Equal(pairID, testPairID) {
		t.Fatalf("pair_id mismatch")
	}
}

// TestUnwrap_WrongPassphrase — wrong passphrase must return ErrDecrypt
// (opaque; no oracle) and must not panic.
func TestUnwrap_WrongPassphrase(t *testing.T) {
	c := validCapsuleCopy(t)
	_, _, err := capsule.Unwrap([]byte("not-the-right-passphrase"), c)
	if !errors.Is(err, capsule.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

// TestWrap_CapsuleSize — the wrapped capsule is exactly 109 bytes.
func TestWrap_CapsuleSize(t *testing.T) {
	c := validCapsuleCopy(t)
	if len(c) != capsule.CapsuleSize {
		t.Fatalf("len(capsule) = %d, want %d", len(c), capsule.CapsuleSize)
	}
}

// TestWrap_MagicAndVersion — first 4 bytes spell "DDC1", byte 4 is
// 0x01 (§1 and §1.0).
func TestWrap_MagicAndVersion(t *testing.T) {
	c := validCapsuleCopy(t)
	if string(c[capsule.OffsetMagic:capsule.OffsetVersion]) != capsule.Magic {
		t.Fatalf("magic = %q, want %q",
			c[capsule.OffsetMagic:capsule.OffsetVersion], capsule.Magic)
	}
	if c[capsule.OffsetVersion] != capsule.Version {
		t.Fatalf("version = 0x%02x, want 0x%02x",
			c[capsule.OffsetVersion], capsule.Version)
	}
}

// TestUnwrap_BadMagic — any mutation to the magic field is rejected
// before Argon2id runs.
func TestUnwrap_BadMagic(t *testing.T) {
	c := synthCapsule()
	c[capsule.OffsetMagic] ^= 0x01
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

// TestUnwrap_BadVersion — any outer-version byte other than 0x01 is
// rejected; 0x02 is representative.
func TestUnwrap_BadVersion(t *testing.T) {
	c := synthCapsule()
	c[capsule.OffsetVersion] = 0x02
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

// TestUnwrap_BadSize — any size other than 109 is rejected, checked
// before magic / version so truncated inputs don't risk panics.
func TestUnwrap_BadSize(t *testing.T) {
	short := make([]byte, capsule.CapsuleSize-1)
	long := make([]byte, capsule.CapsuleSize+1)

	if _, _, err := capsule.Unwrap(testPassphrase, short); !errors.Is(err, capsule.ErrBadSize) {
		t.Fatalf("short: want ErrBadSize, got %v", err)
	}
	if _, _, err := capsule.Unwrap(testPassphrase, long); !errors.Is(err, capsule.ErrBadSize) {
		t.Fatalf("long: want ErrBadSize, got %v", err)
	}
}

// paramByte returns the absolute offset within the capsule of the
// Nth byte inside the argon2_params block.
func paramByte(n int) int { return capsule.OffsetArgon2Params + n }

// TestUnwrap_ParamFloor — m_cost_log2 one below the floor trips
// ErrParamFloor before Argon2id runs.
func TestUnwrap_ParamFloor(t *testing.T) {
	c := synthCapsule()
	c[paramByte(1)] = capsule.MinMCostLog2 - 1
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrParamFloor) {
		t.Fatalf("want ErrParamFloor, got %v", err)
	}
}

// TestUnwrap_ParamCeiling — m_cost_log2 one above the ceiling trips
// ErrParamCeiling before Argon2id runs.
func TestUnwrap_ParamCeiling(t *testing.T) {
	c := synthCapsule()
	c[paramByte(1)] = capsule.MaxMCostLog2 + 1
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrParamCeiling) {
		t.Fatalf("want ErrParamCeiling, got %v", err)
	}
}

// TestUnwrap_ReservedNonZero — a non-zero reserved byte is rejected.
func TestUnwrap_ReservedNonZero(t *testing.T) {
	c := synthCapsule()
	c[paramByte(6)] = 0x01
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrParamReserved) {
		t.Fatalf("want ErrParamReserved, got %v", err)
	}
}

// TestWrap_Nonce_Unique — two wraps of the same inputs produce
// distinct nonce fields (fresh crypto/rand per call).
func TestWrap_Nonce_Unique(t *testing.T) {
	a, err := capsule.Wrap(testPassphrase, testPSK, testPairID)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := capsule.Wrap(testPassphrase, testPSK, testPairID)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	nonceA := a[capsule.OffsetNonce:capsule.OffsetWrapCT]
	nonceB := b[capsule.OffsetNonce:capsule.OffsetWrapCT]
	if bytes.Equal(nonceA, nonceB) {
		t.Fatalf("nonce collision across two wraps: %x", nonceA)
	}
}

// TestWrap_Salt_Unique — two wraps of the same inputs produce
// distinct argon2_salt fields (fresh crypto/rand per call).
func TestWrap_Salt_Unique(t *testing.T) {
	a, err := capsule.Wrap(testPassphrase, testPSK, testPairID)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := capsule.Wrap(testPassphrase, testPSK, testPairID)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	saltA := a[capsule.OffsetArgon2Salt:capsule.OffsetArgon2Params]
	saltB := b[capsule.OffsetArgon2Salt:capsule.OffsetArgon2Params]
	if bytes.Equal(saltA, saltB) {
		t.Fatalf("argon2_salt collision across two wraps: %x", saltA)
	}
}

// TestUnwrap_TamperedCapsuleAD — flipping a bit in the salt region
// breaks AD binding and/or shifts the derived passphrase_key; either
// way Unwrap must return ErrDecrypt.
func TestUnwrap_TamperedCapsuleAD(t *testing.T) {
	c := validCapsuleCopy(t)
	c[capsule.OffsetArgon2Salt] ^= 0x01
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

// TestWrap_Unwrap_EmptyPassphrase — empty passphrase must wrap and
// unwrap cleanly; locks in the contract that passphrase policy lives
// strictly above this package.
func TestWrap_Unwrap_EmptyPassphrase(t *testing.T) {
	c, err := capsule.Wrap([]byte{}, testPSK, testPairID)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	psk, pairID, err := capsule.Unwrap([]byte{}, c)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(psk, testPSK) || !bytes.Equal(pairID, testPairID) {
		t.Fatalf("empty-passphrase round-trip: PSK/pair_id mismatch")
	}
}

// TestWrap_BadPSKSize — a wrong-sized PSK is rejected before
// Argon2id runs.
func TestWrap_BadPSKSize(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		_, err := capsule.Wrap(testPassphrase, make([]byte, n), testPairID)
		if !errors.Is(err, capsule.ErrBadPSKSize) {
			t.Errorf("psk=%d: want ErrBadPSKSize, got %v", n, err)
		}
	}
}

// TestWrap_BadPairIDSize — a wrong-sized pair_id is rejected before
// Argon2id runs.
func TestWrap_BadPairIDSize(t *testing.T) {
	for _, n := range []int{0, 7, 9, 16} {
		_, err := capsule.Wrap(testPassphrase, testPSK, make([]byte, n))
		if !errors.Is(err, capsule.ErrBadPairIDSize) {
			t.Errorf("pair_id=%d: want ErrBadPairIDSize, got %v", n, err)
		}
	}
}

// TestUnwrap_BadKDFVersion — any kdf_version != 0x01 is rejected.
func TestUnwrap_BadKDFVersion(t *testing.T) {
	c := synthCapsule()
	c[paramByte(0)] = 0x02
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrBadKDFVersion) {
		t.Fatalf("want ErrBadKDFVersion, got %v", err)
	}
}

// TestUnwrap_BadKeyLen — keylen must be 32 exactly; other values
// reject.
func TestUnwrap_BadKeyLen(t *testing.T) {
	c := synthCapsule()
	c[paramByte(4)] = 16
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrBadKeyLen) {
		t.Fatalf("want ErrBadKeyLen, got %v", err)
	}
}

// TestUnwrap_BadSaltLen — saltlen must be 16 exactly; other values
// reject.
func TestUnwrap_BadSaltLen(t *testing.T) {
	c := synthCapsule()
	c[paramByte(5)] = 8
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrBadSaltLen) {
		t.Fatalf("want ErrBadSaltLen, got %v", err)
	}
}

// TestUnwrap_TCostFloor — t_cost below MinTCost trips ErrParamFloor.
func TestUnwrap_TCostFloor(t *testing.T) {
	c := synthCapsule()
	c[paramByte(2)] = capsule.MinTCost - 1
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrParamFloor) {
		t.Fatalf("want ErrParamFloor, got %v", err)
	}
}

// TestUnwrap_PCostCeiling — p_cost above MaxPCost trips
// ErrParamCeiling.
func TestUnwrap_PCostCeiling(t *testing.T) {
	c := synthCapsule()
	c[paramByte(3)] = capsule.MaxPCost + 1
	_, _, err := capsule.Unwrap(testPassphrase, c)
	if !errors.Is(err, capsule.ErrParamCeiling) {
		t.Fatalf("want ErrParamCeiling, got %v", err)
	}
}
