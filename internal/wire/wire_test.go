// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/nmicic/deaddrop/internal/wire"
)

// 23. TestParseVersion_PlainB — 0x01 is accepted; first return is the
// byte, second return is nil.
func TestParseVersion_PlainB(t *testing.T) {
	v, err := wire.ParseVersion([]byte{0x01, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v != wire.VersionPlainB {
		t.Fatalf("version = 0x%02x, want 0x01", v)
	}
}

// 24. TestParseVersion_BootstrapLeg12 — 0x02 → ErrUnsupportedVersion
// with the version byte preserved in the first return.
func TestParseVersion_BootstrapLeg12(t *testing.T) {
	v, err := wire.ParseVersion([]byte{0x02, 0xDE, 0xAD})
	if !errors.Is(err, wire.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	if v != wire.VersionBootLeg12 {
		t.Fatalf("version = 0x%02x, want 0x02", v)
	}
}

// 25. TestParseVersion_BootstrapLeg3 — 0x03 → ErrUnsupportedVersion.
func TestParseVersion_BootstrapLeg3(t *testing.T) {
	v, err := wire.ParseVersion([]byte{0x03, 0xBE, 0xEF})
	if !errors.Is(err, wire.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	if v != wire.VersionBootLeg3 {
		t.Fatalf("version = 0x%02x, want 0x03", v)
	}
}

// 26. TestParseVersion_Reserved — 0x00, 0x05, 0xFE, 0xFF are all
// reserved and must reject with ErrReservedVersion. (0x04 was
// reserved earlier but is now VersionPlainBE2E per D-68.)
func TestParseVersion_Reserved(t *testing.T) {
	for _, b := range []byte{0x00, 0x05, 0xFE, 0xFF} {
		v, err := wire.ParseVersion([]byte{b, 0xCC})
		if !errors.Is(err, wire.ErrReservedVersion) {
			t.Errorf("byte 0x%02x: want ErrReservedVersion, got %v", b, err)
		}
		if v != b {
			t.Errorf("byte 0x%02x: version = 0x%02x, want 0x%02x", b, v, b)
		}
	}
}

// TestParseVersion_PlainBE2E — 0x04 (D-68) is now an accepted plain-
// body wire version with the same body shape as 0x01.
func TestParseVersion_PlainBE2E(t *testing.T) {
	v, err := wire.ParseVersion([]byte{0x04, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("ParseVersion(0x04): %v", err)
	}
	if v != wire.VersionPlainBE2E {
		t.Fatalf("version = 0x%02x, want 0x04", v)
	}
}

// TestIsPlainBody — 0x01 and 0x04 are plain bodies; everything else
// (including bootstrap legs) returns false.
func TestIsPlainBody(t *testing.T) {
	for _, c := range []struct {
		v    byte
		want bool
	}{
		{wire.VersionPlainB, true},
		{wire.VersionPlainBE2E, true},
		{wire.VersionBootLeg12, false},
		{wire.VersionBootLeg3, false},
		{0x00, false},
		{0x05, false},
		{0xFF, false},
	} {
		if got := wire.IsPlainBody(c.v); got != c.want {
			t.Errorf("IsPlainBody(0x%02x) = %v, want %v", c.v, got, c.want)
		}
	}
}

// 27. TestParseVersion_EmptyBody — []byte{} → (0, ErrEmptyBody).
func TestParseVersion_EmptyBody(t *testing.T) {
	v, err := wire.ParseVersion(nil)
	if !errors.Is(err, wire.ErrEmptyBody) {
		t.Errorf("nil body: want ErrEmptyBody, got %v", err)
	}
	if v != 0 {
		t.Errorf("nil body: version = 0x%02x, want 0x00", v)
	}

	v2, err2 := wire.ParseVersion([]byte{})
	if !errors.Is(err2, wire.ErrEmptyBody) {
		t.Errorf("empty slice: want ErrEmptyBody, got %v", err2)
	}
	if v2 != 0 {
		t.Errorf("empty slice: version = 0x%02x, want 0x00", v2)
	}
}

// 28. TestParseVersion_ReturnsVersionByte — for every non-empty
// single-byte input 0x00..0xFF, the first return value is that byte
// verbatim (covers both ok and error paths).
func TestParseVersion_ReturnsVersionByte(t *testing.T) {
	for i := 0; i < 256; i++ {
		b := byte(i)
		v, _ := wire.ParseVersion([]byte{b})
		if v != b {
			t.Error("byte 0x" + strconv.FormatUint(uint64(i), 16) +
				": version = 0x" + strconv.FormatUint(uint64(v), 16) +
				", want 0x" + strconv.FormatUint(uint64(i), 16))
		}
	}
}
