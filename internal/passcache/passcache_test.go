// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package passcache

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
)

func TestIDForCapsule_Golden(t *testing.T) {
	// Build a minimal capsule-sized blob with a known 16-byte salt at
	// offset 5 (OffsetArgon2Salt). All other bytes zero.
	salt := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	blob := make([]byte, capsule.CapsuleSize)
	copy(blob[capsule.OffsetArgon2Salt:], salt[:])

	h := sha256.Sum256(salt[:])
	want := "deaddrop:" + hex.EncodeToString(h[:8])

	got, err := IDForCapsule(blob)
	if err != nil {
		t.Fatalf("IDForCapsule: %v", err)
	}
	if got != want {
		t.Fatalf("IDForCapsule = %q, want %q", got, want)
	}
	// Pin the literal value so any accidental change to the hash or
	// truncation length is caught by a regression vector.
	const goldenID = "deaddrop:5dfbabeedf318bf3"
	if got != goldenID {
		t.Fatalf("golden mismatch: got %q, want %q", got, goldenID)
	}
}

func TestIDForCapsule_TooShort(t *testing.T) {
	_, err := IDForCapsule([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short blob")
	}
}
