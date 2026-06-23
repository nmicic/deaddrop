// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package capsule_test

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
)

//go:embed testdata/derive/capsule_fpr.json
var capsuleFprJSON []byte

type fprCaseInputs struct {
	PSK    string `json:"PSK"`
	PairID string `json:"pair_id"`
}

type fprCase struct {
	Name        string        `json:"name"`
	Inputs      fprCaseInputs `json:"inputs"`
	HKDFInfoHex string        `json:"hkdf_info_hex"`
	ExpectedHex string        `json:"expected_hex"`
}

type fprFile struct {
	Cases []fprCase `json:"cases"`
}

func loadFingerprintVectors(t *testing.T) fprFile {
	t.Helper()
	var vf fprFile
	if err := json.Unmarshal(capsuleFprJSON, &vf); err != nil {
		t.Fatalf("unmarshal capsule_fpr.json: %v", err)
	}
	if len(vf.Cases) == 0 {
		t.Fatalf("no cases in capsule_fpr.json")
	}
	return vf
}

func findFprCase(t *testing.T, vf fprFile, name string) fprCase {
	t.Helper()
	for _, c := range vf.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("case %q not found", name)
	return fprCase{}
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex-decode %q: %v", s, err)
	}
	return b
}

// TestFingerprint_Canonical — the canonical PSK/pair_id inputs from
// capsule_fpr.json must derive byte-identical to expected_hex under
// the §1.6 HKDF-SHA256 formula.
func TestFingerprint_Canonical(t *testing.T) {
	vf := loadFingerprintVectors(t)
	c := findFprCase(t, vf, "canonical")

	psk := decode(t, c.Inputs.PSK)
	pairID := decode(t, c.Inputs.PairID)
	want := decode(t, c.ExpectedHex)

	got, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if len(got) != capsule.FingerprintSize {
		t.Fatalf("len = %d, want %d", len(got), capsule.FingerprintSize)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fingerprint mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestFingerprint_PairIDMutated — mutating the final pair_id byte
// produces the distinct vector in the second case; confirms both
// the pair_id binding and that the golden value isn't accidentally
// constant across inputs.
func TestFingerprint_PairIDMutated(t *testing.T) {
	vf := loadFingerprintVectors(t)
	canonical := findFprCase(t, vf, "canonical")
	mutated := findFprCase(t, vf, "pair_id-last-byte-mutated")

	psk := decode(t, mutated.Inputs.PSK)
	pairID := decode(t, mutated.Inputs.PairID)
	wantMutated := decode(t, mutated.ExpectedHex)
	wantCanonical := decode(t, canonical.ExpectedHex)

	got, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !bytes.Equal(got, wantMutated) {
		t.Fatalf("mutated fingerprint mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), hex.EncodeToString(wantMutated))
	}
	if bytes.Equal(got, wantCanonical) {
		t.Fatalf("mutated fingerprint must differ from canonical; both = %s",
			hex.EncodeToString(got))
	}
}

// TestFingerprint_Deterministic — same inputs twice produce the
// identical output (pure function of PSK + pair_id).
func TestFingerprint_Deterministic(t *testing.T) {
	vf := loadFingerprintVectors(t)
	c := findFprCase(t, vf, "canonical")
	psk := decode(t, c.Inputs.PSK)
	pairID := decode(t, c.Inputs.PairID)

	a, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint a: %v", err)
	}
	b, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic")
	}
}

// TestFingerprint_HexRendering — hex-encoding the 16-byte fingerprint
// yields 32 lowercase hex characters matching the canonical vector's
// expected_hex.
func TestFingerprint_HexRendering(t *testing.T) {
	vf := loadFingerprintVectors(t)
	c := findFprCase(t, vf, "canonical")
	psk := decode(t, c.Inputs.PSK)
	pairID := decode(t, c.Inputs.PairID)

	got, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	rendered := hex.EncodeToString(got)
	if len(rendered) != 32 {
		t.Fatalf("hex length = %d, want 32", len(rendered))
	}
	if rendered != c.ExpectedHex {
		t.Fatalf("hex render mismatch\n  got:  %s\n  want: %s", rendered, c.ExpectedHex)
	}
	for _, r := range rendered {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("non-lowercase-hex char %q in %s", r, rendered)
		}
	}
}
