// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/nmicic/deaddrop/internal/crypto"
)

//go:embed testdata/aead/rfc_vectors.json
var rfcVectorsJSON []byte

//go:embed testdata/aead/ad_binding.json
var adBindingJSON []byte

type caseInputs struct {
	KeyHex        string `json:"key_hex,omitempty"`
	AEADKeyHex    string `json:"aead_key_hex,omitempty"`
	NonceHex      string `json:"nonce_hex"`
	AADHex        string `json:"aad_hex"`
	PlaintextHex  string `json:"plaintext_hex,omitempty"`
	CiphertextHex string `json:"ciphertext_hex,omitempty"`
	TagHex        string `json:"tag_hex,omitempty"`
}

type caseExpected struct {
	CiphertextHex string `json:"ciphertext_hex,omitempty"`
	TagHex        string `json:"tag_hex,omitempty"`
	DecryptOK     bool   `json:"decrypt_ok"`
	FailureReason string `json:"failure_reason,omitempty"`
}

type vectorCase struct {
	Name     string       `json:"name"`
	Inputs   caseInputs   `json:"inputs"`
	Expected caseExpected `json:"expected"`
}

type vectorFile struct {
	Cases []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T, raw []byte) vectorFile {
	t.Helper()
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}
	if len(vf.Cases) == 0 {
		t.Fatalf("no cases in vectors")
	}
	return vf
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// keyHex returns the AEAD key for a case (supports both RFC `key_hex` and
// ad_binding `aead_key_hex` input shapes).
func (c caseInputs) keyHex() string {
	if c.KeyHex != "" {
		return c.KeyHex
	}
	return c.AEADKeyHex
}

// TestSeal_Open_RFCVectors verifies byte-identical XChaCha20-Poly1305 output
// against RFC conformance vectors for every decrypt_ok=true case.
func TestSeal_Open_RFCVectors(t *testing.T) {
	vf := loadVectors(t, rfcVectorsJSON)
	ran := 0
	for _, c := range vf.Cases {
		if !c.Expected.DecryptOK {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			key := mustDecodeHex(t, c.Inputs.keyHex())
			nonce := mustDecodeHex(t, c.Inputs.NonceHex)
			aad := mustDecodeHex(t, c.Inputs.AADHex)
			plaintext := mustDecodeHex(t, c.Inputs.PlaintextHex)
			ctExpected := mustDecodeHex(t, c.Expected.CiphertextHex)
			tagExpected := mustDecodeHex(t, c.Expected.TagHex)
			want := append(append([]byte{}, ctExpected...), tagExpected...)

			got, err := crypto.Seal(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal mismatch\n  got:  %s\n  want: %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}

			pt, err := crypto.Open(key, nonce, got, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("Open plaintext mismatch\n  got:  %s\n  want: %s",
					hex.EncodeToString(pt), hex.EncodeToString(plaintext))
			}
		})
	}
	if ran == 0 {
		t.Fatalf("no decrypt_ok=true cases exercised")
	}
}

// TestOpen_RFCVectors_AADFlip asserts that every decrypt_ok=false RFC case
// (currently an AAD bit-flip variant) rejects Open with ErrOpen.
func TestOpen_RFCVectors_AADFlip(t *testing.T) {
	vf := loadVectors(t, rfcVectorsJSON)
	ran := 0
	for _, c := range vf.Cases {
		if c.Expected.DecryptOK {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			key := mustDecodeHex(t, c.Inputs.keyHex())
			nonce := mustDecodeHex(t, c.Inputs.NonceHex)
			aad := mustDecodeHex(t, c.Inputs.AADHex)
			ct := mustDecodeHex(t, c.Inputs.CiphertextHex)
			tag := mustDecodeHex(t, c.Inputs.TagHex)
			ctWithTag := append(append([]byte{}, ct...), tag...)

			_, err := crypto.Open(key, nonce, ctWithTag, aad)
			if !errors.Is(err, crypto.ErrOpen) {
				t.Fatalf("Open: want ErrOpen, got %v", err)
			}
		})
	}
	if ran == 0 {
		t.Fatalf("no decrypt_ok=false cases exercised")
	}
}

// findCase returns the named case from vf or fails the test.
func findCase(t *testing.T, vf vectorFile, name string) vectorCase {
	t.Helper()
	for _, c := range vf.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("case %q not found", name)
	return vectorCase{}
}

// TestSeal_Open_ADBinding_Canonical verifies the deaddrop canonical
// AD-binding vector round-trips byte-identically.
func TestSeal_Open_ADBinding_Canonical(t *testing.T) {
	vf := loadVectors(t, adBindingJSON)
	c := findCase(t, vf, "canonical")

	key := mustDecodeHex(t, c.Inputs.AEADKeyHex)
	nonce := mustDecodeHex(t, c.Inputs.NonceHex)
	aad := mustDecodeHex(t, c.Inputs.AADHex)
	plaintext := mustDecodeHex(t, c.Inputs.PlaintextHex)
	ctExpected := mustDecodeHex(t, c.Expected.CiphertextHex)
	tagExpected := mustDecodeHex(t, c.Expected.TagHex)
	want := append(append([]byte{}, ctExpected...), tagExpected...)

	got, err := crypto.Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical AD-binding Seal mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	pt, err := crypto.Open(key, nonce, got, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("canonical AD-binding plaintext mismatch")
	}
}

// TestOpen_ADBinding_Mutations asserts that every AD mutation case from
// ad_binding.json (service_id/slot_id/version flipped, trailing byte
// appended) is rejected with ErrOpen.
func TestOpen_ADBinding_Mutations(t *testing.T) {
	vf := loadVectors(t, adBindingJSON)
	ran := 0
	for _, c := range vf.Cases {
		if c.Expected.DecryptOK {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			key := mustDecodeHex(t, c.Inputs.AEADKeyHex)
			nonce := mustDecodeHex(t, c.Inputs.NonceHex)
			aad := mustDecodeHex(t, c.Inputs.AADHex)
			ct := mustDecodeHex(t, c.Inputs.CiphertextHex)
			tag := mustDecodeHex(t, c.Inputs.TagHex)
			ctWithTag := append(append([]byte{}, ct...), tag...)

			_, err := crypto.Open(key, nonce, ctWithTag, aad)
			if !errors.Is(err, crypto.ErrOpen) {
				t.Fatalf("Open: want ErrOpen, got %v", err)
			}
		})
	}
	if ran != 4 {
		t.Fatalf("expected 4 mutation cases, exercised %d", ran)
	}
}

// TestSeal_KeySize covers both short and long key rejection.
func TestSeal_KeySize(t *testing.T) {
	nonce := make([]byte, crypto.NonceSize)
	plaintext := []byte("hello")
	ad := []byte("ad")

	for _, size := range []int{0, 31, 33, 64} {
		size := size
		t.Run(name2("len", size), func(t *testing.T) {
			key := make([]byte, size)
			_, err := crypto.Seal(key, nonce, plaintext, ad)
			if !errors.Is(err, crypto.ErrKeySize) {
				t.Fatalf("Seal(key=%d): want ErrKeySize, got %v", size, err)
			}
		})
	}
}

// TestOpen_KeySize covers both short and long key rejection on Open.
func TestOpen_KeySize(t *testing.T) {
	nonce := make([]byte, crypto.NonceSize)
	ctWithTag := make([]byte, crypto.TagSize)
	ad := []byte("ad")

	for _, size := range []int{0, 31, 33, 64} {
		size := size
		t.Run(name2("len", size), func(t *testing.T) {
			key := make([]byte, size)
			_, err := crypto.Open(key, nonce, ctWithTag, ad)
			if !errors.Is(err, crypto.ErrKeySize) {
				t.Fatalf("Open(key=%d): want ErrKeySize, got %v", size, err)
			}
		})
	}
}

// TestSeal_NonceSize covers both short and long nonce rejection.
func TestSeal_NonceSize(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	plaintext := []byte("hello")
	ad := []byte("ad")

	for _, size := range []int{0, 23, 25, 12} {
		size := size
		t.Run(name2("len", size), func(t *testing.T) {
			nonce := make([]byte, size)
			_, err := crypto.Seal(key, nonce, plaintext, ad)
			if !errors.Is(err, crypto.ErrNonceSize) {
				t.Fatalf("Seal(nonce=%d): want ErrNonceSize, got %v", size, err)
			}
		})
	}
}

// TestOpen_Truncated asserts that input shorter than TagSize is rejected
// with ErrOpen (no panic, no oracle).
func TestOpen_Truncated(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	nonce := make([]byte, crypto.NonceSize)
	ad := []byte("ad")

	for _, size := range []int{0, 1, crypto.TagSize - 1} {
		size := size
		t.Run(name2("len", size), func(t *testing.T) {
			ctWithTag := make([]byte, size)
			_, err := crypto.Open(key, nonce, ctWithTag, ad)
			if !errors.Is(err, crypto.ErrOpen) {
				t.Fatalf("Open(ct=%d): want ErrOpen, got %v", size, err)
			}
		})
	}
}

// TestSeal_Open_RoundTrip exercises Seal+Open with cryptographically
// random key, nonce, plaintext, and AD.
func TestSeal_Open_RoundTrip(t *testing.T) {
	key := randomBytes(t, crypto.KeySize)
	nonce := randomBytes(t, crypto.NonceSize)
	plaintext := randomBytes(t, 137)
	ad := randomBytes(t, 33)

	ct, err := crypto.Seal(key, nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ct) != len(plaintext)+crypto.TagSize {
		t.Fatalf("Seal output length: got %d, want %d", len(ct), len(plaintext)+crypto.TagSize)
	}
	pt, err := crypto.Open(key, nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip plaintext mismatch")
	}
}

// TestOpen_TagFlip flips bit 0 of the final byte of ct||tag (inside the
// Poly1305 tag region) and verifies Open rejects with ErrOpen.
func TestOpen_TagFlip(t *testing.T) {
	key := randomBytes(t, crypto.KeySize)
	nonce := randomBytes(t, crypto.NonceSize)
	plaintext := []byte("deaddrop tag-flip test")
	ad := []byte("ad-binding-33-byte-stand-in------")

	ct, err := crypto.Seal(key, nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ct) < crypto.TagSize {
		t.Fatalf("ct shorter than TagSize")
	}
	ct[len(ct)-1] ^= 0x01

	_, err = crypto.Open(key, nonce, ct, ad)
	if !errors.Is(err, crypto.ErrOpen) {
		t.Fatalf("tag-flip: want ErrOpen, got %v", err)
	}
}

// TestOpen_CrossSlot Seals under AD with slot_id_A and Opens with AD
// where slot_id is flipped (byte 16 of the canonical 33-byte AD).
func TestOpen_CrossSlot(t *testing.T) {
	vf := loadVectors(t, adBindingJSON)
	c := findCase(t, vf, "canonical")
	key := mustDecodeHex(t, c.Inputs.AEADKeyHex)
	nonce := mustDecodeHex(t, c.Inputs.NonceHex)
	adA := mustDecodeHex(t, c.Inputs.AADHex)
	plaintext := mustDecodeHex(t, c.Inputs.PlaintextHex)

	if len(adA) != 33 {
		t.Fatalf("canonical AD length: got %d, want 33", len(adA))
	}

	ct, err := crypto.Seal(key, nonce, plaintext, adA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	adB := append([]byte{}, adA...)
	adB[16] ^= 0x01 // slot_id bit-flip (bytes 16..31 are slot_id per PROTOCOL.md §7).

	_, err = crypto.Open(key, nonce, ct, adB)
	if !errors.Is(err, crypto.ErrOpen) {
		t.Fatalf("cross-slot: want ErrOpen, got %v", err)
	}
}

// randomBytes returns n cryptographically random bytes; fails the test on
// entropy read error.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// name2 formats a subtest label like "len=31". `fmt` is banned under C-5
// even in test files, so we compose via strconv.
func name2(prefix string, n int) string {
	return prefix + "=" + strconv.Itoa(n)
}
