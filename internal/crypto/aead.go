// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20-Poly1305 parameter sizes, in bytes.
const (
	KeySize   = 32
	NonceSize = 24
	TagSize   = 16
)

// Sentinel errors. Returned values are opaque by design: an Open failure
// conveys no information about whether the key, nonce, AD, ciphertext, or
// tag was at fault (no decryption oracle).
var (
	ErrOpen      = errors.New("aead: open failed")
	ErrKeySize   = errors.New("aead: invalid key size")
	ErrNonceSize = errors.New("aead: invalid nonce size")
)

// Seal encrypts plaintext under the given key, nonce, and associated data
// using XChaCha20-Poly1305. It returns ciphertext || tag (the 16-byte
// Poly1305 tag appended to the ciphertext), which is the single-slice form
// consumed by Open.
//
// key must be KeySize (32) bytes. nonce must be NonceSize (24) bytes.
// The caller owns the key slice and is responsible for zeroizing it once
// the key is no longer needed; Seal does not copy or retain the key.
// The nonce must be unique per (key) — reuse is catastrophic for
// confidentiality. This package does not generate nonces; callers are
// responsible for nonce discipline.
func Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	if len(nonce) != NonceSize {
		return nil, ErrNonceSize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// Open authenticates and decrypts ctWithTag (ciphertext || tag, as
// returned by Seal) under the given key, nonce, and associated data.
// Returns the plaintext on success.
//
// Any failure — wrong key, wrong nonce, tampered ciphertext, tampered
// tag, mismatched AD, or a truncated input shorter than TagSize — returns
// ErrOpen with no further detail.
//
// key must be KeySize (32) bytes. nonce must be NonceSize (24) bytes.
// The caller owns the key slice and is responsible for zeroizing it once
// the key is no longer needed; Open does not copy or retain the key.
func Open(key, nonce, ctWithTag, ad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	if len(nonce) != NonceSize {
		return nil, ErrNonceSize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	pt, err := aead.Open(nil, nonce, ctWithTag, ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
