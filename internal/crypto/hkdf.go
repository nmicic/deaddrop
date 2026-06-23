// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfSHA256MaxLen is the RFC 5869 ceiling on HKDF output:
// 255 * HashLen = 255 * 32 = 8160 bytes for SHA-256.
const hkdfSHA256MaxLen = 255 * sha256.Size

// ErrHKDFLength is returned by DeriveKey when length <= 0 or length
// exceeds the HKDF-SHA256 maximum of 255 * 32 = 8160 bytes.
var ErrHKDFLength = errors.New("hkdf: invalid output length")

// DeriveKey computes HKDF-SHA256 and returns a freshly allocated slice of
// the requested length.
//
// secret is the input keying material (IKM).
// salt may be nil or empty; per RFC 5869, HKDF substitutes a zero-filled
// salt of HashLen bytes in that case.
// info is the context/application-specific info string binding the
// derived key to its purpose (callers should encode deployment and
// version identifiers here).
// length must satisfy 0 < length <= 255*32.
//
// The caller owns the returned slice and is responsible for zeroizing it
// when the derived key is no longer needed.
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > hkdfSHA256MaxLen {
		return nil, ErrHKDFLength
	}
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, ErrHKDFLength
	}
	return out, nil
}
