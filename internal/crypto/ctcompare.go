// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto

import "crypto/subtle"

// ConstantTimeEqual reports whether a and b have the same length and
// identical byte contents. Its running time depends on the length of
// the slices but not on their contents: two equal-length inputs are
// compared in constant time with respect to the bytes.
//
// Length is not treated as secret. nil and zero-length slices compare
// equal. Typical use: passphrase and tag comparisons where an early
// length-mismatch short-circuit leaks only a non-secret fact (wrong
// input shape) and never key material.
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
