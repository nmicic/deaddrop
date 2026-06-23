// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto

// IsAllZero reports whether b is composed entirely of zero bytes. It
// runs in time independent of which byte (if any) is non-zero — used
// by callers checking X25519 outputs for the all-zero "DH-zero" signal
// emitted when the peer pubkey lies on a small-order subgroup.
//
// Hoisted from internal/bootstrap/leg3.go (D-66) so the content-AEAD
// derivation in internal/client/e2e.go can reuse it without
// duplicating the four-line helper. Both bootstrap and the E2E
// content layer perform the same X25519-then-zero-check guard; the
// helper lives here so future curve-using slices have one canonical
// implementation.
func IsAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
