// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package capsule

import "github.com/nmicic/deaddrop/internal/crypto"

// fingerprintInfoPrefix is the ASCII label that binds derived
// fingerprints to the v2 HKDF formula (SPEC_DRAFT_B_capsule.md §1.6).
// It must not be re-specified elsewhere; §1.6 is the sole normative
// source.
const fingerprintInfoPrefix = "deaddrop-fingerprint-v2"

// FingerprintSize is the byte length of a capsule fingerprint.
// Rendered as 32 lowercase hex chars (hex.EncodeToString) for OOB
// comparison.
const FingerprintSize = 16

// Fingerprint computes the 16-byte capsule fingerprint per
// SPEC_DRAFT_B_capsule.md §1.6:
//
//	fingerprint = HKDF-SHA256(
//	    secret = PSK,
//	    salt   = "",
//	    info   = "deaddrop-fingerprint-v2" || pair_id(8),
//	    length = 16,
//	)
//
// The fingerprint is a pure function of (psk, pairID); it is stable
// across passphrase rotations (re-wrapping the same PSK under a new
// passphrase preserves the fingerprint). Callers render it via
// hex.EncodeToString to obtain the canonical 32-char lowercase hex
// form used for read-aloud OOB verification.
func Fingerprint(psk, pairID []byte) ([]byte, error) {
	info := make([]byte, 0, len(fingerprintInfoPrefix)+len(pairID))
	info = append(info, []byte(fingerprintInfoPrefix)...)
	info = append(info, pairID...)
	return crypto.DeriveKey(psk, nil, info, FingerprintSize)
}
