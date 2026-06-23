// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"errors"

	"github.com/nmicic/deaddrop/internal/crypto"
)

// Wire body version bytes (PROTOCOL.md §12, SPEC_DRAFT_B_capsule.md §3).
// 0x00 and 0xFF are reserved and MUST reject. 0x05+ is reserved for
// future protocol revisions. 0x02 / 0x03 are the two bootstrap legs
// whose parser ships with the bootstrap implementation. 0x04 (D-68) is the E2E-wrapped plain
// body whose layout is byte-identical to 0x01; only the inner-AEAD-
// presence semantics differ.
const (
	VersionPlainB    = 0x01
	VersionBootLeg12 = 0x02
	VersionBootLeg3  = 0x03
	VersionPlainBE2E = 0x04
)

// Plain-body wire overhead constants. VersionPlainB bodies carry the outer
// envelope only; VersionPlainBE2E bodies also carry the inner content-AEAD
// nonce+tag. The relay is body-opaque, so its default body cap must budget
// for the larger currently-shipped plain-body form.
const (
	PlainBodyOuterOverhead = 1 + crypto.NonceSize + crypto.TagSize
	PlainBodyE2EOverhead   = PlainBodyOuterOverhead + crypto.NonceSize + crypto.TagSize
)

// Sentinel errors. ErrUnsupportedVersion names a version that is part
// of the specified protocol but whose parser is not in this release.
// ErrReservedVersion names a version outside any specified range.
// Keeping these distinct lets relay / client code log the shape of
// rejection without a lookup table.
var (
	ErrUnsupportedVersion = errors.New("wire: unsupported version")
	ErrReservedVersion    = errors.New("wire: reserved version")
	ErrEmptyBody          = errors.New("wire: empty body")
)

// IsPlainBody reports whether v is one of the plain-body wire
// versions (0x01 legacy or 0x04 E2E-wrapped). Used by recv to
// dispatch on the inner-AEAD-presence semantics without scattering
// literal byte comparisons. Bootstrap-leg versions return false.
func IsPlainBody(v byte) bool {
	return v == VersionPlainB || v == VersionPlainBE2E
}

// ParseVersion reads the leading version byte from a wire body and
// classifies it. The first return value is always body[0] when body
// is non-empty — including for error cases — so callers may log the
// rejected byte without reparsing. For an empty body the first return
// value is 0 and the error is ErrEmptyBody.
//
// Acceptance: 0x01 (plain B legacy) and 0x04 (plain B
// E2E-wrapped, D-68).
// Unsupported: 0x02, 0x03 (bootstrap legs, parsed by bootstrap code).
// Reserved: 0x00, 0x05–0xFE, 0xFF.
func ParseVersion(body []byte) (byte, error) {
	if len(body) == 0 {
		return 0, ErrEmptyBody
	}
	v := body[0]
	switch v {
	case VersionPlainB, VersionPlainBE2E:
		return v, nil
	case VersionBootLeg12, VersionBootLeg3:
		return v, ErrUnsupportedVersion
	default:
		return v, ErrReservedVersion
	}
}
