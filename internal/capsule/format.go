// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package capsule

import "errors"

// Capsule magic and outer file version. Per SPEC_DRAFT_B_capsule.md §1
// and §1.0, receivers MUST verify both before touching any other field.
const (
	Magic       = "DDC1"
	Version     = 0x01
	CapsuleSize = 109
)

// Field offsets within the 109-byte capsule
// (SPEC_DRAFT_B_capsule.md §1).
const (
	OffsetMagic        = 0
	OffsetVersion      = 4
	OffsetArgon2Salt   = 5
	OffsetArgon2Params = 21
	OffsetNonce        = 29
	OffsetWrapCT       = 53
	OffsetWrapTag      = 93
)

// Field sizes.
const (
	MagicSize        = 4
	VersionSize      = 1
	Argon2SaltSize   = 16
	Argon2ParamsSize = 8
	NonceSize        = 24
	WrapCTSize       = 40
	WrapTagSize      = 16
	PSKSize          = 32
	PairIDSize       = 8
)

// Default Argon2id profile (SPEC_DRAFT_B_capsule.md §1.1 normative
// default: 128 MiB / t=3 / p=4).
const (
	DefaultKDFVersion = 0x01
	DefaultMCostLog2  = 17
	DefaultTCost      = 3
	DefaultPCost      = 4
	DefaultKeyLen     = 32
	DefaultSaltLen    = 16
)

// Argon2id param floor and ceiling (SPEC_DRAFT_B_capsule.md §1.2).
// Floor defeats brute-force downgrades; ceiling defeats OOM / CPU-bomb
// payloads. Both endpoints are inclusive.
const (
	MinMCostLog2 = 15
	MaxMCostLog2 = 22
	MinTCost     = 3
	MaxTCost     = 10
	MinPCost     = 1
	MaxPCost     = 16
)

// Offsets inside the 8-byte argon2_params block
// (SPEC_DRAFT_B_capsule.md §1.1).
const (
	paramOffKDFVersion = 0
	paramOffMCostLog2  = 1
	paramOffTCost      = 2
	paramOffPCost      = 3
	paramOffKeyLen     = 4
	paramOffSaltLen    = 5
	paramOffReserved0  = 6
	paramOffReserved1  = 7
)

// Sentinel errors. ErrDecrypt is the single opaque bucket for any
// authenticated-decryption failure — wrong passphrase, tampered
// ciphertext/tag, or AD mismatch — to avoid a decryption oracle.
// The structural errors below cover framing and param-validation
// failures that a receiver can surface before attempting Argon2id.
var (
	ErrDecrypt       = errors.New("capsule: decrypt failed")
	ErrBadMagic      = errors.New("capsule: invalid magic")
	ErrBadVersion    = errors.New("capsule: unsupported version")
	ErrBadSize       = errors.New("capsule: invalid capsule size")
	ErrBadKDFVersion = errors.New("capsule: unsupported kdf version")
	ErrParamFloor    = errors.New("capsule: argon2id params below floor")
	ErrParamCeiling  = errors.New("capsule: argon2id params above ceiling")
	ErrBadKeyLen     = errors.New("capsule: invalid keylen")
	ErrBadSaltLen    = errors.New("capsule: invalid saltlen")
	ErrParamReserved = errors.New("capsule: reserved bytes non-zero")
	ErrBadPSKSize    = errors.New("capsule: invalid PSK size")
	ErrBadPairIDSize = errors.New("capsule: invalid pair_id size")
)

// ValidateParams verifies the 8-byte argon2_params block against the
// normative layout (§1.1) and policy range (§1.2). Ordering of checks
// is not security-sensitive: all structural rejects happen before any
// Argon2id derivation attempt.
func ValidateParams(params [Argon2ParamsSize]byte) error {
	if params[paramOffKDFVersion] != DefaultKDFVersion {
		return ErrBadKDFVersion
	}
	m := params[paramOffMCostLog2]
	t := params[paramOffTCost]
	p := params[paramOffPCost]
	switch {
	case m < MinMCostLog2, t < MinTCost, p < MinPCost:
		return ErrParamFloor
	case m > MaxMCostLog2, t > MaxTCost, p > MaxPCost:
		return ErrParamCeiling
	}
	if params[paramOffKeyLen] != DefaultKeyLen {
		return ErrBadKeyLen
	}
	if params[paramOffSaltLen] != DefaultSaltLen {
		return ErrBadSaltLen
	}
	if params[paramOffReserved0] != 0 || params[paramOffReserved1] != 0 {
		return ErrParamReserved
	}
	return nil
}
