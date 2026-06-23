// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package slot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/nmicic/deaddrop/internal/crypto"
)

// Size constants for slot/service-phase outputs.
// SlotKeySize is the full HMAC-SHA256 output width.
// SlotIDSize / AEADKeySize reflect the truncation and HKDF lengths
// specified in SPEC_DRAFT_B_capsule.md §2.
const (
	SlotKeySize = 32
	SlotIDSize  = 16
	AEADKeySize = 32
	PSKSize     = 32
	PairIDSize  = 8
)

// Sentinel errors. All input-size validation fails closed with an
// opaque sentinel — no key material or path information is surfaced.
var (
	ErrBadPSKSize       = errors.New("slot: invalid PSK size")
	ErrBadPairIDSize    = errors.New("slot: invalid pair_id size")
	ErrBadSlotKeySize   = errors.New("slot: invalid slot_key size")
	ErrBadServiceIDSize = errors.New("slot: invalid service_id size")
	ErrBadSlotIDSize    = errors.New("slot: invalid slot_id size")
)

// Domain-separation labels.
const (
	slotKeyPrefix = "slot-key-v1"
	slotIDPrefix  = "slot"
	aeadInfoLabel = "deaddrop-v1-B"
)

// SlotKey derives the per-capsule slot key per
// SPEC_DRAFT_B_capsule.md §2:
//
//	slot_key = HMAC-SHA256(PSK, "slot-key-v1" || pair_id(8))
//
// Returns the full 32-byte HMAC-SHA256 output (no truncation). The
// caller is responsible for zeroizing the returned slice when the
// slot_key is no longer needed.
func SlotKey(psk, pairID []byte) ([]byte, error) {
	if len(psk) != PSKSize {
		return nil, ErrBadPSKSize
	}
	if len(pairID) != PairIDSize {
		return nil, ErrBadPairIDSize
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(slotKeyPrefix))
	mac.Write(pairID)
	return mac.Sum(nil), nil
}

// SlotID derives the per-minute slot identifier per
// SPEC_DRAFT_B_capsule.md §2:
//
//	slot_id = HMAC-SHA256(slot_key, "slot" || enc_u64_be(b) || enc_u32_be(attempt))[:16]
//
// b is the minute bucket, floor(unix_ts / 60). attempt is the retry
// counter (D-36: MAX_SEND_ATTEMPTS = 1, so canonical sends use
// attempt=0). The caller computes b from wall-clock time; this
// package does not import `time` (C-4). Returns 16 bytes.
func SlotID(slotKey []byte, b uint64, attempt uint32) ([]byte, error) {
	if len(slotKey) != SlotKeySize {
		return nil, ErrBadSlotKeySize
	}
	mac := hmac.New(sha256.New, slotKey)
	mac.Write([]byte(slotIDPrefix))
	var bBuf [8]byte
	binary.BigEndian.PutUint64(bBuf[:], b)
	mac.Write(bBuf[:])
	var aBuf [4]byte
	binary.BigEndian.PutUint32(aBuf[:], attempt)
	mac.Write(aBuf[:])
	sum := mac.Sum(nil)
	out := make([]byte, SlotIDSize)
	copy(out, sum[:SlotIDSize])
	return out, nil
}

// AEADKey derives the per-message AEAD key per
// SPEC_DRAFT_B_capsule.md §2:
//
//	aead_key = HKDF-SHA256(
//	    secret = PSK,
//	    salt   = slot_id_bytes(16),
//	    info   = "deaddrop-v1-B" || pair_id(8) || service_id_bytes(16) || version(1),
//	    length = 32,
//	)
//
// The version byte is passed through to the HKDF info so that derived
// keys are bound to the wire version even when the caller has not yet
// validated it via wire.ParseVersion. Delegates to
// internal/crypto.DeriveKey.
func AEADKey(psk, pairID, serviceID, slotID []byte, version byte) ([]byte, error) {
	if len(psk) != PSKSize {
		return nil, ErrBadPSKSize
	}
	if len(pairID) != PairIDSize {
		return nil, ErrBadPairIDSize
	}
	if len(serviceID) != ServiceIDSize {
		return nil, ErrBadServiceIDSize
	}
	if len(slotID) != SlotIDSize {
		return nil, ErrBadSlotIDSize
	}
	info := make([]byte, 0, len(aeadInfoLabel)+len(pairID)+len(serviceID)+1)
	info = append(info, []byte(aeadInfoLabel)...)
	info = append(info, pairID...)
	info = append(info, serviceID...)
	info = append(info, version)
	return crypto.DeriveKey(psk, slotID, info, AEADKeySize)
}
