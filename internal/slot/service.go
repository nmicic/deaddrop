// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package slot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// ServiceIDSize is the byte length of a service_id (HMAC-SHA256
// truncated). Rendered as 32 lowercase hex chars (hex.EncodeToString)
// for inclusion in the rolling URL path.
const ServiceIDSize = 16

// MinDeploySecretLen is the minimum acceptable DEPLOY_SECRET length
// per PROTOCOL.md §8 ("32+ raw bytes"). Deploys may use longer secrets;
// shorter ones are rejected.
const MinDeploySecretLen = 32

// ErrBadDeploySecretLen is returned when DEPLOY_SECRET is shorter than
// MinDeploySecretLen bytes.
var ErrBadDeploySecretLen = errors.New("slot: DEPLOY_SECRET too short")

// serviceIDPrefix is the ASCII domain-separation label that binds
// HMAC output to the service_id role.
const serviceIDPrefix = "svc"

// ServiceID derives the per-hour service prefix per
// SPEC.md §Two-level rolling URL:
//
//	service_id = HMAC-SHA256(DEPLOY_SECRET, "svc" || enc_u64_be(h))[:16]
//
// h is the hour bucket, floor(unix_ts / 3600). The caller computes h
// from wall-clock time; this package does not import `time` (C-4).
// Returns 16 bytes; callers render via hex.EncodeToString for OOB or
// URL-path use.
func ServiceID(deploySecret []byte, h uint64) ([]byte, error) {
	if len(deploySecret) < MinDeploySecretLen {
		return nil, ErrBadDeploySecretLen
	}
	mac := hmac.New(sha256.New, deploySecret)
	mac.Write([]byte(serviceIDPrefix))
	var hBuf [8]byte
	binary.BigEndian.PutUint64(hBuf[:], h)
	mac.Write(hBuf[:])
	sum := mac.Sum(nil)
	out := make([]byte, ServiceIDSize)
	copy(out, sum[:ServiceIDSize])
	return out, nil
}
