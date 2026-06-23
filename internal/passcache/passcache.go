// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package passcache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nmicic/deaddrop/internal/capsule"
)

var ErrMiss = errors.New("passcache: miss")

var ErrUnsupported = errors.New("passcache: unsupported on this platform")

type Cache interface {
	Get(id string) ([]byte, error)
	Put(id string, pass []byte, ttl time.Duration) error
	Forget(id string) error
}

// IDForCapsule returns the canonical cache ID for a capsule blob.
// It hashes the Argon2 salt (offset 5, 16 bytes) with SHA-256 and
// returns "deaddrop:" + first 16 hex chars of the digest.
func IDForCapsule(capsuleBytes []byte) (string, error) {
	if len(capsuleBytes) < capsule.OffsetArgon2Salt+capsule.Argon2SaltSize {
		return "", fmt.Errorf("passcache: capsule too short (%d bytes)", len(capsuleBytes))
	}
	salt := capsuleBytes[capsule.OffsetArgon2Salt : capsule.OffsetArgon2Salt+capsule.Argon2SaltSize]
	h := sha256.Sum256(salt)
	return "deaddrop:" + hex.EncodeToString(h[:8]), nil
}
