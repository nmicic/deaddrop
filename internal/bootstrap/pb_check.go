// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

func CheckPBNotPA(passphraseKey, pbBytes []byte) (bool, error) {
	probeKey := argon2.IDKey(pbBytes, bootstrapSalt[:], 3, 1<<17, 4, 32)
	defer zeroize(probeKey)
	match := subtle.ConstantTimeCompare(passphraseKey, probeKey)
	return match == 1, nil
}
