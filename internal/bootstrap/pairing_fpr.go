// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/hex"

	"github.com/nmicic/deaddrop/internal/crypto"
)

const (
	PairingFPRSize = 16
)

func PairingFingerprint(
	psk [32]byte,
	pairID [8]byte,
	initiatorPK, responderPK [32]byte,
) ([]byte, error) {
	ikm := make([]byte, 0, 104)
	ikm = append(ikm, psk[:]...)
	ikm = append(ikm, pairID[:]...)
	ikm = append(ikm, initiatorPK[:]...)
	ikm = append(ikm, responderPK[:]...)
	defer zeroize(ikm)

	return crypto.DeriveKey(ikm, []byte("deaddrop-bootstrap-fpr-v1"), []byte("fpr"), PairingFPRSize)
}

func FormatPairingFPR(fpr []byte) string {
	if len(fpr) != PairingFPRSize {
		panic("FormatPairingFPR: len(fpr) != PairingFPRSize")
	}
	h := hex.EncodeToString(fpr)
	return h[0:6] + " " + h[6:12] + " " + h[12:18] + " " + h[18:24] + " " + h[24:32]
}
