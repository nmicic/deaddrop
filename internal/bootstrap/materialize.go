// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/nmicic/deaddrop/internal/capsule"
)

func WriteCapsule(capsulePath string, psk [32]byte, pairID [8]byte, passphrase []byte) error {
	data, err := capsule.Wrap(passphrase, psk[:], pairID[:])
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(capsulePath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(capsulePath, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(capsulePath, 0600); err != nil {
		return err
	}
	return nil
}
