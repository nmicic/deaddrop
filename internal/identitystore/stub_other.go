// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package identitystore

// New on platforms without a keyring backend always errors with
// ErrUnsupported. The bootstrap CLI either falls back to Noop()
// (default) or fails with EDDPlatformUnsupported (when
// --require-e2e=true).
//
// Filename is `stub_other.go` (not `keyutils_other.go`) to avoid
// implying any kinship with the Linux keyutils backend (D-61).
func New() (Store, error) {
	return nil, ErrUnsupported
}
