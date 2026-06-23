// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && !cgo

package passcache

// New on macOS without cgo has no Keychain backend: the Keychain
// implementation (keychain_darwin.go) calls Security.framework via cgo
// and is dropped from the build when CGO_ENABLED=0. Behave like an
// unsupported platform (keyutils_other.go) so callers' errors.Is(err,
// ErrUnsupported) branch handles it.
//
// A real macOS build that needs the Keychain passphrase cache must set
// CGO_ENABLED=1 (see HOWTO.md §1).
func New() (Cache, error) {
	return nil, ErrUnsupported
}
