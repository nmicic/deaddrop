// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && !cgo

package identitystore

// New on macOS without cgo has no Keychain backend: the Keychain
// implementation (keychain_darwin.go) calls Security.framework via cgo
// and is dropped from the build when CGO_ENABLED=0. Behave exactly like
// an unsupported platform (stub_other.go) so callers' errors.Is(err,
// ErrUnsupported) branch handles it — the bootstrap CLI falls back to
// Noop() (default) or fails with EDDPlatformUnsupported (--require-e2e).
//
// A real macOS build that needs the Keychain identity store must set
// CGO_ENABLED=1 (see HOWTO.md §1).
func New() (Store, error) {
	return nil, ErrUnsupported
}
