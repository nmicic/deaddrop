// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux || (darwin && cgo)

package identitystore

// zeroize clears b in place. Keep it package-private; the keyutils
// (linux) and Keychain (darwin+cgo) backend files share the helper.
// Constrained to those build configs so the stub builds
// (darwin && !cgo, and !linux && !darwin), which have no caller, do
// not trip the unused linter.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
