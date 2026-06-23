// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Package exitcode names the D-38 exit-code taxonomy used by every
// deaddrop CLI binary. Subcommands return one of these integers; the
// top-level dispatcher formats errors as "ERROR: <Name>: <detail>"
// using Name() to convert the code to its canonical D-38 label.
package exitcode

// Exit-code constants (D-38). The numeric values are normative and
// shared with shell callers and operator runbooks — do not renumber.
const (
	OK                  = 0
	NotFound            = 1   // EDDNotFound — recv: probed all buckets, no message found
	Usage               = 2   // EDDUsage
	CryptoLocal         = 10  // EDDCryptoLocal
	RelayUnreachable    = 11  // EDDRelayUnreachable
	Collision           = 12  // EDDCollision
	Auth                = 13  // EDDAuth
	SizeCap             = 14  // EDDSizeCap
	CapsuleUnwrap       = 15  // EDDCapsuleUnwrap
	RelayOverloaded     = 16  // EDDRelayOverloaded
	BootstrapMITM       = 17  // EDDBootstrapMITM
	BootstrapAuth       = 18  // EDDBootstrapAuthFail
	BootstrapTimeout    = 19  // EDDBootstrapTimeout
	Internal            = 20  // EDDInternal
	E2EUnwrap           = 21  // EDDE2EUnwrap — content-AEAD open failed (recv-side, after capsule open succeeded)
	IdentityMiss        = 22  // EDDIdentityMiss — identity store has no entry for this pair
	IdentityStore       = 23  // EDDIdentityStore — generic identity store backend error
	PlatformUnsupported = 24  // EDDPlatformUnsupported — identity store backend not implemented on this OS and --require-e2e was set
	Interrupted         = 130 // EDDInterrupted — signal exit convention (SIGINT/SIGTERM during --watch)
)

// names is the reverse map used by Name(). 0 and unassigned codes
// deliberately have no entry — the caller should not print an error
// banner for a successful exit, and an unknown code is a programming
// bug that should surface as such rather than as a made-up label.
var names = map[int]string{
	NotFound:            "EDDNotFound",
	Usage:               "EDDUsage",
	CryptoLocal:         "EDDCryptoLocal",
	RelayUnreachable:    "EDDRelayUnreachable",
	Collision:           "EDDCollision",
	Auth:                "EDDAuth",
	SizeCap:             "EDDSizeCap",
	CapsuleUnwrap:       "EDDCapsuleUnwrap",
	RelayOverloaded:     "EDDRelayOverloaded",
	BootstrapMITM:       "EDDBootstrapMITM",
	BootstrapAuth:       "EDDBootstrapAuthFail",
	BootstrapTimeout:    "EDDBootstrapTimeout",
	Internal:            "EDDInternal",
	E2EUnwrap:           "EDDE2EUnwrap",
	IdentityMiss:        "EDDIdentityMiss",
	IdentityStore:       "EDDIdentityStore",
	PlatformUnsupported: "EDDPlatformUnsupported",
	Interrupted:         "EDDInterrupted",
}

// Name returns the D-38 error name for code. OK and any unrecognised
// code return "" so callers can omit the banner for zero exits and
// fail loudly on unknown codes.
func Name(code int) string {
	return names[code]
}
