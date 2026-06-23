// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/nmicic/deaddrop/internal/identitystore"

// newIdentityStore is the constructor used by send / recv / bootstrap
// to resolve the per-pair identity-store backend. Tests override this
// to inject a fake store. Production code never reassigns it.
//
// Mirrors the newCache pattern in passcache.go (D-65 test-seam parity).
var newIdentityStore = identitystore.New
