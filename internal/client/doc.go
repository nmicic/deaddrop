// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Package client implements the user-facing send/recv flows.
// It depends on internal/crypto, internal/slot, and internal/wire
// for cryptographic primitives, and accepts an HTTP client and clock
// interface as injected dependencies so tests can run without
// network or wall-clock coupling.
package client
