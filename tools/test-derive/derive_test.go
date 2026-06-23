// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"testing"
)

func TestDerive_GoldenVector(t *testing.T) {
	const wantHex = "0a39bbc48ec257e4977a5ad0dfc70b5b4764f71144c7dd811e8cc360bd170ede" +
		"ffa2c877055bfa0648d53e35b48bbd481b0472692f5d532c6447273ecae09e879" +
		"97588d52e4ef2919262eea8f69e38d23f99187951c49ca49fd84626fbf424f516" +
		"85e99ca75db2fe19c809e4e5174e78bb9a6dde57fae1b213fcade3bbbca39b"

	got := derive("derive-golden", "derive-golden")
	gotHex := hex.EncodeToString(got)

	if gotHex != wantHex {
		t.Fatalf("derive golden vector mismatch\n got: %s\nwant: %s", gotHex, wantHex)
	}
}

func TestDerivePrefix_GoldenVector(t *testing.T) {
	// Pinned regression vector for the CADDY_PREFIX derivation. Update only
	// when intentionally changing prefixLabel / params; downstream relay
	// deployments must re-provision when this changes.
	const wantHex = "83cff50776618ac188a877bc1b8a1f5d"

	got := derivePrefix("derive-golden")
	gotHex := hex.EncodeToString(got)

	if gotHex != wantHex {
		t.Fatalf("derivePrefix golden vector mismatch\n got: %s\nwant: %s", gotHex, wantHex)
	}
}
