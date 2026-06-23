// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"testing"

	"github.com/nmicic/deaddrop/internal/crypto"
)

func TestConstantTimeEqual_Equal(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !crypto.ConstantTimeEqual(a, b) {
		t.Fatalf("want true for identical slices")
	}
}

func TestConstantTimeEqual_NotEqual(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x06}
	if crypto.ConstantTimeEqual(a, b) {
		t.Fatalf("want false for differing last byte")
	}

	c := []byte{0x81, 0x02, 0x03, 0x04, 0x05}
	if crypto.ConstantTimeEqual(a, c) {
		t.Fatalf("want false for differing first byte")
	}
}

func TestConstantTimeEqual_DifferentLengths(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	if crypto.ConstantTimeEqual(a, b) {
		t.Fatalf("want false for different-length slices")
	}
	if crypto.ConstantTimeEqual(b, a) {
		t.Fatalf("want false for different-length slices (swapped)")
	}
}

func TestConstantTimeEqual_Empty(t *testing.T) {
	a := []byte{}
	b := []byte{}
	if !crypto.ConstantTimeEqual(a, b) {
		t.Fatalf("want true for two empty slices")
	}
}

func TestConstantTimeEqual_NilVsEmpty(t *testing.T) {
	if !crypto.ConstantTimeEqual(nil, []byte{}) {
		t.Fatalf("want true for nil vs empty")
	}
	if !crypto.ConstantTimeEqual([]byte{}, nil) {
		t.Fatalf("want true for empty vs nil")
	}
}

func TestConstantTimeEqual_NilVsNil(t *testing.T) {
	if !crypto.ConstantTimeEqual(nil, nil) {
		t.Fatalf("want true for nil vs nil")
	}
}
