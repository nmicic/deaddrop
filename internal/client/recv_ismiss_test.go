// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"
	"testing"

	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/exitcode"
)

// TestIsMiss_NotFound — IsMiss returns true for a RecvError with
// code NotFound.
func TestIsMiss_NotFound(t *testing.T) {
	err := &client.RecvError{Code: exitcode.NotFound, Detail: "no message found"}
	if !client.IsMiss(err) {
		t.Fatal("IsMiss(NotFound) = false, want true")
	}
}

// TestIsMiss_OtherCode — IsMiss returns false for a RecvError with
// a code other than NotFound.
func TestIsMiss_OtherCode(t *testing.T) {
	codes := []int{
		exitcode.Auth,
		exitcode.RelayOverloaded,
		exitcode.CryptoLocal,
		exitcode.RelayUnreachable,
		exitcode.Internal,
	}
	for _, code := range codes {
		err := &client.RecvError{Code: code, Detail: "some error"}
		if client.IsMiss(err) {
			t.Errorf("IsMiss(code=%d) = true, want false", code)
		}
	}
}

// TestIsMiss_NilError — IsMiss returns false for nil.
func TestIsMiss_NilError(t *testing.T) {
	if client.IsMiss(nil) {
		t.Fatal("IsMiss(nil) = true, want false")
	}
}

// TestIsMiss_WrappedRecvError — IsMiss returns true when a NotFound
// RecvError is wrapped via fmt.Errorf %w (errors.As unwraps it).
func TestIsMiss_WrappedRecvError(t *testing.T) {
	inner := &client.RecvError{Code: exitcode.NotFound, Detail: "wrapped"}
	err := fmt.Errorf("outer: %w", inner)
	if !client.IsMiss(err) {
		t.Fatal("IsMiss(fmt.Errorf wrapping NotFound) = false, want true")
	}
}

// TestIsMiss_NonRecvError — IsMiss returns false for a plain error.
func TestIsMiss_NonRecvError(t *testing.T) {
	err := fmt.Errorf("plain error")
	if client.IsMiss(err) {
		t.Fatal("IsMiss(plain error) = true, want false")
	}
}
