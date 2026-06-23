// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package exitcode_test

import (
	"testing"

	"github.com/nmicic/deaddrop/internal/exitcode"
)

// 1. TestName_Known — every named D-38 code maps to its canonical label.
func TestName_Known(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{exitcode.NotFound, "EDDNotFound"},
		{exitcode.Usage, "EDDUsage"},
		{exitcode.CryptoLocal, "EDDCryptoLocal"},
		{exitcode.RelayUnreachable, "EDDRelayUnreachable"},
		{exitcode.Collision, "EDDCollision"},
		{exitcode.Auth, "EDDAuth"},
		{exitcode.SizeCap, "EDDSizeCap"},
		{exitcode.CapsuleUnwrap, "EDDCapsuleUnwrap"},
		{exitcode.RelayOverloaded, "EDDRelayOverloaded"},
		{exitcode.BootstrapMITM, "EDDBootstrapMITM"},
		{exitcode.BootstrapAuth, "EDDBootstrapAuthFail"},
		{exitcode.BootstrapTimeout, "EDDBootstrapTimeout"},
		{exitcode.Internal, "EDDInternal"},
	}
	for _, c := range cases {
		if got := exitcode.Name(c.code); got != c.want {
			t.Errorf("Name(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// 2. TestName_Unknown — an unrecognised code returns "" (no label).
func TestName_Unknown(t *testing.T) {
	if got := exitcode.Name(99); got != "" {
		t.Errorf("Name(99) = %q, want \"\"", got)
	}
}

// 3. TestName_Zero — OK returns "" (successful exit has no banner).
func TestName_Zero(t *testing.T) {
	if got := exitcode.Name(exitcode.OK); got != "" {
		t.Errorf("Name(OK) = %q, want \"\"", got)
	}
}
