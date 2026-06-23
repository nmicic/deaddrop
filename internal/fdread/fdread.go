// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Package fdread reads a single secret value from an open file
// descriptor. Used by --deploy-secret-fd / --write-token-fd flags
// across the deaddrop binaries (D-43). The fd's contents flow
// through internal/secretparse.Parse unchanged after one trailing
// LF (and one preceding CR, if present) are stripped — fd does
// not bypass the hex:/b64: prefix discipline (PROTOCOL.md §8).
package fdread

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxBytes is the hard cap on the secret length read from a single
// fd. Any reasonable hex:/b64:-prefixed 32-byte secret fits in well
// under 100 bytes; 1 KiB gives generous headroom for future growth
// (e.g. larger keys) while bounding runaway reads from a
// misconfigured or adversarial fd. Inputs that exceed this cap
// without a terminating LF are rejected with an error rather than
// truncated, so the caller never silently accepts an oversized
// secret.
const MaxBytes = 1024

// ReadString reads one line from fdNum: bytes up to the first LF
// (`\n`) or EOF, capped at MaxBytes. The returned string excludes
// the trailing LF; if a CR (`\r`) precedes the LF, that is dropped
// too. No other trimming is performed — boundary-whitespace
// handling stays in secretparse.Parse so fd / env / argv share the
// same validation rules.
//
// If the fd contains more than MaxBytes bytes before the first LF,
// ReadString returns a "secret exceeds N-byte cap" error rather
// than truncating the value. The cap is an integrity check, not a
// truncation primitive: a caller that needs a longer-than-cap
// secret should re-evaluate whether the fd path is the right
// channel for it.
//
// The fd is closed before ReadString returns. Callers that need to
// keep the fd open (rare; --deploy-secret-fd is a one-shot per
// process) should dup the fd before passing it in.
func ReadString(fdNum int, flagName string) (string, error) {
	if fdNum < 0 {
		return "", fmt.Errorf("%s: negative fd number %d", flagName, fdNum)
	}
	f := os.NewFile(uintptr(fdNum), flagName)
	if f == nil {
		return "", fmt.Errorf("%s: fd %d not open", flagName, fdNum)
	}
	defer f.Close()

	// Read at most MaxBytes+1 bytes through a LimitReader; the +1 is
	// the canary byte that lets us detect a missing-LF overflow vs.
	// a value that exactly fills the cap and is LF-terminated within
	// that budget.
	buf := make([]byte, 0, MaxBytes+1)
	var b [1]byte
	lr := io.LimitReader(f, int64(MaxBytes)+1)
	for {
		n, err := lr.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				// Strip a trailing CR if the line was CRLF-terminated.
				if m := len(buf); m > 0 && buf[m-1] == '\r' {
					buf = buf[:m-1]
				}
				return string(buf), nil
			}
			if len(buf) == MaxBytes {
				// We have already consumed MaxBytes payload bytes and
				// the next byte (currently in b) is not LF: the value
				// exceeds the cap. Reject rather than truncate.
				return "", fmt.Errorf("%s: secret exceeds %d-byte cap (no LF within budget)", flagName, MaxBytes)
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return string(buf), nil
			}
			return "", fmt.Errorf("%s: read: %w", flagName, err)
		}
	}
}
