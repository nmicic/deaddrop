// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package passphrase

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Reader obtains a passphrase from the user. Each implementation
// handles a different D-31 entry path. The returned byte slice is
// owned by the caller and must be zeroized after use.
type Reader interface {
	ReadPassphrase(prompt string) ([]byte, error)
}

// TTYReader prompts on /dev/tty with echo disabled. Reading directly
// from the controlling terminal (not stdin) lets callers keep stdin
// free for piped data — the usual shape for `cmd ... < file.txt`.
type TTYReader struct{}

// ReadPassphrase opens /dev/tty, writes prompt, disables echo, reads
// a line, and returns the raw bytes.
func (TTYReader) ReadPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Wrap with ErrNotExist so callers can distinguish "no TTY
		// available" from read errors.
		return nil, fmt.Errorf("opening /dev/tty: %w", errors.Join(err, os.ErrNotExist))
	}
	defer tty.Close()

	if _, err := io.WriteString(tty, prompt); err != nil {
		return nil, fmt.Errorf("writing prompt: %w", err)
	}
	out, err := term.ReadPassword(int(tty.Fd()))
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	// ReadPassword suppresses echo but also suppresses the user's
	// Enter newline on output — emit a newline so subsequent prompts
	// start on a fresh line.
	if _, err := io.WriteString(tty, "\n"); err != nil {
		return nil, fmt.Errorf("writing newline: %w", err)
	}
	return out, nil
}

// FDReader reads a single newline-delimited line from the given file
// descriptor. Used by `--passphrase-fd`: the caller pipes the
// passphrase in and the CLI does not see a terminal. The prompt
// parameter is ignored.
type FDReader struct {
	FD int
}

// ReadPassphrase reads byte-by-byte from r.FD until '\n' or EOF. A
// trailing CRLF is stripped. Byte-wise reads (rather than a fresh
// bufio.NewReader per call) are load-bearing: ReadPassphraseConfirm
// issues two sequential reads on the same fd, and a bufio would have
// gulped the second line into its internal buffer on the first call.
func (r FDReader) ReadPassphrase(_ string) ([]byte, error) {
	f := os.NewFile(uintptr(r.FD), "passphrase-fd")
	if f == nil {
		return nil, fmt.Errorf("passphrase fd %d: invalid", r.FD)
	}
	// Do NOT close f — the FD is owned by the caller; closing here
	// would also invalidate it for subsequent ReadPassphrase calls
	// (as used by ReadPassphraseConfirm).

	var out []byte
	var buf [1]byte
	for {
		n, err := f.Read(buf[:])
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			out = append(out, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("reading passphrase fd: %w", err)
		}
	}
	// Strip trailing CR for CRLF-terminated lines.
	if len(out) > 0 && out[len(out)-1] == '\r' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// EnvReader returns the passphrase from an environment variable.
// Used by `--passphrase-env <VAR>`. Emits a one-line security warning
// on Stderr before returning the value, because env vars tend to
// leak via `ps e`, crash dumps, and child-process inheritance.
type EnvReader struct {
	VarName string
	Stderr  io.Writer
}

// ReadPassphrase looks up r.VarName, warns on Stderr, and returns
// the raw bytes. An unset or empty variable returns an error.
func (r EnvReader) ReadPassphrase(_ string) ([]byte, error) {
	v := os.Getenv(r.VarName)
	if v == "" {
		return nil, fmt.Errorf("environment variable %s is unset or empty", r.VarName)
	}
	if r.Stderr != nil {
		fmt.Fprintf(r.Stderr, "warning: reading passphrase from environment variable %s\n", r.VarName)
	}
	return []byte(v), nil
}

// ReadPassphraseConfirm prompts twice and returns the passphrase only
// if both reads match. On mismatch, both buffers are zeroized before
// the error is returned so the plaintext does not linger in memory.
// EnvReader inherently always matches (it returns the same env value
// on both calls); confirm is meaningful for TTY and fd paths.
func ReadPassphraseConfirm(r Reader) ([]byte, error) {
	first, err := r.ReadPassphrase("Passphrase: ")
	if err != nil {
		return nil, err
	}
	second, err := r.ReadPassphrase("Confirm passphrase: ")
	if err != nil {
		zeroize(first)
		return nil, err
	}
	if !bytesEqual(first, second) {
		zeroize(first)
		zeroize(second)
		return nil, errors.New("passphrases do not match")
	}
	zeroize(second)
	return first, nil
}

// bytesEqual is a length-first byte-by-byte equality check. Not
// constant-time — mismatched passphrases during confirm are a local
// UX concern, not an oracle exposure, and both buffers are zeroized
// on return either way.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// zeroize overwrites b in place. Best-effort.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
