// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package passphrase_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/nmicic/deaddrop/internal/passphrase"
)

// pipeWithData creates an os.Pipe and writes data to the write end,
// closes it, and returns the read-end fd. Tests treat the fd as the
// --passphrase-fd stand-in.
func pipeWithData(t *testing.T, data string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return int(r.Fd())
}

// 1. TestFDReader — a newline-terminated line is returned without
// the '\n'.
func TestFDReader(t *testing.T) {
	fd := pipeWithData(t, "test-passphrase\n")
	got, err := (passphrase.FDReader{FD: fd}).ReadPassphrase("")
	if err != nil {
		t.Fatalf("ReadPassphrase: %v", err)
	}
	if string(got) != "test-passphrase" {
		t.Fatalf("got %q, want %q", got, "test-passphrase")
	}
}

// 2. TestFDReader_NoNewline — no trailing newline, EOF terminates.
func TestFDReader_NoNewline(t *testing.T) {
	fd := pipeWithData(t, "no-newline")
	got, err := (passphrase.FDReader{FD: fd}).ReadPassphrase("")
	if err != nil {
		t.Fatalf("ReadPassphrase: %v", err)
	}
	if string(got) != "no-newline" {
		t.Fatalf("got %q, want %q", got, "no-newline")
	}
}

// 3. TestFDReader_CRLF — trailing CR is stripped with the LF.
func TestFDReader_CRLF(t *testing.T) {
	fd := pipeWithData(t, "windows\r\n")
	got, err := (passphrase.FDReader{FD: fd}).ReadPassphrase("")
	if err != nil {
		t.Fatalf("ReadPassphrase: %v", err)
	}
	if string(got) != "windows" {
		t.Fatalf("got %q, want %q", got, "windows")
	}
}

// 4. TestEnvReader — env var value returned, stderr warning emitted.
func TestEnvReader(t *testing.T) {
	t.Setenv("TEST_PASS_XYZ", "from-env")
	var buf bytes.Buffer
	got, err := (passphrase.EnvReader{VarName: "TEST_PASS_XYZ", Stderr: &buf}).ReadPassphrase("")
	if err != nil {
		t.Fatalf("ReadPassphrase: %v", err)
	}
	if string(got) != "from-env" {
		t.Fatalf("got %q, want %q", got, "from-env")
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("stderr = %q, want to contain \"warning\"", buf.String())
	}
}

// 5. TestEnvReader_Empty — unset / empty var returns an error.
func TestEnvReader_Empty(t *testing.T) {
	t.Setenv("TEST_PASS_MISSING", "")
	_, err := (passphrase.EnvReader{VarName: "TEST_PASS_MISSING", Stderr: &bytes.Buffer{}}).ReadPassphrase("")
	if err == nil {
		t.Fatalf("expected error for empty env var, got nil")
	}
}

// staticReader always returns the same value (for Confirm match test).
type staticReader struct{ val string }

func (s staticReader) ReadPassphrase(_ string) ([]byte, error) {
	return []byte(s.val), nil
}

// sequenceReader returns values from a slice, advancing on each call.
type sequenceReader struct {
	values []string
	idx    int
}

func (s *sequenceReader) ReadPassphrase(_ string) ([]byte, error) {
	v := s.values[s.idx]
	s.idx++
	return []byte(v), nil
}

// 6. TestReadPassphraseConfirm_Match — identical reads return the value.
func TestReadPassphraseConfirm_Match(t *testing.T) {
	got, err := passphrase.ReadPassphraseConfirm(staticReader{val: "matched"})
	if err != nil {
		t.Fatalf("ReadPassphraseConfirm: %v", err)
	}
	if string(got) != "matched" {
		t.Fatalf("got %q, want %q", got, "matched")
	}
}

// 7. TestReadPassphraseConfirm_Mismatch — differing reads return an
// error (and both buffers are zeroized internally; we can only
// observe the error).
func TestReadPassphraseConfirm_Mismatch(t *testing.T) {
	r := &sequenceReader{values: []string{"a", "b"}}
	_, err := passphrase.ReadPassphraseConfirm(r)
	if err == nil {
		t.Fatalf("expected mismatch error, got nil")
	}
}
