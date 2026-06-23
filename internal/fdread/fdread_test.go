// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package fdread_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/nmicic/deaddrop/internal/fdread"
)

// pipeWith writes data to an os.Pipe and returns the read fd. The
// write end is closed so EOF terminates a final line missing LF.
func pipeWith(t *testing.T, data string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return int(r.Fd())
}

func TestReadString_TrailingLF(t *testing.T) {
	fd := pipeWith(t, "hex:abcd\n")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "hex:abcd" {
		t.Fatalf("got %q, want %q", got, "hex:abcd")
	}
}

func TestReadString_TrailingCRLF(t *testing.T) {
	fd := pipeWith(t, "hex:abcd\r\n")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "hex:abcd" {
		t.Fatalf("got %q, want %q", got, "hex:abcd")
	}
}

func TestReadString_NoTrailingNewline(t *testing.T) {
	fd := pipeWith(t, "hex:abcd")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "hex:abcd" {
		t.Fatalf("got %q, want %q", got, "hex:abcd")
	}
}

func TestReadString_PreservesEmbeddedAndLeadingSpace(t *testing.T) {
	// fdread does not trim boundary whitespace — that's secretparse.Parse's
	// job, so fd / env / argv share validation.
	fd := pipeWith(t, " hex:ab cd\n")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != " hex:ab cd" {
		t.Fatalf("got %q, want %q", got, " hex:ab cd")
	}
}

func TestReadString_NegativeFD(t *testing.T) {
	_, err := fdread.ReadString(-1, "--deploy-secret-fd")
	if err == nil || !strings.Contains(err.Error(), "negative fd") {
		t.Fatalf("err = %v, want negative-fd diagnostic", err)
	}
}

func TestReadString_OnlyOneTrailingLFStripped(t *testing.T) {
	// "abc\n\n" -> "abc\n" — only one LF dropped. The reader stops at
	// the first LF, so the second LF is never read; that behavior is
	// intentional (one secret per fd).
	fd := pipeWith(t, "hex:abcd\n\n")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "hex:abcd" {
		t.Fatalf("got %q, want %q", got, "hex:abcd")
	}
}

// TestReadString_ExceedsMaxBytes_NoLF — 4 KiB of 'x' with no LF must
// error. Today (before B-1 fix) this succeeds because bufio.NewReaderSize
// only sizes the initial buffer; ReadBytes('\n') keeps growing.
func TestReadString_ExceedsMaxBytes_NoLF(t *testing.T) {
	big := bytes.Repeat([]byte{'x'}, 4096)
	fd := pipeWith(t, string(big))
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err == nil {
		t.Fatalf("expected error for >MaxBytes input with no LF; got %d-byte value, no error", len(got))
	}
	if !strings.Contains(err.Error(), "cap") && !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want a cap-exceeded diagnostic", err)
	}
}

// TestReadString_ExactlyMaxBytesWithLF — 1023 bytes of 'x' + '\n'
// (1024 bytes total including LF) must succeed and return 1023 bytes.
// One byte under the cap, LF terminates within the cap.
func TestReadString_ExactlyMaxBytesWithLF(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, fdread.MaxBytes-1)
	fd := pipeWith(t, string(body)+"\n")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if len(got) != fdread.MaxBytes-1 {
		t.Fatalf("got len %d, want %d", len(got), fdread.MaxBytes-1)
	}
}

// TestReadString_LargeContentWithEarlyLF — 4 KiB of 'x' with LF at
// byte 500 must return the first 500 bytes. The cap protects against
// runaway reads but a short value followed by garbage past LF still
// works (we stop at the LF; trailing bytes stay in the fd).
func TestReadString_LargeContentWithEarlyLF(t *testing.T) {
	prefix := bytes.Repeat([]byte{'x'}, 500)
	suffix := bytes.Repeat([]byte{'y'}, 4096-500-1) // -1 for LF
	data := append(append([]byte{}, prefix...), '\n')
	data = append(data, suffix...)
	fd := pipeWith(t, string(data))
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if len(got) != 500 {
		t.Fatalf("got len %d, want 500", len(got))
	}
	for i, c := range got {
		if c != 'x' {
			t.Fatalf("byte %d = %q, want 'x' (suffix bytes leaked into output)", i, c)
		}
	}
}

// TestReadString_EmptyFd — fd at EOF immediately returns ("", nil).
// An empty value will fail the downstream secretparse.Parse check; the
// fdread layer is value-agnostic.
func TestReadString_EmptyFd(t *testing.T) {
	fd := pipeWith(t, "")
	got, err := fdread.ReadString(fd, "--deploy-secret-fd")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
