// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package secretparse

import (
	"bytes"
	"strings"
	"testing"
)

// PROTOCOL.md §8 lines 321-324 are the spec source for the
// hex:/b64: prefix discipline. PROTOCOL.md §8 b64 paragraph
// (added in v0.1.0 tag-blockers slice) pins b64 to RFC 4648 §4
// standard, padded — URL-safe and unpadded MUST be rejected.

func TestParse_Empty(t *testing.T) {
	out, err := Parse("--deploy-secret", "")
	if err == nil {
		t.Fatalf("Parse(\"\") returned no error; got bytes=%x", out)
	}
	if !strings.Contains(err.Error(), "--deploy-secret") {
		t.Errorf("error %q missing flag name", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q missing 'empty' diagnostic", err)
	}
}

func TestParse_MissingPrefix(t *testing.T) {
	bare := "0102030405060708090a0b0c0d0e0f10"
	_, err := Parse("--deploy-secret", bare)
	if err == nil {
		t.Fatal("missing prefix accepted; want error")
	}
	if !strings.Contains(err.Error(), "missing hex:/b64: prefix") {
		t.Errorf("error %q missing 'missing hex:/b64: prefix'", err)
	}
}

func TestParse_UppercasePrefix_Rejected(t *testing.T) {
	for _, v := range []string{
		"HEX:0102030405060708",
		"Hex:0102030405060708",
		"hEx:0102030405060708",
		"B64:AAECAwQFBgcICQoLDA0ODw==",
		"B64:AAECAwQFBgcICQoLDA0ODw==",
		"Hex:0102030405060708",
	} {
		_, err := Parse("--deploy-secret", v)
		if err == nil {
			t.Errorf("Parse(%q) accepted uppercase/title-case prefix", v)
			continue
		}
		if !strings.Contains(err.Error(), "missing hex:/b64: prefix") {
			t.Errorf("Parse(%q) error = %q, want 'missing hex:/b64: prefix'", v, err.Error())
		}
	}
}

func TestParse_HexPrefixOnly(t *testing.T) {
	out, err := Parse("--deploy-secret", "hex:")
	if err != nil {
		t.Fatalf("Parse(\"hex:\") error = %v; want nil (parser does not enforce length)", err)
	}
	if len(out) != 0 {
		t.Errorf("Parse(\"hex:\") = %x, want empty bytes", out)
	}
}

func TestParse_B64PrefixOnly(t *testing.T) {
	out, err := Parse("--deploy-secret", "b64:")
	if err != nil {
		t.Fatalf("Parse(\"b64:\") error = %v; want nil (parser does not enforce length)", err)
	}
	if len(out) != 0 {
		t.Errorf("Parse(\"b64:\") = %x, want empty bytes", out)
	}
}

func TestParse_HexHappyPath_Lowercase(t *testing.T) {
	in := "hex:0102030405060708090a0b0c0d0e0f10"
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	got, err := Parse("--deploy-secret", in)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", in, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Parse(%q) = %x, want %x", in, got, want)
	}
}

func TestParse_HexHappyPath_MixedCase(t *testing.T) {
	in := "hex:0102030405060708090A0B0C0D0E0F10"
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	got, err := Parse("--deploy-secret", in)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v (relay's decodeHexFlag accepted mixed case; parser must too)", in, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Parse(%q) = %x, want %x", in, got, want)
	}
}

func TestParse_HexInvalidSuffix_OddLength(t *testing.T) {
	_, err := Parse("--deploy-secret", "hex:010")
	if err == nil {
		t.Fatal("odd-length hex suffix accepted; want error")
	}
	if !strings.Contains(err.Error(), "hex-decode") {
		t.Errorf("error %q missing 'hex-decode' diagnostic", err)
	}
}

func TestParse_HexInvalidSuffix_NonHexChar(t *testing.T) {
	_, err := Parse("--deploy-secret", "hex:01gg")
	if err == nil {
		t.Fatal("non-hex char accepted; want error")
	}
	if !strings.Contains(err.Error(), "hex-decode") {
		t.Errorf("error %q missing 'hex-decode' diagnostic", err)
	}
}

func TestParse_B64HappyPath(t *testing.T) {
	in := "b64:AQIDBAUGBwgJCgsMDQ4PEA=="
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	got, err := Parse("--deploy-secret", in)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", in, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Parse(%q) = %x, want %x", in, got, want)
	}
}

func TestParse_B64URLSafeRejected(t *testing.T) {
	// URL-safe base64 substitutes - and _ for + and /. Construct a
	// suffix that contains a URL-safe-only character so StdEncoding
	// rejects it. PROTOCOL.md §8 (v0.1.0 amendment) requires this
	// rejection on both client and relay.
	in := "b64:AQIDBAUGBwgJCgsMDQ4P-A=="
	_, err := Parse("--deploy-secret", in)
	if err == nil {
		t.Fatal("URL-safe base64 char '-' accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "b64-decode") {
		t.Errorf("error %q missing 'b64-decode' diagnostic", err)
	}
}

func TestParse_B64UnpaddedRejected(t *testing.T) {
	// Same payload as TestParse_B64HappyPath but with the trailing
	// "==" stripped — RawStdEncoding accepts; StdEncoding rejects.
	in := "b64:AQIDBAUGBwgJCgsMDQ4PEA"
	_, err := Parse("--deploy-secret", in)
	if err == nil {
		t.Fatal("unpadded base64 accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "b64-decode") {
		t.Errorf("error %q missing 'b64-decode' diagnostic", err)
	}
}

// base64.StdEncoding silently accepts embedded \r / \n carry-overs
// from RFC 4648's "MIME" lineage. The whole motivation of this
// parser is whitespace-confusion-resistant secret parsing, so the
// b64 branch MUST detect-and-reject any ASCII whitespace in the
// suffix before delegating to the stdlib. Embedded ' ' already
// errors via stdlib (illegal-byte) but is pinned for completeness.
func TestParse_B64EmbeddedLF(t *testing.T) {
	in := "b64:AQID\nBAUG"
	_, err := Parse("--deploy-secret", in)
	if err == nil {
		t.Fatalf("Parse(%q) accepted embedded LF; stdlib base64.StdEncoding silently tolerates it", in)
	}
	if !strings.Contains(err.Error(), "embedded whitespace in b64: value") {
		t.Errorf("Parse(%q) error = %q, want 'embedded whitespace in b64: value'", in, err.Error())
	}
}

func TestParse_B64EmbeddedCRLF(t *testing.T) {
	in := "b64:AQID\r\nBAUG"
	_, err := Parse("--deploy-secret", in)
	if err == nil {
		t.Fatalf("Parse(%q) accepted embedded CRLF; stdlib base64.StdEncoding silently tolerates it", in)
	}
	if !strings.Contains(err.Error(), "embedded whitespace in b64: value") {
		t.Errorf("Parse(%q) error = %q, want 'embedded whitespace in b64: value'", in, err.Error())
	}
}

func TestParse_B64EmbeddedSpace(t *testing.T) {
	in := "b64:AQ ID"
	_, err := Parse("--deploy-secret", in)
	if err == nil {
		t.Fatalf("Parse(%q) accepted embedded space", in)
	}
	if !strings.Contains(err.Error(), "embedded whitespace in b64: value") {
		t.Errorf("Parse(%q) error = %q, want 'embedded whitespace in b64: value' (parser-level reject before stdlib)", in, err.Error())
	}
}

func TestParse_B64InvalidSuffix(t *testing.T) {
	_, err := Parse("--deploy-secret", "b64:!!!not-base64@@@")
	if err == nil {
		t.Fatal("garbage base64 accepted; want error")
	}
	if !strings.Contains(err.Error(), "b64-decode") {
		t.Errorf("error %q missing 'b64-decode' diagnostic", err)
	}
}

func TestParse_LeadingWhitespace(t *testing.T) {
	for _, v := range []string{
		" hex:0102",
		"\thex:0102",
		"\nhex:0102",
	} {
		_, err := Parse("--deploy-secret", v)
		if err == nil {
			t.Errorf("Parse(%q) accepted leading whitespace", v)
			continue
		}
		if !strings.Contains(err.Error(), "leading/trailing whitespace") {
			t.Errorf("Parse(%q) error = %q, want 'leading/trailing whitespace'", v, err.Error())
		}
	}
}

func TestParse_TrailingWhitespace(t *testing.T) {
	for _, v := range []string{
		"hex:0102 ",
		"hex:0102\t",
		"hex:0102\n",
	} {
		_, err := Parse("--deploy-secret", v)
		if err == nil {
			t.Errorf("Parse(%q) accepted trailing whitespace", v)
			continue
		}
		if !strings.Contains(err.Error(), "leading/trailing whitespace") {
			t.Errorf("Parse(%q) error = %q, want 'leading/trailing whitespace'", v, err.Error())
		}
	}
}

func TestParse_FlagNameInError(t *testing.T) {
	for _, name := range []string{"--deploy-secret", "--write-token"} {
		_, err := Parse(name, "")
		if err == nil {
			t.Fatalf("Parse(%q, \"\") returned nil error", name)
		}
		if !strings.HasPrefix(err.Error(), name+":") {
			t.Errorf("Parse(%q, ...) error = %q; want prefix %q", name, err.Error(), name+":")
		}
	}
}
