// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Package secretparse decodes CLI-supplied secret values per the
// PROTOCOL.md §8 prefix discipline: every --deploy-secret value
// (and every --write-token value passed to a binary that decodes
// rather than forwards it) MUST begin with a lowercase "hex:" or
// "b64:" prefix. The parser is source-agnostic — it takes a string
// the caller already obtained (from argv, env, or future fd-read)
// and returns the decoded bytes. Length is the caller's concern;
// the parser only validates encoding.
package secretparse

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	hexPrefix = "hex:"
	b64Prefix = "b64:"
)

// Parse decodes value per PROTOCOL.md §8. flagName is the leading
// token of the returned error so callers surface a shaped diagnostic
// (e.g. "--deploy-secret: missing hex:/b64: prefix"). Length checks
// stay at the callsite (slot.MinDeploySecretLen for --deploy-secret).
func Parse(flagName, value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New(flagName + ": empty")
	}
	if hasBoundaryWhitespace(value) {
		return nil, errors.New(flagName + ": leading/trailing whitespace")
	}
	switch {
	case strings.HasPrefix(value, hexPrefix):
		decoded, err := hex.DecodeString(value[len(hexPrefix):])
		if err != nil {
			return nil, errors.New(flagName + ": hex-decode: " + err.Error())
		}
		return decoded, nil
	case strings.HasPrefix(value, b64Prefix):
		// base64.StdEncoding silently tolerates embedded \r and \n
		// (RFC 4648 historical "MIME" carry-over). The whole point
		// of this slice is whitespace-confusion-resistant secret
		// parsing, so detect-and-reject any ASCII whitespace in the
		// suffix before delegating to the stdlib.
		suffix := value[len(b64Prefix):]
		if hasAnyASCIISpace(suffix) {
			return nil, errors.New(flagName + ": embedded whitespace in b64: value")
		}
		decoded, err := base64.StdEncoding.DecodeString(suffix)
		if err != nil {
			return nil, errors.New(flagName + ": b64-decode: " + err.Error())
		}
		return decoded, nil
	default:
		return nil, errors.New(flagName + ": missing hex:/b64: prefix")
	}
}

func hasBoundaryWhitespace(s string) bool {
	if len(s) == 0 {
		return false
	}
	return isASCIISpace(s[0]) || isASCIISpace(s[len(s)-1])
}

func hasAnyASCIISpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if isASCIISpace(s[i]) {
			return true
		}
	}
	return false
}

func isASCIISpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}
