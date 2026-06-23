// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/slot"
	"github.com/nmicic/deaddrop/internal/wire"
)

// DeleteTokenSize is the byte length of the client-generated delete
// token (D-26). The relay stores sha256(token); Send sends the hash
// in X-DeadDrop-Delete-Hash and returns the raw token for the caller
// to use or discard per D-35.
const DeleteTokenSize = 32

// SendConfig bundles every dependency a send needs. HTTPClient and
// Clock are injected so tests can drive the flow deterministically
// without a live relay or wall-clock coupling.
type SendConfig struct {
	PSK          []byte // 32 bytes (from capsule Unwrap)
	PairID       []byte // 8 bytes (from capsule Unwrap)
	DeploySecret []byte // ≥32 bytes (relay DEPLOY_SECRET)
	WriteToken   string
	RelayBaseURL string
	HTTPClient   *http.Client
	Clock        func() time.Time

	// ContentLayer, if non-nil, double-wraps the file payload with
	// the per-pair content-AEAD key before the outer capsule-AEAD
	// seal (D-66). When set, the wire body emits
	// VersionPlainBE2E (0x04) at byte 0 (D-65 / D-68); when nil,
	// byte 0 is VersionPlainB (0x01) and the body shape is
	// unchanged from v0.1.4. The CLI layer is responsible for
	// resolving the identity entry and constructing the layer
	// (cmd/deaddrop/send.go).
	ContentLayer *ContentLayer
}

// SendError carries a D-38 exit code alongside a human-readable
// detail. The CLI unwraps it to produce the canonical
// "ERROR: <EDDName>: <detail>" banner.
type SendError struct {
	Code   int
	Detail string
}

func (e *SendError) Error() string { return e.Detail }

// Send encrypts plaintext and POSTs the wire body to the relay. It
// returns the 32-byte delete token on success (D-35: ephemeral,
// in-process only) or a *SendError carrying the exit code + detail.
// D-36 applies: attempt is always 0, and 409 is a hard failure —
// the caller does not retry.
func Send(cfg SendConfig, plaintext []byte) ([]byte, error) {
	now := cfg.Clock()
	h := uint64(now.Unix()) / 3600
	b := uint64(now.Unix()) / 60

	serviceID, err := slot.ServiceID(cfg.DeploySecret, h)
	if err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "deriving service_id: " + err.Error()}
	}

	slotKey, err := slot.SlotKey(cfg.PSK, cfg.PairID)
	if err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "deriving slot_key: " + err.Error()}
	}
	defer zeroize(slotKey)

	slotID, err := slot.SlotID(slotKey, b, 0)
	if err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "deriving slot_id: " + err.Error()}
	}

	// Wire version is decided up front from the presence of a
	// ContentLayer (D-65). It is bound into THREE downstream sites:
	// the outer-key derivation, the outer AD, AND body[0]. Drift
	// between any two is a guaranteed decrypt failure on the
	// receiver, so keep the version decision in one local value.
	wireVersion := byte(wire.VersionPlainB)
	if cfg.ContentLayer != nil {
		wireVersion = wire.VersionPlainBE2E
	}

	aeadKey, err := slot.AEADKey(cfg.PSK, cfg.PairID, serviceID, slotID, wireVersion)
	if err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "deriving aead_key: " + err.Error()}
	}
	defer zeroize(aeadKey)

	nonce := make([]byte, crypto.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "generating nonce: " + err.Error()}
	}
	defer zeroize(nonce)

	// AD = service_id(16) || slot_id(16) || version(1) — 33 bytes
	// per PROTOCOL.md §7 / D-27. version MUST be wireVersion to
	// match the receiver's AD recomputation.
	ad := make([]byte, 0, slot.ServiceIDSize+slot.SlotIDSize+1)
	ad = append(ad, serviceID...)
	ad = append(ad, slotID...)
	ad = append(ad, wireVersion)

	// Optional content-AEAD wrap (D-66). The sealed inner blob
	// (`content_nonce(24) || content_ct||tag`) becomes the new
	// "plaintext" handed to the outer crypto.Seal — wire body
	// shape is unchanged.
	outerPlaintext := plaintext
	if cfg.ContentLayer != nil {
		sealed, err := cfg.ContentLayer.Seal(plaintext)
		if err != nil {
			return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "content-aead seal: " + err.Error()}
		}
		defer zeroize(sealed)
		outerPlaintext = sealed
	}

	ctWithTag, err := crypto.Seal(aeadKey, nonce, outerPlaintext, ad)
	if err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "aead seal: " + err.Error()}
	}

	// Wire body: version(1) || nonce(24) || ct||tag per PROTOCOL.md §7.
	body := make([]byte, 0, 1+crypto.NonceSize+len(ctWithTag))
	body = append(body, wireVersion)
	body = append(body, nonce...)
	body = append(body, ctWithTag...)

	deleteToken := make([]byte, DeleteTokenSize)
	if _, err := rand.Read(deleteToken); err != nil {
		return nil, &SendError{Code: exitcode.CryptoLocal, Detail: "generating delete token: " + err.Error()}
	}
	deleteHash := sha256.Sum256(deleteToken)

	url := cfg.RelayBaseURL + "/" + hex.EncodeToString(serviceID) + "/" + hex.EncodeToString(slotID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &SendError{Code: exitcode.Internal, Detail: "building request: " + err.Error()}
	}
	req.Header.Set("X-DeadDrop-Write", cfg.WriteToken)
	req.Header.Set("X-DeadDrop-Delete-Hash", hex.EncodeToString(deleteHash[:]))

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		// DNS / connect / TLS / timeout — resp is nil, must not defer
		// resp.Body.Close() before this guard.
		return nil, &SendError{Code: exitcode.RelayUnreachable, Detail: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusCreated:
		return deleteToken, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, &SendError{Code: exitcode.Auth, Detail: "relay rejected write token"}
	case http.StatusConflict:
		return nil, &SendError{Code: exitcode.Collision, Detail: "slot already exists (409)"}
	case http.StatusRequestEntityTooLarge:
		return nil, &SendError{Code: exitcode.SizeCap, Detail: "payload too large (413)"}
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, &SendError{
			Code:   exitcode.RelayOverloaded,
			Detail: "relay overloaded (" + strconv.Itoa(resp.StatusCode) + ")",
		}
	default:
		return nil, &SendError{
			Code:   exitcode.RelayUnreachable,
			Detail: fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// zeroize overwrites b in place. Best-effort; the compiler and
// runtime may keep copies outside the reachable slice.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
