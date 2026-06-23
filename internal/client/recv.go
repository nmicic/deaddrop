// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/hex"
	"errors"
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

// probeCount is the number of past-only minute buckets recv inspects
// on every invocation (D-36, PROTOCOL.md §9). Always three:
// current, current-1, current-2. Never probes into the future.
const probeCount = 3

// maxRecvBody caps a 200 GET response at 11 MiB — one MiB over the
// D-25 blob ceiling, leaving headroom for wire overhead + any
// deployment tweaks. Defense-in-depth against a malicious relay
// emitting unbounded data; the client does not trust the relay.
const maxRecvBody = 11 * 1024 * 1024

// RecvConfig bundles every dependency the recv probe loop needs.
// HTTPClient and Clock are injected so tests drive the flow
// deterministically without live network or wall-clock coupling.
//
// Recv is a read-only path; per D-45 it MUST NOT carry a
// write-token on the GET request, so this struct does not have
// a WriteToken field.
type RecvConfig struct {
	PSK          []byte
	PairID       []byte
	DeploySecret []byte
	RelayBaseURL string
	HTTPClient   *http.Client
	Clock        func() time.Time

	// ContentLayer, if non-nil, unwraps the inner content-AEAD
	// layer after the outer capsule-AEAD open succeeds (D-66).
	// The CLI layer resolves the identity entry per pair and
	// constructs the layer (cmd/deaddrop/recv.go).
	ContentLayer *ContentLayer

	// RequireE2E is the recv-side strict-mode flag (D-65). When
	// true, a body that arrives with VersionPlainB (0x01) for a
	// pair that has identity entry exits EDDIdentityMiss instead
	// of warning.
	RequireE2E bool

	// WarnSink receives non-fatal recv-side warnings (e.g., legacy
	// sender on a pair that has identity). The CLI populates this
	// with stderr; in-process tests pass a *bytes.Buffer. nil is
	// acceptable (warnings silently dropped).
	WarnSink io.Writer
}

// RecvError carries a D-38 exit code alongside a human-readable
// detail. The CLI unwraps it to produce the canonical
// "ERROR: <EDDName>: <detail>" banner.
type RecvError struct {
	Code   int
	Detail string
}

func (e *RecvError) Error() string { return e.Detail }

// IsMiss reports whether err is a *RecvError with code NotFound
// (the all-buckets-empty exit). Used by the --watch polling loop
// to distinguish "no message yet" from hard failures (D-70).
func IsMiss(err error) bool {
	var re *RecvError
	return errors.As(err, &re) && re.Code == exitcode.NotFound
}

// RecvCtx is the context-aware variant of Recv. Each bucket GET
// uses http.NewRequestWithContext so that context cancellation
// (e.g., SIGINT during --watch) aborts the in-flight HTTP round-trip
// within ~1 s (D-70). The existing Recv delegates here with
// context.Background().
func RecvCtx(ctx context.Context, cfg RecvConfig) ([]byte, error) {
	now := cfg.Clock()
	bNow := uint64(now.Unix()) / 60

	slotKey, err := slot.SlotKey(cfg.PSK, cfg.PairID)
	if err != nil {
		return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "deriving slot_key: " + err.Error()}
	}
	defer zeroize(slotKey)

	for offset := uint64(0); offset < probeCount; offset++ {
		b := bNow - offset
		// AC-ROLL-03: hour derives from THIS bucket, not bNow. At an
		// hour boundary the three probed buckets may straddle two
		// hours; each one uses its own service_id.
		h := b / 60

		serviceID, err := slot.ServiceID(cfg.DeploySecret, h)
		if err != nil {
			return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "deriving service_id: " + err.Error()}
		}
		slotID, err := slot.SlotID(slotKey, b, 0)
		if err != nil {
			return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "deriving slot_id: " + err.Error()}
		}

		url := cfg.RelayBaseURL + "/" + hex.EncodeToString(serviceID) + "/" + hex.EncodeToString(slotID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, &RecvError{Code: exitcode.Internal, Detail: "building request: " + err.Error()}
		}
		// D-45: GET MUST NOT carry the write-token.

		resp, err := cfg.HTTPClient.Do(req)
		if err != nil {
			// Nil-check before any defer: resp is nil on DNS /
			// connect / TLS / timeout failure.
			return nil, &RecvError{Code: exitcode.RelayUnreachable, Detail: err.Error()}
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRecvBody))
		resp.Body.Close()
		if readErr != nil {
			return nil, &RecvError{Code: exitcode.RelayUnreachable, Detail: "reading response: " + readErr.Error()}
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// Version check first — rejects 0x00 / 0x02-0x03 / 0x05-0xFF
			// before any AEAD work. Only 0x01 (legacy) and 0x04
			// (E2E-double-wrap) are accepted (D-68 / SPEC §3).
			wireVersion, err := wire.ParseVersion(body)
			if err != nil {
				return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "version: " + err.Error()}
			}
			if !wire.IsPlainBody(wireVersion) {
				return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: fmt.Sprintf("unsupported wire version 0x%02x", wireVersion)}
			}
			if len(body) < 1+crypto.NonceSize+crypto.TagSize {
				return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "body too short"}
			}

			// D-65 dispatch matrix: refuse early if the body declares
			// 0x04 but the receiver has no ContentLayer resolved. This
			// is the "E2E-only sender, legacy receiver" surface — it
			// must NOT slip into a confusing AEAD failure later.
			if wireVersion == wire.VersionPlainBE2E && cfg.ContentLayer == nil {
				return nil, &RecvError{
					Code:   exitcode.IdentityMiss,
					Detail: "sender used E2E (0x04) but no identity entry is available for this pair — rebootstrap to enable E2E",
				}
			}
			// D-65 strict-mode: legacy sender on a pair where the
			// receiver has identity. With --require-e2e the receiver
			// hard-fails; otherwise warn (handled after Open below).
			if wireVersion == wire.VersionPlainB && cfg.ContentLayer != nil && cfg.RequireE2E {
				return nil, &RecvError{
					Code:   exitcode.IdentityMiss,
					Detail: "strict mode (--require-e2e): sender used legacy (0x01) on a pair with identity entry; refusing to accept",
				}
			}

			aeadKey, err := slot.AEADKey(cfg.PSK, cfg.PairID, serviceID, slotID, wireVersion)
			if err != nil {
				return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "deriving aead_key: " + err.Error()}
			}

			nonce := body[1 : 1+crypto.NonceSize]
			ctWithTag := body[1+crypto.NonceSize:]

			ad := make([]byte, 0, slot.ServiceIDSize+slot.SlotIDSize+1)
			ad = append(ad, serviceID...)
			ad = append(ad, slotID...)
			ad = append(ad, wireVersion)

			outerPT, err := crypto.Open(aeadKey, nonce, ctWithTag, ad)
			zeroize(aeadKey)
			if err != nil {
				// No oracle detail (D-14) — the client cannot
				// distinguish wrong key from tampered ciphertext.
				return nil, &RecvError{Code: exitcode.CryptoLocal, Detail: "decrypt failed"}
			}

			// D-66 inner unwrap. By construction we only reach this
			// branch when ContentLayer is non-nil (the early miss
			// check above guards 0x04 with no layer).
			if wireVersion == wire.VersionPlainBE2E {
				payload, err := cfg.ContentLayer.Open(outerPT)
				if err != nil {
					// Outer AEAD passed but inner failed — the
					// peer's identity does not match what the
					// receiver has on file. Distinct from a wrong-
					// PSK error, hence its own exit code.
					return nil, &RecvError{
						Code:   exitcode.E2EUnwrap,
						Detail: "inner content-AEAD open failed: peer identity mismatch (rebootstrap if a key rotated)",
					}
				}
				return payload, nil
			}

			// VersionPlainB on a pair with ContentLayer in non-strict
			// mode: deliver, but warn so the operator notices the
			// asymmetry (D-65). RequireE2E was already handled above.
			if cfg.ContentLayer != nil && cfg.WarnSink != nil {
				fmt.Fprintln(cfg.WarnSink,
					"warning: sender used legacy capsule (0x01) but this receiver has an identity entry for the pair; "+
						"the message is authentic at the capsule layer but not E2E-verified")
			}
			return outerPT, nil

		case http.StatusNotFound:
			// Uniform 404 per D-14: continue to the next bucket.
			continue

		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, &RecvError{Code: exitcode.Auth, Detail: "relay rejected credentials"}

		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			return nil, &RecvError{
				Code:   exitcode.RelayOverloaded,
				Detail: "relay overloaded (" + strconv.Itoa(resp.StatusCode) + ")",
			}

		default:
			return nil, &RecvError{
				Code:   exitcode.RelayUnreachable,
				Detail: "unexpected status: " + strconv.Itoa(resp.StatusCode),
			}
		}
	}

	return nil, &RecvError{Code: exitcode.NotFound, Detail: "no message found (probed 3 buckets)"}
}

// Recv probes 3 minute buckets past-only (bNow, bNow-1, bNow-2),
// GETs each slot path, and decrypts the first 200 response it
// observes. Returns the plaintext or a *RecvError with the mapped
// D-38 exit code. 404 on a bucket means "not in this bucket; try
// the next one" — the loop only surrenders NotFound after all three
// probes miss. Any other non-200 status is a hard stop (no retry).
//
// Thin wrapper around RecvCtx with context.Background().
func Recv(cfg RecvConfig) ([]byte, error) {
	return RecvCtx(context.Background(), cfg)
}
