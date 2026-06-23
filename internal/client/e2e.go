// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"

	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/identitystore"
)

// ContentLayerVersion is the version byte bound into the content-AEAD
// AD. Independent of capsule.Version and wire-version constants —
// see D-66. A future content-layer change (e.g., a key-derivation
// tweak) bumps this byte without touching capsule or wire versions.
const ContentLayerVersion byte = 0x01

// contentInfoLabel is the HKDF info-label prefix for content-key
// derivation. The full info bytes are
// `info_label || PairID(8)` (D-66) — PairID-only, NOT
// service_id/slot_id/version, since those are per-send values that
// would force re-derivation on every send and break D-60's static-
// static derive-once-per-pair model.
const contentInfoLabel = "deaddrop-e2e-content-v1"

// ContentLayer carries the resolved per-pair content-AEAD key. It is
// constructed once at the CLI layer (after identitystore.Get) and
// flows down into SendConfig / RecvConfig via the ContentLayer field.
// The constructor (newContentLayer) is the only path that touches
// the raw OwnSK; once contentKey is derived, the SK is zeroized at
// the call site and never re-read.
type ContentLayer struct {
	pairID     [8]byte
	contentKey []byte // 32 bytes; zeroized via Wipe at the CLI's defer
}

// PairID returns the pair the content layer was derived for. Used
// by tests asserting AD/info derivations.
func (cl *ContentLayer) PairID() [8]byte { return cl.pairID }

// Wipe zeros the in-memory content key. CLI callers should defer
// Wipe immediately after newContentLayer succeeds.
func (cl *ContentLayer) Wipe() {
	if cl == nil {
		return
	}
	zeroize(cl.contentKey)
}

// contentAD constructs the AD bound by both Seal and Open. AD is
// `info_label(23) || PairID(8) || ContentLayerVersion(1)` = 32 bytes,
// matching D-66.
func (cl *ContentLayer) contentAD() []byte {
	ad := make([]byte, 0, len(contentInfoLabel)+8+1)
	ad = append(ad, []byte(contentInfoLabel)...)
	ad = append(ad, cl.pairID[:]...)
	ad = append(ad, ContentLayerVersion)
	return ad
}

// Seal wraps plaintext with the content-AEAD layer and returns
// `content_nonce(24) || content_ct||content_tag`. Caller is
// responsible for any plaintext-side zeroization.
func (cl *ContentLayer) Seal(plaintext []byte) ([]byte, error) {
	if cl == nil {
		return nil, errors.New("client: nil ContentLayer")
	}
	if len(cl.contentKey) != crypto.KeySize {
		return nil, errors.New("client: ContentLayer not initialised")
	}
	nonce := make([]byte, crypto.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ad := cl.contentAD()
	ct, err := crypto.Seal(cl.contentKey, nonce, plaintext, ad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open reverses Seal: input is `content_nonce(24) ||
// content_ct||content_tag`. AEAD-failure is mapped at the CLI layer
// to EDDE2EUnwrap.
func (cl *ContentLayer) Open(blob []byte) ([]byte, error) {
	if cl == nil {
		return nil, errors.New("client: nil ContentLayer")
	}
	if len(cl.contentKey) != crypto.KeySize {
		return nil, errors.New("client: ContentLayer not initialised")
	}
	if len(blob) < crypto.NonceSize+crypto.TagSize {
		return nil, errors.New("client: content blob too short")
	}
	nonce := blob[:crypto.NonceSize]
	ctWithTag := blob[crypto.NonceSize:]
	ad := cl.contentAD()
	pt, err := crypto.Open(cl.contentKey, nonce, ctWithTag, ad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// newContentLayer derives the per-pair content-AEAD key from the
// resolved identity entry per D-66:
//
//  1. ikm = curve25519.X25519(entry.OwnSK, entry.PeerPK)
//  2. Reject if X25519 errored OR ikm is all-zero (low-order
//     PeerPK or DH-trivial peer).
//  3. info = "deaddrop-e2e-content-v1" || PairID
//  4. content_key = HKDF-SHA256(ikm, nil, info, 32)
//  5. Zero ikm before returning.
//
// The constructor never retains the SK or the IKM. Any error here
// is fatal at the CLI: the operator either has a corrupt entry or
// a malicious peer pubkey was injected at bootstrap. Either way,
// fall-through to legacy 0x01 mode is forbidden — surface as
// EDDIdentityStore with a "rebootstrap to recover" message.
func newContentLayer(entry *identitystore.Entry, pairID [8]byte) (*ContentLayer, error) {
	if entry == nil {
		return nil, errors.New("client: nil identity entry")
	}
	ikm, err := curve25519.X25519(entry.OwnSK[:], entry.PeerPK[:])
	if err != nil {
		// Go's X25519 returns an error when the DH output is the
		// all-zero point (small-order peer pubkey) — surface as a
		// constructor failure so the CLI maps it to
		// EDDIdentityStore. Defense-in-depth: also check the IKM
		// bytes directly, in case a future stdlib version stops
		// erroring on the low-order case.
		return nil, errors.New("client: X25519 failed (low-order peer pubkey?)")
	}
	defer zeroize(ikm)
	if crypto.IsAllZero(ikm) {
		return nil, errors.New("client: X25519 produced all-zero shared secret (low-order peer pubkey)")
	}

	info := make([]byte, 0, len(contentInfoLabel)+len(pairID))
	info = append(info, []byte(contentInfoLabel)...)
	info = append(info, pairID[:]...)

	key, err := crypto.DeriveKey(ikm, nil, info, crypto.KeySize)
	if err != nil {
		return nil, err
	}
	return &ContentLayer{
		pairID:     pairID,
		contentKey: key,
	}, nil
}

// NewContentLayerFromEntry is the exported constructor wrapper. CLI
// code in cmd/deaddrop calls this after resolving the identity entry;
// internal client tests use newContentLayer directly. The exported
// shape is provided so cmd/deaddrop does not have to reach into the
// package's lowercased helper.
func NewContentLayerFromEntry(entry *identitystore.Entry, pairID [8]byte) (*ContentLayer, error) {
	return newContentLayer(entry, pairID)
}
