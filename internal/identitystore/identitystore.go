// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Package identitystore persists per-pair long-term X25519 identity
// keys behind a uniform Get/Put/Forget interface. It mirrors the
// shape of internal/passcache but lives in its own namespace so the
// passphrase-cache lifecycle (TTL'd, per-cache-id) and the identity-
// store lifecycle (persistent, per-pair, never expires) cannot leak
// into one another. See SPEC_BOOTSTRAP / DECISIONS D-61..D-68, D-69
// for the design rationale behind this split.
//
// On Linux, New() anchors entries in the UID-scoped persistent keyring
// via KEYCTL_GET_PERSISTENT (D-69). If the kernel lacks
// CONFIG_PERSISTENT_KEYRINGS (ENOSYS) or the namespace forbids it
// (EPERM), New() falls back to the session keyring with a stderr WARN.
//
// New() is intentionally NOT declared in this file. It is defined
// exactly once per build, in the corresponding tagged backend file
// (keychain_darwin.go, keyutils_linux.go, or stub_other.go). Forward-
// declaring it here would produce a duplicate-definition build error
// on every platform whose tagged file also defines it.
package identitystore

import "errors"

// Role bytes serialized at offset 0 of every Entry blob (D-64).
// The fingerprint code in internal/bootstrap/pairing_fpr.go takes
// (initiatorPK, responderPK) as ordered arguments — recovering that
// order at fingerprint time requires knowing which side persisted
// the entry. RoleInitiator and RoleResponder are the only legal
// values; any other byte at offset 0 is treated as a corrupt blob
// and surfaces ErrMiss.
const (
	RoleInitiator byte = 0x00
	RoleResponder byte = 0x01

	// EntrySize is the on-wire (and in-keyring) size of a serialized
	// Entry. Layout: Role(1) || OwnSK(32) || OwnPK(32) || PeerPK(32)
	// (D-64). Fixed-width binary; no ASN.1 / JSON / CFG.
	EntrySize = 97
)

// Entry holds the per-pair identity material. Role tells the
// fingerprint reconstructor which of OwnPK/PeerPK is the initiator
// pubkey and which is the responder pubkey (D-67). OwnPK is
// redundant — it is derivable from OwnSK via curve25519.ScalarBaseMult
// — but storing it costs 32 bytes and saves a curve op on every send/
// recv (D-64).
type Entry struct {
	Role   byte
	OwnSK  [32]byte
	OwnPK  [32]byte
	PeerPK [32]byte
}

// Store is the persistence shape every backend implements.
// pairID is the canonical lookup key (already in capsule plaintext;
// no extra state needs to flow through send/recv config). The
// interface intentionally has no TTL parameter — identity entries
// are persistent for the life of the pair (per D-63 the Linux
// session keyring lifetime is bounded by login, but that bound is
// kernel-side, not Store-API-side).
type Store interface {
	Get(pairID [8]byte) (*Entry, error)
	Put(pairID [8]byte, e *Entry) error
	Forget(pairID [8]byte) error
}

// Sentinel errors. ErrMiss is the operator-friendly "no entry for
// this pair" signal; the bootstrap CLI translates it to a
// rebootstrap-instruction. ErrUnsupported names the
// platform-stub-backend case (no keyring available); the bootstrap
// CLI either falls back to Noop() (default) or fails with
// EDDPlatformUnsupported (when --require-e2e is set).
var (
	ErrMiss        = errors.New("identitystore: no entry for pair")
	ErrUnsupported = errors.New("identitystore: backend not available on this platform")
)

// noopStore is the always-miss / silent-Put fallback. It is the
// well-defined Store the bootstrap CLI installs when New() returns
// ErrUnsupported and the operator did not pass --require-e2e=true.
// With Noop active, a pair completes bootstrap in legacy mode (no
// identity persisted) and send/recv dispatch on the absence of any
// entry.
type noopStore struct{}

func (noopStore) Get(_ [8]byte) (*Entry, error) { return nil, ErrMiss }
func (noopStore) Put(_ [8]byte, _ *Entry) error { return nil }
func (noopStore) Forget(_ [8]byte) error        { return nil }

// Noop returns the well-defined no-op Store described above. Defined
// in this build-tag-free file because it has no platform dependencies
// and is needed on every OS (the CLI's ErrUnsupported branch installs
// it on darwin / linux / windows alike).
func Noop() Store { return noopStore{} }

// MarshalEntry serializes e into a fresh EntrySize-byte slice in the
// canonical D-64 order: Role(1) || OwnSK(32) || OwnPK(32) || PeerPK(32).
// The caller owns the returned slice and is responsible for zeroizing
// it once the keyring write returns.
func MarshalEntry(e *Entry) []byte {
	out := make([]byte, 0, EntrySize)
	out = append(out, e.Role)
	out = append(out, e.OwnSK[:]...)
	out = append(out, e.OwnPK[:]...)
	out = append(out, e.PeerPK[:]...)
	return out
}

// UnmarshalEntry parses a canonical entry blob. Returns ErrMiss for
// any structural failure (wrong length, illegal Role byte) so the
// operator gets the rebootstrap path rather than a corrupt-entry
// mystery (D-64).
func UnmarshalEntry(blob []byte) (*Entry, error) {
	if len(blob) != EntrySize {
		return nil, ErrMiss
	}
	role := blob[0]
	if role != RoleInitiator && role != RoleResponder {
		return nil, ErrMiss
	}
	e := &Entry{Role: role}
	copy(e.OwnSK[:], blob[1:33])
	copy(e.OwnPK[:], blob[33:65])
	copy(e.PeerPK[:], blob[65:97])
	return e, nil
}
