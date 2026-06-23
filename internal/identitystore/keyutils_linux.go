// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package identitystore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	// idKeyType is the standard "user" type used by both passcache
	// and identitystore — the kernel does not distinguish payload
	// shapes by type.
	idKeyType = "user"

	// idDescPrefix is the keyutils description prefix for identity
	// entries. Distinct from passcache's "deaddrop:" so
	// `keyctl list @s` shows the two services separately (D-63).
	idDescPrefix = "deaddrop-id-"
)

type keyutilsStore struct {
	ring int
}

// New constructs the Linux keyutils identitystore backed by the
// UID-scoped persistent keyring (D-69). Falls back to the session
// keyring with a stderr WARN on ENOSYS/EPERM. Returns ErrUnsupported
// when neither keyring is reachable.
func New() (Store, error) {
	// KEYCTL_GET_PERSISTENT(uid=-1, dest=session) links the calling
	// UID's persistent keyring into the session keyring and returns
	// its serial. The persistent keyring is UID-scoped, kernel-RAM
	// resident, and survives logout for at least the value at
	// /proc/sys/kernel/keys/persistent_keyring_expiry (default 3 days).
	// Any access resets the timer (D-69).
	ring, err := unix.KeyctlInt(
		unix.KEYCTL_GET_PERSISTENT, -1,
		unix.KEY_SPEC_SESSION_KEYRING, 0, 0)
	if err == nil {
		return &keyutilsStore{ring: ring}, nil
	}
	// ENOSYS = kernel built without CONFIG_PERSISTENT_KEYRINGS; EPERM =
	// lockdown / namespace restriction. Fall back to the session keyring
	// so legacy 0x01 mode + visible WARN beats a hard exit on platforms
	// the operator cannot upgrade (D-69 fallback).
	persistErr := err
	if errors.Is(persistErr, unix.ENOSYS) || errors.Is(persistErr, unix.EPERM) {
		ring, fbErr := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false)
		if fbErr == nil {
			fmt.Fprintf(os.Stderr,
				"WARN: KEYCTL_GET_PERSISTENT failed: %v; "+
					"falling back to session keyring — identity will not "+
					"survive logout (re-bootstrap required after logout)\n",
				persistErr)
			return &keyutilsStore{ring: ring}, nil
		}
	}
	return nil, ErrUnsupported
}

func description(pairID [8]byte) string {
	return idDescPrefix + hex.EncodeToString(pairID[:])
}

func (c *keyutilsStore) Get(pairID [8]byte) (*Entry, error) {
	desc := description(pairID)
	keyID, err := unix.KeyctlSearch(c.ring, idKeyType, desc, 0)
	if err != nil {
		return nil, ErrMiss
	}
	buf := make([]byte, EntrySize)
	defer func() { zeroize(buf) }()
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
	if err != nil {
		return nil, ErrMiss
	}
	if n > len(buf) {
		// Rare: the in-keyring blob is larger than the canonical
		// EntrySize. Grow and retry once. UnmarshalEntry will then
		// reject the unexpected length as ErrMiss.
		buf = make([]byte, n)
		n, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
		if err != nil {
			return nil, ErrMiss
		}
	}
	if n != EntrySize {
		return nil, ErrMiss
	}
	return UnmarshalEntry(buf[:n])
}

func (c *keyutilsStore) Put(pairID [8]byte, e *Entry) error {
	if e == nil {
		return errors.New("identitystore: refusing to store nil entry")
	}
	if e.Role != RoleInitiator && e.Role != RoleResponder {
		return errors.New("identitystore: invalid role byte")
	}
	blob := MarshalEntry(e)
	defer zeroize(blob)

	// CRITICAL D-63 deviation from passcache: do NOT call
	// KEYCTL_SET_TIMEOUT. The kernel default for a key with no
	// timeout is "live until unlinked or session ends" — which is
	// exactly the desired identity-entry semantics. Copying the
	// passcache `if ttl == 0 { return nil }` guard would be fatal.
	_, err := unix.AddKey(idKeyType, description(pairID), blob, c.ring)
	return err
}

func (c *keyutilsStore) Forget(pairID [8]byte) error {
	keyID, err := unix.KeyctlSearch(c.ring, idKeyType, description(pairID), 0)
	if err != nil {
		// Idempotent: not found is success.
		return nil
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, c.ring, 0, 0)
	return err
}
