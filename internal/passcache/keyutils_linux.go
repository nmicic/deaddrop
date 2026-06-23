// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package passcache

import (
	"time"

	"golang.org/x/sys/unix"
)

const keyType = "user"

type keyutilsCache struct {
	ring int
}

func New() (Cache, error) {
	ring, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, false)
	if err != nil {
		return nil, ErrUnsupported
	}
	return &keyutilsCache{ring: ring}, nil
}

func (c *keyutilsCache) Get(id string) ([]byte, error) {
	keyID, err := unix.KeyctlSearch(c.ring, keyType, id, 0)
	if err != nil {
		return nil, ErrMiss
	}
	buf := make([]byte, 4096)
	// Closure (not `defer zeroize(buf)`) so the reassignment in the
	// grow-and-retry path zeroes the buffer that actually held the
	// secret, not the original 4096-byte stub.
	defer func() { zeroize(buf) }()
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
	if err != nil {
		return nil, ErrMiss
	}
	if n > len(buf) {
		buf = make([]byte, n)
		n, err = unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
		if err != nil {
			return nil, ErrMiss
		}
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *keyutilsCache) Put(id string, pass []byte, ttl time.Duration) error {
	if ttl == 0 {
		return nil
	}
	// AddKey creates or updates atomically if the same type+description
	// already exists in the keyring.
	keyID, err := unix.AddKey(keyType, id, pass, c.ring)
	if err != nil {
		return err
	}
	ttlSec := int(ttl.Seconds())
	if ttlSec <= 0 {
		ttlSec = 1
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, keyID, ttlSec, 0, 0)
	return err
}

func (c *keyutilsCache) Forget(id string) error {
	keyID, err := unix.KeyctlSearch(c.ring, keyType, id, 0)
	if err != nil {
		return nil
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, c.ring, 0, 0)
	return err
}
