// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && identitystore_keychain

package identitystore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"testing"
)

// keychainTestSetup gates every subtest on the same env-var dance the
// passcache keychain tests use. The default dev-loop must NOT touch
// the user's real Keychain, so we Skip unless the operator opts in
// with DEADDROP_IDENTITYSTORE_KEYCHAIN_TEST=1.
//
// The returned (store, pairID) is unique per subtest invocation; the
// cleanup hook deletes the entry on success or panic.
func keychainTestSetup(t *testing.T) (Store, [8]byte) {
	t.Helper()
	if os.Getenv("DEADDROP_IDENTITYSTORE_KEYCHAIN_TEST") != "1" {
		t.Skip("set DEADDROP_IDENTITYSTORE_KEYCHAIN_TEST=1 to run keychain integration tests")
	}
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	// Defensive Forget at start in case a prior run crashed mid-test.
	_ = s.Forget(id)
	t.Cleanup(func() { _ = s.Forget(id) })
	return s, id
}

func randomEntry(t *testing.T) *Entry {
	t.Helper()
	e := &Entry{Role: RoleInitiator}
	if _, err := rand.Read(e.OwnSK[:]); err != nil {
		t.Fatalf("rand.Read OwnSK: %v", err)
	}
	if _, err := rand.Read(e.OwnPK[:]); err != nil {
		t.Fatalf("rand.Read OwnPK: %v", err)
	}
	if _, err := rand.Read(e.PeerPK[:]); err != nil {
		t.Fatalf("rand.Read PeerPK: %v", err)
	}
	return e
}

func entryEqual(a, b *Entry) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Role == b.Role &&
		bytes.Equal(a.OwnSK[:], b.OwnSK[:]) &&
		bytes.Equal(a.OwnPK[:], b.OwnPK[:]) &&
		bytes.Equal(a.PeerPK[:], b.PeerPK[:])
}

func TestKeychainIdentity_PutGet(t *testing.T) {
	s, id := keychainTestSetup(t)
	want := randomEntry(t)

	if err := s.Put(id, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !entryEqual(got, want) {
		t.Fatalf("Get returned a non-matching entry")
	}
}

func TestKeychainIdentity_ForgetGet(t *testing.T) {
	s, id := keychainTestSetup(t)
	if err := s.Put(id, randomEntry(t)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Forget(id); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	_, err := s.Get(id)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("Get after Forget: err = %v, want ErrMiss", err)
	}
}

func TestKeychainIdentity_PutIdempotent(t *testing.T) {
	s, id := keychainTestSetup(t)
	first := randomEntry(t)
	if err := s.Put(id, first); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	second := randomEntry(t)
	second.Role = RoleResponder
	if err := s.Put(id, second); err != nil {
		t.Fatalf("second Put (overwrite): %v", err)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !entryEqual(got, second) {
		t.Fatalf("overwrite did not take: Get returned the first entry")
	}
}

func TestKeychainIdentity_GetMiss(t *testing.T) {
	s, id := keychainTestSetup(t)
	// Make sure we never wrote: the setup's Forget already ran.
	_, err := s.Get(id)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("Get on empty pair: err = %v, want ErrMiss", err)
	}
}
