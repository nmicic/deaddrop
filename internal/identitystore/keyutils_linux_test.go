// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package identitystore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"testing"
)

// keyutilsTestSetup gates the linux integration tests behind an env
// var, mirroring the passcache pattern. The default `go test ./...`
// must NOT touch the user's session keyring; an opt-in keeps CI noise
// off shared boxes.
func keyutilsTestSetup(t *testing.T) (Store, [8]byte) {
	t.Helper()
	if os.Getenv("DEADDROP_IDENTITYSTORE_KEYUTILS_TEST") != "1" {
		t.Skip("set DEADDROP_IDENTITYSTORE_KEYUTILS_TEST=1 to run keyutils integration tests")
	}
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand.Read pairID: %v", err)
	}
	_ = s.Forget(id)
	t.Cleanup(func() { _ = s.Forget(id) })
	return s, id
}

func keyutilsRandomEntry(t *testing.T) *Entry {
	t.Helper()
	e := &Entry{Role: RoleResponder}
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

func TestKeyutilsIdentity_PutGet(t *testing.T) {
	s, id := keyutilsTestSetup(t)
	want := keyutilsRandomEntry(t)
	if err := s.Put(id, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Role != want.Role ||
		!bytes.Equal(got.OwnSK[:], want.OwnSK[:]) ||
		!bytes.Equal(got.OwnPK[:], want.OwnPK[:]) ||
		!bytes.Equal(got.PeerPK[:], want.PeerPK[:]) {
		t.Fatalf("Get returned non-matching entry")
	}
}

func TestKeyutilsIdentity_ForgetGet(t *testing.T) {
	s, id := keyutilsTestSetup(t)
	if err := s.Put(id, keyutilsRandomEntry(t)); err != nil {
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

func TestKeyutilsIdentity_PutOverwrite(t *testing.T) {
	s, id := keyutilsTestSetup(t)
	first := keyutilsRandomEntry(t)
	if err := s.Put(id, first); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	second := keyutilsRandomEntry(t)
	second.Role = RoleInitiator
	if err := s.Put(id, second); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Role != second.Role || !bytes.Equal(got.OwnSK[:], second.OwnSK[:]) {
		t.Fatalf("overwrite did not take")
	}
}
