// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package identitystore

import (
	"bytes"
	"errors"
	"testing"
)

func TestMarshalUnmarshalRoundtrip(t *testing.T) {
	want := &Entry{Role: RoleInitiator}
	for i := range want.OwnSK {
		want.OwnSK[i] = byte(i)
	}
	for i := range want.OwnPK {
		want.OwnPK[i] = byte(255 - i)
	}
	for i := range want.PeerPK {
		want.PeerPK[i] = byte(i ^ 0x55)
	}

	blob := MarshalEntry(want)
	if len(blob) != EntrySize {
		t.Fatalf("MarshalEntry len = %d, want %d", len(blob), EntrySize)
	}
	got, err := UnmarshalEntry(blob)
	if err != nil {
		t.Fatalf("UnmarshalEntry: %v", err)
	}
	if got.Role != want.Role ||
		!bytes.Equal(got.OwnSK[:], want.OwnSK[:]) ||
		!bytes.Equal(got.OwnPK[:], want.OwnPK[:]) ||
		!bytes.Equal(got.PeerPK[:], want.PeerPK[:]) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestUnmarshalEntry_RejectsBadInput(t *testing.T) {
	if _, err := UnmarshalEntry(make([]byte, EntrySize-1)); !errors.Is(err, ErrMiss) {
		t.Fatalf("short blob: err = %v, want ErrMiss", err)
	}
	if _, err := UnmarshalEntry(make([]byte, EntrySize+1)); !errors.Is(err, ErrMiss) {
		t.Fatalf("long blob: err = %v, want ErrMiss", err)
	}
	bad := make([]byte, EntrySize)
	bad[0] = 0xFF
	if _, err := UnmarshalEntry(bad); !errors.Is(err, ErrMiss) {
		t.Fatalf("bad role byte: err = %v, want ErrMiss", err)
	}
}

// TestNoop_PutGetForget asserts the contract documented on noopStore:
// Get is always a miss, Put silently accepts, Forget never errors.
func TestNoop_PutGetForget(t *testing.T) {
	s := Noop()
	var id [8]byte
	id[0] = 0xAB

	if err := s.Put(id, &Entry{Role: RoleInitiator}); err != nil {
		t.Fatalf("Noop Put: %v", err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrMiss) {
		t.Fatalf("Noop Get: err = %v, want ErrMiss", err)
	}
	if err := s.Forget(id); err != nil {
		t.Fatalf("Noop Forget: %v", err)
	}
}
