// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/identitystore"
)

type mockPBResponse struct {
	data []byte
	err  error
}

type mockPBReader struct {
	responses []mockPBResponse
	idx       int
}

func (m *mockPBReader) ReadPassphrase(_ string) ([]byte, error) {
	if m.idx >= len(m.responses) {
		return nil, io.EOF
	}
	r := m.responses[m.idx]
	m.idx++
	if r.err != nil {
		return nil, r.err
	}
	return r.data, nil
}

func finishState(pa string) *State {
	return &State{
		PassphraseKey: DerivePassphraseKey([]byte(pa)),
	}
}

func TestFinishBootstrap_Happy(t *testing.T) {
	s := finishState("pa")
	defer s.Zeroize()

	var psk [32]byte
	var pairID [8]byte
	for i := range psk {
		psk[i] = 0x55
	}
	for i := range pairID {
		pairID[i] = 0xAA
	}
	var iPK, rPK [32]byte
	for i := range iPK {
		iPK[i] = 0x10
	}
	for i := range rPK {
		rPK[i] = 0x20
	}

	enter := strings.NewReader("\n")
	pb := &mockPBReader{responses: []mockPBResponse{
		{data: []byte("pb-different")},
	}}
	var stdout bytes.Buffer
	capsulePath := t.TempDir() + "/capsule"

	err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &stdout, capsulePath)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal("capsule file not created:", err)
	}
	gotPSK, gotPairID, err := capsule.Unwrap([]byte("pb-different"), data)
	if err != nil {
		t.Fatal("capsule unwrap failed:", err)
	}
	for i := range psk {
		if gotPSK[i] != psk[i] {
			t.Fatalf("PSK mismatch at byte %d", i)
		}
	}
	for i := range pairID {
		if gotPairID[i] != pairID[i] {
			t.Fatalf("pairID mismatch at byte %d", i)
		}
	}

	out := stdout.String()
	if !strings.Contains(out, "pairing fingerprint:") {
		t.Error("missing 'pairing fingerprint:' in stdout")
	}
	if !strings.Contains(out, "MITM") {
		t.Error("missing 'MITM' in stdout")
	}
	if !strings.Contains(out, "Ctrl-C") {
		t.Error("missing 'Ctrl-C' in stdout")
	}
}

func TestFinishBootstrap_FingerprintAbort(t *testing.T) {
	s := finishState("pa")
	defer s.Zeroize()

	var psk [32]byte
	var pairID [8]byte
	var iPK, rPK [32]byte

	enter := strings.NewReader("")
	pb := &mockPBReader{}
	capsulePath := t.TempDir() + "/capsule"

	err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &bytes.Buffer{}, capsulePath)
	if err != ErrFingerprintAbort {
		t.Fatalf("got %v, want ErrFingerprintAbort", err)
	}
	if _, statErr := os.Stat(capsulePath); statErr == nil {
		t.Fatal("capsule file should not exist after abort")
	}
}

func TestFinishBootstrap_PBReuse(t *testing.T) {
	s := finishState("pa")
	defer s.Zeroize()

	var psk [32]byte
	var pairID [8]byte
	var iPK, rPK [32]byte

	enter := strings.NewReader("\n")
	pb := &mockPBReader{responses: []mockPBResponse{
		{data: []byte("pa")},
		{data: []byte("pb-different")},
	}}
	var stdout bytes.Buffer
	capsulePath := t.TempDir() + "/capsule"

	err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &stdout, capsulePath)
	if err != nil {
		t.Fatal(err)
	}

	out := stdout.String()
	if !strings.Contains(out, "P_B must differ from P_A") {
		t.Error("missing re-prompt message in stdout")
	}

	if _, err := os.Stat(capsulePath); err != nil {
		t.Fatal("capsule file not created")
	}
}

// fakeStore is an in-memory Store backend used to assert that
// FinishBootstrap actually calls Put with the right pair / role.
type fakeStore struct {
	puts    map[[8]byte]*identitystore.Entry
	failPut error
}

func newFakeStore() *fakeStore {
	return &fakeStore{puts: map[[8]byte]*identitystore.Entry{}}
}

func (f *fakeStore) Get(id [8]byte) (*identitystore.Entry, error) {
	e, ok := f.puts[id]
	if !ok {
		return nil, identitystore.ErrMiss
	}
	return e, nil
}

func (f *fakeStore) Put(id [8]byte, e *identitystore.Entry) error {
	if f.failPut != nil {
		return f.failPut
	}
	cp := *e
	f.puts[id] = &cp
	return nil
}

func (f *fakeStore) Forget(id [8]byte) error {
	delete(f.puts, id)
	return nil
}

func TestFinishBootstrap_PersistsIdentity(t *testing.T) {
	s := finishState("pa")
	defer s.ZeroizeBootstrap()

	store := newFakeStore()
	s.IdentityStore = store
	s.Role = Responder
	for i := range s.IdentitySK {
		s.IdentitySK[i] = byte(0x70 + i)
	}
	for i := range s.IdentityPK {
		s.IdentityPK[i] = byte(0x80 + i)
	}
	for i := range s.PeerPK {
		s.PeerPK[i] = byte(0x90 + i)
	}
	wantOwnSK := s.IdentitySK
	wantOwnPK := s.IdentityPK
	wantPeerPK := s.PeerPK

	var psk [32]byte
	var pairID [8]byte
	for i := range pairID {
		pairID[i] = byte(0xA0 + i)
	}
	var iPK, rPK [32]byte

	enter := strings.NewReader("\n")
	pb := &mockPBReader{responses: []mockPBResponse{
		{data: []byte("pb-different")},
	}}
	capsulePath := t.TempDir() + "/capsule"

	if err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &bytes.Buffer{}, capsulePath); err != nil {
		t.Fatal(err)
	}

	got, ok := store.puts[pairID]
	if !ok {
		t.Fatal("identitystore.Put was not called for pairID")
	}
	if got.Role != identitystore.RoleResponder {
		t.Fatalf("entry.Role = %d, want RoleResponder", got.Role)
	}
	if got.OwnSK != wantOwnSK {
		t.Fatalf("entry.OwnSK does not match")
	}
	if got.OwnPK != wantOwnPK {
		t.Fatalf("entry.OwnPK does not match")
	}
	if got.PeerPK != wantPeerPK {
		t.Fatalf("entry.PeerPK does not match")
	}

	// D-65 split: identity fields must be zeroized once Put returned.
	for _, b := range s.IdentitySK {
		if b != 0 {
			t.Fatal("IdentitySK was not zeroized after FinishBootstrap")
		}
	}
	for _, b := range s.PeerPK {
		if b != 0 {
			t.Fatal("PeerPK was not zeroized after FinishBootstrap")
		}
	}
}

func TestFinishBootstrap_IdentityStorePutFailure(t *testing.T) {
	s := finishState("pa")
	defer s.ZeroizeBootstrap()

	store := newFakeStore()
	store.failPut = errors.New("backend down")
	s.IdentityStore = store

	var psk [32]byte
	var pairID [8]byte
	var iPK, rPK [32]byte

	enter := strings.NewReader("\n")
	pb := &mockPBReader{responses: []mockPBResponse{
		{data: []byte("pb-different")},
	}}
	capsulePath := t.TempDir() + "/capsule"

	err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &bytes.Buffer{}, capsulePath)
	if err == nil {
		t.Fatal("expected error from identitystore.Put failure")
	}
	if !strings.Contains(err.Error(), "rebootstrap to recover") {
		t.Fatalf("expected rebootstrap-to-recover guidance in error, got: %v", err)
	}
	// Capsule must remain on disk so the operator can re-run from a
	// known state. The half-written warning is the operator's UX.
	if _, statErr := os.Stat(capsulePath); statErr != nil {
		t.Fatalf("capsule should still exist after Put failure: %v", statErr)
	}
}

func TestFinishBootstrap_PBReadError(t *testing.T) {
	s := finishState("pa")
	defer s.Zeroize()

	var psk [32]byte
	var pairID [8]byte
	var iPK, rPK [32]byte

	enter := strings.NewReader("\n")
	pb := &mockPBReader{responses: []mockPBResponse{
		{err: io.ErrUnexpectedEOF},
	}}
	capsulePath := t.TempDir() + "/capsule"

	err := FinishBootstrap(s, psk, pairID, iPK, rPK, enter, pb, &bytes.Buffer{}, capsulePath)
	if err == nil {
		t.Fatal("expected error")
	}
	if err == ErrFingerprintAbort {
		t.Fatal("error should not be ErrFingerprintAbort")
	}
	if _, statErr := os.Stat(capsulePath); statErr == nil {
		t.Fatal("capsule file should not exist after pb read error")
	}
}
