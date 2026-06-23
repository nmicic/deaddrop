// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
)

func TestWriteCapsule_RoundTrip(t *testing.T) {
	var psk [32]byte
	var pairID [8]byte
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range pairID {
		pairID[i] = byte(i + 100)
	}
	pass := []byte("test-passphrase")

	path := t.TempDir() + "/capsule"
	if err := WriteCapsule(path, psk, pairID, pass); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	gotPSK, gotPairID, err := capsule.Unwrap(pass, data)
	if err != nil {
		t.Fatal(err)
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
}

func TestWriteCapsule_Mode(t *testing.T) {
	var psk [32]byte
	var pairID [8]byte
	pass := []byte("test-passphrase")

	path := t.TempDir() + "/capsule"
	if err := WriteCapsule(path, psk, pairID, pass); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestWriteCapsule_CreatesParentDir(t *testing.T) {
	var psk [32]byte
	var pairID [8]byte
	pass := []byte("test-passphrase")

	path := t.TempDir() + "/subdir/capsule"
	if err := WriteCapsule(path, psk, pairID, pass); err != nil {
		t.Fatal(err)
	}
}

func TestWriteCapsule_BadPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test permission denial as root")
	}
	var psk [32]byte
	var pairID [8]byte
	pass := []byte("test-passphrase")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)

	path := dir + "/capsule"
	err := WriteCapsule(path, psk, pairID, pass)
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}
}
