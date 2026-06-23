// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux && passcache_keyutils

package passcache

import (
	"os"
	"testing"
	"time"
)

func TestKeyutils_Integration(t *testing.T) {
	if os.Getenv("DEADDROP_PASSCACHE_KEYUTILS_TEST") != "1" {
		t.Skip("set DEADDROP_PASSCACHE_KEYUTILS_TEST=1 to run keyutils integration tests")
	}

	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const id = "deaddrop:test-integration"
	pass := []byte("test-passphrase-42")

	// Clean up any leftover from a prior run.
	_ = c.Forget(id)

	t.Run("PutGet", func(t *testing.T) {
		if err := c.Put(id, pass, 60*time.Second); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := c.Get(id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got) != string(pass) {
			t.Fatalf("Get = %q, want %q", got, pass)
		}
	})

	t.Run("ForgetGet", func(t *testing.T) {
		if err := c.Put(id, pass, 60*time.Second); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := c.Forget(id); err != nil {
			t.Fatalf("Forget: %v", err)
		}
		_, err := c.Get(id)
		if err != ErrMiss {
			t.Fatalf("Get after Forget: err = %v, want ErrMiss", err)
		}
	})

	t.Run("TTLExpiry", func(t *testing.T) {
		if err := c.Put(id, pass, 1*time.Second); err != nil {
			t.Fatalf("Put: %v", err)
		}
		time.Sleep(2 * time.Second)
		_, err := c.Get(id)
		if err != ErrMiss {
			t.Fatalf("Get after TTL: err = %v, want ErrMiss", err)
		}
	})

	t.Run("ZeroTTLNoStore", func(t *testing.T) {
		_ = c.Forget(id)
		if err := c.Put(id, pass, 0); err != nil {
			t.Fatalf("Put(ttl=0): %v", err)
		}
		_, err := c.Get(id)
		if err != ErrMiss {
			t.Fatalf("Get after Put(ttl=0): err = %v, want ErrMiss", err)
		}
	})
}
