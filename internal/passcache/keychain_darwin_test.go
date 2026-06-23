// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && passcache_keychain

package passcache

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// randomTestID returns a unique cache ID per subtest run so we never
// collide with the operator's real cached entries.
func randomTestID(t *testing.T) string {
	t.Helper()
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return "deaddrop:test-" + hex.EncodeToString(buf[:])
}

// keychainTestSetup gates every subtest on the env var and constructs
// a fresh cache. Callers register their own t.Cleanup so leaks are
// scoped to the subtest, not to the parent.
func keychainTestSetup(t *testing.T) (Cache, string) {
	t.Helper()
	if os.Getenv("DEADDROP_PASSCACHE_KEYCHAIN_TEST") != "1" {
		t.Skip("set DEADDROP_PASSCACHE_KEYCHAIN_TEST=1 to run keychain integration tests")
	}
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id := randomTestID(t)
	// Defensive Forget at start in case a prior run crashed mid-test.
	_ = c.Forget(id)
	t.Cleanup(func() { _ = c.Forget(id) })
	return c, id
}

func TestKeychain_PutGet(t *testing.T) {
	c, id := keychainTestSetup(t)
	pass := []byte("test-passphrase-PutGet")

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
}

func TestKeychain_ForgetGet(t *testing.T) {
	c, id := keychainTestSetup(t)
	pass := []byte("test-passphrase-ForgetGet")

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
}

func TestKeychain_PutOverwrite(t *testing.T) {
	c, id := keychainTestSetup(t)
	first := []byte("first-value")
	second := []byte("second-value")

	if err := c.Put(id, first, 60*time.Second); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := c.Put(id, second, 60*time.Second); err != nil {
		t.Fatalf("Put second (Update path): %v", err)
	}
	got, err := c.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(second) {
		t.Fatalf("Get = %q, want %q (overwrite via Update should win)", got, second)
	}
}

func TestKeychain_TTLIgnored(t *testing.T) {
	c, id := keychainTestSetup(t)
	pass := []byte("ttl-ignored-test")

	// Put with ttl=1s; on darwin this is documented as ignored.
	if err := c.Put(id, pass, 1*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(2 * time.Second)
	got, err := c.Get(id)
	if err != nil {
		t.Fatalf("Get after 2s sleep: err = %v, want value (ttl ignored on darwin)", err)
	}
	if string(got) != string(pass) {
		t.Fatalf("Get = %q, want %q", got, pass)
	}
}

func TestKeychain_ForgetMissing(t *testing.T) {
	c, _ := keychainTestSetup(t)
	missingID := randomTestID(t)
	t.Cleanup(func() { _ = c.Forget(missingID) })

	if err := c.Forget(missingID); err != nil {
		t.Fatalf("Forget on never-existed ID: err = %v, want nil", err)
	}
}

func TestKeychain_NoiCloudSync(t *testing.T) {
	c, id := keychainTestSetup(t)
	pass := []byte("no-icloud-sync-test")

	if err := c.Put(id, pass, 60*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}

	found, syncPresent, syncValue, err := testQuerySynchronizable(id)
	if err != nil {
		t.Fatalf("testQuerySynchronizable: %v", err)
	}
	if !found {
		t.Fatalf("item not found after Put")
	}
	// Acceptance: synchronizable attr is absent OR present and false.
	// FAIL if syncPresent && syncValue (i.e., true).
	if syncPresent && syncValue {
		t.Fatalf("kSecAttrSynchronizable is true — iCloud Keychain sync would be enabled. " +
			"design decision 2 requires AccessibleWhenUnlockedThisDeviceOnly.")
	}
}
