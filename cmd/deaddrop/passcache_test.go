// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nmicic/deaddrop/internal/passcache"
)

// fakeCache is an in-memory Cache for CLI integration tests.
type fakeCache struct {
	mu          sync.Mutex
	entries     map[string][]byte
	getCalls    int
	putCalls    int
	forgetCalls int
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string][]byte{}}
}

func (f *fakeCache) Get(id string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	v, ok := f.entries[id]
	if !ok {
		return nil, passcache.ErrMiss
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *fakeCache) Put(id string, pass []byte, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls++
	if ttl == 0 {
		return nil
	}
	v := make([]byte, len(pass))
	copy(v, pass)
	f.entries[id] = v
	return nil
}

func (f *fakeCache) Forget(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgetCalls++
	delete(f.entries, id)
	return nil
}

func withFakeCache(t *testing.T, fc *fakeCache) {
	t.Helper()
	orig := newCache
	newCache = func() (passcache.Cache, error) {
		return fc, nil
	}
	t.Cleanup(func() { newCache = orig })
}

// withUnsupportedCache makes newCache return ErrUnsupported, simulating
// a non-Linux platform or missing keyutils.
func withUnsupportedCache(t *testing.T) {
	t.Helper()
	orig := newCache
	newCache = func() (passcache.Cache, error) {
		return nil, passcache.ErrUnsupported
	}
	t.Cleanup(func() { newCache = orig })
}

// TestSendPasscache_NoneIgnoresCache verifies --passcache=none never
// calls Get on the fake cache.
func TestSendPasscache_NoneIgnoresCache(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "cache-none")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := pipeWithData(t, "cache-none\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "none",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.getCalls != 0 {
		t.Fatalf("Get called %d times, want 0 with --passcache=none", fc.getCalls)
	}
}

// TestRecvPasscache_NoneIgnoresCache — same for recv.
func TestRecvPasscache_NoneIgnoresCache(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "rcache-none")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendInto(t, capsulePath, "rcache-none", srv.URL, plainPath)

	// Reset counters — sendInto triggers cache operations too.
	fc.mu.Lock()
	fc.getCalls = 0
	fc.putCalls = 0
	fc.forgetCalls = 0
	fc.mu.Unlock()

	fd := pipeWithData(t, "rcache-none\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "none",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.getCalls != 0 {
		t.Fatalf("Get called %d times, want 0", fc.getCalls)
	}
}

// TestSendPasscache_AutoUnsupported — auto on unsupported platform
// falls back to prompt path successfully.
func TestSendPasscache_AutoUnsupported(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withUnsupportedCache(t)

	capsulePath := keygenFreshCapsule(t, "unsup")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := pipeWithData(t, "unsup\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	hasWarning := strings.Contains(stderr.String(), "keyutils unavailable")
	if runtime.GOOS == "linux" && !hasWarning {
		t.Fatalf("Linux: expected keyutils unavailable warning; stderr = %q", stderr.String())
	}
	if runtime.GOOS != "linux" && hasWarning {
		t.Fatalf("non-Linux: warning should be silent; stderr = %q", stderr.String())
	}
}

// TestSendPasscache_CacheHitWrongValue — stale cache entry triggers
// Forget + prompt fallback.
func TestSendPasscache_CacheHitWrongValue(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "stale-hit")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-populate cache with wrong passphrase.
	capsuleData, _ := os.ReadFile(capsulePath)
	cacheID, _ := passcache.IDForCapsule(capsuleData)
	fc.entries[cacheID] = []byte("wrong-password")

	fd := pipeWithData(t, "stale-hit\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.forgetCalls == 0 {
		t.Fatal("Forget not called on stale cache hit")
	}
	// After prompt success, Put should have been called.
	if fc.putCalls == 0 {
		t.Fatal("Put not called after successful prompt fallback")
	}
}

// TestRecvPasscache_CacheHitWrongValue — same for recv.
func TestRecvPasscache_CacheHitWrongValue(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "rstale-hit")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendInto(t, capsulePath, "rstale-hit", srv.URL, plainPath)

	fc.mu.Lock()
	fc.getCalls = 0
	fc.putCalls = 0
	fc.forgetCalls = 0
	fc.mu.Unlock()

	capsuleData, _ := os.ReadFile(capsulePath)
	cacheID, _ := passcache.IDForCapsule(capsuleData)
	fc.entries[cacheID] = []byte("wrong-password")

	fd := pipeWithData(t, "rstale-hit\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.forgetCalls == 0 {
		t.Fatal("Forget not called on stale cache hit")
	}
}

// TestSendPasscache_ForgetPasscache — --forget-passcache calls Forget
// then continues normally.
func TestSendPasscache_ForgetPasscache(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "forget-flag")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	capsuleData, _ := os.ReadFile(capsulePath)
	cacheID, _ := passcache.IDForCapsule(capsuleData)
	fc.entries[cacheID] = []byte("forget-flag")

	fd := pipeWithData(t, "forget-flag\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--forget-passcache",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.forgetCalls == 0 {
		t.Fatal("Forget not called with --forget-passcache")
	}
}

// TestSendPasscache_CacheHit — correct cached value skips prompt.
func TestSendPasscache_CacheHit(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "cache-hit")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	capsuleData, _ := os.ReadFile(capsulePath)
	cacheID, _ := passcache.IDForCapsule(capsuleData)
	fc.entries[cacheID] = []byte("cache-hit")

	// No passphrase-fd — if cache hit works, no prompt is needed.
	// Use --passphrase-env with an empty var so the fallback would fail.
	t.Setenv("EMPTY_PW", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--relay", srv.URL,
		"--no-require-e2e",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	// Put should NOT be called on cache hit.
	if fc.putCalls != 0 {
		t.Fatalf("Put called %d times on cache hit, want 0", fc.putCalls)
	}
}

// TestSendPasscache_KeychainTTLAsymmetryWarning — on darwin, explicitly
// passing --passcache-ttl with --passcache=keychain emits the
// documented stderr note.
func TestSendPasscache_KeychainTTLAsymmetryWarning(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain mode is darwin-only")
	}
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "kc-ttl-warn")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := pipeWithData(t, "kc-ttl-warn\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "keychain",
		"--passcache-ttl", "300",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--passcache-ttl is ignored on macOS") {
		t.Fatalf("expected TTL asymmetry warning on stderr, got: %q", stderr.String())
	}
}

// TestSendPasscache_KeychainOnLinuxErrors — on linux, --passcache=
// keychain returns a usage error mentioning darwin-only.
func TestSendPasscache_KeychainOnLinuxErrors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test asserts the linux-side rejection of --passcache=keychain")
	}
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	// Use the unsupported-cache seam so we do not depend on real
	// keyutils availability for the platform check itself.
	withUnsupportedCache(t)

	capsulePath := keygenFreshCapsule(t, "kc-linux")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "keychain",
		plainPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit on linux for --passcache=keychain")
	}
	if !strings.Contains(stderr.String(), "darwin-only") {
		t.Fatalf("expected stderr to mention darwin-only, got: %q", stderr.String())
	}
}

// TestSendPasscache_KeychainModeSucceeds — on darwin, --passcache=
// keychain routes through the test seam (newCache override), so the
// fake cache's Put is exercised and the run exits 0.
func TestSendPasscache_KeychainModeSucceeds(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain mode is darwin-only")
	}
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "kc-succeed")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := pipeWithData(t, "kc-succeed\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "keychain",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.putCalls == 0 {
		t.Fatalf("Put not called — keychain mode did not route through the test seam")
	}
}

// TestSendPasscache_AutoOnDarwinUsesCache — auto on darwin must
// resolve to the keychain backend (not the silent-no-op path) and
// must NOT emit the linux-only "keyutils unavailable" diagnostic.
func TestSendPasscache_AutoOnDarwinUsesCache(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("auto routes to keychain only on darwin")
	}
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fc := newFakeCache()
	withFakeCache(t, fc)

	capsulePath := keygenFreshCapsule(t, "auto-darwin")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := pipeWithData(t, "auto-darwin\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passcache", "auto",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %s", code, stderr.String())
	}
	if fc.putCalls == 0 {
		t.Fatalf("Put not called — auto on darwin did not resolve to keychain backend")
	}
	if strings.Contains(stderr.String(), "keyutils unavailable") {
		t.Fatalf("auto on darwin should not emit the linux keyutils diagnostic: %q", stderr.String())
	}
}
