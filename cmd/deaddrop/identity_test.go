// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nmicic/deaddrop/internal/identitystore"
)

// fakeIdentityStore is an in-memory Store for CLI integration tests.
// It mirrors fakeCache (passcache_test.go): a hand-rolled stub the
// CLI reaches via the newIdentityStore test seam.
type fakeIdentityStore struct {
	mu      sync.Mutex
	entries map[[8]byte]*identitystore.Entry
	getErr  error // when set, Get returns this error regardless of pairID
}

func (f *fakeIdentityStore) Get(pairID [8]byte) (*identitystore.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	e, ok := f.entries[pairID]
	if !ok {
		return nil, identitystore.ErrMiss
	}
	return e, nil
}

func (f *fakeIdentityStore) Put(pairID [8]byte, e *identitystore.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries == nil {
		f.entries = map[[8]byte]*identitystore.Entry{}
	}
	f.entries[pairID] = e
	return nil
}

func (f *fakeIdentityStore) Forget(pairID [8]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, pairID)
	return nil
}

// withMissingIdentityStore makes newIdentityStore return a Store whose
// Get always reports ErrMiss. Exercises the legacy-fallback warn path
// in send / recv (and the strict --require-e2e ErrMiss path).
func withMissingIdentityStore(t *testing.T) {
	t.Helper()
	orig := newIdentityStore
	newIdentityStore = func() (identitystore.Store, error) {
		return &fakeIdentityStore{getErr: identitystore.ErrMiss}, nil
	}
	t.Cleanup(func() { newIdentityStore = orig })
}

// withUnsupportedIdentityStore makes newIdentityStore return
// (nil, ErrUnsupported), simulating a platform with no keyring backend.
// Exercises the bootstrap WARN-and-Noop path and the --require-e2e
// PlatformUnsupported path.
func withUnsupportedIdentityStore(t *testing.T) {
	t.Helper()
	orig := newIdentityStore
	newIdentityStore = func() (identitystore.Store, error) {
		return nil, identitystore.ErrUnsupported
	}
	t.Cleanup(func() { newIdentityStore = orig })
}

const idMissWarnSubstring = "no E2E identity entry"
const idUnsupportedWarnSubstring = "bootstrap will proceed without persistent E2E identity"
const sendUnsupportedWarnSubstring = "sending in legacy mode"
const recvUnsupportedWarnSubstring = "receiving in legacy mode"

// 1. TestSend_IdentityMissNonStrictWarns — when the identity store
// has no entry for this pair, send must succeed in legacy mode and
// emit a stderr WARN (per D-65 fix).
func TestSend_IdentityMissNonStrictWarns(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withMissingIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-miss-send")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	fd := pipeWithData(t, "id-miss-send\n")

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
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), idMissWarnSubstring) {
		t.Fatalf("stderr missing legacy-fallback WARN; got: %q", stderr.String())
	}
}

// 2. TestSend_RequireE2EFailsOnMiss — with --require-e2e (now the
// default), an identity-store miss must exit EDDIdentityMiss (22)
// without emitting the legacy WARN.
func TestSend_RequireE2EFailsOnMiss(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withMissingIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-miss-send-strict")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	fd := pipeWithData(t, "id-miss-send-strict\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--passcache", "none",
		plainPath,
	}, &stdout, &stderr)
	if code != 22 {
		t.Fatalf("code = %d, want 22 (EDDIdentityMiss); stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), idMissWarnSubstring) {
		t.Fatalf("strict path should not emit legacy WARN; stderr=%q", stderr.String())
	}
}

// 3. TestRecv_IdentityMissNonStrictWarns — symmetric to test 1.
// Sends in legacy mode (also via the fake miss store), then recvs
// and asserts the recv-side stderr contains the WARN. The capturing
// relay is replaced by a round-trip relay so recv has a body to GET.
func TestRecv_IdentityMissNonStrictWarns(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withMissingIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-miss-recv")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	plaintext := []byte("recv-warn-payload")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	sendInto(t, capsulePath, "id-miss-recv", srv.URL, plainPath)

	fd := pipeWithData(t, "id-miss-recv\n")
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
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), plaintext) {
		t.Fatalf("recv stdout = %q, want %q", stdout.String(), string(plaintext))
	}
	if !strings.Contains(stderr.String(), idMissWarnSubstring) {
		t.Fatalf("stderr missing legacy-fallback WARN; got: %q", stderr.String())
	}
}

// 4. TestRecv_RequireE2EFailsOnMiss — recv with --require-e2e (now the
// default) must exit EDDIdentityMiss when no entry is present.
func TestRecv_RequireE2EFailsOnMiss(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withMissingIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-miss-recv-strict")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	// sendInto runs send in legacy mode (also misses, also warns); we
	// don't care — the WARN goes into sendInto's own buffer, not ours.
	sendInto(t, capsulePath, "id-miss-recv-strict", srv.URL, plainPath)

	fd := pipeWithData(t, "id-miss-recv-strict\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--passcache", "none",
	}, &stdout, &stderr)
	if code != 22 {
		t.Fatalf("code = %d, want 22 (EDDIdentityMiss); stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), idMissWarnSubstring) {
		t.Fatalf("strict path should not emit legacy WARN; stderr=%q", stderr.String())
	}
}

// 5. TestBootstrap_UnsupportedBackendNonStrictWarns — when the
// platform has no keyring backend, bootstrap must emit a WARN and
// proceed with Noop. We stand up a relay that 500s every request so
// the leg work fails quickly; the test asserts the WARN was emitted
// before that failure (i.e., bootstrap got past the strict gate).
func TestBootstrap_UnsupportedBackendNonStrictWarns(t *testing.T) {
	withUnsupportedIdentityStore(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	fd := goroutineSafePipe(t, "bs-pa\nbs-pb\n")
	capsulePath := filepath.Join(t.TempDir(), "capsule")

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passphrase-fd", strconv.Itoa(fd),
		"--capsule", capsulePath,
		"--timeout", "2",
	}, &stdout, &stderr)

	// Bootstrap will fail (the relay 500s every leg), but the WARN
	// must have been emitted before that — this is the contract of
	// the non-strict unsupported path.
	if !strings.Contains(stderr.String(), idUnsupportedWarnSubstring) {
		t.Fatalf("stderr missing unsupported-backend WARN; got: %q", stderr.String())
	}
	if code == 24 {
		t.Fatalf("non-strict path returned EDDPlatformUnsupported (24); should have proceeded past the gate")
	}
}

// 5b. TestSend_UnsupportedBackendNonStrictWarns — when the platform
// has no keyring backend, send must succeed in legacy mode and emit a
// stderr WARN. Covers the ErrUnsupported branch in send.go.
func TestSend_UnsupportedBackendNonStrictWarns(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withUnsupportedIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-unsup-send")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	fd := pipeWithData(t, "id-unsup-send\n")

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
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), sendUnsupportedWarnSubstring) {
		t.Fatalf("stderr missing unsupported-backend WARN; got: %q", stderr.String())
	}
}

// 5c. TestSend_RequireE2EFailsOnUnsupported — strict mode (now the
// default) must exit EDDPlatformUnsupported (24) on the
// unsupported-backend branch.
func TestSend_RequireE2EFailsOnUnsupported(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withUnsupportedIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-unsup-send-strict")
	srv, _ := newCapturingRelay(t, 201)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	fd := pipeWithData(t, "id-unsup-send-strict\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--passcache", "none",
		plainPath,
	}, &stdout, &stderr)
	if code != 24 {
		t.Fatalf("code = %d, want 24 (EDDPlatformUnsupported); stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), sendUnsupportedWarnSubstring) {
		t.Fatalf("strict path should not emit legacy WARN; stderr=%q", stderr.String())
	}
}

// 5d. TestRecv_UnsupportedBackendNonStrictWarns — recv-side analog.
// Covers the ErrUnsupported branch in recv.go.
func TestRecv_UnsupportedBackendNonStrictWarns(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withUnsupportedIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-unsup-recv")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	plaintext := []byte("recv-unsup-payload")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	sendInto(t, capsulePath, "id-unsup-recv", srv.URL, plainPath)

	fd := pipeWithData(t, "id-unsup-recv\n")
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
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), plaintext) {
		t.Fatalf("recv stdout = %q, want %q", stdout.String(), string(plaintext))
	}
	if !strings.Contains(stderr.String(), recvUnsupportedWarnSubstring) {
		t.Fatalf("stderr missing unsupported-backend WARN; got: %q", stderr.String())
	}
}

// 5e. TestRecv_RequireE2EFailsOnUnsupported — recv strict mode (now the
// default) must exit EDDPlatformUnsupported on unsupported-backend.
func TestRecv_RequireE2EFailsOnUnsupported(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	withUnsupportedIdentityStore(t)

	capsulePath := keygenFreshCapsule(t, "id-unsup-recv-strict")
	srv := newRoundTripRelay(t)
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	sendInto(t, capsulePath, "id-unsup-recv-strict", srv.URL, plainPath)

	fd := pipeWithData(t, "id-unsup-recv-strict\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--passcache", "none",
	}, &stdout, &stderr)
	if code != 24 {
		t.Fatalf("code = %d, want 24 (EDDPlatformUnsupported); stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), recvUnsupportedWarnSubstring) {
		t.Fatalf("strict path should not emit legacy WARN; stderr=%q", stderr.String())
	}
}

// 6. TestBootstrap_RequireE2EFailsOnUnsupported — with --require-e2e
// (now the default), an unsupported backend must exit
// EDDPlatformUnsupported (24) immediately, without emitting the
// legacy WARN and without any leg work being attempted.
func TestBootstrap_RequireE2EFailsOnUnsupported(t *testing.T) {
	withUnsupportedIdentityStore(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	// No relay needed — strict path returns before any HTTP call. We
	// still pass a syntactically valid URL so flag parsing succeeds.
	fd := goroutineSafePipe(t, "bs-pa\nbs-pb\n")
	capsulePath := filepath.Join(t.TempDir(), "capsule")

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--relay", "http://127.0.0.1:1",
		"--passphrase-fd", strconv.Itoa(fd),
		"--capsule", capsulePath,
		"--timeout", "2",
	}, &stdout, &stderr)
	if code != 24 {
		t.Fatalf("code = %d, want 24 (EDDPlatformUnsupported); stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), idUnsupportedWarnSubstring) {
		t.Fatalf("strict path should not emit legacy WARN; stderr=%q", stderr.String())
	}
}
