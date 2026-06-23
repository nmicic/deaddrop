// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
)

// pipeWith returns the read fd of a pipe pre-loaded with data; the
// write end is closed so EOF terminates the final read.
func pipeWith(t *testing.T, data string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return int(r.Fd())
}

// noopListen is a serverRunFn stand-in for tests: it records that run
// reached the listen step and returns immediately without binding a
// socket. Tests that expect validation to fail before listen assert
// that listen was NOT called.
func noopListen(called *bool) serverRunFn {
	return func(_ *http.Server, _ net.Listener) error {
		if called != nil {
			*called = true
		}
		return nil
	}
}

func captureListen(called *bool, captured **http.Server) serverRunFn {
	return func(srv *http.Server, _ net.Listener) error {
		if called != nil {
			*called = true
		}
		if captured != nil {
			*captured = srv
		}
		return nil
	}
}

// TestMainFlags_MissingDeploySecret — run() must refuse to start
// without --deploy-secret. Validation fires before any lifecycle
// syscall (mlockall / PR_SET_DUMPABLE) or listen call, so the test
// is platform-independent.
func TestMainFlags_MissingDeploySecret(t *testing.T) {
	var stderr bytes.Buffer
	var listenCalled bool

	t.Setenv(envDeploySecret, "")
	t.Setenv(envDeploySecretLegacy, "")
	t.Setenv(envWriteToken, "")
	t.Setenv(envWriteTokenLegacy, "")

	err := run([]string{"--local-only"}, &stderr, noopListen(&listenCalled), nil)
	if err == nil {
		t.Fatalf("run() returned nil; expected an error for missing --deploy-secret")
	}
	if !strings.Contains(err.Error(), "--deploy-secret") {
		t.Fatalf("error message = %q; expected it to mention --deploy-secret", err.Error())
	}
	if listenCalled {
		t.Fatalf("listen must not be invoked when validation fails")
	}
}

const (
	testDeploySecret = "hex:0101010101010101010101010101010101010101010101010101010101010101"
	testWriteToken   = "hex:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
)

// TestRelay_DeploySecretFd — fd path resolves and run reaches listen
// (D-43). No argv WARN, no env WARN.
func TestRelay_DeploySecretFd(t *testing.T) {
	t.Setenv(envDeploySecret, "")
	t.Setenv(envDeploySecretLegacy, "")
	t.Setenv(envWriteToken, "")
	t.Setenv(envWriteTokenLegacy, "")

	dsFD := pipeWith(t, testDeploySecret+"\n")
	wtFD := pipeWith(t, testWriteToken+"\n")
	var stderr bytes.Buffer
	var listenCalled bool
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--deploy-secret-fd", itoa(dsFD),
		"--write-token-fd", itoa(wtFD),
		"--local-only",
	}, &stderr, noopListen(&listenCalled), nil)
	if err != nil {
		t.Fatalf("run() = %v; want nil", err)
	}
	if !listenCalled {
		t.Fatalf("listen was not invoked; run aborted before reaching it")
	}
	if strings.Contains(stderr.String(), "deprecated") {
		t.Fatalf("stderr unexpectedly mentions \"deprecated\" with fd-only invocation: %s", stderr.String())
	}
}

func TestRelay_HTTPServerTimeouts(t *testing.T) {
	t.Setenv(envDeploySecret, testDeploySecret)
	t.Setenv(envDeploySecretLegacy, "")
	t.Setenv(envWriteToken, testWriteToken)
	t.Setenv(envWriteTokenLegacy, "")

	var stderr bytes.Buffer
	var listenCalled bool
	var srv *http.Server
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--local-only",
	}, &stderr, captureListen(&listenCalled, &srv), nil)
	if err != nil {
		t.Fatalf("run() = %v; want nil", err)
	}
	if !listenCalled || srv == nil {
		t.Fatalf("listen was not invoked with a server")
	}
	if srv.ReadHeaderTimeout != defaultReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %s, want %s", srv.ReadHeaderTimeout, defaultReadHeaderTimeout)
	}
	if srv.ReadTimeout != defaultReadTimeout {
		t.Fatalf("ReadTimeout = %s, want %s", srv.ReadTimeout, defaultReadTimeout)
	}
	if srv.WriteTimeout != defaultWriteTimeout {
		t.Fatalf("WriteTimeout = %s, want %s", srv.WriteTimeout, defaultWriteTimeout)
	}
	if srv.IdleTimeout != defaultIdleTimeout {
		t.Fatalf("IdleTimeout = %s, want %s", srv.IdleTimeout, defaultIdleTimeout)
	}
}

// TestRelay_DeploySecretArgvRejected — --deploy-secret on argv is
// rejected with a migration message (D-72, v0.2.0).
func TestRelay_DeploySecretArgvRejected(t *testing.T) {
	t.Setenv(envDeploySecret, "")
	t.Setenv(envDeploySecretLegacy, "")
	t.Setenv(envWriteToken, "")
	t.Setenv(envWriteTokenLegacy, "")

	var stderr bytes.Buffer
	var listenCalled bool
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--deploy-secret", testDeploySecret,
		"--write-token", testWriteToken,
		"--local-only",
	}, &stderr, noopListen(&listenCalled), nil)
	if err == nil {
		t.Fatalf("run() returned nil; expected rejection of --deploy-secret on argv")
	}
	if !strings.Contains(err.Error(), "--deploy-secret was removed") {
		t.Fatalf("error = %q; want mention of --deploy-secret removal", err.Error())
	}
	if listenCalled {
		t.Fatalf("listen must not be invoked when argv is rejected")
	}
}

// TestRelay_LegacyEnvDeprecationWarn — DEPLOY_SECRET (unprefixed)
// works for backward compatibility but emits a stderr WARN naming
// the canonical DEADDROP_DEPLOY_SECRET.
func TestRelay_LegacyEnvDeprecationWarn(t *testing.T) {
	t.Setenv(envDeploySecret, "")
	t.Setenv(envDeploySecretLegacy, testDeploySecret)
	t.Setenv(envWriteToken, "")
	t.Setenv(envWriteTokenLegacy, testWriteToken)

	var stderr bytes.Buffer
	var listenCalled bool
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--local-only",
	}, &stderr, noopListen(&listenCalled), nil)
	if err != nil {
		t.Fatalf("run() = %v; want nil", err)
	}
	if !listenCalled {
		t.Fatalf("listen not invoked")
	}
	if !strings.Contains(stderr.String(), "$DEPLOY_SECRET is deprecated") {
		t.Fatalf("stderr missing legacy-env WARN; got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "DEADDROP_DEPLOY_SECRET") {
		t.Fatalf("legacy WARN must name canonical DEADDROP_DEPLOY_SECRET; got %q", stderr.String())
	}
}

// TestRelay_DeploySecretArgvEqualsRejected — --deploy-secret=VALUE
// (equals form) on argv is also rejected (D-72, v0.2.0).
func TestRelay_DeploySecretArgvEqualsRejected(t *testing.T) {
	t.Setenv(envDeploySecret, testDeploySecret)
	t.Setenv(envDeploySecretLegacy, "")
	t.Setenv(envWriteToken, testWriteToken)
	t.Setenv(envWriteTokenLegacy, "")

	var stderr bytes.Buffer
	var listenCalled bool
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--deploy-secret=" + testDeploySecret,
		"--local-only",
	}, &stderr, noopListen(&listenCalled), nil)
	if err == nil {
		t.Fatalf("run() returned nil; expected rejection of --deploy-secret= on argv")
	}
	if !strings.Contains(err.Error(), "--deploy-secret was removed") {
		t.Fatalf("error = %q; want mention of --deploy-secret removal", err.Error())
	}
	if listenCalled {
		t.Fatalf("listen must not be invoked when argv is rejected")
	}
}

// TestRelay_BothEnvVarsSet_CanonicalWins — both DEADDROP_DEPLOY_SECRET
// and the legacy DEPLOY_SECRET set. Asserts (a) the canonical value
// is the one that drives the relay (proven by passing a deliberately
// invalid hex prefix in legacy and a valid one in canonical — if the
// legacy value were used, secretparse.Parse would error and the
// listen step would never run), (b) the precedence WARN fires naming
// the canonical and instructing the operator to drop the legacy.
func TestRelay_BothEnvVarsSet_CanonicalWins(t *testing.T) {
	// Canonical is valid; legacy is structurally invalid (no hex:/b64:
	// prefix). If resolveRelaySecret returned the legacy value, the
	// downstream secretparse.Parse would error and run() would return
	// non-nil. We therefore assert (i) run succeeds, (ii) listen is
	// reached, (iii) the precedence WARN fires.
	t.Setenv(envDeploySecret, testDeploySecret)
	t.Setenv(envDeploySecretLegacy, "not-a-valid-prefixed-secret")
	t.Setenv(envWriteToken, testWriteToken)
	t.Setenv(envWriteTokenLegacy, "")

	var stderr bytes.Buffer
	var listenCalled bool
	err := run([]string{
		"--listen", "127.0.0.1:0",
		"--local-only",
	}, &stderr, noopListen(&listenCalled), nil)
	if err != nil {
		t.Fatalf("run() = %v; want nil (canonical should override invalid legacy); stderr=%s", err, stderr.String())
	}
	if !listenCalled {
		t.Fatalf("listen not invoked; canonical-wins path failed")
	}
	if !strings.Contains(stderr.String(),
		"both $DEADDROP_DEPLOY_SECRET and $DEPLOY_SECRET are set; using canonical $DEADDROP_DEPLOY_SECRET") {
		t.Fatalf("stderr missing both-set precedence WARN; got %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "--deploy-secret on argv is deprecated") {
		t.Fatalf("argv WARN unexpectedly present (argv not set): %q", stderr.String())
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
