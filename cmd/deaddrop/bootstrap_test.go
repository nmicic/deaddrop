// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/nmicic/deaddrop/internal/bootstrap"
	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/exitcode"
)

const testDeploySecretHex = "hex:0102030405060708091011121314151617181920212223242526272829303132"

type chanReader struct {
	ch chan byte
}

func (r *chanReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b, ok := <-r.ch
	if !ok {
		return 0, io.EOF
	}
	p[0] = b
	return 1, nil
}

func newEnterReader(n int) *chanReader {
	ch := make(chan byte, n)
	for i := 0; i < n; i++ {
		ch <- '\n'
	}
	close(ch)
	return &chanReader{ch: ch}
}

type mockRelay struct {
	mu         sync.Mutex
	blobs      map[string][]byte
	writeToken string
	tamperGet  func([]byte) []byte
}

func (m *mockRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		if m.writeToken != "" && r.Header.Get("X-DeadDrop-Write") != m.writeToken {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		if _, exists := m.blobs[r.URL.Path]; exists {
			m.mu.Unlock()
			w.WriteHeader(409)
			return
		}
		m.blobs[r.URL.Path] = body
		m.mu.Unlock()
		w.WriteHeader(201)
	case "GET":
		// regression tripwire: real relays MUST NOT inspect the
		// header per D-45 (PROTOCOL.md §«GET» MUST NOT). This test
		// fixture rejects on presence so client GET-leak regressions
		// surface in tests. Production relays ignore the header on
		// GET; this 400 is fixture-only behavior.
		if r.Header.Get("X-DeadDrop-Write") != "" {
			w.WriteHeader(400)
			return
		}
		m.mu.Lock()
		body, ok := m.blobs[r.URL.Path]
		m.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		if m.tamperGet != nil {
			body = m.tamperGet(body)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(body)
	default:
		w.WriteHeader(405)
	}
}

func extractFingerprint(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "pairing fingerprint:") {
			parts := strings.SplitN(line, "pairing fingerprint:", 2)
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func goroutineSafePipe(t *testing.T, data string) int {
	t.Helper()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		t.Fatalf("syscall.Pipe: %v", err)
	}
	if _, err := syscall.Write(fds[1], []byte(data)); err != nil {
		t.Fatalf("syscall.Write: %v", err)
	}
	syscall.Close(fds[1])
	t.Cleanup(func() { syscall.Close(fds[0]) })
	return fds[0]
}

func randomDeploySecretHex(t *testing.T) string {
	t.Helper()
	ds := make([]byte, 32)
	if _, err := rand.Read(ds); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return "hex:" + hex.EncodeToString(ds)
}

func TestBootstrap_EndToEnd(t *testing.T) {
	old := bootstrapEnterReader
	bootstrapEnterReader = newEnterReader(2)
	defer func() { bootstrapEnterReader = old }()

	relay := &mockRelay{blobs: make(map[string][]byte)}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	dsHex := randomDeploySecretHex(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", dsHex)

	iFD := goroutineSafePipe(t, "test-pa\ntest-pb-i\n")
	rFD := goroutineSafePipe(t, "test-pa\ntest-pb-r\n")

	iCapsule := filepath.Join(t.TempDir(), "capsule-i")
	rCapsule := filepath.Join(t.TempDir(), "capsule-r")

	var iStdout, iStderr, rStdout, rStderr bytes.Buffer
	var iResult, rResult int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		iResult = runBootstrap([]string{
			"--role", "initiator",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(iFD),
			"--capsule", iCapsule,
			"--timeout", "30",
		}, &iStdout, &iStderr)
	}()
	go func() {
		defer wg.Done()
		rResult = runBootstrap([]string{
			"--role", "responder",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(rFD),
			"--capsule", rCapsule,
			"--timeout", "30",
		}, &rStdout, &rStderr)
	}()
	wg.Wait()

	if iResult != exitcode.OK {
		t.Fatalf("initiator exit %d; stderr: %s", iResult, iStderr.String())
	}
	if rResult != exitcode.OK {
		t.Fatalf("responder exit %d; stderr: %s", rResult, rStderr.String())
	}

	if _, err := os.Stat(iCapsule); err != nil {
		t.Fatalf("initiator capsule missing: %v", err)
	}
	if _, err := os.Stat(rCapsule); err != nil {
		t.Fatalf("responder capsule missing: %v", err)
	}

	if !strings.Contains(iStdout.String(), "pairing fingerprint:") {
		t.Fatalf("initiator stdout missing fingerprint: %s", iStdout.String())
	}
	if !strings.Contains(rStdout.String(), "pairing fingerprint:") {
		t.Fatalf("responder stdout missing fingerprint: %s", rStdout.String())
	}

	iFPR := extractFingerprint(iStdout.String())
	rFPR := extractFingerprint(rStdout.String())
	if iFPR != rFPR {
		t.Fatalf("fingerprints differ: initiator=%q responder=%q", iFPR, rFPR)
	}
	if iFPR == "" {
		t.Fatal("fingerprint is empty")
	}

	iData, err := os.ReadFile(iCapsule)
	if err != nil {
		t.Fatalf("read initiator capsule: %v", err)
	}
	iPSK, iPairID, err := capsule.Unwrap([]byte("test-pb-i"), iData)
	if err != nil {
		t.Fatalf("unwrap initiator capsule: %v", err)
	}

	rData, err := os.ReadFile(rCapsule)
	if err != nil {
		t.Fatalf("read responder capsule: %v", err)
	}
	rPSK, rPairID, err := capsule.Unwrap([]byte("test-pb-r"), rData)
	if err != nil {
		t.Fatalf("unwrap responder capsule: %v", err)
	}

	if !bytes.Equal(iPSK, rPSK) {
		t.Fatal("PSK mismatch between capsules")
	}
	if !bytes.Equal(iPairID, rPairID) {
		t.Fatal("pairID mismatch between capsules")
	}
}

func TestBootstrap_EndToEnd_Handover(t *testing.T) {
	sendTestEnv(t)

	old := bootstrapEnterReader
	bootstrapEnterReader = newEnterReader(2)
	defer func() { bootstrapEnterReader = old }()

	relay := &mockRelay{blobs: make(map[string][]byte)}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	dsHex := randomDeploySecretHex(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", dsHex)

	iFD := goroutineSafePipe(t, "test-pa\ntest-pb-i\n")
	rFD := goroutineSafePipe(t, "test-pa\ntest-pb-r\n")

	iCapsule := filepath.Join(t.TempDir(), "capsule-i")
	rCapsule := filepath.Join(t.TempDir(), "capsule-r")

	var iStdout, iStderr, rStdout, rStderr bytes.Buffer
	var iResult, rResult int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		iResult = runBootstrap([]string{
			"--role", "initiator",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(iFD),
			"--capsule", iCapsule,
			"--timeout", "30",
		}, &iStdout, &iStderr)
	}()
	go func() {
		defer wg.Done()
		rResult = runBootstrap([]string{
			"--role", "responder",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(rFD),
			"--capsule", rCapsule,
			"--timeout", "30",
		}, &rStdout, &rStderr)
	}()
	wg.Wait()

	if iResult != exitcode.OK {
		t.Fatalf("bootstrap initiator exit %d; stderr: %s", iResult, iStderr.String())
	}
	if rResult != exitcode.OK {
		t.Fatalf("bootstrap responder exit %d; stderr: %s", rResult, rStderr.String())
	}

	plaintext := []byte("handover-test-payload")
	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	sendFD := goroutineSafePipe(t, "test-pb-i\n")
	var sendStdout, sendStderr bytes.Buffer
	sendCode := run([]string{
		"send",
		"--capsule", iCapsule,
		"--passphrase-fd", strconv.Itoa(sendFD),
		"--relay", srv.URL,
		"--no-require-e2e",
		plainPath,
	}, &sendStdout, &sendStderr)
	if sendCode != 0 {
		t.Fatalf("send exit %d; stderr: %s", sendCode, sendStderr.String())
	}

	recvFD := goroutineSafePipe(t, "test-pb-i\n")
	var recvStdout, recvStderr bytes.Buffer
	recvCode := run([]string{
		"recv",
		"--capsule", iCapsule,
		"--passphrase-fd", strconv.Itoa(recvFD),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &recvStdout, &recvStderr)
	if recvCode != 0 {
		t.Fatalf("recv exit %d; stderr: %s", recvCode, recvStderr.String())
	}
	if !bytes.Equal(recvStdout.Bytes(), plaintext) {
		t.Fatalf("recv output mismatch: got %q, want %q", recvStdout.String(), string(plaintext))
	}
}

func TestBootstrap_WrongPA(t *testing.T) {
	old := bootstrapEnterReader
	bootstrapEnterReader = newEnterReader(2)
	defer func() { bootstrapEnterReader = old }()

	relay := &mockRelay{blobs: make(map[string][]byte)}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	dsHex := randomDeploySecretHex(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", dsHex)

	iFD := goroutineSafePipe(t, "alpha\ntest-pb\n")
	rFD := goroutineSafePipe(t, "beta\ntest-pb\n")
	iCapsule := filepath.Join(t.TempDir(), "cap-i")
	rCapsule := filepath.Join(t.TempDir(), "cap-r")

	var iStdout, iStderr, rStdout, rStderr bytes.Buffer
	var iResult, rResult int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		iResult = runBootstrap([]string{
			"--role", "initiator",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(iFD),
			"--capsule", iCapsule,
			"--timeout", "5",
		}, &iStdout, &iStderr)
	}()
	go func() {
		defer wg.Done()
		rResult = runBootstrap([]string{
			"--role", "responder",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(rFD),
			"--capsule", rCapsule,
			"--timeout", "5",
		}, &rStdout, &rStderr)
	}()
	wg.Wait()

	authOrTimeout := func(code int) bool {
		return code == exitcode.BootstrapAuth || code == exitcode.BootstrapTimeout
	}
	if !authOrTimeout(iResult) || !authOrTimeout(rResult) {
		t.Fatalf("expected both in {BootstrapAuth(18), BootstrapTimeout(19)}; got initiator=%d responder=%d\nistderr=%s\nrstderr=%s",
			iResult, rResult, iStderr.String(), rStderr.String())
	}
}

func TestBootstrap_Timeout(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	relay := &mockRelay{blobs: make(map[string][]byte)}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	fd := goroutineSafePipe(t, "test-pa\ntest-pb\n")
	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passphrase-fd", strconv.Itoa(fd),
		"--capsule", filepath.Join(t.TempDir(), "cap"),
		"--timeout", "2",
	}, &stdout, &stderr)
	if code != exitcode.BootstrapTimeout {
		t.Fatalf("exit code: got %d, want %d (BootstrapTimeout); stderr: %s", code, exitcode.BootstrapTimeout, stderr.String())
	}
}

func TestBootstrap_MITM(t *testing.T) {
	old := bootstrapEnterReader
	bootstrapEnterReader = newEnterReader(2)
	defer func() { bootstrapEnterReader = old }()

	relay := &mockRelay{
		blobs: make(map[string][]byte),
		tamperGet: func(body []byte) []byte {
			if len(body) == bootstrap.Leg3BodySize {
				tampered := make([]byte, len(body))
				copy(tampered, body)
				tampered[60] ^= 0xFF
				return tampered
			}
			return body
		},
	}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	dsHex := randomDeploySecretHex(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", dsHex)

	iFD := goroutineSafePipe(t, "test-pa\ntest-pb-i\n")
	rFD := goroutineSafePipe(t, "test-pa\ntest-pb-r\n")
	iCapsule := filepath.Join(t.TempDir(), "cap-i")
	rCapsule := filepath.Join(t.TempDir(), "cap-r")

	var iStdout, iStderr, rStdout, rStderr bytes.Buffer
	var iResult, rResult int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		iResult = runBootstrap([]string{
			"--role", "initiator",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(iFD),
			"--capsule", iCapsule,
			"--timeout", "30",
		}, &iStdout, &iStderr)
	}()
	go func() {
		defer wg.Done()
		rResult = runBootstrap([]string{
			"--role", "responder",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(rFD),
			"--capsule", rCapsule,
			"--timeout", "30",
		}, &rStdout, &rStderr)
	}()
	wg.Wait()

	_ = rResult
	_ = rStdout.String()
	_ = rStderr.String()

	if iResult != exitcode.BootstrapMITM {
		t.Fatalf("initiator exit %d, want %d (BootstrapMITM); stderr: %s", iResult, exitcode.BootstrapMITM, iStderr.String())
	}
}

func TestBootstrap_Leg1Collision(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(409)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	fd := goroutineSafePipe(t, "test-pa\ntest-pb\n")
	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--relay", srv.URL,
		"--no-require-e2e",
		"--passphrase-fd", strconv.Itoa(fd),
		"--capsule", filepath.Join(t.TempDir(), "cap"),
		"--timeout", "10",
	}, &stdout, &stderr)
	if code != exitcode.Collision {
		t.Fatalf("exit code: got %d, want %d (Collision); stderr: %s", code, exitcode.Collision, stderr.String())
	}
}

func TestBootstrap_PassphraseFD(t *testing.T) {
	old := bootstrapEnterReader
	bootstrapEnterReader = newEnterReader(2)
	defer func() { bootstrapEnterReader = old }()

	relay := &mockRelay{blobs: make(map[string][]byte)}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	dsHex := randomDeploySecretHex(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", dsHex)

	iFD := goroutineSafePipe(t, "scripted-pa\nscripted-pb-i\n")
	rFD := goroutineSafePipe(t, "scripted-pa\nscripted-pb-r\n")
	iCapsule := filepath.Join(t.TempDir(), "capsule-i")
	rCapsule := filepath.Join(t.TempDir(), "capsule-r")

	var iStdout, iStderr, rStdout, rStderr bytes.Buffer
	var iResult, rResult int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		iResult = runBootstrap([]string{
			"--role", "initiator",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(iFD),
			"--capsule", iCapsule,
			"--timeout", "30",
		}, &iStdout, &iStderr)
	}()
	go func() {
		defer wg.Done()
		rResult = runBootstrap([]string{
			"--role", "responder",
			"--relay", srv.URL,
			"--no-require-e2e",
			"--passphrase-fd", strconv.Itoa(rFD),
			"--capsule", rCapsule,
			"--timeout", "30",
		}, &rStdout, &rStderr)
	}()
	wg.Wait()

	if iResult != exitcode.OK {
		t.Fatalf("initiator exit %d; stderr: %s", iResult, iStderr.String())
	}
	if rResult != exitcode.OK {
		t.Fatalf("responder exit %d; stderr: %s", rResult, rStderr.String())
	}
}

func TestBootstrap_KeepKeysRejected(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--keep-keys",
		"--role", "initiator",
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("exit code: got %d, want %d", code, exitcode.Usage)
	}
	if !strings.Contains(stderr.String(), "--keep-keys") {
		t.Error("stderr missing --keep-keys mention")
	}
	if !strings.Contains(stderr.String(), "F-34") {
		t.Error("stderr missing F-34 reference")
	}
}

func TestBootstrap_BurnAccepted(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	fd := goroutineSafePipe(t, "test-pa\ntest-pb\n")
	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--burn",
		"--role", "initiator",
		"--relay", "http://localhost:1",
		"--no-require-e2e",
		"--passphrase-fd", strconv.Itoa(fd),
		"--timeout", "2",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit (no relay running)")
	}
	if strings.Contains(stderr.String(), "--burn") {
		t.Errorf("stderr mentions --burn, suggesting rejection: %s", stderr.String())
	}
}

func TestBootstrap_MissingRole(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("exit code: got %d, want %d", code, exitcode.Usage)
	}
}

func TestBootstrap_InvalidRole(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "observer",
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("exit code: got %d, want %d", code, exitcode.Usage)
	}
	if !strings.Contains(stderr.String(), "invalid --role") {
		t.Error("stderr missing invalid role message")
	}
}

func TestBootstrap_MissingRelay(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", testDeploySecretHex)
	t.Setenv("DEADDROP_RELAY", "")

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("exit code: got %d, want %d", code, exitcode.Usage)
	}
}

func TestBootstrap_MissingDeploySecret(t *testing.T) {
	t.Setenv("DEADDROP_DEPLOY_SECRET", "")

	var stdout, stderr bytes.Buffer
	code := runBootstrap([]string{
		"--role", "initiator",
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("exit code: got %d, want %d", code, exitcode.Usage)
	}
}
