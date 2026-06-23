// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/wire"
)

// pipeWithData writes data to a fresh os.Pipe and returns the read fd.
// The write end is closed so EOF terminates the final line.
func pipeWithData(t *testing.T, data string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.WriteString(data); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return int(r.Fd())
}

// 1. TestNoArgs — empty argv prints usage and exits 2.
func TestNoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "usage") {
		t.Fatalf("stderr = %q, want to mention usage", stderr.String())
	}
}

// 2. TestUnknownSubcommand — unknown subcommand exits 2.
func TestUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// 2a. TestHelp_LongFlag — --help writes the banner to stdout, exits 0,
// and shows the live bootstrap line + --deploy-secret-fd placeholder.
// v0.2.0: --deploy-secret was removed; banner shows --deploy-secret-fd.
func TestHelp_LongFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty (--help is a success path)", stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "bootstrap --role=") {
		t.Errorf("stdout missing live bootstrap line: %s", out)
	}
	if !strings.Contains(out, "--deploy-secret-fd N") {
		t.Errorf("stdout missing --deploy-secret-fd placeholder: %s", out)
	}
	if strings.Contains(out, "--deploy-secret hex:HEX|b64:B64") {
		t.Errorf("stdout still contains removed --deploy-secret argv placeholder: %s", out)
	}
	if strings.Contains(out, "bootstrap ...") || strings.Contains(out, "bootstrap not yet implemented") {
		t.Errorf("stdout still contains stale bootstrap banner: %s", out)
	}
	if strings.HasPrefix(out, "ERROR:") {
		t.Errorf("stdout banner begins with ERROR: prefix on success path: %s", out)
	}
}

// 2b. TestHelp_ShortFlag — -h behaves identically to --help.
func TestHelp_ShortFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "bootstrap --role=") {
		t.Errorf("stdout missing live bootstrap line: %s", stdout.String())
	}
}

// 2c. TestUnknownSubcommand_SplitStreamInvariant — unknown subcommand
// emits ERROR header to stderr, exits 2, AND emits zero bytes on
// stdout. Proves no split-stream regression from DEL-3's split.
func TestUnknownSubcommand_SplitStreamInvariant(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"somecommandthatdoesnotexist"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (error path must not write to stdout)", stdout.String())
	}
	if !strings.HasPrefix(stderr.String(), "ERROR: EDDUsage:") {
		t.Fatalf("stderr = %q, want to begin with \"ERROR: EDDUsage:\"", stderr.String())
	}
}

// 2d. TestNoArgs_SplitStreamInvariant — preserves the error path
// shape under the new printUsage/printUsageBanner split.
func TestNoArgs_SplitStreamInvariant(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (no-args is an error path)", stdout.String())
	}
	if !strings.HasPrefix(stderr.String(), "ERROR: EDDUsage:") {
		t.Fatalf("stderr = %q, want \"ERROR: EDDUsage:\" prefix", stderr.String())
	}
}

// 3. TestPassphraseForbidden — --passphrase anywhere in argv rejects.
func TestPassphraseForbidden(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase", "secret", "/tmp/out"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--passphrase is forbidden") {
		t.Fatalf("stderr = %q, want --passphrase forbidden message", stderr.String())
	}
}

// 4. TestPassphraseForbiddenEquals — --passphrase=… also rejects.
func TestPassphraseForbiddenEquals(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--passphrase=secret"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// 5. TestKeygen_MissingOutPath — keygen without <out-path> fails usage.
func TestKeygen_MissingOutPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// 6. TestKeygen_OutputExists — refuse to overwrite existing file.
func TestKeygen_OutputExists(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "capsule")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	fd := pipeWithData(t, "test-passphrase\ntest-passphrase\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase-fd", strconv.Itoa(fd), tmp}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("stderr = %q, want to mention already exists", stderr.String())
	}
}

// 7. TestKeygen_HappyPath — full happy path end-to-end.
func TestKeygen_HappyPath(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "capsule")
	fd := pipeWithData(t, "test-passphrase\ntest-passphrase\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase-fd", strconv.Itoa(fd), tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}

	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("stat capsule: %v", err)
	}
	if info.Size() != int64(capsule.CapsuleSize) {
		t.Fatalf("size = %d, want %d", info.Size(), capsule.CapsuleSize)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 0600", perm)
	}

	printed := strings.TrimRight(stdout.String(), "\n")
	if len(printed) != 32 {
		t.Fatalf("stdout fingerprint length = %d, want 32 (got %q)", len(printed), printed)
	}
	// Round-trip: Unwrap and verify the fingerprint matches stdout.
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read capsule: %v", err)
	}
	psk, pairID, err := capsule.Unwrap([]byte("test-passphrase"), data)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	fp, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if hex.EncodeToString(fp) != printed {
		t.Fatalf("printed fingerprint %q != computed %q", printed, hex.EncodeToString(fp))
	}
}

// keygenFreshCapsule creates a capsule in a temp dir, returning the
// path + passphrase used. Helper for fingerprint-side tests.
func keygenFreshCapsule(t *testing.T, pw string) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "capsule")
	fd := pipeWithData(t, pw+"\n"+pw+"\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase-fd", strconv.Itoa(fd), tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("keygen setup failed: code=%d stderr=%s", code, stderr.String())
	}
	return tmp
}

// 8. TestFingerprint_HappyPath — keygen then fingerprint produce the
// same hex string.
func TestFingerprint_HappyPath(t *testing.T) {
	path := keygenFreshCapsule(t, "fp-happy")

	// Re-run keygen under a different temp path just to capture the
	// expected hex via the printed fingerprint of our original run.
	// Here we prefer re-Unwrapping the same file to compute ground truth.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	psk, pairID, err := capsule.Unwrap([]byte("fp-happy"), data)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	want, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	fd := pipeWithData(t, "fp-happy\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"fingerprint", "--capsule", path, "--passphrase-fd", strconv.Itoa(fd)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	printed := strings.TrimRight(stdout.String(), "\n")
	if printed != hex.EncodeToString(want) {
		t.Fatalf("printed fingerprint %q != expected %q", printed, hex.EncodeToString(want))
	}
}

// 9. TestFingerprint_WrongPassphrase — wrong passphrase → exit 15.
func TestFingerprint_WrongPassphrase(t *testing.T) {
	path := keygenFreshCapsule(t, "correct")
	fd := pipeWithData(t, "wrong\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"fingerprint", "--capsule", path, "--passphrase-fd", strconv.Itoa(fd)}, &stdout, &stderr)
	if code != 15 {
		t.Fatalf("code = %d, want 15 (EDDCapsuleUnwrap); stderr=%s", code, stderr.String())
	}
}

// 10. TestFingerprint_MissingCapsule — path that doesn't exist → exit 2.
func TestFingerprint_MissingCapsule(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	var stdout, stderr bytes.Buffer
	code := run([]string{"fingerprint", "--capsule", missing}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage)", code)
	}
}

// 11. TestStubSubcommands — rotate-capsule still stub.
// (`send`, `recv`, and `bootstrap` are no longer stubs.)
func TestStubSubcommands(t *testing.T) {
	for _, sub := range []string{"rotate-capsule"} {
		sub := sub
		t.Run(sub, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{sub}, &stdout, &stderr)
			if code != 2 {
				t.Errorf("code = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), "not yet implemented") {
				t.Errorf("stderr = %q, want \"not yet implemented\"", stderr.String())
			}
		})
	}
}

// 12. TestKeygen_PassphraseMismatch — two different reads → exit 2
// and no output file created.
func TestKeygen_PassphraseMismatch(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "capsule")
	fd := pipeWithData(t, "first\nsecond\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase-fd", strconv.Itoa(fd), tmp}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "match") {
		t.Fatalf("stderr = %q, want to mention mismatch", stderr.String())
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("output file should not exist on mismatch; stat err = %v", err)
	}
}

// 13. TestKeygen_PassphraseEnv — --passphrase-env happy path with
// stderr warning.
func TestKeygen_PassphraseEnv(t *testing.T) {
	t.Setenv("TEST_DD_PASS", "env-pass")
	tmp := filepath.Join(t.TempDir(), "capsule")
	var stdout, stderr bytes.Buffer
	code := run([]string{"keygen", "--passphrase-env", "TEST_DD_PASS", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("stat capsule: %v", err)
	}
	if info.Size() != int64(capsule.CapsuleSize) {
		t.Fatalf("size = %d, want %d", info.Size(), capsule.CapsuleSize)
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Fatalf("stderr = %q, want to contain \"warning\"", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Send subcommand tests (14-22).
// ---------------------------------------------------------------------------

// sendTestEnv clears the three env vars the send subcommand reads
// from. Tests that need specific env values call t.Setenv after.
func sendTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DEADDROP_RELAY", "")
	t.Setenv("DEADDROP_WRITE_TOKEN", "")
	t.Setenv("DEADDROP_DEPLOY_SECRET", "")
}

// deploySecretHex is a fixed 32-byte hex value (with the mandatory
// "hex:" prefix per PROTOCOL.md §8) used across the send CLI tests.
// 64 hex chars after the prefix = 32 decoded bytes, meeting MinDeploySecretLen.
const deploySecretHex = "hex:0101010101010101010101010101010101010101010101010101010101010101"

// 14. TestSend_MissingFile — send with no positional → exit 2.
func TestSend_MissingFile(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--relay", "http://localhost", "--no-require-e2e"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "send requires") {
		t.Fatalf("stderr = %q, want mention of missing file argument", stderr.String())
	}
}

// 15. TestSend_MissingRelay — no --relay and no $DEADDROP_RELAY → 2.
func TestSend_MissingRelay(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	tmp := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--no-require-e2e", tmp}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "relay") {
		t.Fatalf("stderr = %q, want mention of relay", stderr.String())
	}
}

// 16a. TestSend_DeploySecretArgvRejected — v0.2.0: --deploy-secret on
// argv is rejected with exit 2 and the migration message.
func TestSend_DeploySecretArgvRejected(t *testing.T) {
	sendTestEnv(t)
	tmp := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--relay", "http://localhost",
		"--deploy-secret", deploySecretHex,
		tmp,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret was removed in v0.2.0") {
		t.Fatalf("stderr = %q, want migration message", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret-fd") {
		t.Fatalf("stderr = %q, want to mention --deploy-secret-fd", stderr.String())
	}
}

// 16b. TestRecv_DeploySecretArgvRejected — v0.2.0: --deploy-secret on
// argv is rejected for recv too.
func TestRecv_DeploySecretArgvRejected(t *testing.T) {
	sendTestEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--relay", "http://localhost",
		"--deploy-secret", deploySecretHex,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret was removed in v0.2.0") {
		t.Fatalf("stderr = %q, want migration message", stderr.String())
	}
}

// 16c. TestBootstrap_DeploySecretArgvRejected — v0.2.0: --deploy-secret
// on argv is rejected for bootstrap too.
func TestBootstrap_DeploySecretArgvRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"bootstrap",
		"--role", "initiator",
		"--relay", "http://localhost",
		"--deploy-secret", deploySecretHex,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret was removed in v0.2.0") {
		t.Fatalf("stderr = %q, want migration message", stderr.String())
	}
}

// 16d. TestSend_DeploySecretEqualsFormRejected — --deploy-secret=value
// form is also rejected.
func TestSend_DeploySecretEqualsFormRejected(t *testing.T) {
	sendTestEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--deploy-secret=" + deploySecretHex,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret was removed in v0.2.0") {
		t.Fatalf("stderr = %q, want migration message", stderr.String())
	}
}

// 16e. TestSend_RequireE2EFalseRejected — --require-e2e=false is rejected
// with a message pointing to --no-require-e2e.
func TestSend_RequireE2EFalseRejected(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--require-e2e=false",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--no-require-e2e") {
		t.Fatalf("stderr = %q, want to mention --no-require-e2e", stderr.String())
	}
}

// 16f. TestSend_RequireE2EConflict — --require-e2e and --no-require-e2e
// together is rejected.
func TestSend_RequireE2EConflict(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	tmp := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--relay", "http://localhost",
		"--require-e2e",
		"--no-require-e2e",
		tmp,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (EDDUsage); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("stderr = %q, want to mention mutually exclusive", stderr.String())
	}
}

// 16. TestSend_MissingDeploySecret — no --deploy-secret-fd and no env → 2.
func TestSend_MissingDeploySecret(t *testing.T) {
	sendTestEnv(t)
	tmp := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--relay", "http://localhost", "--no-require-e2e", tmp}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%s", code, stderr.String())
	}
}

// capturingRelay stands up a fake relay that records the first
// request and returns the given status. pStatus may be nil; a zero
// pointer picks the default status.
type sendRelayCapture struct {
	received atomic.Bool
	path     atomic.Value // string
	header   atomic.Value // http.Header
	body     atomic.Value // []byte
}

func newCapturingRelay(t *testing.T, status int) (*httptest.Server, *sendRelayCapture) {
	t.Helper()
	cap := &sendRelayCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path.Store(r.URL.Path)
		cap.header.Store(r.Header.Clone())
		body, _ := io.ReadAll(r.Body)
		cap.body.Store(body)
		cap.received.Store(true)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// 17. TestSend_HappyPath — full CLI integration; body structural
// checks only (no AEAD round-trip here; see DEL-3 TestSend_BodyStructure
// which runs with a fixed clock).
func TestSend_HappyPath(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "send-happy")
	srv, cap := newCapturingRelay(t, http.StatusCreated)

	plainPath := filepath.Join(t.TempDir(), "plaintext")
	if err := os.WriteFile(plainPath, []byte("hello-cli-send"), 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	fd := pipeWithData(t, "send-happy\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		"--write-token", "hex:0101010101010101010101010101010101010101010101010101010101010101",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (D-38: send prints nothing on success)", stdout.String())
	}
	if !cap.received.Load() {
		t.Fatalf("relay did not receive the request")
	}

	path, _ := cap.path.Load().(string)
	parts := strings.Split(path, "/")
	if len(parts) != 3 || len(parts[1]) != 32 || len(parts[2]) != 32 {
		t.Fatalf("path = %q, want /{32-hex}/{32-hex}", path)
	}

	body, _ := cap.body.Load().([]byte)
	if len(body) < 1+24+16 {
		t.Fatalf("body len = %d, want ≥ 41", len(body))
	}
	if body[0] != wire.VersionPlainB {
		t.Fatalf("body[0] = 0x%02x, want 0x01", body[0])
	}

	hdr, _ := cap.header.Load().(http.Header)
	if got := hdr.Get("X-DeadDrop-Write"); got != "0101010101010101010101010101010101010101010101010101010101010101" {
		t.Fatalf("X-DeadDrop-Write = %q, want hex-encoded token", got)
	}
}

// 18. TestSend_CapsuleNotFound — nonexistent --capsule → exit 2.
func TestSend_CapsuleNotFound(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	tmp := filepath.Join(t.TempDir(), "plaintext")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code := run([]string{
		"send",
		"--capsule", filepath.Join(t.TempDir(), "nope"),
		"--relay", "http://localhost",
		"--no-require-e2e",
		tmp,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%s", code, stderr.String())
	}
}

// 19. TestSend_WrongPassphrase — capsule keyed with "correct", send
// supplies "wrong" → exit 15.
func TestSend_WrongPassphrase(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "correct")
	srv, _ := newCapturingRelay(t, http.StatusCreated)

	tmp := filepath.Join(t.TempDir(), "plaintext")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fd := pipeWithData(t, "wrong\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		tmp,
	}, &stdout, &stderr)
	if code != 15 {
		t.Fatalf("code = %d, want 15 (EDDCapsuleUnwrap); stderr=%s", code, stderr.String())
	}
}

// 20. TestSend_Relay409 — fake relay returns 409 → exit 12 (Collision).
func TestSend_Relay409(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "collide")
	srv, _ := newCapturingRelay(t, http.StatusConflict)

	tmp := filepath.Join(t.TempDir(), "plaintext")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fd := pipeWithData(t, "collide\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		tmp,
	}, &stdout, &stderr)
	if code != 12 {
		t.Fatalf("code = %d, want 12 (EDDCollision); stderr=%s", code, stderr.String())
	}
}

// 21. TestSend_Relay503 — fake relay returns 503 → exit 16 (RelayOverloaded).
func TestSend_Relay503(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "overload")
	srv, _ := newCapturingRelay(t, http.StatusServiceUnavailable)

	tmp := filepath.Join(t.TempDir(), "plaintext")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fd := pipeWithData(t, "overload\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		tmp,
	}, &stdout, &stderr)
	if code != 16 {
		t.Fatalf("code = %d, want 16 (EDDRelayOverloaded); stderr=%s", code, stderr.String())
	}
}

// 22. TestSend_FileTooLarge — file > maxBlobBytes → exit 14
// (EDDSizeCap). Exercises the client-side pre-check in DEL-4 step 6
// that fails before the passphrase prompt.
func TestSend_FileTooLarge(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "big")
	srv, _ := newCapturingRelay(t, http.StatusCreated)

	// 10 MiB + 1 byte — one over the client-side cap.
	bigPath := filepath.Join(t.TempDir(), "big")
	bigFile, err := os.Create(bigPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := bigFile.Truncate(int64(maxBlobBytes) + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	bigFile.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--relay", srv.URL,
		"--no-require-e2e",
		bigPath,
	}, &stdout, &stderr)
	if code != 14 {
		t.Fatalf("code = %d, want 14 (EDDSizeCap); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "file too large") {
		t.Fatalf("stderr = %q, want \"file too large\"", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Recv subcommand tests (23-31).
// ---------------------------------------------------------------------------

// newRoundTripRelay serves a POST-then-GET store keyed by URL path:
// POST stores the body, GET returns 200 + body, or 404 for unknown
// paths. Lets CLI-level tests exercise the full send → recv arc.
func newRoundTripRelay(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	slots := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			slots[r.URL.Path] = body
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			mu.Lock()
			body, ok := slots[r.URL.Path]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sendInto is a helper for tests 26+27: run `deaddrop send` against
// srv using the given capsule + passphrase + plaintext path.
// v0.2.0: uses env var for deploy-secret and --no-require-e2e for
// legacy-mode tests.
func sendInto(t *testing.T, capsulePath, passphrase, relayURL, plainPath string) {
	t.Helper()
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	fd := pipeWithData(t, passphrase+"\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", relayURL,
		"--no-require-e2e",
		"--write-token", "hex:0202020202020202020202020202020202020202020202020202020202020202",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("send setup failed: code=%d stderr=%s", code, stderr.String())
	}
}

// 23. TestRecv_TooManyArgs — recv with two positional args → exit 2.
func TestRecv_TooManyArgs(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv", "out1", "out2",
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "at most one") {
		t.Fatalf("stderr = %q, want mention of \"at most one\"", stderr.String())
	}
}

// 24. TestRecv_MissingRelay — no --relay and no $DEADDROP_RELAY → 2.
func TestRecv_MissingRelay(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{"recv", "--no-require-e2e"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "relay") {
		t.Fatalf("stderr = %q, want mention of relay", stderr.String())
	}
}

// 25. TestRecv_MissingDeploySecret — no --deploy-secret-fd and no env → 2.
func TestRecv_MissingDeploySecret(t *testing.T) {
	sendTestEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"recv", "--relay", "http://localhost", "--no-require-e2e"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// 26. TestRecv_HappyPath — full send → recv CLI round-trip via an
// in-process POST/GET relay.
func TestRecv_HappyPath(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "recv-happy")
	srv := newRoundTripRelay(t)

	plainPath := filepath.Join(t.TempDir(), "plaintext")
	payload := []byte("round-trip-payload-3.3")
	if err := os.WriteFile(plainPath, payload, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	sendInto(t, capsulePath, "recv-happy", srv.URL, plainPath)

	fd := pipeWithData(t, "recv-happy\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), payload) {
		t.Fatalf("stdout = %q, want %q", stdout.String(), payload)
	}
}

// 27. TestRecv_OutputFile — same as 26 but write to file.
func TestRecv_OutputFile(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "recv-file")
	srv := newRoundTripRelay(t)

	plainPath := filepath.Join(t.TempDir(), "plaintext")
	payload := []byte("round-trip-to-file")
	if err := os.WriteFile(plainPath, payload, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	sendInto(t, capsulePath, "recv-file", srv.URL, plainPath)

	outPath := filepath.Join(t.TempDir(), "out")
	fd := pipeWithData(t, "recv-file\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
		outPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when writing to file", stdout.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("output file contents mismatch")
	}
}

// 28. TestRecv_CapsuleNotFound — bad --capsule → exit 2.
func TestRecv_CapsuleNotFound(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", filepath.Join(t.TempDir(), "nope"),
		"--relay", "http://localhost",
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// 29. TestRecv_WrongPassphrase — keygen "correct", recv "wrong" → exit 15.
func TestRecv_WrongPassphrase(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "correct")
	srv := newRoundTripRelay(t)

	fd := pipeWithData(t, "wrong\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 15 {
		t.Fatalf("code = %d, want 15 (EDDCapsuleUnwrap); stderr=%s", code, stderr.String())
	}
}

// 30. TestRecv_NotFound — fake relay returns 404 everywhere → exit 1.
func TestRecv_NotFound(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "missing")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	fd := pipeWithData(t, "missing\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code = %d, want 1 (EDDNotFound); stderr=%s", code, stderr.String())
	}
}

// 31. TestRecv_Relay503 — fake relay returns 503 → exit 16.
func TestRecv_Relay503(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "overload-r")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	fd := pipeWithData(t, "overload-r\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(fd),
		"--relay", srv.URL,
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 16 {
		t.Fatalf("code = %d, want 16 (EDDRelayOverloaded); stderr=%s", code, stderr.String())
	}
}

// ---------------------------------------------------------------------------
// DEL-1 tests (32-37): --deploy-secret-fd + v0.2.0 migration (D-43, D-72).
// ---------------------------------------------------------------------------

// 32. TestSend_DeploySecretFd — fd path lands the secret correctly.
func TestSend_DeploySecretFd(t *testing.T) {
	sendTestEnv(t)
	capsulePath := keygenFreshCapsule(t, "fd-send")
	srv, _ := newCapturingRelay(t, http.StatusCreated)

	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("fd-payload"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pwFD := pipeWithData(t, "fd-send\n")
	dsFD := pipeWithData(t, deploySecretHex+"\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(pwFD),
		"--relay", srv.URL,
		"--deploy-secret-fd", strconv.Itoa(dsFD),
		"--no-require-e2e",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
}

// 35. TestSend_FdTakesPrecedenceOverEnv — fd overrides env; secret
// from fd is used (proven by happy round-trip), the fd-over-env
// precedence WARN fires so the operator can see which source the
// binary used.
func TestSend_FdTakesPrecedenceOverEnv(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	capsulePath := keygenFreshCapsule(t, "fd-over-env")
	srv, _ := newCapturingRelay(t, http.StatusCreated)

	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("fd-over-env-payload"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pwFD := pipeWithData(t, "fd-over-env\n")
	dsFD := pipeWithData(t, deploySecretHex+"\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"send",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(pwFD),
		"--relay", srv.URL,
		"--deploy-secret-fd", strconv.Itoa(dsFD),
		"--no-require-e2e",
		plainPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--deploy-secret-fd takes precedence over $DEADDROP_DEPLOY_SECRET") {
		t.Fatalf("stderr missing fd-over-env precedence WARN; got %q", stderr.String())
	}
}

// 37. TestRecv_DeploySecretFd — recv reads the secret from fd.
func TestRecv_DeploySecretFd(t *testing.T) {
	sendTestEnv(t)
	capsulePath := keygenFreshCapsule(t, "recv-fd")
	srv := newRoundTripRelay(t)

	plainPath := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plainPath, []byte("recv-fd-payload"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sendInto(t, capsulePath, "recv-fd", srv.URL, plainPath)

	pwFD := pipeWithData(t, "recv-fd\n")
	dsFD := pipeWithData(t, deploySecretHex+"\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--capsule", capsulePath,
		"--passphrase-fd", strconv.Itoa(pwFD),
		"--relay", srv.URL,
		"--deploy-secret-fd", strconv.Itoa(dsFD),
		"--no-require-e2e",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
}
