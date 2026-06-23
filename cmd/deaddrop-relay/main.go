// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Command deaddrop-relay is the in-memory slot relay HTTP server.
// It is body-opaque: it stores opaque ciphertext bytes and never
// sees plaintext or keys (D-01, D-02).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nmicic/deaddrop/internal/clock"
	"github.com/nmicic/deaddrop/internal/fdread"
	"github.com/nmicic/deaddrop/internal/relay"
	"github.com/nmicic/deaddrop/internal/secretparse"
	"github.com/nmicic/deaddrop/internal/slot"
)

// Env-var contract (D-43, D-48). Canonical names use the
// DEADDROP_* prefix. Legacy unprefixed names are accepted with a
// deprecation WARN for backward compatibility with the existing
// /etc/deaddrop/relay.env shape; the legacy path is removed in
// v0.2.
const (
	envDeploySecret       = "DEADDROP_DEPLOY_SECRET"
	envWriteToken         = "DEADDROP_WRITE_TOKEN"
	envDeploySecretLegacy = "DEPLOY_SECRET"
	envWriteTokenLegacy   = "WRITE_TOKEN"
)

// resolveRelaySecret implements the precedence used by the relay's
// deploy-secret / write-token reads (D-43): --<flag>-fd > canonical
// DEADDROP_* env > legacy unprefixed env > --<flag> argv. When the
// argv path is used at all, the deprecation WARN fires; the relay
// is long-lived so argv exposure persists in `ps` for the entire
// process lifetime, not just a brief one-shot. Stderr-write errors
// are swallowed (best-effort; daemon supervisors may detach
// stderr).
//
// flagBase is the kebab-case flag stem (e.g. "deploy-secret"),
// canonicalEnv is "DEADDROP_DEPLOY_SECRET", legacyEnv is
// "DEPLOY_SECRET". The returned string flows into
// secretparse.Parse unchanged.
// resolveRelaySecret resolves a secret for the relay binary (used
// for both deploy-secret and write-token). Precedence: fd > canonical
// env > legacy env > argv. For deploy-secret, the argv path is dead
// code post-D-72 (pre-dispatch scan blocks it), but write-token
// still uses it.
func resolveRelaySecret(
	fs *flag.FlagSet,
	flagBase string,
	fdFlag int,
	argvFlag, canonicalEnvVal, legacyEnvVal string,
	stderr io.Writer,
) (string, error) {
	argvSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == flagBase {
			argvSet = true
		}
	})
	canonicalEnvName := "DEADDROP_" + strings.ToUpper(strings.ReplaceAll(flagBase, "-", "_"))
	legacyEnvName := strings.ToUpper(strings.ReplaceAll(flagBase, "-", "_"))

	if fdFlag >= 0 {
		s, err := fdread.ReadString(fdFlag, "--"+flagBase+"-fd")
		if err != nil {
			return "", err
		}
		if canonicalEnvVal != "" || legacyEnvVal != "" {
			_, _ = fmt.Fprintf(stderr, "WARNING: --%s-fd takes precedence over $%s / $%s\n",
				flagBase, canonicalEnvName, legacyEnvName)
		}
		return s, nil
	}
	if canonicalEnvVal != "" {
		if legacyEnvVal != "" {
			_, _ = fmt.Fprintf(stderr,
				"WARNING: both $%s and $%s are set; using canonical $%s. Drop the legacy variable.\n",
				canonicalEnvName, legacyEnvName, canonicalEnvName)
		}
		return canonicalEnvVal, nil
	}
	if legacyEnvVal != "" {
		_, _ = fmt.Fprintf(stderr,
			"WARNING: $%s is deprecated; rename to $%s.\n",
			legacyEnvName, canonicalEnvName)
		return legacyEnvVal, nil
	}
	if argvSet {
		return argvFlag, nil
	}
	return "", nil
}

const (
	defaultGCInterval        = 60 * time.Second
	defaultMaxConcurrentGets = 100
	defaultMaxStoreBytes     = int64(512) * int64(relay.DefaultMaxBlobBytes)

	shutdownTimeout = 2 * time.Second
)

const (
	minWriteTokenLen  = 32
	defaultListenAddr = ":8080"
)

// serverRunFn starts srv and blocks until it stops. When ln is non-nil
// the function calls srv.Serve(ln); otherwise it calls
// srv.ListenAndServe. Tests pass a no-op to validate flag parsing
// without binding a socket.
type serverRunFn func(srv *http.Server, ln net.Listener) error

// run parses args, validates configuration, wires the HTTP server,
// and blocks in the listen function until shutdown completes. sigCh
// (if non-nil) drives graceful shutdown: the first signal triggers
// http.Server.Shutdown with a 2-second drain window, followed by
// GC.Stop and Store.ZeroizeAll to wipe every live slot from memory.
func run(args []string, stderr io.Writer, listen serverRunFn, sigCh <-chan os.Signal) error {
	fs := flag.NewFlagSet("deaddrop-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listenAddr := fs.String("listen", defaultListenAddr, "Listen address (host:port, :port, or unix:/path/to.sock)")
	deploySecretFD := fs.Int("deploy-secret-fd", -1, "Read DEPLOY_SECRET from this file descriptor (precedence: -fd > $DEADDROP_DEPLOY_SECRET > legacy $DEPLOY_SECRET)")
	writeTokenFlag := fs.String("write-token", "", "WRITE_TOKEN as hex:HEX or b64:B64 (DEPRECATED — use --write-token-fd or $DEADDROP_WRITE_TOKEN)")
	writeTokenFD := fs.Int("write-token-fd", -1, "Read WRITE_TOKEN from this file descriptor (precedence same as --deploy-secret-fd)")
	maxBlobBytes := fs.Int64("max-blob-bytes", relay.DefaultMaxBlobBytes, "Per-slot body cap")
	maxConcurrentGets := fs.Int("max-concurrent-gets", defaultMaxConcurrentGets,
		"Max concurrent in-flight GET requests (0 = unlimited)")
	maxStoreBytes := fs.Int64("max-store-bytes", defaultMaxStoreBytes,
		"Max total stored bytes; POST rejected 503 when exceeded (0 = unlimited)")
	localOnly := fs.Bool("local-only", false,
		"Allow empty WRITE_TOKEN and skip mlockall/PR_SET_DUMPABLE for local-only deployments")

	// D-72: reject --deploy-secret on argv (removed in v0.2.0).
	// Match single-dash too — Go's flag package normalizes them.
	for _, a := range args {
		if a == "--deploy-secret" || a == "-deploy-secret" ||
			strings.HasPrefix(a, "--deploy-secret=") || strings.HasPrefix(a, "-deploy-secret=") {
			return fmt.Errorf("--deploy-secret was removed in v0.2.0; use --deploy-secret-fd <n> or $DEADDROP_DEPLOY_SECRET (see CHANGELOG.md v0.2.0)")
		}
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	deploySecretValue, err := resolveRelaySecret(fs, "deploy-secret", *deploySecretFD, "",
		os.Getenv(envDeploySecret), os.Getenv(envDeploySecretLegacy), stderr)
	if err != nil {
		return err
	}
	if deploySecretValue == "" {
		return errors.New("--deploy-secret-fd or $DEADDROP_DEPLOY_SECRET is required")
	}
	deploySecret, err := secretparse.Parse("--deploy-secret", deploySecretValue)
	if err != nil {
		return err
	}
	if len(deploySecret) < slot.MinDeploySecretLen {
		return fmt.Errorf("--deploy-secret must decode to at least %d bytes, got %d",
			slot.MinDeploySecretLen, len(deploySecret))
	}

	writeTokenValue, err := resolveRelaySecret(fs, "write-token", *writeTokenFD, *writeTokenFlag,
		os.Getenv(envWriteToken), os.Getenv(envWriteTokenLegacy), stderr)
	if err != nil {
		return err
	}
	var writeToken []byte
	if writeTokenValue != "" {
		writeToken, err = secretparse.Parse("--write-token", writeTokenValue)
		if err != nil {
			return err
		}
		if len(writeToken) < minWriteTokenLen {
			return fmt.Errorf("--write-token must decode to at least %d bytes, got %d",
				minWriteTokenLen, len(writeToken))
		}
	}
	if len(writeToken) == 0 && !*localOnly {
		return errors.New("WRITE_TOKEN required for internet-facing deployments; pass --local-only to suppress")
	}

	// D-39: lock all pages in RAM and forbid core dumps. Hard error in
	// production mode; --local-only downgrades to a warning for dev /
	// CI hosts where CAP_IPC_LOCK or Linux itself isn't available.
	if err := relay.Mlockall(); err != nil {
		if !*localOnly {
			return fmt.Errorf("mlockall: %w (pass --local-only to skip)", err)
		}
		fmt.Fprintf(stderr, "warning: mlockall failed: %v (--local-only, continuing)\n", err)
	}
	if err := relay.DisableCoreDump(); err != nil {
		if !*localOnly {
			return fmt.Errorf("PR_SET_DUMPABLE: %w (pass --local-only to skip)", err)
		}
		fmt.Fprintf(stderr, "warning: PR_SET_DUMPABLE failed: %v (--local-only, continuing)\n", err)
	}

	clk := clock.NewRealClock()
	store := relay.NewStore(clk, *maxStoreBytes)
	handler := relay.NewHandler(relay.Config{
		Store:             store,
		DeploySecret:      deploySecret,
		WriteToken:        writeToken,
		MaxBlobBytes:      *maxBlobBytes,
		MaxConcurrentGets: *maxConcurrentGets,
		Clock:             clk,
	})

	var ln net.Listener
	addr := *listenAddr
	if strings.HasPrefix(addr, "unix:") {
		sockPath := strings.TrimPrefix(addr, "unix:")
		if err := os.Remove(sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing stale socket %s: %w", sockPath, err)
		}
		ln, err = net.Listen("unix", sockPath)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", sockPath, err)
		}
		defer ln.Close()
		if err := os.Chmod(sockPath, 0666); err != nil {
			return fmt.Errorf("chmod socket %s: %w", sockPath, err)
		}
		addr = ""
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	gc := relay.NewGC(store, defaultGCInterval)
	gc.Start()

	// shutdownDone is closed after srv.Shutdown returns (all in-flight
	// requests drained, or the 2-second timeout fired). listen returns
	// ErrServerClosed as soon as the listener closes — which can happen
	// before handlers finish — so we must wait here before wiping the
	// store, or ZeroizeAll could race an active handler.
	shutdownDone := make(chan struct{})
	if sigCh != nil {
		go func() {
			<-sigCh
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = srv.Shutdown(ctx)
			close(shutdownDone)
		}()
	}

	listenErr := listen(srv, ln)
	if errors.Is(listenErr, http.ErrServerClosed) && sigCh != nil {
		<-shutdownDone
	}

	gc.Stop()
	store.ZeroizeAll()

	if errors.Is(listenErr, http.ErrServerClosed) {
		return nil
	}
	return listenErr
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	listen := func(srv *http.Server, ln net.Listener) error {
		if ln != nil {
			return srv.Serve(ln)
		}
		return srv.ListenAndServe()
	}

	if err := run(os.Args[1:], os.Stderr, listen, sigCh); err != nil {
		fmt.Fprintln(os.Stderr, "deaddrop-relay:", err)
		os.Exit(1)
	}
}
