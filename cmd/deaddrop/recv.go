// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/identitystore"
	"github.com/nmicic/deaddrop/internal/passcache"
	"github.com/nmicic/deaddrop/internal/secretparse"
	"github.com/nmicic/deaddrop/internal/slot"
)

// recvHTTPTimeout is the per-GET client timeout; matches send's
// sendHTTPTimeout for operator-expectation symmetry.
const recvHTTPTimeout = 30 * time.Second

// watchIntervalFloor is the minimum --watch-interval the CLI accepts.
// Enforced in both prod and tests (D-70) — the watchClock seam lets
// tests inject a fast sleep without lowering the flag validation
// floor.
const watchIntervalFloor = 30 * time.Second

// watchDurationCeiling is the maximum --duration the CLI accepts.
const watchDurationCeiling = 24 * time.Hour

// recvOnce is a thin wrapper around client.RecvCtx used as the
// default Probe in production watchClock.
func recvOnce(ctx context.Context, cfg client.RecvConfig) ([]byte, error) {
	return client.RecvCtx(ctx, cfg)
}

// watchClock is the testability seam for runRecvWatch. Tests inject
// fake implementations of Now, Sleep, and Probe; production code
// uses realWatchClock().
type watchClock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	Probe func(ctx context.Context, cfg client.RecvConfig) ([]byte, error)
}

// realWatchClock returns the production watchClock using real time
// and real recv probes.
func realWatchClock() watchClock {
	return watchClock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		Probe: recvOnce,
	}
}

// runRecvWatch implements the --watch polling loop (D-70). It probes
// immediately, then sleeps min(interval, time.Until(deadline)) between
// probes. On success it writes the plaintext and returns 0. On a
// non-miss RecvError it returns the error's exit code (terminal —
// 429/503 are NOT retried). On context cancellation it returns
// Interrupted (130). On deadline expiry it returns NotFound (1).
//
// deadline==nil means unbounded (duration 0); the loop runs until
// success, a hard error, or context cancellation.
func runRecvWatch(ctx context.Context, wc watchClock, cfg client.RecvConfig, deadline *time.Time, interval time.Duration, out io.Writer, outputPath string, stderr io.Writer) int {
	for {
		plaintext, err := wc.Probe(ctx, cfg)
		if err == nil {
			// Success — write plaintext.
			defer zeroize(plaintext)
			if outputPath != "" {
				if wErr := os.WriteFile(outputPath, plaintext, 0o600); wErr != nil {
					return exitError(stderr, exitcode.Internal, "writing output: "+wErr.Error())
				}
				return exitcode.OK
			}
			if _, wErr := out.Write(plaintext); wErr != nil {
				return exitError(stderr, exitcode.Internal, "writing output: "+wErr.Error())
			}
			return exitcode.OK
		}

		if !client.IsMiss(err) {
			// Context cancellation during an in-flight HTTP probe
			// surfaces as a non-miss error (RelayUnreachable wrapping
			// context.Canceled). Check ctx before treating it as
			// terminal so SIGINT always exits 130, not 11.
			if ctx.Err() != nil {
				return exitcode.Interrupted
			}
			var re *client.RecvError
			if errors.As(err, &re) {
				return exitError(stderr, re.Code, re.Detail)
			}
			return exitError(stderr, exitcode.Internal, err.Error())
		}

		// IsMiss: check context cancellation first.
		select {
		case <-ctx.Done():
			return exitcode.Interrupted
		default:
		}

		// Check deadline.
		if deadline != nil {
			now := wc.Now()
			if !now.Before(*deadline) {
				return exitError(stderr, exitcode.NotFound, "no message found within --duration")
			}
			// Sleep the smaller of interval and remaining time.
			remaining := deadline.Sub(now)
			if remaining < interval {
				if sleepErr := wc.Sleep(ctx, remaining); sleepErr != nil {
					return exitcode.Interrupted
				}
			} else {
				if sleepErr := wc.Sleep(ctx, interval); sleepErr != nil {
					return exitcode.Interrupted
				}
			}
		} else {
			// No deadline (unbounded).
			if sleepErr := wc.Sleep(ctx, interval); sleepErr != nil {
				return exitcode.Interrupted
			}
		}
	}
}

// runRecv implements `deaddrop recv [output]`. It unwraps the
// capsule, calls client.Recv (3-bucket past-only probe), and writes
// the plaintext either to the given file (mode 0600) or to stdout.
func runRecv(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	capsuleFlag := fs.String("capsule", "", "Capsule file path (defaults to $DEADDROP_CAPSULE or ~/.deaddrop/capsule)")
	fdFlag := fs.Int("passphrase-fd", -1, "Read passphrase from this file descriptor")
	envFlag := fs.String("passphrase-env", "", "Read passphrase from this environment variable")
	relayFlag := fs.String("relay", os.Getenv(envRelay), "Relay base URL (or $DEADDROP_RELAY)")
	envDeploy := os.Getenv(envDeploySecret)
	deploySecretFD := fs.Int("deploy-secret-fd", -1, "Read DEPLOY_SECRET from this file descriptor (precedence: -fd > env)")
	passcacheMode := fs.String("passcache", "auto", "Passphrase cache backend: auto (keyutils on Linux, keychain on macOS), none, keyutils, keychain")
	passcacheTTL := fs.Int("passcache-ttl", 3600, "Passphrase cache TTL in seconds (0 = disable caching for this command)")
	forgetPasscache := fs.Bool("forget-passcache", false, "Forget cached passphrase for this capsule before running")
	requireE2EFlag := fs.Bool("require-e2e", true, "Require a per-pair E2E identity entry (default; pass --no-require-e2e to allow legacy 0x01 fallback)")
	noRequireE2EFlag := fs.Bool("no-require-e2e", false, "Allow legacy 0x01 mode when no identity entry exists (DEPRECATED — rebootstrap to enable E2E)")
	watchFlag := fs.Bool("watch", false, "Poll for a message until found, deadline, or signal (D-70)")
	durationFlag := fs.Duration("duration", 1*time.Hour, "Maximum wall-clock duration for --watch (default 1h, max 24h; 0 = unbounded)")
	watchIntervalFlag := fs.Duration("watch-interval", 60*time.Second, "Polling interval for --watch (default 60s, min 30s)")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}

	// D-71: reject conflicting flags.
	requireE2EExplicit := false
	noRequireE2EExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "require-e2e" {
			requireE2EExplicit = true
		}
		if f.Name == "no-require-e2e" {
			noRequireE2EExplicit = true
		}
	})
	if requireE2EExplicit && noRequireE2EExplicit {
		return exitError(stderr, exitcode.Usage,
			"--require-e2e and --no-require-e2e are mutually exclusive")
	}
	if *noRequireE2EFlag {
		fmt.Fprintln(stderr, "WARNING: --no-require-e2e is deprecated; rebootstrap to enable E2E instead of disabling the safety check")
		*requireE2EFlag = false
	}

	positional := fs.Args()
	if len(positional) > 1 {
		return exitError(stderr, exitcode.Usage, "recv takes at most one [output] argument")
	}
	var outputPath string
	if len(positional) == 1 {
		outputPath = positional[0]
	}

	// Validate --watch-related flags.
	durationSet := false
	intervalSet := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "duration":
			durationSet = true
		case "watch-interval":
			intervalSet = true
		}
	})

	if !*watchFlag && (durationSet || intervalSet) {
		return exitError(stderr, exitcode.Usage, "--duration and --watch-interval require --watch")
	}
	if *watchFlag {
		if *watchIntervalFlag < watchIntervalFloor {
			return exitError(stderr, exitcode.Usage, fmt.Sprintf("--watch-interval must be >= %s", watchIntervalFloor))
		}
		if *durationFlag != 0 && *durationFlag > watchDurationCeiling {
			return exitError(stderr, exitcode.Usage, fmt.Sprintf("--duration must be <= %s", watchDurationCeiling))
		}
	}

	if *relayFlag == "" {
		return exitError(stderr, exitcode.Usage, "--relay URL is required (or set $DEADDROP_RELAY)")
	}

	deploySecretValue, err := resolveDeploySecret(*deploySecretFD, envDeploy, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	if deploySecretValue == "" {
		return exitError(stderr, exitcode.Usage, "--deploy-secret-fd or $DEADDROP_DEPLOY_SECRET is required")
	}

	deploySecret, err := secretparse.Parse("--deploy-secret", deploySecretValue)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	if len(deploySecret) < slot.MinDeploySecretLen {
		return exitError(stderr, exitcode.Usage, "--deploy-secret too short (minimum 32 bytes)")
	}

	capsulePath := resolveCapsulePath(*capsuleFlag)
	capsuleInfo, err := os.Stat(capsulePath)
	if err != nil {
		return exitError(stderr, exitcode.Usage, "capsule not found: "+capsulePath)
	}
	if capsuleInfo.Size() != int64(capsule.CapsuleSize) {
		return exitError(stderr, exitcode.CapsuleUnwrap, "capsule size mismatch")
	}
	capsuleData, err := os.ReadFile(capsulePath)
	if err != nil {
		return exitError(stderr, exitcode.Internal, "reading capsule: "+err.Error())
	}

	ttlExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "passcache-ttl" {
			ttlExplicit = true
		}
	})
	cache, cacheTTL, cacheErr := resolvePasscache(*passcacheMode, *passcacheTTL, ttlExplicit, stderr)
	if cacheErr != nil {
		return exitError(stderr, exitcode.Usage, cacheErr.Error())
	}

	var cacheID string
	if cache != nil {
		cacheID, _ = passcache.IDForCapsule(capsuleData)
	}

	if *forgetPasscache && cache != nil && cacheID != "" {
		_ = cache.Forget(cacheID)
	}

	var psk, pairID []byte

	if cache != nil && cacheID != "" {
		cached, getErr := cache.Get(cacheID)
		if getErr == nil {
			psk, pairID, err = capsule.Unwrap(cached, capsuleData)
			zeroize(cached)
			if err != nil {
				_ = cache.Forget(cacheID)
			}
		}
	}

	if psk == nil {
		reader, err := resolvePassphraseReader(*fdFlag, *envFlag, stderr)
		if err != nil {
			return exitError(stderr, exitcode.Usage, err.Error())
		}
		pw, err := reader.ReadPassphrase("Passphrase: ")
		if err != nil {
			return exitError(stderr, exitcode.Usage, err.Error())
		}
		psk, pairID, err = capsule.Unwrap(pw, capsuleData)
		if err != nil {
			zeroize(pw)
			code, detail := classifyUnwrapError(err)
			return exitError(stderr, code, detail)
		}
		if cache != nil && cacheID != "" {
			_ = cache.Put(cacheID, pw, cacheTTL)
		}
		zeroize(pw)
	}
	defer zeroize(psk)
	defer zeroize(pairID)

	// D-65 / D-66: identity-store resolution mirrors the send-side
	// path. ErrUnsupported + --require-e2e → EDDPlatformUnsupported.
	// ErrMiss + --require-e2e → EDDIdentityMiss. Otherwise we may fall
	// through to legacy mode and let Recv warn on body[0]==0x01.
	var contentLayer *client.ContentLayer
	var pairIDArr [8]byte
	copy(pairIDArr[:], pairID)
	idStore, idStoreErr := newIdentityStore()
	switch {
	case idStoreErr == nil:
		entry, getErr := idStore.Get(pairIDArr)
		if getErr == nil {
			cl, clErr := client.NewContentLayerFromEntry(entry, pairIDArr)
			zeroize(entry.OwnSK[:])
			zeroize(entry.OwnPK[:])
			zeroize(entry.PeerPK[:])
			if clErr != nil {
				return exitError(stderr, exitcode.IdentityStore,
					"identity entry resolved but content-layer derivation failed: "+clErr.Error())
			}
			contentLayer = cl
			defer contentLayer.Wipe()
		} else if errors.Is(getErr, identitystore.ErrMiss) {
			if *requireE2EFlag {
				return exitError(stderr, exitcode.IdentityMiss,
					"--require-e2e set but no identity entry exists for this pair (rebootstrap to enable E2E)")
			}
			fmt.Fprintln(stderr, "WARN: no E2E identity entry for this pair; receiving in legacy mode (rerun bootstrap to enable E2E, or pass --require-e2e to refuse legacy)")
		} else {
			return exitError(stderr, exitcode.IdentityStore, getErr.Error())
		}
	case errors.Is(idStoreErr, identitystore.ErrUnsupported):
		if *requireE2EFlag {
			return exitError(stderr, exitcode.PlatformUnsupported,
				"--require-e2e set but no identity store backend is available on this OS")
		}
		fmt.Fprintln(stderr, "WARN: no identity store backend available on this OS; receiving in legacy mode")
	default:
		return exitError(stderr, exitcode.IdentityStore, idStoreErr.Error())
	}

	cfg := client.RecvConfig{
		PSK:          psk,
		PairID:       pairID,
		DeploySecret: deploySecret,
		RelayBaseURL: *relayFlag,
		HTTPClient:   &http.Client{Timeout: recvHTTPTimeout},
		Clock:        time.Now,
		ContentLayer: contentLayer,
		RequireE2E:   *requireE2EFlag,
		WarnSink:     stderr,
	}

	// --watch path: polling loop with signal handling (D-70).
	if *watchFlag {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		wc := realWatchClock()

		var deadline *time.Time
		if *durationFlag != 0 {
			d := wc.Now().Add(*durationFlag)
			deadline = &d
		}

		return runRecvWatch(ctx, wc, cfg, deadline, *watchIntervalFlag, stdout, outputPath, stderr)
	}

	// Single-shot path (--watch absent) — unchanged from before D-70.
	plaintext, err := client.Recv(cfg)
	if err != nil {
		var re *client.RecvError
		if errors.As(err, &re) {
			return exitError(stderr, re.Code, re.Detail)
		}
		return exitError(stderr, exitcode.Internal, err.Error())
	}
	defer zeroize(plaintext)

	if outputPath != "" {
		if err := os.WriteFile(outputPath, plaintext, 0o600); err != nil {
			return exitError(stderr, exitcode.Internal, "writing output: "+err.Error())
		}
		return exitcode.OK
	}
	if _, err := stdout.Write(plaintext); err != nil {
		return exitError(stderr, exitcode.Internal, "writing output: "+err.Error())
	}
	return exitcode.OK
}
