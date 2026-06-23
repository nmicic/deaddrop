// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/identitystore"
	"github.com/nmicic/deaddrop/internal/passcache"
	"github.com/nmicic/deaddrop/internal/secretparse"
	"github.com/nmicic/deaddrop/internal/slot"
)

// CLI-local knobs. See D-46 (client-side maxBlobBytes) and D-38 (exit codes).
const (
	// maxBlobBytes caps the plaintext file size client-side before
	// any crypto work runs. The wire body grows by version(1) +
	// outer nonce(24) + outer tag(16), and by another nonce+tag when
	// the E2E content layer is active. The relay's default body cap
	// includes that currently-shipped max overhead.
	maxBlobBytes = 10 * 1024 * 1024 // 10 MiB (D-46)

	sendHTTPTimeout = 30 * time.Second

	envRelay        = "DEADDROP_RELAY"
	envWriteToken   = "DEADDROP_WRITE_TOKEN"
	envDeploySecret = "DEADDROP_DEPLOY_SECRET"
)

// runSend implements `deaddrop send <file>`. It unwraps the capsule,
// reads the plaintext, and hands off to client.Send, then maps any
// *client.SendError to the matching D-38 banner + exit code.
func runSend(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(stderr)
	capsuleFlag := fs.String("capsule", "", "Capsule file path (defaults to $DEADDROP_CAPSULE or ~/.deaddrop/capsule)")
	fdFlag := fs.Int("passphrase-fd", -1, "Read passphrase from this file descriptor")
	envFlag := fs.String("passphrase-env", "", "Read passphrase from this environment variable")
	relayFlag := fs.String("relay", os.Getenv(envRelay), "Relay base URL (or $DEADDROP_RELAY)")
	writeTokenFlag := fs.String("write-token", os.Getenv(envWriteToken), "Relay write token (or $DEADDROP_WRITE_TOKEN)")
	envDeploy := os.Getenv(envDeploySecret)
	deploySecretFD := fs.Int("deploy-secret-fd", -1, "Read DEPLOY_SECRET from this file descriptor (precedence: -fd > env)")
	passcacheMode := fs.String("passcache", "auto", "Passphrase cache backend: auto (keyutils on Linux, keychain on macOS), none, keyutils, keychain")
	passcacheTTL := fs.Int("passcache-ttl", 3600, "Passphrase cache TTL in seconds (0 = disable caching for this command)")
	forgetPasscache := fs.Bool("forget-passcache", false, "Forget cached passphrase for this capsule before running")
	requireE2EFlag := fs.Bool("require-e2e", true, "Require a per-pair E2E identity entry (default; pass --no-require-e2e to allow legacy 0x01 fallback)")
	noRequireE2EFlag := fs.Bool("no-require-e2e", false, "Allow legacy 0x01 mode when no identity entry exists (DEPRECATED — rebootstrap to enable E2E)")
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
	if len(positional) != 1 {
		return exitError(stderr, exitcode.Usage, "send requires exactly one <file> argument")
	}
	filePath := positional[0]

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

	// Capsule path resolution and size gate.
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

	// Pre-read file-size check — fail fast before prompting for the
	// passphrase, so the user is not asked to type in a secret just
	// to learn their file is too big.
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return exitError(stderr, exitcode.Usage, "input file not found: "+filePath)
	}
	if fileInfo.Size() > int64(maxBlobBytes) {
		return exitError(stderr, exitcode.SizeCap, "file too large (limit "+itoa(maxBlobBytes)+" bytes)")
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

	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return exitError(stderr, exitcode.Internal, "reading input file: "+err.Error())
	}
	defer zeroize(plaintext)

	var writeTokenWire string
	if *writeTokenFlag != "" {
		wtBytes, wtErr := secretparse.Parse("--write-token", *writeTokenFlag)
		if wtErr != nil {
			return exitError(stderr, exitcode.Usage, wtErr.Error())
		}
		writeTokenWire = hex.EncodeToString(wtBytes)
	}

	// D-65 / D-66: resolve the per-pair identity entry and build the
	// content-AEAD layer if one exists. Three terminal cases:
	//   1. Store missing (ErrUnsupported) and --require-e2e → exit
	//      EDDPlatformUnsupported.
	//   2. Store present but no entry for the pair (ErrMiss) and
	//      --require-e2e → exit EDDIdentityMiss.
	//   3. Generic store error → exit EDDIdentityStore.
	// Otherwise we proceed in legacy mode (ContentLayer == nil) or
	// E2E mode depending on whether an entry was found.
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
			fmt.Fprintln(stderr, "WARN: no E2E identity entry for this pair; sending in legacy mode (rerun bootstrap to enable E2E, or pass --require-e2e to refuse legacy)")
		} else {
			return exitError(stderr, exitcode.IdentityStore, getErr.Error())
		}
	case errors.Is(idStoreErr, identitystore.ErrUnsupported):
		if *requireE2EFlag {
			return exitError(stderr, exitcode.PlatformUnsupported,
				"--require-e2e set but no identity store backend is available on this OS")
		}
		fmt.Fprintln(stderr, "WARN: no identity store backend available on this OS; sending in legacy mode")
	default:
		return exitError(stderr, exitcode.IdentityStore, idStoreErr.Error())
	}

	cfg := client.SendConfig{
		PSK:          psk,
		PairID:       pairID,
		DeploySecret: deploySecret,
		WriteToken:   writeTokenWire,
		RelayBaseURL: *relayFlag,
		HTTPClient:   &http.Client{Timeout: sendHTTPTimeout},
		Clock:        time.Now,
		ContentLayer: contentLayer,
	}

	deleteToken, err := client.Send(cfg, plaintext)
	if err != nil {
		var se *client.SendError
		if errors.As(err, &se) {
			return exitError(stderr, se.Code, se.Detail)
		}
		return exitError(stderr, exitcode.Internal, err.Error())
	}
	// D-35: delete token is ephemeral / in-process only. Zeroize and
	// drop — v1 has no transactional batch to reference it.
	zeroize(deleteToken)
	_ = stdout // success prints nothing (D-38).
	return exitcode.OK
}

// itoa is a fmt-free int → decimal string helper for error details.
// Using fmt is fine here (cmd/deaddrop may import fmt), but keeping
// the simple detail-string construction explicit makes the size
// message deterministic across Go versions' fmt formatting.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
