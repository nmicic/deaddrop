// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/nmicic/deaddrop/internal/identitystore"
	"golang.org/x/sys/unix"
)

// Exit codes used by the probe child to disambiguate outcomes for the
// parent. The parent treats anything else as an unexpected failure.
const (
	childExitGetOK      = 0 // child reached the entry across sessions
	childExitGetErrMiss = 2 // child got ErrMiss with a fresh session keyring
	childExitOther      = 3 // setup/syscall/other unexpected failure
)

func main() {
	os.Exit(run())
}

func run() int {
	// 0. Probe parent's keyring mode directly. We do NOT rely on
	// identitystore.New()'s side-effect WARN because that path is
	// what we are validating — circular if the same call decides
	// the expected outcome below.
	parentMode := "persistent"
	if _, err := unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, -1,
		unix.KEY_SPEC_SESSION_KEYRING, 0, 0); err != nil {
		parentMode = "fallback"
		fmt.Fprintf(os.Stderr,
			"PROBE: KEYCTL_GET_PERSISTENT errno=%v; parent on session fallback\n",
			err)
	} else {
		fmt.Fprintln(os.Stderr,
			"PROBE: KEYCTL_GET_PERSISTENT ok; parent on persistent keyring")
	}
	fmt.Fprintf(os.Stderr, "PROBE: parent_mode=%s\n", parentMode)

	// 1. Open the identity store.
	store, err := identitystore.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: New() failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "PROBE: New() OK")

	// 2. Put a known entry under a random PairID.
	var pairID [8]byte
	if _, err := rand.Read(pairID[:]); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: rand pairID: %v\n", err)
		return 1
	}
	entry := &identitystore.Entry{Role: identitystore.RoleInitiator}
	if _, err := rand.Read(entry.OwnSK[:]); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: rand OwnSK: %v\n", err)
		return 1
	}
	if _, err := rand.Read(entry.OwnPK[:]); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: rand OwnPK: %v\n", err)
		return 1
	}
	if _, err := rand.Read(entry.PeerPK[:]); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: rand PeerPK: %v\n", err)
		return 1
	}
	if err := store.Put(pairID, entry); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: Put() failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "PROBE: Put() OK")

	// 3. Get it back and verify.
	got, err := store.Get(pairID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: Get() failed: %v\n", err)
		return 1
	}
	if got.Role != entry.Role ||
		!bytes.Equal(got.OwnSK[:], entry.OwnSK[:]) ||
		!bytes.Equal(got.OwnPK[:], entry.OwnPK[:]) ||
		!bytes.Equal(got.PeerPK[:], entry.PeerPK[:]) {
		fmt.Fprintln(os.Stderr, "PROBE: Get() returned non-matching entry")
		return 1
	}
	fmt.Fprintln(os.Stderr, "PROBE: Get() round-trip OK")

	// 4. Spawn a child that explicitly joins a fresh session keyring
	// before opening the store. Without that, a session keyring
	// inherited via fork+exec on a fallback-mode parent would
	// false-green the cross-session test on every kernel.
	//   - parent persistent + child Get OK     → persistent confirmed
	//   - parent fallback   + child ErrMiss    → fallback isolated
	//   - any other combination                → unexpected, fail
	pairHex := fmt.Sprintf("%x", pairID)
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"PROBE_CHILD=1",
		"PROBE_PAIRID="+pairHex)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	childErr := cmd.Run()
	childExit := 0
	if childErr != nil {
		var exitErr *exec.ExitError
		if errors.As(childErr, &exitErr) {
			childExit = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "PROBE: child run error: %v\n", childErr)
			childExit = -1
		}
	}
	fmt.Fprintf(os.Stderr, "PROBE: child_exit=%d\n", childExit)

	// 5. Clean up.
	_ = store.Forget(pairID)

	// 6. Validate child outcome matches parent mode.
	switch parentMode {
	case "persistent":
		if childExit != childExitGetOK {
			fmt.Fprintf(os.Stderr,
				"PROBE: BUG: parent_mode=persistent but child_exit=%d "+
					"(expected %d for cross-session Get OK)\n",
				childExit, childExitGetOK)
			return 1
		}
		fmt.Fprintln(os.Stderr, "PROBE: MODE=persistent CROSS_SESSION=ok")
		return 0
	case "fallback":
		if childExit != childExitGetErrMiss {
			fmt.Fprintf(os.Stderr,
				"PROBE: BUG: parent_mode=fallback but child_exit=%d "+
					"(expected %d for ErrMiss in fresh session keyring)\n",
				childExit, childExitGetErrMiss)
			return 1
		}
		fmt.Fprintln(os.Stderr, "PROBE: MODE=fallback CROSS_SESSION=isolated")
		return 0
	}
	fmt.Fprintf(os.Stderr, "PROBE: BUG: unknown parent_mode=%q\n", parentMode)
	return 1
}

func init() {
	if os.Getenv("PROBE_CHILD") != "1" {
		return
	}
	// Replace any inherited session keyring with a fresh, uniquely
	// named one. Without this, a parent on session-fallback could
	// leak its session keyring into the child via fork+exec
	// inheritance, false-greening the cross-session test.
	childRingName := fmt.Sprintf("deaddrop-probe-child-%d", os.Getpid())
	if _, err := unix.KeyctlJoinSessionKeyring(childRingName); err != nil {
		fmt.Fprintf(os.Stderr,
			"PROBE-CHILD: KEYCTL_JOIN_SESSION_KEYRING failed: %v\n", err)
		os.Exit(childExitOther)
	}
	store, err := identitystore.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PROBE-CHILD: New() failed: %v\n", err)
		os.Exit(childExitOther)
	}
	pairHex := os.Getenv("PROBE_PAIRID")
	if len(pairHex) != 16 {
		fmt.Fprintf(os.Stderr,
			"PROBE-CHILD: bad PROBE_PAIRID length: %d\n", len(pairHex))
		os.Exit(childExitOther)
	}
	var pairID [8]byte
	for i := 0; i < 8; i++ {
		_, _ = fmt.Sscanf(pairHex[i*2:i*2+2], "%02x", &pairID[i])
	}
	_, err = store.Get(pairID)
	if err != nil {
		// ErrMiss is the expected outcome on the fallback path:
		// fresh session keyring + parent's session-keyring entry
		// is unreachable. Distinguish from genuine errors.
		if errors.Is(err, identitystore.ErrMiss) {
			fmt.Fprintln(os.Stderr,
				"PROBE-CHILD: Get() returned ErrMiss (fresh session keyring isolated)")
			os.Exit(childExitGetErrMiss)
		}
		fmt.Fprintf(os.Stderr,
			"PROBE-CHILD: Get() returned unexpected error: %v\n", err)
		os.Exit(childExitOther)
	}
	fmt.Fprintln(os.Stderr,
		"PROBE-CHILD: Get() OK (persistent keyring confirmed)")
	os.Exit(childExitGetOK)
}
