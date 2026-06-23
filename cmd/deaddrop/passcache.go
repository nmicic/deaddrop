// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/nmicic/deaddrop/internal/passcache"
)

// newCache is the constructor used by resolvePasscache. Tests override
// this to inject a fake Cache. Production code never reassigns it.
var newCache = passcache.New

// resolvePasscache returns a Cache and the effective TTL given the CLI
// flags. Returns (nil, 0, nil) when caching is disabled.
//
// ttlExplicit reflects whether the caller passed --passcache-ttl on the
// command line (regardless of value). On darwin, an explicit TTL emits
// the documented asymmetry warning to stderr — keychain has no per-item
// expiry.
func resolvePasscache(mode string, ttlSec int, ttlExplicit bool, stderr io.Writer) (passcache.Cache, time.Duration, error) {
	ttl := time.Duration(ttlSec) * time.Second

	switch mode {
	case "none":
		return nil, 0, nil
	case "auto":
		c, err := newCache()
		if err != nil {
			if errors.Is(err, passcache.ErrUnsupported) {
				// Warn only on Linux: there, ErrUnsupported means the
				// session keyring is missing or unreachable (operator
				// signal). On other platforms it's the structural
				// stub — silent is the documented contract.
				if runtime.GOOS == "linux" {
					fmt.Fprintln(stderr, "passcache: keyutils unavailable, caching disabled")
				}
				return nil, 0, nil
			}
			return nil, 0, err
		}
		// auto on darwin routes to keychain. Emit the TTL asymmetry
		// note when the operator explicitly requested a TTL value, so
		// they are not silently surprised when the entry persists past
		// it. Only fire the warning on darwin (the platform where the
		// keychain backend is selected by auto).
		if runtime.GOOS == "darwin" && ttlExplicit {
			fmt.Fprintln(stderr,
				"note: --passcache-ttl is ignored on macOS; entries persist until keychain lock")
		}
		// auto is best-effort on every platform — Put/Forget failures
		// stay silent. Do NOT wrap in strictCache here.
		return c, ttl, nil
	case "keyutils":
		if runtime.GOOS == "darwin" {
			return nil, 0, errors.New(
				"--passcache=keyutils is Linux-only; use keychain or auto on macOS")
		}
		c, err := newCache()
		if err != nil {
			return nil, 0, fmt.Errorf("passcache: keyutils backend: %w", err)
		}
		return &strictCache{inner: c, stderr: stderr}, ttl, nil
	case "keychain":
		if runtime.GOOS != "darwin" {
			return nil, 0, errors.New(
				"--passcache=keychain is darwin-only; use keyutils or auto on Linux")
		}
		c, err := newCache()
		if err != nil {
			return nil, 0, fmt.Errorf("passcache: keychain backend: %w", err)
		}
		if ttlExplicit {
			fmt.Fprintln(stderr,
				"note: --passcache-ttl is ignored on macOS; entries persist until keychain lock")
		}
		return &strictCache{inner: c, stderr: stderr}, ttl, nil
	default:
		return nil, 0, fmt.Errorf("unknown --passcache mode %q (use auto, none, keyutils, or keychain)", mode)
	}
}

// strictCache wraps a Cache so that Put/Forget runtime failures are
// surfaced on stderr instead of swallowed. Used only by --passcache=
// keyutils (the user explicitly asked for caching to work); in auto
// mode the cache is best-effort and silent. Exit code is unchanged —
// the transport already succeeded by the time these run.
type strictCache struct {
	inner  passcache.Cache
	stderr io.Writer
}

func (s *strictCache) Get(id string) ([]byte, error) {
	return s.inner.Get(id)
}

func (s *strictCache) Put(id string, pass []byte, ttl time.Duration) error {
	err := s.inner.Put(id, pass, ttl)
	if err != nil {
		fmt.Fprintf(s.stderr, "passcache: Put failed in strict mode: %v\n", err)
	}
	return err
}

func (s *strictCache) Forget(id string) error {
	err := s.inner.Forget(id)
	if err != nil {
		fmt.Fprintf(s.stderr, "passcache: Forget failed in strict mode: %v\n", err)
	}
	return err
}
