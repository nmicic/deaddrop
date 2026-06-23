// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

import "errors"

// errNotLinux is returned from Mlockall and DisableCoreDump on
// non-Linux platforms (macOS, Windows, BSD). The CLI converts this
// to a fatal error unless --local-only is set; developers running
// tests on non-Linux hosts must therefore use --local-only.
var errNotLinux = errors.New("relay: mlockall / PR_SET_DUMPABLE require Linux")

// Mlockall is unimplemented off Linux. D-39 mlockall is a Linux
// syscall; other OSes have neither a direct equivalent (macOS) nor
// the same threat model (Windows).
func Mlockall() error { return errNotLinux }

// DisableCoreDump is unimplemented off Linux. macOS uses
// setrlimit(RLIMIT_CORE,0) instead of prctl; we do not wire that
// here because production deployments are Linux per BACKEND_VM.md §5.
func DisableCoreDump() error { return errNotLinux }
