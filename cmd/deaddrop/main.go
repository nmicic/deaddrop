// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

// Command deaddrop is the user-facing CLI. It dispatches subcommands
// and owns shared concerns: argv-passphrase detection (D-31), capsule
// path resolution (D-31), and D-38 error formatting.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/fdread"
	"github.com/nmicic/deaddrop/internal/passphrase"
)

const (
	envCapsulePath        = "DEADDROP_CAPSULE"
	defaultCapsuleRelPath = ".deaddrop/capsule"
)

// run is the testable entry point. Subcommand dispatch, argv audit,
// and usage messages live here; main() just wraps it with real
// stdio and calls os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	// D-31: reject --passphrase / --passphrase=... anywhere in argv
	// before dispatch so subcommands cannot be tricked into leaking
	// the passphrase via `ps` or shell history.
	for _, a := range args {
		if a == "--passphrase" || strings.HasPrefix(a, "--passphrase=") {
			return exitError(stderr, exitcode.Usage,
				"--passphrase is forbidden (passphrase visible in ps/history); use --passphrase-fd or --passphrase-env")
		}
	}

	// D-72: reject --deploy-secret on argv (removed in v0.2.0).
	// Scan before subcommand dispatch so the operator gets the
	// migration message rather than Go's generic flag-parse error.
	// Match both single-dash and double-dash (Go's flag package
	// normalizes them).
	for _, a := range args {
		if a == "--deploy-secret" || a == "-deploy-secret" ||
			strings.HasPrefix(a, "--deploy-secret=") || strings.HasPrefix(a, "-deploy-secret=") {
			return exitError(stderr, exitcode.Usage,
				"--deploy-secret was removed in v0.2.0; use --deploy-secret-fd <n> or $DEADDROP_DEPLOY_SECRET (see CHANGELOG.md v0.2.0)")
		}
	}

	// D-71: reject any --require-e2e=<value> form (must use
	// --no-require-e2e for the opt-out). Go's flag package accepts
	// 0, f, F, false, FALSE as boolean-false — matching only "false"
	// would let the others slip through silently.
	for _, a := range args {
		if strings.HasPrefix(a, "--require-e2e=") || strings.HasPrefix(a, "-require-e2e=") {
			return exitError(stderr, exitcode.Usage,
				"--require-e2e=<value> is not supported; --require-e2e is default-on, use --no-require-e2e to allow legacy 0x01 fallback")
		}
	}

	if len(args) == 0 {
		printUsage(stderr)
		return exitcode.Usage
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help":
		printUsageBanner(stdout)
		return exitcode.OK
	case "keygen":
		return runKeygen(rest, stdout, stderr)
	case "fingerprint":
		return runFingerprint(rest, stdout, stderr)
	case "send":
		return runSend(rest, stdout, stderr)
	case "recv":
		return runRecv(rest, stdout, stderr)
	case "bootstrap":
		return runBootstrap(rest, stdout, stderr)
	case "rotate-capsule":
		return exitError(stderr, exitcode.Usage, sub+" not yet implemented")
	default:
		printUsage(stderr)
		return exitcode.Usage
	}
}

// classifyUnwrapError maps capsule-level errors to D-38 exit codes.
// Lives in main.go so both fingerprint.go and send.go can call it
// without duplicating the switch. Anything capsule-structural or
// AEAD-related is CapsuleUnwrap; an unknown error is Internal so the
// CLI never swallows a bug quietly.
func classifyUnwrapError(err error) (int, string) {
	switch {
	case errors.Is(err, capsule.ErrDecrypt):
		return exitcode.CapsuleUnwrap, "wrong passphrase or corrupt capsule"
	case errors.Is(err, capsule.ErrBadMagic):
		return exitcode.CapsuleUnwrap, "bad magic (not a deaddrop capsule?)"
	case errors.Is(err, capsule.ErrBadVersion):
		return exitcode.CapsuleUnwrap, "unsupported capsule version"
	case errors.Is(err, capsule.ErrBadSize):
		return exitcode.CapsuleUnwrap, "capsule size mismatch"
	case errors.Is(err, capsule.ErrParamFloor),
		errors.Is(err, capsule.ErrParamCeiling),
		errors.Is(err, capsule.ErrBadKDFVersion),
		errors.Is(err, capsule.ErrBadKeyLen),
		errors.Is(err, capsule.ErrBadSaltLen),
		errors.Is(err, capsule.ErrParamReserved):
		return exitcode.CapsuleUnwrap, err.Error()
	default:
		return exitcode.Internal, err.Error()
	}
}

// exitError emits the D-38 single-line error banner and returns the
// exit code so callers can `return exitError(...)`.
func exitError(w io.Writer, code int, detail string) int {
	name := exitcode.Name(code)
	if name == "" {
		name = "EDDInternal"
	}
	fmt.Fprintf(w, "ERROR: %s: %s\n", name, detail)
	return code
}

// printUsageBanner writes the subcommand index to w. Used directly
// by --help / -h (success path; w is stdout). The error-path wrapper
// printUsage prepends the "ERROR: EDDUsage:" header.
func printUsageBanner(w io.Writer) {
	fmt.Fprint(w,
		"  deaddrop keygen <out-path> [--passphrase-fd N | --passphrase-env VAR]\n"+
			"  deaddrop fingerprint [--capsule PATH] [--identity] [--passphrase-fd N | --passphrase-env VAR]\n"+
			"  deaddrop send <file> --relay URL [--deploy-secret-fd N] [--capsule PATH] [--write-token TOKEN] [--no-require-e2e] [--passcache=auto|none|keyutils|keychain] [--passcache-ttl SECONDS] [--forget-passcache]\n"+
			"  deaddrop recv [output] --relay URL [--deploy-secret-fd N] [--capsule PATH] [--no-require-e2e] [--watch] [--duration 1h] [--watch-interval 60s] [--passcache=auto|none|keyutils|keychain] [--passcache-ttl SECONDS] [--forget-passcache]\n"+
			"  deaddrop bootstrap --role={initiator|responder} --relay URL [--deploy-secret-fd N] [--capsule PATH] [--write-token TOKEN] [--no-require-e2e] [--passphrase-fd N | --passphrase-env VAR] [--timeout SECONDS]\n"+
			"  deaddrop rotate-capsule ... (not yet implemented)\n")
}

// printUsage writes the error-path header followed by the subcommand
// index to w. The message format is stable — scripts may parse it.
func printUsage(w io.Writer) {
	fmt.Fprint(w, "ERROR: EDDUsage: deaddrop usage\n")
	printUsageBanner(w)
}

// resolveCapsulePath returns the capsule file path per D-31 priority:
// explicit --capsule flag > DEADDROP_CAPSULE env > $HOME/.deaddrop/capsule.
// os.UserHomeDir is preferred; on its failure the function falls
// back to $HOME to keep CI runners without a passwd entry working.
func resolveCapsulePath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv(envCapsulePath); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, defaultCapsuleRelPath)
}

// resolvePassphraseReader picks the reader based on flags. --passphrase-fd
// and --passphrase-env are mutually exclusive; a default TTY reader
// is returned when neither is set.
func resolvePassphraseReader(fdFlag int, envFlag string, stderr io.Writer) (passphrase.Reader, error) {
	if fdFlag >= 0 && envFlag != "" {
		return nil, errors.New("--passphrase-fd and --passphrase-env are mutually exclusive")
	}
	if fdFlag >= 0 {
		return passphrase.FDReader{FD: fdFlag}, nil
	}
	if envFlag != "" {
		return passphrase.EnvReader{VarName: envFlag, Stderr: stderr}, nil
	}
	return passphrase.TTYReader{}, nil
}

// resolveDeploySecret implements the precedence used by every
// deploy-secret-reading client subcommand: --deploy-secret-fd >
// $DEADDROP_DEPLOY_SECRET. The argv --deploy-secret flag was removed
// in v0.2.0 (D-72); the pre-dispatch scan in run() rejects it with
// a migration message before this function is reached.
//
// fdFlag < 0 means "fd not set". envValue is the captured os.Getenv
// at FlagSet construction time.
func resolveDeploySecret(fdFlag int, envValue string, stderr io.Writer) (string, error) {
	if fdFlag >= 0 {
		s, err := fdread.ReadString(fdFlag, "--deploy-secret-fd")
		if err != nil {
			return "", err
		}
		if envValue != "" {
			fmt.Fprintln(stderr, "WARNING: --deploy-secret-fd takes precedence over $DEADDROP_DEPLOY_SECRET")
		}
		return s, nil
	}
	if envValue != "" {
		return envValue, nil
	}
	return "", nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
