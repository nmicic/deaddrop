// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/passphrase"
)

// runKeygen implements `deaddrop keygen <out-path>`. It generates a
// random PSK and pair_id, asks for a passphrase (with confirm),
// wraps the capsule, and writes the 109-byte file with mode 0600.
// The capsule fingerprint is printed on stdout so the user can read
// it aloud during pairing (SPEC_DRAFT_B_capsule.md §1.6).
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fdFlag := fs.Int("passphrase-fd", -1, "Read passphrase from this file descriptor")
	envFlag := fs.String("passphrase-env", "", "Read passphrase from this environment variable")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}

	positional := fs.Args()
	if len(positional) != 1 {
		return exitError(stderr, exitcode.Usage, "keygen requires exactly one <out-path> argument")
	}
	outPath := positional[0]

	if _, err := os.Stat(outPath); err == nil {
		return exitError(stderr, exitcode.Usage,
			"output file already exists: "+outPath+" (use rotate-capsule to change passphrase)")
	}

	reader, err := resolvePassphraseReader(*fdFlag, *envFlag, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}

	pw, err := passphrase.ReadPassphraseConfirm(reader)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	defer zeroize(pw)

	psk := make([]byte, capsule.PSKSize)
	if _, err := rand.Read(psk); err != nil {
		return exitError(stderr, exitcode.CryptoLocal, "generating PSK: "+err.Error())
	}
	defer zeroize(psk)

	pairID := make([]byte, capsule.PairIDSize)
	if _, err := rand.Read(pairID); err != nil {
		return exitError(stderr, exitcode.CryptoLocal, "generating pair_id: "+err.Error())
	}
	defer zeroize(pairID)

	cap, err := capsule.Wrap(pw, psk, pairID)
	if err != nil {
		return exitError(stderr, exitcode.CryptoLocal, "wrap: "+err.Error())
	}

	if err := os.WriteFile(outPath, cap, 0o600); err != nil {
		return exitError(stderr, exitcode.Internal, "writing capsule: "+err.Error())
	}
	// Belt-and-suspenders: some umasks / filesystems may drop the
	// mode bits on WriteFile. An explicit Chmod guarantees 0600.
	if err := os.Chmod(outPath, 0o600); err != nil {
		return exitError(stderr, exitcode.Internal, "chmod capsule: "+err.Error())
	}

	fp, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		return exitError(stderr, exitcode.CryptoLocal, "fingerprint computation failed")
	}
	fmt.Fprintln(stdout, hex.EncodeToString(fp))
	return exitcode.OK
}

// zeroize overwrites b in place. Best-effort; the compiler may retain
// copies in registers or stack frames outside the public API.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
