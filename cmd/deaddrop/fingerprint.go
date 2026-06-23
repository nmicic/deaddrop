// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nmicic/deaddrop/internal/bootstrap"
	"github.com/nmicic/deaddrop/internal/capsule"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/identitystore"
)

// runFingerprint implements `deaddrop fingerprint`. It resolves the
// capsule path per D-31 priority, reads the passphrase once (no
// confirm — this is a read-only operation), unwraps the capsule, and
// prints the 32-char lowercase hex fingerprint to stdout.
func runFingerprint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	capsuleFlag := fs.String("capsule", "", "Capsule file path (defaults to $DEADDROP_CAPSULE or ~/.deaddrop/capsule)")
	fdFlag := fs.Int("passphrase-fd", -1, "Read passphrase from this file descriptor")
	envFlag := fs.String("passphrase-env", "", "Read passphrase from this environment variable")
	identityFlag := fs.Bool("identity", false, "Print the pairing fingerprint (PSK || PairID || initPK || respPK) using the local identity entry (D-67)")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}

	path := resolveCapsulePath(*capsuleFlag)
	info, err := os.Stat(path)
	if err != nil {
		return exitError(stderr, exitcode.Usage, "capsule not found: "+path)
	}
	if info.Size() != int64(capsule.CapsuleSize) {
		return exitError(stderr, exitcode.CapsuleUnwrap,
			fmt.Sprintf("capsule size %d is not %d", info.Size(), capsule.CapsuleSize))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return exitError(stderr, exitcode.Internal, "reading capsule: "+err.Error())
	}

	reader, err := resolvePassphraseReader(*fdFlag, *envFlag, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	pw, err := reader.ReadPassphrase("Passphrase: ")
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	defer zeroize(pw)

	psk, pairID, err := capsule.Unwrap(pw, data)
	if err != nil {
		code, detail := classifyUnwrapError(err)
		return exitError(stderr, code, detail)
	}
	defer zeroize(psk)
	defer zeroize(pairID)

	if *identityFlag {
		// D-67: pairing fingerprint mode. Resolve the identity entry,
		// reconstruct (initiatorPK, responderPK) order from the
		// stored Role byte, and print the canonical 32-char hex with
		// 6-6-6-6-8 spacing produced by FormatPairingFPR.
		idStore, idErr := newIdentityStore()
		if idErr != nil {
			if errors.Is(idErr, identitystore.ErrUnsupported) {
				return exitError(stderr, exitcode.PlatformUnsupported,
					"--identity requested but no identity store backend is available on this OS")
			}
			return exitError(stderr, exitcode.IdentityStore, idErr.Error())
		}
		var pairIDArr [8]byte
		copy(pairIDArr[:], pairID)
		entry, getErr := idStore.Get(pairIDArr)
		if getErr != nil {
			if errors.Is(getErr, identitystore.ErrMiss) {
				return exitError(stderr, exitcode.IdentityMiss,
					"no identity entry for this pair (rebootstrap to enable E2E)")
			}
			return exitError(stderr, exitcode.IdentityStore, getErr.Error())
		}
		var initPK, respPK [32]byte
		switch entry.Role {
		case identitystore.RoleInitiator:
			initPK = entry.OwnPK
			respPK = entry.PeerPK
		case identitystore.RoleResponder:
			initPK = entry.PeerPK
			respPK = entry.OwnPK
		default:
			zeroize(entry.OwnSK[:])
			return exitError(stderr, exitcode.IdentityStore, "corrupt identity entry: bad role byte")
		}
		var pskArr [32]byte
		copy(pskArr[:], psk)
		fpr, err := bootstrap.PairingFingerprint(pskArr, pairIDArr, initPK, respPK)
		zeroize(entry.OwnSK[:])
		zeroize(entry.OwnPK[:])
		zeroize(entry.PeerPK[:])
		if err != nil {
			return exitError(stderr, exitcode.CryptoLocal, "pairing fingerprint computation failed")
		}
		fmt.Fprintln(stdout, bootstrap.FormatPairingFPR(fpr))
		return exitcode.OK
	}

	fp, err := capsule.Fingerprint(psk, pairID)
	if err != nil {
		return exitError(stderr, exitcode.CryptoLocal, "fingerprint computation failed")
	}
	fmt.Fprintln(stdout, hex.EncodeToString(fp))
	return exitcode.OK
}
