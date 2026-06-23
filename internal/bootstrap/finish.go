// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/nmicic/deaddrop/internal/identitystore"
	"github.com/nmicic/deaddrop/internal/passphrase"
)

var ErrFingerprintAbort = errors.New("bootstrap: fingerprint confirmation abandoned")

// roleByteFor maps the in-process Role enum to the canonical
// identitystore.Role byte (D-64 Role-byte serialization).
func roleByteFor(r Role) byte {
	if r == Responder {
		return identitystore.RoleResponder
	}
	return identitystore.RoleInitiator
}

// FinishBootstrap completes the bootstrap flow: prints the pairing
// fingerprint, prompts for the at-rest capsule passphrase P_B,
// writes the capsule, and persists the per-pair identity entry into
// s.IdentityStore (D-65 work item). On success it emits a Linux-only
// note about the session-keyring lifetime and returns nil.
//
// Half-written behavior (capsule on disk, identity-store write
// fails) is surfaced with a clear "rebootstrap to recover" message;
// see the risk-surface section of the slice spec.
func FinishBootstrap(
	s *State,
	psk [32]byte,
	pairID [8]byte,
	initiatorPK, responderPK [32]byte,
	enterReader io.Reader,
	pbReader passphrase.Reader,
	stdout io.Writer,
	capsulePath string,
) error {
	fpr, err := PairingFingerprint(psk, pairID, initiatorPK, responderPK)
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "bootstrap complete — compare fingerprint OOB before proceeding:")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  pairing fingerprint:  "+FormatPairingFPR(fpr))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "both operators: read this to each other now. If the two sides see")
	fmt.Fprintln(stdout, "different fingerprints, bootstrap was MITM'd — Ctrl-C out and rerun")
	fmt.Fprintln(stdout, "with a fresh P_A.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "press ENTER to continue to local capsule passphrase prompt, or")
	fmt.Fprintln(stdout, "Ctrl-C to abort (nothing has been written to disk yet).")

	_, err = bufio.NewReader(enterReader).ReadString('\n')
	if err != nil {
		return ErrFingerprintAbort
	}

	var pb []byte
	for {
		pb, err = pbReader.ReadPassphrase("At-rest capsule passphrase (P_B): ")
		if err != nil {
			zeroize(pb)
			return err
		}
		reuse, err := CheckPBNotPA(s.PassphraseKey, pb)
		if err != nil {
			zeroize(pb)
			return err
		}
		if reuse {
			zeroize(pb)
			fmt.Fprintln(stdout, "P_B must differ from P_A — try again:")
			continue
		}
		defer zeroize(pb)
		break
	}

	if err := WriteCapsule(capsulePath, psk, pairID, pb); err != nil {
		return err
	}

	// Persist identity entry for this pair. Capsule already on disk;
	// if this fails the operator must rebootstrap. The pair is
	// usable in legacy mode but cannot do E2E until that happens.
	// s.IdentityStore is guaranteed non-nil by the bootstrap CLI
	// (D-61) — either New() succeeded or Noop() was substituted.
	if s.IdentityStore != nil {
		entry := &identitystore.Entry{
			Role:   roleByteFor(s.Role),
			OwnSK:  s.IdentitySK,
			OwnPK:  s.IdentityPK,
			PeerPK: s.PeerPK,
		}
		// Zero the in-memory copies once the keyring has accepted
		// the entry. ZeroizeBootstrap (called at CLI return) does
		// NOT touch these fields after the D-65 split.
		defer func() {
			zeroize(entry.OwnSK[:])
			zeroize(entry.OwnPK[:])
			zeroize(entry.PeerPK[:])
			s.ZeroizeIdentity()
		}()

		if err := s.IdentityStore.Put(pairID, entry); err != nil {
			return fmt.Errorf(
				"identity store write failed (capsule was written; rebootstrap to recover): %w",
				err,
			)
		}

		if runtime.GOOS == "linux" {
			fmt.Fprintln(stdout,
				"note: identity is stored in the UID-scoped Linux persistent "+
					"keyring (D-69); it survives logout and is wiped on reboot. "+
					"On kernels without CONFIG_PERSISTENT_KEYRINGS the store falls "+
					"back to the session keyring and a WARN is printed at first use.")
		}
	}

	return nil
}
