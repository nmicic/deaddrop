// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package capsule

import (
	"bytes"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/nmicic/deaddrop/internal/crypto"
)

// Wrap encrypts psk and pairID under passphrase and returns a 109-byte
// capsule per SPEC_DRAFT_B_capsule.md §1. passphrase is taken as raw
// bytes; the caller is responsible for UTF-8 / NFC normalization.
//
// A fresh 16-byte argon2_salt and 24-byte nonce are drawn from
// crypto/rand on every call. The default Argon2id profile (§1.1) is
// used: m = 128 MiB, t = 3, p = 4. No strength or length validation is
// applied to the passphrase — that is a CLI-layer concern.
//
// The caller owns passphrase and psk. Wrap does not zeroize them; the
// passphrase_key derived internally is zeroized on every exit path.
func Wrap(passphrase, psk, pairID []byte) ([]byte, error) {
	if len(psk) != PSKSize {
		return nil, ErrBadPSKSize
	}
	if len(pairID) != PairIDSize {
		return nil, ErrBadPairIDSize
	}

	salt := make([]byte, Argon2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	params := defaultParamsBlock()

	passphraseKey := argon2.IDKey(
		passphrase, salt,
		DefaultTCost, 1<<DefaultMCostLog2, DefaultPCost,
		DefaultKeyLen,
	)
	defer zeroize(passphraseKey)

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0, PSKSize+PairIDSize)
	plaintext = append(plaintext, psk...)
	plaintext = append(plaintext, pairID...)
	defer zeroize(plaintext)

	capsuleAD := buildCapsuleAD(salt, params[:])

	ctWithTag, err := crypto.Seal(passphraseKey, nonce, plaintext, capsuleAD)
	if err != nil {
		return nil, err
	}
	if len(ctWithTag) != WrapCTSize+WrapTagSize {
		return nil, ErrDecrypt
	}

	out := make([]byte, CapsuleSize)
	copy(out[OffsetMagic:OffsetVersion], []byte(Magic))
	out[OffsetVersion] = Version
	copy(out[OffsetArgon2Salt:OffsetArgon2Params], salt)
	copy(out[OffsetArgon2Params:OffsetNonce], params[:])
	copy(out[OffsetNonce:OffsetWrapCT], nonce)
	copy(out[OffsetWrapCT:OffsetWrapTag], ctWithTag[:WrapCTSize])
	copy(out[OffsetWrapTag:CapsuleSize], ctWithTag[WrapCTSize:])
	return out, nil
}

// Unwrap parses a 109-byte capsule and returns (psk, pairID) on
// successful authenticated decryption under passphrase.
//
// Structural failures (wrong size, bad magic, bad version, param
// violations) return specific errors before any Argon2id derivation is
// attempted; they are not timing-sensitive. Authenticated-decryption
// failure — wrong passphrase, tampered ciphertext, tampered AD —
// returns ErrDecrypt with no further detail (no oracle).
func Unwrap(passphrase, capsule []byte) (psk, pairID []byte, err error) {
	if len(capsule) != CapsuleSize {
		return nil, nil, ErrBadSize
	}
	if !bytes.Equal(capsule[OffsetMagic:OffsetVersion], []byte(Magic)) {
		return nil, nil, ErrBadMagic
	}
	if capsule[OffsetVersion] != Version {
		return nil, nil, ErrBadVersion
	}

	var params [Argon2ParamsSize]byte
	copy(params[:], capsule[OffsetArgon2Params:OffsetNonce])
	if err := ValidateParams(params); err != nil {
		return nil, nil, err
	}

	tCost := uint32(params[paramOffTCost])
	mCost := uint32(1) << params[paramOffMCostLog2]
	pCost := params[paramOffPCost]
	keyLen := uint32(params[paramOffKeyLen])

	salt := capsule[OffsetArgon2Salt:OffsetArgon2Params]

	passphraseKey := argon2.IDKey(passphrase, salt, tCost, mCost, pCost, keyLen)
	defer zeroize(passphraseKey)

	nonce := capsule[OffsetNonce:OffsetWrapCT]

	ctWithTag := make([]byte, WrapCTSize+WrapTagSize)
	copy(ctWithTag[:WrapCTSize], capsule[OffsetWrapCT:OffsetWrapTag])
	copy(ctWithTag[WrapCTSize:], capsule[OffsetWrapTag:CapsuleSize])

	capsuleAD := capsule[OffsetMagic:OffsetNonce]

	plaintext, err := crypto.Open(passphraseKey, nonce, ctWithTag, capsuleAD)
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	defer zeroize(plaintext)

	if len(plaintext) != PSKSize+PairIDSize {
		return nil, nil, ErrDecrypt
	}

	psk = make([]byte, PSKSize)
	pairID = make([]byte, PairIDSize)
	copy(psk, plaintext[:PSKSize])
	copy(pairID, plaintext[PSKSize:])
	return psk, pairID, nil
}

// defaultParamsBlock returns the 8-byte argon2_params block populated
// with the §1.1 normative default profile.
func defaultParamsBlock() [Argon2ParamsSize]byte {
	var p [Argon2ParamsSize]byte
	p[paramOffKDFVersion] = DefaultKDFVersion
	p[paramOffMCostLog2] = DefaultMCostLog2
	p[paramOffTCost] = DefaultTCost
	p[paramOffPCost] = DefaultPCost
	p[paramOffKeyLen] = DefaultKeyLen
	p[paramOffSaltLen] = DefaultSaltLen
	// reserved bytes default-zero.
	return p
}

// buildCapsuleAD returns capsule_AD per §1.4: magic || version ||
// argon2_salt || argon2_params. The returned slice is a fresh
// allocation; callers may retain references without aliasing into
// the capsule buffer.
func buildCapsuleAD(salt, params []byte) []byte {
	ad := make([]byte, 0, MagicSize+VersionSize+Argon2SaltSize+Argon2ParamsSize)
	ad = append(ad, []byte(Magic)...)
	ad = append(ad, Version)
	ad = append(ad, salt...)
	ad = append(ad, params...)
	return ad
}

// zeroize overwrites b in place with zeros. Used via defer for
// passphrase_key and plaintext-buffer cleanup on every exit path,
// including panic. This is best-effort: compiler/runtime may keep
// earlier register copies that we cannot reach through the public API.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
