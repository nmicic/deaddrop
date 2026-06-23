// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"

	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/slot"
	"github.com/nmicic/deaddrop/internal/wire"
)

const (
	Leg3Version   = wire.VersionBootLeg3
	Leg3EphPKSize = 32
	Leg3PlainSize = 40 // pair_id(8) + PSK(32)
	Leg3NonceSize = crypto.NonceSize
	Leg3TagSize   = crypto.TagSize
	Leg3BodySize  = 1 + 32 + 24 + 40 + 16 // 113
)

type Leg3Error struct {
	Code   int
	Detail string
}

func (e *Leg3Error) Error() string { return e.Detail }

func GenerateEphemeral() (sk, pk [32]byte, err error) {
	if _, err = rand.Read(sk[:]); err != nil {
		return sk, pk, err
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	if IsLowOrderPoint(pk) {
		return sk, pk, &Leg3Error{Code: exitcode.CryptoLocal, Detail: "generated low-order pubkey"}
	}
	return sk, pk, nil
}

func Leg3SlotRoot(initiatorPK, responderPK [32]byte) ([]byte, error) {
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, initiatorPK[:]...)
	ikm = append(ikm, responderPK[:]...)
	return crypto.DeriveKey(ikm, nil, []byte("deaddrop-bootstrap-leg3"), 32)
}

func Leg3SlotID(leg3Root []byte, b uint64) ([]byte, error) {
	return slot.SlotID(leg3Root, b, 0)
}

func DeriveBodyKey(ephSK, peerPK, ownSK, initiatorPK, responderPK [32]byte) ([]byte, error) {
	dhEph, errEph := curve25519.X25519(ephSK[:], peerPK[:])
	dhStatic, errStatic := curve25519.X25519(ownSK[:], peerPK[:])
	return finishDeriveBodyKey(dhEph, errEph, dhStatic, errStatic, initiatorPK, responderPK)
}

func DeriveBodyKeyFromEphPK(ephPK, peerPK, ownSK, initiatorPK, responderPK [32]byte) ([]byte, error) {
	dhEph, errEph := curve25519.X25519(ownSK[:], ephPK[:])
	dhStatic, errStatic := curve25519.X25519(ownSK[:], peerPK[:])
	return finishDeriveBodyKey(dhEph, errEph, dhStatic, errStatic, initiatorPK, responderPK)
}

func finishDeriveBodyKey(dhEph []byte, errEph error, dhStatic []byte, errStatic error, initiatorPK, responderPK [32]byte) ([]byte, error) {
	defer func() {
		if dhEph != nil {
			zeroize(dhEph)
		}
		if dhStatic != nil {
			zeroize(dhStatic)
		}
	}()

	// X25519 returns an error precisely when the DH output would be the
	// all-zero value (low-order point). Map either failure to dh-zero.
	if errEph != nil || errStatic != nil {
		return nil, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "dh-zero"}
	}
	if crypto.IsAllZero(dhEph) || crypto.IsAllZero(dhStatic) {
		return nil, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "dh-zero"}
	}

	ikm := make([]byte, 0, 64)
	ikm = append(ikm, dhEph...)
	ikm = append(ikm, dhStatic...)
	defer zeroize(ikm)

	info := make([]byte, 0, len("deaddrop-bootstrap-leg3-body")+64)
	info = append(info, []byte("deaddrop-bootstrap-leg3-body")...)
	info = append(info, initiatorPK[:]...)
	info = append(info, responderPK[:]...)

	return crypto.DeriveKey(ikm, nil, info, 32)
}

func leg3AD(serviceID, leg3SlotID []byte, ephPK [32]byte) []byte {
	ad := make([]byte, 0, 69)
	ad = append(ad, serviceID...)
	ad = append(ad, leg3SlotID...)
	ad = append(ad, Leg3Version)
	ad = append(ad, ephPK[:]...)
	ad = append(ad, "leg3"...)
	return ad
}

func SealLeg3(bodyKey, serviceID, leg3SlotID []byte, ephPK [32]byte, pairID [8]byte, psk [32]byte) ([]byte, error) {
	plaintext := make([]byte, 0, Leg3PlainSize)
	plaintext = append(plaintext, pairID[:]...)
	plaintext = append(plaintext, psk[:]...)

	ad := leg3AD(serviceID, leg3SlotID, ephPK)

	nonce := make([]byte, Leg3NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ct, err := crypto.Seal(bodyKey, nonce, plaintext, ad)
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, Leg3BodySize)
	body = append(body, Leg3Version)
	body = append(body, ephPK[:]...)
	body = append(body, nonce...)
	body = append(body, ct...)

	if len(body) != Leg3BodySize {
		panic("leg3: body size invariant violated")
	}
	return body, nil
}

func OpenLeg3(bodyKey, serviceID, leg3SlotID []byte, ephPK [32]byte, body []byte) (pairID [8]byte, psk [32]byte, err error) {
	if len(body) != Leg3BodySize {
		return pairID, psk, &Leg3Error{Code: exitcode.CryptoLocal, Detail: "body too short"}
	}
	if body[0] != Leg3Version {
		return pairID, psk, &Leg3Error{Code: exitcode.CryptoLocal, Detail: "version mismatch"}
	}

	var bodyEphPK [32]byte
	copy(bodyEphPK[:], body[1:33])

	if IsLowOrderPoint(bodyEphPK) {
		return pairID, psk, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "eph-pk-invalid"}
	}
	if bodyEphPK != ephPK {
		return pairID, psk, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "eph-pk-mismatch"}
	}

	nonce := body[33:57]
	ctWithTag := body[57:]

	ad := leg3AD(serviceID, leg3SlotID, ephPK)

	plaintext, err := crypto.Open(bodyKey, nonce, ctWithTag, ad)
	if err != nil {
		return pairID, psk, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "aead open failed"}
	}

	if len(plaintext) != Leg3PlainSize {
		return pairID, psk, &Leg3Error{Code: exitcode.BootstrapMITM, Detail: "leg3-plaintext-length"}
	}

	copy(pairID[:], plaintext[0:8])
	copy(psk[:], plaintext[8:40])
	return pairID, psk, nil
}
