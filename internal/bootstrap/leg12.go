// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/rand"

	"github.com/nmicic/deaddrop/internal/crypto"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/wire"
)

const (
	DirInitiatorToResponder byte = 0x00
	DirResponderToInitiator byte = 0x01
)

const (
	Leg12Version   = wire.VersionBootLeg12
	Leg12PlainSize = 32
	Leg12NonceSize = crypto.NonceSize
	Leg12TagSize   = crypto.TagSize
	Leg12BodySize  = 1 + 24 + 32 + 16 // 73
)

type Leg12Error struct {
	Code   int
	Detail string
}

func (e *Leg12Error) Error() string { return e.Detail }

func leg12AD(serviceID, slotID []byte, direction byte) []byte {
	ad := make([]byte, 0, 39)
	ad = append(ad, serviceID...)
	ad = append(ad, slotID...)
	ad = append(ad, Leg12Version)
	ad = append(ad, direction)
	ad = append(ad, "leg12"...)
	return ad
}

func SealLeg12(legKey, serviceID, slotID []byte, direction byte, pubkey [32]byte) ([]byte, error) {
	ad := leg12AD(serviceID, slotID, direction)

	nonce := make([]byte, Leg12NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ct, err := crypto.Seal(legKey, nonce, pubkey[:], ad)
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, Leg12BodySize)
	body = append(body, Leg12Version)
	body = append(body, nonce...)
	body = append(body, ct...)

	if len(body) != Leg12BodySize {
		panic("leg12: body size invariant violated")
	}
	return body, nil
}

func OpenLeg12(legKey, serviceID, slotID []byte, direction byte, body []byte) ([32]byte, error) {
	var pk [32]byte

	if direction != DirInitiatorToResponder && direction != DirResponderToInitiator {
		return pk, &Leg12Error{Code: exitcode.CryptoLocal, Detail: "reserved-direction-codepoint"}
	}

	if len(body) != Leg12BodySize {
		return pk, &Leg12Error{Code: exitcode.CryptoLocal, Detail: "body too short"}
	}

	if body[0] != Leg12Version {
		return pk, &Leg12Error{Code: exitcode.CryptoLocal, Detail: "version mismatch"}
	}

	nonce := body[1:25]
	ctWithTag := body[25:]

	ad := leg12AD(serviceID, slotID, direction)

	plaintext, err := crypto.Open(legKey, nonce, ctWithTag, ad)
	if err != nil {
		return pk, &Leg12Error{Code: exitcode.BootstrapAuth, Detail: "aead open failed"}
	}

	if len(plaintext) != 32 {
		return pk, &Leg12Error{Code: exitcode.CryptoLocal, Detail: "leg12-plaintext-length"}
	}

	copy(pk[:], plaintext)

	if IsLowOrderPoint(pk) {
		return pk, &Leg12Error{Code: exitcode.BootstrapAuth, Detail: "pubkey-invalid"}
	}

	return pk, nil
}
