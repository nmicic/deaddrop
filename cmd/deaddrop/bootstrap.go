// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/nmicic/deaddrop/internal/bootstrap"
	"github.com/nmicic/deaddrop/internal/exitcode"
	"github.com/nmicic/deaddrop/internal/identitystore"
	"github.com/nmicic/deaddrop/internal/secretparse"
	"github.com/nmicic/deaddrop/internal/slot"
)

var bootstrapEnterReader io.Reader = os.Stdin

type bootstrapError struct {
	code   int
	detail string
}

func (e *bootstrapError) Error() string { return e.detail }

func postLeg(
	ctx context.Context,
	httpClient *http.Client,
	relayURL, writeToken string,
	serviceID, slotID []byte,
	body []byte,
) error {
	url := relayURL + "/" + hex.EncodeToString(serviceID) + "/" + hex.EncodeToString(slotID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &bootstrapError{code: exitcode.RelayUnreachable, detail: err.Error()}
	}
	if writeToken != "" {
		req.Header.Set("X-DeadDrop-Write", writeToken)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
		return &bootstrapError{code: exitcode.RelayUnreachable, detail: err.Error()}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 201:
		return nil
	case 409:
		return &bootstrapError{code: exitcode.Collision, detail: "slot collision (409)"}
	case 401, 403:
		return &bootstrapError{code: exitcode.Auth, detail: "relay rejected write token"}
	case 429, 503:
		return &bootstrapError{code: exitcode.RelayOverloaded, detail: "relay overloaded"}
	default:
		return &bootstrapError{code: exitcode.RelayUnreachable, detail: "unexpected status: " + strconv.Itoa(resp.StatusCode)}
	}
}

func pollLeg(
	ctx context.Context,
	httpClient *http.Client,
	relayURL string,
	serviceID []byte,
	slotIDFunc func(b uint64) ([]byte, error),
	clock func() time.Time,
	pollInterval time.Duration,
) (body []byte, foundBucket uint64, err error) {
	for {
		if ctx.Err() != nil {
			return nil, 0, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
		now := clock()
		bNow := uint64(now.Unix()) / 60
		for _, b := range []uint64{bNow, bNow - 1, bNow - 2} {
			sid, sErr := slotIDFunc(b)
			if sErr != nil {
				return nil, 0, sErr
			}
			url := relayURL + "/" + hex.EncodeToString(serviceID) + "/" + hex.EncodeToString(sid)
			req, rErr := http.NewRequestWithContext(ctx, "GET", url, nil)
			if rErr != nil {
				return nil, 0, &bootstrapError{code: exitcode.RelayUnreachable, detail: rErr.Error()}
			}
			// D-45: GET MUST NOT carry the write-token.
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				if ctx.Err() != nil {
					return nil, 0, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
				}
				return nil, 0, &bootstrapError{code: exitcode.RelayUnreachable, detail: doErr.Error()}
			}
			switch resp.StatusCode {
			case 200:
				data, rdErr := io.ReadAll(io.LimitReader(resp.Body, 256))
				resp.Body.Close()
				if rdErr != nil {
					return nil, 0, &bootstrapError{code: exitcode.RelayUnreachable, detail: rdErr.Error()}
				}
				return data, b, nil
			case 404:
				resp.Body.Close()
			case 401, 403:
				resp.Body.Close()
				return nil, 0, &bootstrapError{code: exitcode.Auth, detail: "relay rejected write token"}
			case 429, 503:
				resp.Body.Close()
				return nil, 0, &bootstrapError{code: exitcode.RelayOverloaded, detail: "relay overloaded"}
			default:
				resp.Body.Close()
				return nil, 0, &bootstrapError{code: exitcode.RelayUnreachable, detail: "unexpected status: " + strconv.Itoa(resp.StatusCode)}
			}
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return nil, 0, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
	}
}

func initiatorBootstrap(
	ctx context.Context,
	s *bootstrap.State,
	httpClient *http.Client,
	relayURL, writeToken string,
	deploySecret []byte,
	clock func() time.Time,
) (psk [32]byte, pairID [8]byte, responderPK [32]byte, err error) {
	legKey, err := bootstrap.LegKey(s.PassphraseKey, bootstrap.DirInitiatorToResponder)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	defer zeroize(legKey)
	slotKey, err := bootstrap.LegSlotKey(s.PassphraseKey, bootstrap.DirInitiatorToResponder)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	now := clock()
	b := uint64(now.Unix()) / 60
	h := uint64(now.Unix()) / 3600
	serviceID, err := slot.ServiceID(deploySecret, h)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	slotID, err := bootstrap.LegSlotID(slotKey, b)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	body, err := bootstrap.SealLeg12(legKey, serviceID, slotID, bootstrap.DirInitiatorToResponder, s.IdentityPK)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}

	if err := postLeg(ctx, httpClient, relayURL, writeToken, serviceID, slotID, body); err != nil {
		return psk, pairID, responderPK, err
	}

	leg2SlotKey, err := bootstrap.LegSlotKey(s.PassphraseKey, bootstrap.DirResponderToInitiator)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}

	var leg2Body []byte
	var foundBucket uint64
	var foundServiceID []byte
	lastLeg1Post := clock()
	for {
		if ctx.Err() != nil {
			return psk, pairID, responderPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}

		if clock().Sub(lastLeg1Post) > 85*time.Second {
			nowR := clock()
			bR := uint64(nowR.Unix()) / 60
			hR := uint64(nowR.Unix()) / 3600
			serviceIDR, svcErr := slot.ServiceID(deploySecret, hR)
			if svcErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: svcErr.Error()}
			}
			slotIDR, sErr := bootstrap.LegSlotID(slotKey, bR)
			if sErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: sErr.Error()}
			}
			legKeyR, lErr := bootstrap.LegKey(s.PassphraseKey, bootstrap.DirInitiatorToResponder)
			if lErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: lErr.Error()}
			}
			bodyR, bErr := bootstrap.SealLeg12(legKeyR, serviceIDR, slotIDR, bootstrap.DirInitiatorToResponder, s.IdentityPK)
			zeroize(legKeyR)
			if bErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: bErr.Error()}
			}
			if pErr := postLeg(ctx, httpClient, relayURL, writeToken, serviceIDR, slotIDR, bodyR); pErr != nil {
				var be *bootstrapError
				if errors.As(pErr, &be) && be.code == exitcode.Collision {
					// ignore 409 on re-POST
				} else {
					return psk, pairID, responderPK, pErr
				}
			}
			lastLeg1Post = clock()
		}

		nowP := clock()
		bNow := uint64(nowP.Unix()) / 60
		found := false
		for _, bCand := range []uint64{bNow, bNow - 1, bNow - 2} {
			hCand := (bCand * 60) / 3600
			svcID, svcErr := slot.ServiceID(deploySecret, hCand)
			if svcErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: svcErr.Error()}
			}
			leg2SlotID, sErr := bootstrap.LegSlotID(leg2SlotKey, bCand)
			if sErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: sErr.Error()}
			}
			url := relayURL + "/" + hex.EncodeToString(svcID) + "/" + hex.EncodeToString(leg2SlotID)
			req, rErr := http.NewRequestWithContext(ctx, "GET", url, nil)
			if rErr != nil {
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: rErr.Error()}
			}
			// D-45: GET MUST NOT carry the write-token.
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				if ctx.Err() != nil {
					return psk, pairID, responderPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
				}
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: doErr.Error()}
			}
			switch resp.StatusCode {
			case 200:
				data, rdErr := io.ReadAll(io.LimitReader(resp.Body, 256))
				resp.Body.Close()
				if rdErr != nil {
					return psk, pairID, responderPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: rdErr.Error()}
				}
				leg2Body = data
				foundBucket = bCand
				foundServiceID = svcID
				found = true
			case 404:
				resp.Body.Close()
			case 401, 403:
				resp.Body.Close()
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.Auth, detail: "relay rejected write token"}
			case 429, 503:
				resp.Body.Close()
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.RelayOverloaded, detail: "relay overloaded"}
			default:
				resp.Body.Close()
				return psk, pairID, responderPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: "unexpected status: " + strconv.Itoa(resp.StatusCode)}
			}
			if found {
				break
			}
		}
		if found {
			break
		}

		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return psk, pairID, responderPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
	}

	zeroize(slotKey)

	leg2Key, err := bootstrap.LegKey(s.PassphraseKey, bootstrap.DirResponderToInitiator)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg2SlotID, err := bootstrap.LegSlotID(leg2SlotKey, foundBucket)
	if err != nil {
		zeroize(leg2Key)
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	peerPK, err := bootstrap.OpenLeg12(leg2Key, foundServiceID, leg2SlotID, bootstrap.DirResponderToInitiator, leg2Body)
	zeroize(leg2Key)
	zeroize(leg2SlotKey)
	if err != nil {
		var le *bootstrap.Leg12Error
		if errors.As(err, &le) {
			return psk, pairID, responderPK, &bootstrapError{code: le.Code, detail: le.Detail}
		}
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	responderPK = peerPK

	leg3Root, err := bootstrap.Leg3SlotRoot(s.IdentityPK, responderPK)
	if err != nil {
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg3SlotIDFunc := func(bk uint64) ([]byte, error) { return bootstrap.Leg3SlotID(leg3Root, bk) }
	leg3Body, leg3Bucket, err := pollLeg(ctx, httpClient, relayURL, foundServiceID, leg3SlotIDFunc, clock, 2*time.Second)
	if err != nil {
		zeroize(leg3Root)
		return psk, pairID, responderPK, err
	}

	if len(leg3Body) < bootstrap.Leg3BodySize {
		zeroize(leg3Root)
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: "leg3 body too short"}
	}
	var ephPK [32]byte
	copy(ephPK[:], leg3Body[1:33])
	bodyKey, err := bootstrap.DeriveBodyKeyFromEphPK(ephPK, responderPK, s.IdentitySK, s.IdentityPK, responderPK)
	if err != nil {
		zeroize(leg3Root)
		var le *bootstrap.Leg3Error
		if errors.As(err, &le) {
			return psk, pairID, responderPK, &bootstrapError{code: le.Code, detail: le.Detail}
		}
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg3SlotID, err := bootstrap.Leg3SlotID(leg3Root, leg3Bucket)
	zeroize(leg3Root)
	if err != nil {
		zeroize(bodyKey)
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	pairID, psk, err = bootstrap.OpenLeg3(bodyKey, foundServiceID, leg3SlotID, ephPK, leg3Body)
	zeroize(bodyKey)
	if err != nil {
		var le *bootstrap.Leg3Error
		if errors.As(err, &le) {
			return psk, pairID, responderPK, &bootstrapError{code: le.Code, detail: le.Detail}
		}
		return psk, pairID, responderPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}

	return psk, pairID, responderPK, nil
}

func responderBootstrap(
	ctx context.Context,
	s *bootstrap.State,
	httpClient *http.Client,
	relayURL, writeToken string,
	deploySecret []byte,
	clock func() time.Time,
) (psk [32]byte, pairID [8]byte, initiatorPK [32]byte, err error) {
	legSlotKey, err := bootstrap.LegSlotKey(s.PassphraseKey, bootstrap.DirInitiatorToResponder)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}

	var leg1Body []byte
	var foundBucket uint64
	for {
		if ctx.Err() != nil {
			return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
		now := clock()
		bNow := uint64(now.Unix()) / 60
		found := false
		for _, bCand := range []uint64{bNow, bNow - 1, bNow - 2} {
			hCand := (bCand * 60) / 3600
			svcID, sErr := slot.ServiceID(deploySecret, hCand)
			if sErr != nil {
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: sErr.Error()}
			}
			sid, slErr := bootstrap.LegSlotID(legSlotKey, bCand)
			if slErr != nil {
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: slErr.Error()}
			}
			url := relayURL + "/" + hex.EncodeToString(svcID) + "/" + hex.EncodeToString(sid)
			req, rErr := http.NewRequestWithContext(ctx, "GET", url, nil)
			if rErr != nil {
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: rErr.Error()}
			}
			// D-45: GET MUST NOT carry the write-token.
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				if ctx.Err() != nil {
					return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
				}
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: doErr.Error()}
			}
			switch resp.StatusCode {
			case 200:
				data, rdErr := io.ReadAll(io.LimitReader(resp.Body, 256))
				resp.Body.Close()
				if rdErr != nil {
					return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: rdErr.Error()}
				}
				leg1Body = data
				foundBucket = bCand
				found = true
			case 404:
				resp.Body.Close()
			case 401, 403:
				resp.Body.Close()
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.Auth, detail: "relay rejected write token"}
			case 429, 503:
				resp.Body.Close()
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.RelayOverloaded, detail: "relay overloaded"}
			default:
				resp.Body.Close()
				return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.RelayUnreachable, detail: "unexpected status: " + strconv.Itoa(resp.StatusCode)}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "timeout"}
		}
	}

	leg1Key, err := bootstrap.LegKey(s.PassphraseKey, bootstrap.DirInitiatorToResponder)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	hFound := (foundBucket * 60) / 3600
	serviceID, err := slot.ServiceID(deploySecret, hFound)
	if err != nil {
		zeroize(leg1Key)
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg1SlotID, err := bootstrap.LegSlotID(legSlotKey, foundBucket)
	if err != nil {
		zeroize(leg1Key)
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	peerPK, err := bootstrap.OpenLeg12(leg1Key, serviceID, leg1SlotID, bootstrap.DirInitiatorToResponder, leg1Body)
	zeroize(leg1Key)
	zeroize(legSlotKey)
	if err != nil {
		var le *bootstrap.Leg12Error
		if errors.As(err, &le) {
			return psk, pairID, initiatorPK, &bootstrapError{code: le.Code, detail: le.Detail}
		}
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	initiatorPK = peerPK

	ephSK, ephPK, err := bootstrap.GenerateEphemeral()
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	defer zeroize(ephSK[:])
	if _, err := rand.Read(psk[:]); err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	if _, err := rand.Read(pairID[:]); err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}

	nowPost := clock()
	bPost := uint64(nowPost.Unix()) / 60
	hPost := uint64(nowPost.Unix()) / 3600
	serviceIDPost, err := slot.ServiceID(deploySecret, hPost)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg2Key, err := bootstrap.LegKey(s.PassphraseKey, bootstrap.DirResponderToInitiator)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg2SlotKey, err := bootstrap.LegSlotKey(s.PassphraseKey, bootstrap.DirResponderToInitiator)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg2SlotID, err := bootstrap.LegSlotID(leg2SlotKey, bPost)
	if err != nil {
		zeroize(leg2Key)
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg2Body, err := bootstrap.SealLeg12(leg2Key, serviceIDPost, leg2SlotID, bootstrap.DirResponderToInitiator, s.IdentityPK)
	zeroize(leg2Key)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	if err := postLeg(ctx, httpClient, relayURL, writeToken, serviceIDPost, leg2SlotID, leg2Body); err != nil {
		zeroize(leg2SlotKey)
		var be *bootstrapError
		if errors.As(err, &be) && be.code == exitcode.Collision {
			return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "leg-2 slot collision"}
		}
		return psk, pairID, initiatorPK, err
	}
	zeroize(leg2SlotKey)

	bodyKey, err := bootstrap.DeriveBodyKey(ephSK, initiatorPK, s.IdentitySK, initiatorPK, s.IdentityPK)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg3Root, err := bootstrap.Leg3SlotRoot(initiatorPK, s.IdentityPK)
	if err != nil {
		zeroize(bodyKey)
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg3SlotID, err := bootstrap.Leg3SlotID(leg3Root, bPost)
	if err != nil {
		zeroize(bodyKey)
		zeroize(leg3Root)
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	leg3Body, err := bootstrap.SealLeg3(bodyKey, serviceIDPost, leg3SlotID, ephPK, pairID, psk)
	zeroize(bodyKey)
	zeroize(leg3Root)
	if err != nil {
		return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.CryptoLocal, detail: err.Error()}
	}
	if err := postLeg(ctx, httpClient, relayURL, writeToken, serviceIDPost, leg3SlotID, leg3Body); err != nil {
		var be *bootstrapError
		if errors.As(err, &be) && be.code == exitcode.Collision {
			return psk, pairID, initiatorPK, &bootstrapError{code: exitcode.BootstrapTimeout, detail: "leg-3 slot collision"}
		}
		return psk, pairID, initiatorPK, err
	}

	return psk, pairID, initiatorPK, nil
}

func runBootstrap(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)

	roleFlag := fs.String("role", "", "Role: initiator or responder")
	relayFlag := fs.String("relay", os.Getenv(envRelay), "Relay base URL (or $DEADDROP_RELAY)")
	envDeploy := os.Getenv(envDeploySecret)
	deploySecretFD := fs.Int("deploy-secret-fd", -1, "Read DEPLOY_SECRET from this file descriptor (precedence: -fd > env)")
	fdFlag := fs.Int("passphrase-fd", -1, "Read passphrase from this file descriptor")
	envFlag := fs.String("passphrase-env", "", "Read passphrase from this environment variable")
	timeoutFlag := fs.Int("timeout", 300, "Bootstrap timeout in seconds")
	keepKeys := fs.Bool("keep-keys", false, "")
	_ = fs.Bool("burn", false, "")
	capsuleFlag := fs.String("capsule", "", "Capsule output path")
	writeTokenFlag := fs.String("write-token", os.Getenv(envWriteToken), "Relay write token (or $DEADDROP_WRITE_TOKEN)")
	requireE2EFlag := fs.Bool("require-e2e", true, "Require the platform identity store to be available (default; pass --no-require-e2e to allow legacy fallback)")
	noRequireE2EFlag := fs.Bool("no-require-e2e", false, "Allow bootstrap without a persistent identity store (DEPRECATED — upgrade your platform)")

	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}

	// D-71: reject conflicting flags.
	requireE2EExplicit := false
	noRequireE2EExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "require-e2e" {
			requireE2EExplicit = true
		}
		if f.Name == "no-require-e2e" {
			noRequireE2EExplicit = true
		}
	})
	if requireE2EExplicit && noRequireE2EExplicit {
		return exitError(stderr, exitcode.Usage,
			"--require-e2e and --no-require-e2e are mutually exclusive")
	}
	if *noRequireE2EFlag {
		fmt.Fprintln(stderr, "WARNING: --no-require-e2e is deprecated; rebootstrap to enable E2E instead of disabling the safety check")
		*requireE2EFlag = false
	}

	if *keepKeys {
		return exitError(stderr, exitcode.Usage,
			"--keep-keys is not supported in v1; gated on agent-style identity-key protection — see FUTURE.md F-34")
	}

	if *roleFlag == "" {
		return exitError(stderr, exitcode.Usage, "missing required flag: --role")
	}
	if *roleFlag != "initiator" && *roleFlag != "responder" {
		return exitError(stderr, exitcode.Usage, "invalid --role: must be initiator or responder")
	}
	if *relayFlag == "" {
		return exitError(stderr, exitcode.Usage, "missing required flag: --relay (or set $DEADDROP_RELAY)")
	}

	deploySecretValue, err := resolveDeploySecret(*deploySecretFD, envDeploy, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	if deploySecretValue == "" {
		return exitError(stderr, exitcode.Usage, "--deploy-secret-fd or $DEADDROP_DEPLOY_SECRET is required")
	}

	dsBytes, err := secretparse.Parse("--deploy-secret", deploySecretValue)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}
	if len(dsBytes) < slot.MinDeploySecretLen {
		return exitError(stderr, exitcode.Usage, "--deploy-secret too short (minimum 32 bytes)")
	}

	pbFD := *fdFlag
	if *fdFlag >= 0 {
		var dupErr error
		pbFD, dupErr = syscall.Dup(*fdFlag)
		if dupErr != nil {
			return exitError(stderr, exitcode.Internal, "dup passphrase fd: "+dupErr.Error())
		}
		defer syscall.Close(pbFD)
	}

	reader, err := resolvePassphraseReader(*fdFlag, *envFlag, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}

	pa, err := reader.ReadPassphrase("Bootstrap passphrase (P_A): ")
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}

	passphraseKey := bootstrap.DerivePassphraseKey(pa)
	zeroize(pa)

	sk, pk, err := bootstrap.GenerateIdentity()
	if err != nil {
		zeroize(passphraseKey[:])
		return exitError(stderr, exitcode.CryptoLocal, err.Error())
	}

	roleEnum := bootstrap.Initiator
	if *roleFlag == "responder" {
		roleEnum = bootstrap.Responder
	}

	// D-61 / D-65: resolve the identity-store backend up front so we can
	// honour --require-e2e before any leg work happens. New() returns
	// ErrUnsupported on platforms without a Keychain / keyutils
	// implementation; we substitute Noop() unless the operator demanded
	// strict mode.
	idStore, idErr := newIdentityStore()
	if idErr != nil {
		if errors.Is(idErr, identitystore.ErrUnsupported) {
			if *requireE2EFlag {
				zeroize(passphraseKey)
				zeroize(sk[:])
				return exitError(stderr, exitcode.PlatformUnsupported,
					"--require-e2e was set but no identity store backend is available on this OS")
			}
			fmt.Fprintln(stderr, "WARN: no identity store backend available on this OS; bootstrap will proceed without persistent E2E identity (legacy 0x01 mode)")
			idStore = identitystore.Noop()
		} else {
			zeroize(passphraseKey)
			zeroize(sk[:])
			return exitError(stderr, exitcode.IdentityStore, idErr.Error())
		}
	}

	s := &bootstrap.State{
		IdentitySK:    sk,
		IdentityPK:    pk,
		PassphraseKey: passphraseKey,
		Role:          roleEnum,
		IdentityStore: idStore,
	}
	// D-65 split: ZeroizeBootstrap wipes only PassphraseKey.
	// FinishBootstrap zeros the identity fields (IdentitySK / IdentityPK
	// / PeerPK) in its own defer once the keyring accepts the entry —
	// but if any leg work errors before FinishBootstrap is reached,
	// those fields would leak. The catch-all defer below is idempotent:
	// in the success path it zeros already-zeroed memory.
	defer s.ZeroizeBootstrap()
	defer s.ZeroizeIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutFlag)*time.Second)
	defer cancel()

	httpClient := &http.Client{Timeout: 30 * time.Second}

	capsulePath := resolveCapsulePath(*capsuleFlag)

	pbReader, err := resolvePassphraseReader(pbFD, *envFlag, stderr)
	if err != nil {
		return exitError(stderr, exitcode.Usage, err.Error())
	}

	var pskVal [32]byte
	var pairIDVal [8]byte
	var peerPK [32]byte

	var writeTokenWire string
	if *writeTokenFlag != "" {
		wtBytes, wtErr := secretparse.Parse("--write-token", *writeTokenFlag)
		if wtErr != nil {
			return exitError(stderr, exitcode.Usage, wtErr.Error())
		}
		writeTokenWire = hex.EncodeToString(wtBytes)
	}

	switch *roleFlag {
	case "initiator":
		pskVal, pairIDVal, peerPK, err = initiatorBootstrap(
			ctx, s, httpClient, *relayFlag, writeTokenWire, dsBytes, time.Now,
		)
	case "responder":
		pskVal, pairIDVal, peerPK, err = responderBootstrap(
			ctx, s, httpClient, *relayFlag, writeTokenWire, dsBytes, time.Now,
		)
	}
	defer func() { pskVal = [32]byte{}; pairIDVal = [8]byte{} }()

	if err != nil {
		var be *bootstrapError
		if errors.As(err, &be) {
			return exitError(stderr, be.code, be.detail)
		}
		return exitError(stderr, exitcode.Internal, err.Error())
	}

	var initPK, respPK [32]byte
	if *roleFlag == "initiator" {
		initPK = s.IdentityPK
		respPK = peerPK
	} else {
		initPK = peerPK
		respPK = s.IdentityPK
	}
	// D-65: FinishBootstrap reads PeerPK off the state to construct
	// the identitystore.Entry. Set it now (the role-specific funcs
	// return it as a value but the State carries the canonical copy).
	s.PeerPK = peerPK

	if err := bootstrap.FinishBootstrap(
		s, pskVal, pairIDVal, initPK, respPK,
		bootstrapEnterReader, pbReader, stdout, capsulePath,
	); err != nil {
		if errors.Is(err, bootstrap.ErrFingerprintAbort) {
			return exitError(stderr, exitcode.Usage, "fingerprint confirmation abandoned")
		}
		var be *bootstrapError
		if errors.As(err, &be) {
			return exitError(stderr, be.code, be.detail)
		}
		return exitError(stderr, exitcode.Internal, err.Error())
	}

	return exitcode.OK
}
