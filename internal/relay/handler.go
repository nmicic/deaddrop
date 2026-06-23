// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nmicic/deaddrop/internal/clock"
	"github.com/nmicic/deaddrop/internal/slot"
)

// deleteHashSize is the byte width of X-DeadDrop-Delete-Hash (a
// SHA-256 digest). The handler accepts a hex-encoded string and
// decodes to exactly this length.
const deleteHashSize = 32

// Config carries the dependencies a Handler needs at startup. All
// fields are required except WriteToken (empty disables write-auth,
// intended for --local-only deployments), GetHook (test-only
// injection point), and MaxConcurrentGets (0 disables the semaphore
// gate, also for --local-only / tests).
type Config struct {
	Store             *Store
	DeploySecret      []byte
	WriteToken        []byte
	MaxBlobBytes      int64
	MaxConcurrentGets int
	Clock             clock.Clock
	// GetHook is called inside handleGet immediately after the
	// semaphore has been acquired (or unconditionally if no semaphore
	// is configured). Production wires nil. Tests use it to hold a
	// semaphore slot so a second GET observes the full state.
	GetHook func()
}

// Handler is the HTTP front for a Store. It is a concrete type per
// C-8 role-naming; there is no Handler interface.
type Handler struct {
	store         *Store
	deploySecret  []byte
	writeToken    []byte
	writeTokenHex string
	maxBlobBytes  int64
	clock         clock.Clock
	// getSem is a buffered channel whose capacity is the maximum
	// concurrent in-flight GETs. A non-blocking acquire (select /
	// default) in handleGet means that exceeding the gate rejects
	// instantly with 503 — no queueing, no latency amplification.
	// nil disables the gate (unlimited concurrency).
	getSem  chan struct{}
	getHook func()
}

// NewHandler returns a Handler configured from cfg. If
// cfg.MaxConcurrentGets > 0 a buffered semaphore of that size is
// allocated; otherwise the semaphore gate is disabled.
func NewHandler(cfg Config) *Handler {
	h := &Handler{
		store:         cfg.Store,
		deploySecret:  cfg.DeploySecret,
		writeToken:    cfg.WriteToken,
		writeTokenHex: hex.EncodeToString(cfg.WriteToken),
		maxBlobBytes:  cfg.MaxBlobBytes,
		clock:         cfg.Clock,
		getHook:       cfg.GetHook,
	}
	if cfg.MaxConcurrentGets > 0 {
		h.getSem = make(chan struct{}, cfg.MaxConcurrentGets)
	}
	return h
}

// ServeHTTP dispatches on path shape and method. Every path failure
// (shape, hex-decode, unknown method) funnels through the single
// uniform404 helper for D-14 byte-identical 404 responses.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	svc, slotID, ok := parsePath(r.URL.Path)
	if !ok {
		uniform404(w)
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r, svc, slotID)
	case http.MethodGet:
		h.handleGet(w, r, svc, slotID)
	case http.MethodDelete:
		h.handleDelete(w, r, svc, slotID)
	default:
		// PROTOCOL.md §3 classifies HEAD / PUT / everything-else as
		// "unrecognized method" → uniform 404.
		uniform404(w)
	}
}

// parsePath accepts exactly `/{32-hex}/{32-hex}` and returns the two
// decoded 16-byte values. Any deviation (too few / too many segments,
// wrong length, non-hex) fails closed with ok=false.
func parsePath(p string) (svc, slotID [16]byte, ok bool) {
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != "" {
		return svc, slotID, false
	}
	svcHex, slotHex := parts[1], parts[2]
	if len(svcHex) != 32 || len(slotHex) != 32 {
		return svc, slotID, false
	}
	svcBytes, err := hex.DecodeString(svcHex)
	if err != nil {
		return svc, slotID, false
	}
	slotBytes, err := hex.DecodeString(slotHex)
	if err != nil {
		return svc, slotID, false
	}
	copy(svc[:], svcBytes)
	copy(slotID[:], slotBytes)
	return svc, slotID, true
}

// handlePost implements the one-shot POST path per PROTOCOL.md §3:
// write-token auth, service_id hour tolerance, size-bounded body read,
// TTL + reads parsing, and Store.Put dispatch.
func (h *Handler) handlePost(w http.ResponseWriter, r *http.Request, svc, slotID [16]byte) {
	// Write-token check. ConstantTimeCompare leaks length when inputs
	// differ; WRITE_TOKEN is ≥32 bytes high-entropy hex, so the leak
	// is not exploitable.
	if len(h.writeToken) > 0 {
		header := r.Header.Get("X-DeadDrop-Write")
		if header == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(header), []byte(h.writeTokenHex)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Service_id hour tolerance. Evaluate both comparisons
	// unconditionally so timing does not leak which hour matched.
	now := h.clock.Now()
	hCurrent := uint64(now.Unix()) / 3600
	svcCurrent, err := slot.ServiceID(h.deploySecret, hCurrent)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Guard against underflow when hCurrent == 0 (wall-clock before
	// 1970-01-01 01:00 UTC): skip the previous-hour branch entirely.
	var svcPrev []byte
	if hCurrent > 0 {
		svcPrev, err = slot.ServiceID(h.deploySecret, hCurrent-1)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		svcPrev = make([]byte, slot.ServiceIDSize)
	}
	matchCur := subtle.ConstantTimeCompare(svc[:], svcCurrent)
	matchPrev := subtle.ConstantTimeCompare(svc[:], svcPrev)
	if matchCur|matchPrev != 1 {
		uniform404(w)
		return
	}

	// Body read with a +1 cap so a body of exactly maxBlobBytes+1
	// succeeds at the reader level and is then rejected by the
	// post-read length check below. Bodies larger than +1 bytes fail
	// earlier via *http.MaxBytesError. Both paths map to 413.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBlobBytes+1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if int64(len(body)) > h.maxBlobBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) == 0 {
		// Relay is body-opaque but an empty blob is never a valid
		// wrapped body (PROTOCOL.md §7).
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	ttl := parseClampedDuration(r.URL.Query().Get("ttl"), 600, DefaultMaxTTLSeconds)
	reads := parseClampedReads(r.URL.Query().Get("reads"), DefaultReads, DefaultMaxReads)

	// Optional X-DeadDrop-Delete-Hash header. Absent or empty string
	// disables DELETE for this slot (zero-value deleteHash). Malformed
	// hex / wrong length is a client bug → 400, distinct from 404.
	var deleteHash [deleteHashSize]byte
	if raw := r.Header.Get("X-DeadDrop-Delete-Hash"); raw != "" {
		decoded, err := hex.DecodeString(raw)
		if err != nil || len(decoded) != deleteHashSize {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		copy(deleteHash[:], decoded)
	}

	switch err := h.store.Put(svc, slotID, body, ttl, reads, deleteHash); {
	case errors.Is(err, ErrSlotExists):
		w.WriteHeader(http.StatusConflict)
	case errors.Is(err, ErrStoreFull):
		// D-39 / BACKEND_VM.md §3.2: a full store rejects writes with
		// 503 until GC or reads free space. Same status as the
		// semaphore gate but a distinct reason; the body is empty
		// either way (no oracle on which guardrail tripped).
		w.WriteHeader(http.StatusServiceUnavailable)
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusCreated)
	}
}

// handleDelete authenticates a DELETE request via SHA-256(token) and
// dispatches to the store. Per D-26 every failure — missing header,
// malformed hex, wrong token, expired slot, never-posted slot —
// funnels through uniform404 so the client cannot distinguish them.
// Only a matching non-expired slot with a registered hash returns 204.
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, svc, slotID [16]byte) {
	// Drain/discard the body — DELETE does not accept one.
	r.Body = http.MaxBytesReader(w, r.Body, 0)
	_, _ = io.Copy(io.Discard, r.Body)

	raw := r.Header.Get("X-DeadDrop-Delete-Token")
	if raw == "" {
		uniform404(w)
		return
	}
	token, err := hex.DecodeString(raw)
	if err != nil {
		uniform404(w)
		return
	}
	tokenHash := sha256.Sum256(token)
	if !h.store.Delete(svc, slotID, tokenHash) {
		uniform404(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseClampedDuration parses a non-negative integer seconds value
// from raw, applying the default on parse error or non-positive value
// and clamping positive values to maxSec.
func parseClampedDuration(raw string, defaultSec, maxSec int) time.Duration {
	if raw == "" {
		return time.Duration(defaultSec) * time.Second
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return time.Duration(defaultSec) * time.Second
	}
	if v > maxSec {
		v = maxSec
	}
	return time.Duration(v) * time.Second
}

// parseClampedReads parses a positive integer from raw, applying the
// default on parse error or non-positive value and clamping positive
// values to maxReads.
func parseClampedReads(raw string, defaultReads, maxReads int) uint32 {
	if raw == "" {
		return uint32(defaultReads)
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return uint32(defaultReads)
	}
	if v > maxReads {
		v = maxReads
	}
	return uint32(v)
}

// handleGet implements the strict one-shot GET path per
// BACKEND_VM.md §3.2. No hour validation here — store keys are
// exact-match by design (PROTOCOL.md §2), so slots stored under a
// previous hour remain retrievable until TTL.
//
// The semaphore gate (non-blocking acquire) caps in-flight GETs so
// one slow client cannot pin an unbounded number of goroutines to
// the relay (AC-OVERLOAD-01). DELETE is intentionally ungated —
// it's rare, authenticated, and returns fast.
func (h *Handler) handleGet(w http.ResponseWriter, _ *http.Request, svc, slotID [16]byte) {
	if h.getSem != nil {
		select {
		case h.getSem <- struct{}{}:
			defer func() { <-h.getSem }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	if h.getHook != nil {
		h.getHook()
	}
	ct, readsLeft, ok := h.store.Take(svc, slotID)
	if !ok {
		uniform404(w)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-DeadDrop-Reads-Left", strconv.FormatUint(uint64(readsLeft), 10))
	w.WriteHeader(http.StatusOK)
	// Discard the write error: the slot has been consumed under the
	// lock already, and a client disconnect at this point is the
	// strict one-shot contract (BACKEND_VM.md §3.2).
	_, _ = w.Write(ct)
}

// uniform404 emits the single canonical 404 response used for every
// "not found" class (D-14). Empty body, fixed Content-Type, no
// X-Error-* headers — tests assert byte-identity across all
// five failure classes.
func uniform404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
}
