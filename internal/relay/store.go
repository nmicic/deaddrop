// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/nmicic/deaddrop/internal/clock"
)

// Defaults exported for the handler and the CLI to share one source of
// truth. These mirror PROTOCOL.md §8 operational parameters.
const (
	DefaultMaxBlobBytes  = 10_485_760 // 10 MiB
	DefaultMaxTTLSeconds = 3600       // 1 hour
	DefaultMaxReads      = 10
	DefaultReads         = 1
)

// ErrSlotExists is returned by Put when the (service_id, slot_id) key
// is already populated with a non-expired entry (duplicate POST, 409).
var ErrSlotExists = errors.New("relay: slot already exists")

// ErrStoreFull is returned by Put when accepting the new blob would
// push s.bytes past the configured maxStoreBytes cap. Mapped by the
// handler to HTTP 503 (D-39, PROTOCOL.md §3).
var ErrStoreFull = errors.New("relay: store capacity exceeded")

// storeKey is the in-memory index key per D-39 / BACKEND_VM.md §3.1.
// svc is the raw 16 bytes of the service_id the client presented at
// POST time — not recomputed from the current-hour derivation, so
// GET retrieval remains exact-match across hour rollovers.
type storeKey struct {
	svc  [16]byte
	slot [16]byte
}

// slotEntry is the in-memory per-slot record. Unexported, and named
// "slotEntry" rather than "slot" to avoid a collision with the
// imported slot package in this same relay package.
//
// deleteHash holds SHA-256(delete_token) when the POST included the
// optional X-DeadDrop-Delete-Hash header; zero value means DELETE is
// disabled for this slot (D-26).
type slotEntry struct {
	ct         []byte
	expiresAt  time.Time
	readsLeft  uint32
	deleteHash [32]byte
}

// Store is the goroutine-safe in-memory slot store. Exactly one Store
// lives per relay process; it holds opaque ciphertext bytes and has
// no knowledge of keys or plaintext (D-01, D-02).
//
// maxStoreBytes is the total-capacity ceiling in bytes (D-39).
// Passing 0 (or a negative value) disables the cap — intended for
// tests and local-only deployments. Production wiring in main.go
// passes a positive value.
type Store struct {
	mu            sync.Mutex
	bytes         int64
	maxStoreBytes int64
	m             map[storeKey]*slotEntry
	clock         clock.Clock
}

// NewStore returns an initialised Store bound to the given clock and
// total-capacity cap. maxStoreBytes <= 0 disables the cap.
func NewStore(c clock.Clock, maxStoreBytes int64) *Store {
	return &Store{
		m:             make(map[storeKey]*slotEntry),
		clock:         c,
		maxStoreBytes: maxStoreBytes,
	}
}

// Put inserts ct under (svc, slotID) with the given TTL, read-count,
// and optional delete-hash. Passing the zero value for deleteHash
// disables DELETE for this slot (D-26).
//
// Returns ErrSlotExists if the slot is already populated with a
// non-expired entry. An expired entry is evicted (ct + deleteHash
// zeroized, bytes decremented) before the new value is written.
func (s *Store) Put(svc, slotID [16]byte, ct []byte, ttl time.Duration, reads uint32, deleteHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := storeKey{svc: svc, slot: slotID}
	if existing, ok := s.m[k]; ok {
		if s.clock.Now().Before(existing.expiresAt) {
			return ErrSlotExists
		}
		// Expired — evict in place; the map write below overwrites.
		// This MUST happen before the cap check so a POST to a slot
		// whose predecessor expired reclaims the predecessor's bytes
		// first and does not 503 on an already-freed entry.
		zeroize(existing.ct)
		zeroizeHash(&existing.deleteHash)
		s.bytes -= int64(len(existing.ct))
	}
	if s.maxStoreBytes > 0 && s.bytes+int64(len(ct)) > s.maxStoreBytes {
		return ErrStoreFull
	}
	s.m[k] = &slotEntry{
		ct:         ct,
		expiresAt:  s.clock.Now().Add(ttl),
		readsLeft:  reads,
		deleteHash: deleteHash,
	}
	s.bytes += int64(len(ct))
	return nil
}

// Take implements D-39's strict one-shot read: copy the ciphertext out,
// decrement the read counter under lock, delete when exhausted.
//
// Returns (ct, readsLeftAfter, true) on a successful read.
// Returns (nil, 0, false) if the slot is absent or expired.
//
// The readsLeftAfter value is post-decrement — used by the handler to
// populate X-DeadDrop-Reads-Left so clients can see when the slot has
// been fully consumed without needing another round-trip.
//
// Expired slots are evicted on discovery (ct + deleteHash zeroized,
// bytes decremented, map entry deleted). Boundary tie at exactly
// expiresAt favours the reader: time.After(expiresAt) is false at
// that instant.
func (s *Store) Take(svc, slotID [16]byte) ([]byte, uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := storeKey{svc: svc, slot: slotID}
	sl, ok := s.m[k]
	if !ok {
		return nil, 0, false
	}
	if s.clock.Now().After(sl.expiresAt) {
		zeroize(sl.ct)
		zeroizeHash(&sl.deleteHash)
		s.bytes -= int64(len(sl.ct))
		delete(s.m, k)
		return nil, 0, false
	}
	out := append([]byte(nil), sl.ct...)
	sl.readsLeft--
	left := sl.readsLeft
	if left == 0 {
		zeroize(sl.ct)
		zeroizeHash(&sl.deleteHash)
		s.bytes -= int64(len(sl.ct))
		delete(s.m, k)
	}
	return out, left, true
}

// Delete implements the authenticated one-shot DELETE per D-26 and
// PROTOCOL.md §3. All false returns are indistinguishable at the HTTP
// layer (they funnel to the same uniform404 helper); only a match
// against a non-zero registered hash under a non-expired slot returns
// true.
//
// The comparison uses crypto/subtle.ConstantTimeCompare so a timing
// channel does not leak partial-match information about the stored
// hash.
func (s *Store) Delete(svc, slotID [16]byte, tokenHash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := storeKey{svc: svc, slot: slotID}
	sl, ok := s.m[k]
	if !ok {
		return false
	}
	if s.clock.Now().After(sl.expiresAt) {
		zeroize(sl.ct)
		zeroizeHash(&sl.deleteHash)
		s.bytes -= int64(len(sl.ct))
		delete(s.m, k)
		return false
	}
	// Zero-value deleteHash means DELETE is disabled for this slot.
	// Check in constant time so presence-vs-absence of the registered
	// hash does not leak by timing.
	var zero [32]byte
	zeroed := subtle.ConstantTimeCompare(sl.deleteHash[:], zero[:]) == 1
	matched := subtle.ConstantTimeCompare(sl.deleteHash[:], tokenHash[:]) == 1
	if zeroed || !matched {
		return false
	}
	zeroize(sl.ct)
	zeroizeHash(&sl.deleteHash)
	s.bytes -= int64(len(sl.ct))
	delete(s.m, k)
	return true
}

// Sweep evicts every expired entry and returns the count. Safe to
// call from a TTL-GC goroutine (see gc.go). Iterating and deleting
// from a map in the same range loop is permitted by the Go spec.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	evicted := 0
	for k, sl := range s.m {
		if now.After(sl.expiresAt) {
			zeroize(sl.ct)
			zeroizeHash(&sl.deleteHash)
			s.bytes -= int64(len(sl.ct))
			delete(s.m, k)
			evicted++
		}
	}
	return evicted
}

// ZeroizeAll wipes every live slot's ciphertext and delete-hash under
// the store mutex and returns the count evicted. Used by the graceful
// shutdown path (D-39): holding s.mu for the full iteration means no
// GET / DELETE / Sweep can race a wipe in progress, so the handler
// callers either complete fully before ZeroizeAll starts or observe
// an empty store once it releases.
func (s *Store) ZeroizeAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for k, sl := range s.m {
		zeroize(sl.ct)
		zeroizeHash(&sl.deleteHash)
		s.bytes -= int64(len(sl.ct))
		delete(s.m, k)
		count++
	}
	return count
}

// StoreBytes returns the total bytes currently stored across all live
// slots. The handler's POST path uses this as the hook
// checks against maxStoreBytes via Put's internal cap logic.
func (s *Store) StoreBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// Len returns the current slot count.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// zeroize overwrites b in place with zeros. Best-effort; the compiler
// and runtime may retain earlier copies that are not reachable through
// the public API.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeHash overwrites the 32-byte hash buffer in place. Separate
// from zeroize so eviction paths can neutralise the delete-hash
// without allocating a slice header.
func zeroizeHash(h *[32]byte) {
	for i := range h {
		h[i] = 0
	}
}
