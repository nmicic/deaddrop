// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"sync"
	"time"
)

// GC drives a periodic Store.Sweep at a fixed interval. The ticker
// controls cadence (real wall-clock time in production, injectable for
// tests); Sweep itself uses store.clock.Now() for expiry judgment, so
// a FakeClock in tests can make entries appear expired without waiting.
//
// BACKEND_VM.md §3.1 requires a 60-second sweep in production; tests
// may pick a shorter interval via NewGC.
type GC struct {
	store    *Store
	interval time.Duration
	// newTicker is the ticker factory. Tests override this to inject a
	// deterministic channel; production uses time.NewTicker.
	newTicker func(time.Duration) *time.Ticker
	once      sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// NewGC returns a GC bound to store, sweeping every interval. The
// caller must call Start before eviction begins and Stop at shutdown.
func NewGC(store *Store, interval time.Duration) *GC {
	return &GC{
		store:     store,
		interval:  interval,
		newTicker: time.NewTicker,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Start launches the sweep goroutine. Subsequent calls are no-ops —
// sync.Once guarantees the goroutine and the done channel close
// exactly once, so double-start cannot panic on close(done).
func (g *GC) Start() {
	g.once.Do(func() {
		go g.run()
	})
}

func (g *GC) run() {
	ticker := g.newTicker(g.interval)
	for {
		select {
		case <-ticker.C:
			g.store.Sweep()
		case <-g.stop:
			ticker.Stop()
			close(g.done)
			return
		}
	}
}

// Stop signals the sweep goroutine to exit and blocks until it does.
// Graceful shutdown is its canonical caller; tests call it
// to avoid leaking goroutines.
func (g *GC) Stop() {
	close(g.stop)
	<-g.done
}
