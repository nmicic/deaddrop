// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package clock

import (
	"sync"
	"time"
)

// FakeClock is a goroutine-safe deterministic clock for testing.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock initialised to t.
func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{now: t}
}

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set overwrites the fake time.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance moves the fake time forward by d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
