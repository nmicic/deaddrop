// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package clock_test

import (
	"sync"
	"testing"
	"time"

	"github.com/nmicic/deaddrop/internal/clock"
)

func TestRealClock_UTC(t *testing.T) {
	c := clock.NewRealClock()
	if loc := c.Now().Location(); loc != time.UTC {
		t.Fatalf("RealClock.Now() location = %v, want UTC", loc)
	}
}

func TestFakeClock_Set(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewFakeClock(ts)
	c.Set(ts)
	if got := c.Now(); !got.Equal(ts) {
		t.Fatalf("FakeClock.Now() = %v, want %v", got, ts)
	}
}

func TestFakeClock_Advance(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewFakeClock(ts)
	c.Set(ts)
	c.Advance(5 * time.Minute)
	want := ts.Add(5 * time.Minute)
	if got := c.Now(); !got.Equal(want) {
		t.Fatalf("FakeClock.Now() after Advance = %v, want %v", got, want)
	}
}

func TestFakeClock_Concurrent(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewFakeClock(ts)

	var wg sync.WaitGroup
	wg.Add(200)
	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			c.Advance(time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			_ = c.Now()
		}()
	}
	wg.Wait()
}
