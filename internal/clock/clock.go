// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package clock

import "time"

// Clock provides the current time. All production code takes a Clock
// rather than calling time.Now directly (C-4).
type Clock interface {
	Now() time.Time
}

// RealClock returns wall-clock time in UTC.
type RealClock struct{}

// NewRealClock returns a RealClock.
func NewRealClock() RealClock { return RealClock{} }

// Now returns time.Now().UTC().
func (RealClock) Now() time.Time { return time.Now().UTC() }
