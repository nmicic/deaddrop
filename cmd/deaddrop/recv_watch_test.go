// Copyright (c) 2026 Nenad Mićić
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmicic/deaddrop/internal/client"
	"github.com/nmicic/deaddrop/internal/exitcode"
)

// fakeWatchClock returns a watchClock whose Now returns a monotonically
// advancing time (starts at base, each call adds step), Sleep is a
// no-op that checks ctx.Done, and Probe calls the supplied function.
func fakeWatchClock(base time.Time, step time.Duration, probe func(ctx context.Context, cfg client.RecvConfig) ([]byte, error)) watchClock {
	var calls atomic.Int64
	return watchClock{
		Now: func() time.Time {
			n := calls.Add(1) - 1
			return base.Add(time.Duration(n) * step)
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Probe: probe,
	}
}

// 1. TestWatch_HappyPath — fake probe misses N times then returns
// plaintext. Assert exit 0 and correct output.
func TestWatch_HappyPath(t *testing.T) {
	var probeCount int
	wc := fakeWatchClock(time.Now(), time.Second, func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
		probeCount++
		if probeCount < 3 {
			return nil, &client.RecvError{Code: exitcode.NotFound, Detail: "miss"}
		}
		return []byte("found-it"), nil
	})

	deadline := time.Now().Add(time.Hour)
	var out, stderr bytes.Buffer
	code := runRecvWatch(context.Background(), wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, "", &stderr)
	if code != exitcode.OK {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if out.String() != "found-it" {
		t.Fatalf("output = %q, want %q", out.String(), "found-it")
	}
	if probeCount != 3 {
		t.Fatalf("probeCount = %d, want 3", probeCount)
	}
}

// 2. TestWatch_DeadlineReached — fake probe always misses; clock
// advances past deadline. Assert exit 1 (NotFound).
func TestWatch_DeadlineReached(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Each Now() call advances 10 minutes. Deadline is 5 minutes out.
	wc := fakeWatchClock(base, 10*time.Minute, func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
		return nil, &client.RecvError{Code: exitcode.NotFound, Detail: "miss"}
	})

	deadline := base.Add(5 * time.Minute)
	var out, stderr bytes.Buffer
	code := runRecvWatch(context.Background(), wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, "", &stderr)
	if code != exitcode.NotFound {
		t.Fatalf("code = %d, want %d (NotFound); stderr=%s", code, exitcode.NotFound, stderr.String())
	}
}

// 3. TestWatch_NonMissErrorTerminal — fake probe returns auth error
// on first call. Assert that exit code matches Auth, not NotFound.
func TestWatch_NonMissErrorTerminal(t *testing.T) {
	wc := fakeWatchClock(time.Now(), time.Second, func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
		return nil, &client.RecvError{Code: exitcode.Auth, Detail: "relay rejected credentials"}
	})

	deadline := time.Now().Add(time.Hour)
	var out, stderr bytes.Buffer
	code := runRecvWatch(context.Background(), wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, "", &stderr)
	if code != exitcode.Auth {
		t.Fatalf("code = %d, want %d (Auth); stderr=%s", code, exitcode.Auth, stderr.String())
	}
}

// 4. TestWatch_DeadlineNoOvershoot — duration 250ms, interval 1h;
// must exit near the deadline, not wait a full hour. We use a wall-
// clock-advancing fake to verify the sleep is clamped.
func TestWatch_DeadlineNoOvershoot(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	duration := 250 * time.Millisecond
	interval := time.Hour

	var sleepCalls int
	var lastSleep time.Duration
	wc := watchClock{
		Now: func() time.Time {
			// After each sleep, time has advanced by the sleep duration.
			return base.Add(time.Duration(sleepCalls) * duration)
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleepCalls++
			lastSleep = d
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Probe: func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
			return nil, &client.RecvError{Code: exitcode.NotFound, Detail: "miss"}
		},
	}

	deadline := base.Add(duration)
	var out, stderr bytes.Buffer
	code := runRecvWatch(context.Background(), wc, client.RecvConfig{}, &deadline, interval, &out, "", &stderr)
	if code != exitcode.NotFound {
		t.Fatalf("code = %d, want %d (NotFound)", code, exitcode.NotFound)
	}
	// The sleep should have been clamped to remaining time, not the full interval.
	if lastSleep > duration {
		t.Fatalf("lastSleep = %v, want <= %v (clamped to remaining)", lastSleep, duration)
	}
}

// 5. TestWatch_SIGINTExitsCleanly — cancel the context mid-loop.
// Assert exit 130 (Interrupted).
func TestWatch_SIGINTExitsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var probeCount int
	wc := watchClock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			// Cancel context on second sleep to simulate SIGINT.
			cancel()
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Probe: func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
			probeCount++
			return nil, &client.RecvError{Code: exitcode.NotFound, Detail: "miss"}
		},
	}

	deadline := time.Now().Add(time.Hour)
	var out, stderr bytes.Buffer
	code := runRecvWatch(ctx, wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, "", &stderr)
	if code != exitcode.Interrupted {
		t.Fatalf("code = %d, want %d (Interrupted); stderr=%s", code, exitcode.Interrupted, stderr.String())
	}
}

// 5b. TestWatch_SIGINTDuringProbe — cancel context while a probe is
// in-flight (not during sleep). The probe returns a non-miss error
// wrapping context.Canceled; the loop must still exit 130, not 11.
func TestWatch_SIGINTDuringProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	wc := watchClock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Probe: func(ctx context.Context, _ client.RecvConfig) ([]byte, error) {
			cancel()
			return nil, &client.RecvError{Code: exitcode.RelayUnreachable, Detail: "context canceled"}
		},
	}

	deadline := time.Now().Add(time.Hour)
	var out, stderr bytes.Buffer
	code := runRecvWatch(ctx, wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, "", &stderr)
	if code != exitcode.Interrupted {
		t.Fatalf("code = %d, want %d (Interrupted); stderr=%s", code, exitcode.Interrupted, stderr.String())
	}
}

// 6. TestWatch_Duration0Unbounded — duration 0 means no deadline
// (nil pointer). Cancel context to exit. Assert 130.
func TestWatch_Duration0Unbounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var probeCount int
	wc := watchClock{
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			if probeCount >= 2 {
				cancel()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Probe: func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
			probeCount++
			return nil, &client.RecvError{Code: exitcode.NotFound, Detail: "miss"}
		},
	}

	// deadline == nil means unbounded.
	var out, stderr bytes.Buffer
	code := runRecvWatch(ctx, wc, client.RecvConfig{}, nil, 60*time.Second, &out, "", &stderr)
	if code != exitcode.Interrupted {
		t.Fatalf("code = %d, want %d (Interrupted); probeCount=%d", code, exitcode.Interrupted, probeCount)
	}
}

// 7. TestWatch_IntervalFloor — parse --watch --watch-interval 10s.
// Assert exit 2 (Usage) with a message mentioning the floor.
func TestWatch_IntervalFloor(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--relay", "http://localhost",
		"--no-require-e2e",
		"--watch",
		"--watch-interval", "10s",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("code = %d, want %d (Usage); stderr=%s", code, exitcode.Usage, stderr.String())
	}
	if want := fmt.Sprintf(">= %s", watchIntervalFloor); !bytes.Contains(stderr.Bytes(), []byte(">=")) {
		t.Fatalf("stderr = %q, want mention of %q", stderr.String(), want)
	}
}

// 8. TestWatch_FutureInteractionPlaceholder — placeholder for future
// interaction tests (e.g., --watch + bootstrap handoff, persistent
// connection upgrade).
func TestWatch_FutureInteractionPlaceholder(t *testing.T) {
	t.Skip("future interaction tests not yet specified")
}

// TestWatch_DurationWithoutWatch — --duration without --watch → exit 2.
func TestWatch_DurationWithoutWatch(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--relay", "http://localhost",
		"--no-require-e2e",
		"--duration", "30m",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("code = %d, want %d (Usage); stderr=%s", code, exitcode.Usage, stderr.String())
	}
}

// TestWatch_IntervalWithoutWatch — --watch-interval without --watch → exit 2.
func TestWatch_IntervalWithoutWatch(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--relay", "http://localhost",
		"--no-require-e2e",
		"--watch-interval", "45s",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("code = %d, want %d (Usage); stderr=%s", code, exitcode.Usage, stderr.String())
	}
}

// TestWatch_DurationExceeds24h — --duration > 24h → exit 2.
func TestWatch_DurationExceeds24h(t *testing.T) {
	sendTestEnv(t)
	t.Setenv("DEADDROP_DEPLOY_SECRET", deploySecretHex)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"recv",
		"--relay", "http://localhost",
		"--no-require-e2e",
		"--watch",
		"--duration", "25h",
	}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("code = %d, want %d (Usage); stderr=%s", code, exitcode.Usage, stderr.String())
	}
}

// TestWatch_WriteToFile — probe succeeds on first attempt, output
// written to file (not stdout).
func TestWatch_WriteToFile(t *testing.T) {
	wc := fakeWatchClock(time.Now(), time.Second, func(_ context.Context, _ client.RecvConfig) ([]byte, error) {
		return []byte("file-output"), nil
	})

	outPath := t.TempDir() + "/watch-out"
	deadline := time.Now().Add(time.Hour)
	var out, stderr bytes.Buffer
	code := runRecvWatch(context.Background(), wc, client.RecvConfig{}, &deadline, 60*time.Second, &out, outPath, &stderr)
	if code != exitcode.OK {
		t.Fatalf("code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when writing to file", out.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(got) != "file-output" {
		t.Fatalf("file content = %q, want %q", got, "file-output")
	}
}
