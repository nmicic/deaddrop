#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Mićić
# SPDX-License-Identifier: Apache-2.0
#
# Section A item 7 — exercise --deploy-secret-fd on all four
# binaries (send, recv, bootstrap, deaddrop-relay). Each invocation
# reads the secret from fd 3 via a bash here-string. Success means
# the binary parses the secret without an EDDUsage error and
# proceeds to its next operational step (relay binds the listen
# port; clients fail at the next required input rather than at the
# secret-parse boundary).
#
# Requires bash 4+ (here-string syntax). POSIX dash will not work
# here — process substitution returns a path, not an FD.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$(mktemp -d -t v011-fd-smoke-XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

SECRET=$(printf '01%.0s' $(seq 1 32))   # 32 hex bytes -> 64 hex chars
WRITE_TOKEN=$(printf 'a1%.0s' $(seq 1 32))

echo "==> building binaries"
cd "$REPO_ROOT"
go build -trimpath -o "$BUILD_DIR/deaddrop"        ./cmd/deaddrop
go build -trimpath -o "$BUILD_DIR/deaddrop-relay"  ./cmd/deaddrop-relay

# Pick a free TCP port for the relay smoke.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
echo "==> relay smoke on :$PORT"

# Start relay with --deploy-secret-fd 3 + --write-token-fd 4.
# Reads from two distinct fds; bash assigns each here-string a
# unique fd number we control via the redirection list.
"$BUILD_DIR/deaddrop-relay" \
    --listen ":$PORT" \
    --deploy-secret-fd 3 \
    --write-token-fd 4 \
    3<<<"hex:$SECRET" 4<<<"hex:$WRITE_TOKEN" &
RELAY_PID=$!
trap 'kill "$RELAY_PID" 2>/dev/null || true; rm -rf "$BUILD_DIR"' EXIT

# Wait for the relay to bind. A 404 on a random path proves the
# listener is up and the deploy-secret was parsed successfully —
# any failure to parse would have aborted before the bind.
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" 2>/dev/null | grep -q '^4'; then
        break
    fi
    if ! kill -0 "$RELAY_PID" 2>/dev/null; then
        echo "FAIL: relay exited before binding" >&2
        exit 1
    fi
    sleep 0.2
done
if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "FAIL: relay not running after wait" >&2
    exit 1
fi
echo "    relay: parsed --deploy-secret-fd + --write-token-fd OK"

# Smoke each client subcommand. We expect each invocation to parse
# the secret and proceed to its next step (which will fail because
# we are not running a full bootstrap or supplying capsules — the
# point is that the failure must NOT be at the secret-parse
# boundary). EDDUsage from a missing-flag downstream is fine; an
# EDDUsage citing --deploy-secret would fail this smoke.

run_and_check_no_secret_error() {
    local label="$1"; shift
    local stderr
    stderr=$( ( "$@" ) 2>&1 >/dev/null || true )
    if printf '%s' "$stderr" | grep -qE 'deploy-secret|missing hex:|too short'; then
        echo "FAIL: $label — secret-parse error in stderr:" >&2
        echo "$stderr" >&2
        return 1
    fi
    if printf '%s' "$stderr" | grep -qi 'panic'; then
        echo "FAIL: $label — panic:" >&2
        echo "$stderr" >&2
        return 1
    fi
    echo "    $label: secret parsed OK (downstream fail is expected)"
}

# send: missing capsule + nonexistent file → fails downstream.
run_and_check_no_secret_error "send" \
    "$BUILD_DIR/deaddrop" send \
        --relay "http://127.0.0.1:$PORT" \
        --deploy-secret-fd 3 \
        /nonexistent/file 3<<<"hex:$SECRET"

# recv: no capsule → fails downstream.
run_and_check_no_secret_error "recv" \
    "$BUILD_DIR/deaddrop" recv \
        --relay "http://127.0.0.1:$PORT" \
        --deploy-secret-fd 3 3<<<"hex:$SECRET"

# bootstrap: missing --role → fails after secret parse, never
# reaches the bootstrap state machine. We only assert no EDDUsage
# referencing --deploy-secret.
run_and_check_no_secret_error "bootstrap" \
    "$BUILD_DIR/deaddrop" bootstrap \
        --relay "http://127.0.0.1:$PORT" \
        --deploy-secret-fd 3 \
        --capsule "$BUILD_DIR/cap" 3<<<"hex:$SECRET"

echo "==> all four binaries: --deploy-secret-fd OK"
