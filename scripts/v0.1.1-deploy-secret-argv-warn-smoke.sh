#!/usr/bin/env bash
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# v0.2.0 update: --deploy-secret on argv was removed (D-72).
# This script now verifies that all four binaries REJECT the
# removed flag with the migration message, rather than warn.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$(mktemp -d -t v020-argv-reject-smoke-XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

SECRET_HEX=$(printf '01%.0s' $(seq 1 32))
WT_HEX=$(printf 'a1%.0s' $(seq 1 32))
REJECT_SUBSTR='--deploy-secret was removed in v0.2.0'

echo "==> building binaries"
cd "$REPO_ROOT"
go build -trimpath -o "$BUILD_DIR/deaddrop"        ./cmd/deaddrop
go build -trimpath -o "$BUILD_DIR/deaddrop-relay"  ./cmd/deaddrop-relay

# Clean env.
for v in DEADDROP_DEPLOY_SECRET DEPLOY_SECRET DEADDROP_WRITE_TOKEN WRITE_TOKEN; do
    unset "$v" 2>/dev/null || true
done

# check_reject runs a command that should fail (exit != 0) with the
# migration message on stderr.
check_reject() {
    local label="$1"; shift
    local tmpf
    tmpf=$(mktemp)
    local rc=0
    ( "$@" >/dev/null 2>"$tmpf" ) &
    local pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || rc=$?
    local out
    out=$(cat "$tmpf")
    rm -f "$tmpf"
    if printf '%s' "$out" | grep -qF -- "$REJECT_SUBSTR"; then
        echo "    $label: rejection message present"
    else
        echo "FAIL: $label — rejection substring not found in stderr." >&2
        echo "  expected to contain: $REJECT_SUBSTR" >&2
        echo "  got:" >&2
        echo "$out" >&2
        return 1
    fi
}

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

check_reject "relay (argv rejected)" \
    "$BUILD_DIR/deaddrop-relay" --listen ":$PORT" \
    --deploy-secret "hex:$SECRET_HEX" --write-token "hex:$WT_HEX" --local-only --max-store-bytes 0

check_reject "send (argv rejected)" \
    "$BUILD_DIR/deaddrop" send \
        --relay "http://127.0.0.1:1" \
        --deploy-secret "hex:$SECRET_HEX" \
        /nonexistent/file

check_reject "recv (argv rejected)" \
    "$BUILD_DIR/deaddrop" recv \
        --relay "http://127.0.0.1:1" \
        --deploy-secret "hex:$SECRET_HEX"

check_reject "bootstrap (argv rejected)" \
    "$BUILD_DIR/deaddrop" bootstrap \
        --role initiator \
        --relay "http://127.0.0.1:1" \
        --deploy-secret "hex:$SECRET_HEX" \
        --capsule "$BUILD_DIR/cap"

echo "==> all binaries reject --deploy-secret on argv with migration message"
