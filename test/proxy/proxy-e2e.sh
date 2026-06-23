#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end proxy tests for the deaddrop client.
# Runs from the dev host through a local Squid proxy (127.0.0.1:8080)
# against a deployed relay (VPS or VM).
#
# Tests:
#   1. HTTPS_PROXY respected: send/recv through proxy
#   2. HTTP_PROXY respected: same behavior
#   3. Invalid proxy → clean error (no hang)
#   4. NO_PROXY bypasses dead proxy
#   5. recv --watch through proxy
#   6. Large payload (~10 MiB) through proxy
#   7. Bad relay URL through proxy → clean error
#
# Usage:
#   # Set relay env first (from deploy script output):
#   eval "$(./scripts/deploy.sh vps 2>/dev/null | grep export)"
#   ./test/proxy/proxy-e2e.sh
#
#   # Options:
#   ./test/proxy/proxy-e2e.sh --proxy http://127.0.0.1:8080
#   ./test/proxy/proxy-e2e.sh --skip-large    # skip 10 MiB test
set -eu

PROXY="${DEADDROP_PROXY:-http://127.0.0.1:8080}"
SKIP_LARGE=false
PASSPHRASE="proxy-test-passphrase"

while [ $# -gt 0 ]; do
    case "$1" in
        --proxy)      PROXY="$2"; shift 2 ;;
        --skip-large) SKIP_LARGE=true; shift ;;
        --help)       head -24 "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        *)            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

for var in DEADDROP_RELAY DEADDROP_DEPLOY_SECRET DEADDROP_WRITE_TOKEN; do
    eval val=\$$var
    if [ -z "$val" ]; then
        echo "ERROR: $var not set" >&2
        exit 1
    fi
done

if ! curl -sx "$PROXY" -o /dev/null https://example.com 2>/dev/null; then
    echo "ERROR: proxy $PROXY is not reachable" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DD="$WORK/deaddrop"
SEND_ARGS="--capsule $WORK/capsule --passphrase-fd 0 --write-token $DEADDROP_WRITE_TOKEN --no-require-e2e"
RECV_ARGS="--capsule $WORK/capsule --passphrase-fd 0 --no-require-e2e"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  deaddrop proxy tests                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Relay:   $DEADDROP_RELAY"
echo "  Proxy:   $PROXY"
echo "  Git SHA: $GIT_SHA"
echo ""

echo "Building deaddrop client..."
go build -trimpath -o "$DD" ./cmd/deaddrop
echo ""

printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
    | "$DD" keygen --passphrase-fd 0 "$WORK/capsule" >/dev/null 2>&1

PASS=0
FAIL=0

mark_pass() { echo "PASS"; PASS=$((PASS + 1)); }
mark_fail() { echo "FAIL${1:+ ($1)}"; FAIL=$((FAIL + 1)); }

# Helper: send through env. Usage: proxy_send <env_args> <file>
# env_args is passed to env(1) so it applies to the deaddrop process.
proxy_send() {
    _env_args="$1"; _file="$2"
    printf '%s' "$PASSPHRASE" \
        | env $_env_args "$DD" send $SEND_ARGS "$_file" >/dev/null 2>&1
}

proxy_recv() {
    _env_args="$1"; _out="$2"
    printf '%s' "$PASSPHRASE" \
        | env $_env_args "$DD" recv $RECV_ARGS "$_out" >/dev/null 2>&1
}

# ─── Test 1: HTTPS_PROXY send/recv round-trip ───────────────────────
printf "  %-50s " "HTTPS_PROXY send/recv round-trip"

echo "proxy-test-1-$(date +%s)" > "$WORK/msg1.txt"
_ok=true
proxy_send "HTTPS_PROXY=$PROXY" "$WORK/msg1.txt" || _ok=false
if [ "$_ok" = true ]; then
    proxy_recv "HTTPS_PROXY=$PROXY" "$WORK/recv1.txt" || _ok=false
fi
if [ "$_ok" = true ] && diff -q "$WORK/msg1.txt" "$WORK/recv1.txt" >/dev/null 2>&1; then
    mark_pass
else
    mark_fail "send or recv failed through proxy"
fi

# ─── Test 2: http_proxy (lowercase) also works ──────────────────────
printf "  %-50s " "http_proxy (lowercase) works"

echo "proxy-test-2-$(date +%s)" > "$WORK/msg2.txt"
_ok=true
proxy_send "http_proxy=$PROXY" "$WORK/msg2.txt" || _ok=false
if [ "$_ok" = true ]; then
    proxy_recv "http_proxy=$PROXY" "$WORK/recv2.txt" || _ok=false
fi
if [ "$_ok" = true ] && diff -q "$WORK/msg2.txt" "$WORK/recv2.txt" >/dev/null 2>&1; then
    mark_pass
else
    mark_fail "http_proxy not respected"
fi

# ─── Test 3: Invalid proxy → clean error (not hang) ─────────────────
printf "  %-50s " "Invalid proxy -> clean error (no hang)"

echo "proxy-test-3" > "$WORK/msg3.txt"
_exit=0
_t0=$(date +%s)
printf '%s' "$PASSPHRASE" \
    | timeout 15 env HTTPS_PROXY="http://127.0.0.1:1" \
        "$DD" send $SEND_ARGS "$WORK/msg3.txt" >/dev/null 2>&1 \
    || _exit=$?
_t1=$(date +%s)
_elapsed=$((_t1 - _t0))

if [ "$_exit" -ne 0 ] && [ "$_elapsed" -lt 15 ]; then
    mark_pass
else
    mark_fail "exit=$_exit elapsed=${_elapsed}s"
fi

# ─── Test 4: NO_PROXY bypasses dead proxy ────────────────────────────
printf "  %-50s " "NO_PROXY bypasses dead proxy"

_relay_host=$(echo "$DEADDROP_RELAY" | sed 's|https\?://||;s|/.*||')
echo "proxy-test-4-$(date +%s)" > "$WORK/msg4.txt"

_ok=true
proxy_send "HTTPS_PROXY=http://127.0.0.1:1 NO_PROXY=$_relay_host" "$WORK/msg4.txt" || _ok=false
if [ "$_ok" = true ]; then
    proxy_recv "HTTPS_PROXY=http://127.0.0.1:1 NO_PROXY=$_relay_host" "$WORK/recv4.txt" || _ok=false
fi
if [ "$_ok" = true ] && diff -q "$WORK/msg4.txt" "$WORK/recv4.txt" >/dev/null 2>&1; then
    mark_pass
else
    mark_fail "NO_PROXY did not bypass dead proxy"
fi

# ─── Test 5: recv --watch through proxy ──────────────────────────────
printf "  %-50s " "recv --watch through proxy"

echo "proxy-test-5-$(date +%s)" > "$WORK/msg5.txt"

# Send directly (get message into relay)
printf '%s' "$PASSPHRASE" \
    | "$DD" send $SEND_ARGS "$WORK/msg5.txt" >/dev/null 2>&1

# recv --watch through proxy
_exit=0
printf '%s' "$PASSPHRASE" \
    | timeout 60 env HTTPS_PROXY="$PROXY" \
        "$DD" recv $RECV_ARGS --watch --duration 30s \
        "$WORK/recv5.txt" >/dev/null 2>&1 \
    || _exit=$?

if [ "$_exit" -eq 0 ] && diff -q "$WORK/msg5.txt" "$WORK/recv5.txt" >/dev/null 2>&1; then
    mark_pass
else
    mark_fail "exit=$_exit"
fi

# ─── Test 6: Large payload (~10 MiB) through proxy ──────────────────
if [ "$SKIP_LARGE" = false ]; then
    printf "  %-50s " "5 MiB payload through proxy"

    dd if=/dev/urandom of="$WORK/large.bin" bs=1048576 count=5 2>/dev/null

    _ok=true
    proxy_send "HTTPS_PROXY=$PROXY" "$WORK/large.bin" || _ok=false
    if [ "$_ok" = true ]; then
        proxy_recv "HTTPS_PROXY=$PROXY" "$WORK/large_recv.bin" || _ok=false
    fi
    if [ "$_ok" = true ] && diff -q "$WORK/large.bin" "$WORK/large_recv.bin" >/dev/null 2>&1; then
        mark_pass
    else
        mark_fail "data mismatch or transfer failed"
    fi
else
    echo "  [skipped] 10 MiB payload through proxy (--skip-large)"
fi

# ─── Test 7: Bad relay URL through proxy → clean error ───────────────
printf "  %-50s " "Bad relay through proxy -> clean error"

# Use loopback:1 — proxy's CONNECT gets ECONNREFUSED instantly.
_exit=0
_t0=$(date +%s)
printf '%s' "$PASSPHRASE" \
    | timeout 30 env HTTPS_PROXY="$PROXY" DEADDROP_RELAY="https://127.0.0.1:1/deadbeef" \
        "$DD" send $SEND_ARGS "$WORK/msg3.txt" >/dev/null 2>&1 \
    || _exit=$?
_t1=$(date +%s)
_elapsed=$((_t1 - _t0))

if [ "$_exit" -ne 0 ] && [ "$_elapsed" -lt 30 ]; then
    mark_pass
else
    mark_fail "exit=$_exit elapsed=${_elapsed}s"
fi

# ─── Summary ─────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PROXY TEST SUMMARY                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Git SHA: $GIT_SHA"
echo "  Proxy:   $PROXY"
echo "  Relay:   $DEADDROP_RELAY"
echo "  Results: $PASS pass, $FAIL fail"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
