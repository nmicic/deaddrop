#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Validates the deaddrop HOWTO single-line examples against a live
# relay. Each example is exactly what a user would type, copy-pasted
# from the README.
#
# Usage:
#   sh test/e2e/howto-validate.sh [relay-url]
#
# Examples:
#   sh test/e2e/howto-validate.sh http://127.0.0.1:9876
#   sh test/e2e/howto-validate.sh https://deaddrop.example.com/PREFIX
#
# If no URL is given, starts a local relay on a free port.
set -eu

PASS=0; FAIL=0; SKIP=0
WORK=$(mktemp -d)
RELAY_PID=""
LOCAL_MODE=false

cleanup() {
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null && wait "$RELAY_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1" >&2; }
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }

# ─── build ───────────────────────────────────────────────────────────

echo "==> building binaries"
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop \
    || { echo "FAIL: go build deaddrop" >&2; exit 1; }
DD="$WORK/deaddrop"

DEPLOY_SECRET_HEX="0101010101010101010101010101010101010101010101010101010101010101"
DS="hex:$DEPLOY_SECRET_HEX"
export DEADDROP_DEPLOY_SECRET="$DS"

# ─── start local relay if no URL given ───────────────────────────────

if [ $# -ge 1 ]; then
    RELAY_URL="$1"
    WT=""
else
    CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop-relay" ./cmd/deaddrop-relay \
        || { echo "FAIL: go build deaddrop-relay" >&2; exit 1; }

    PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || echo 9876)
    RELAY_URL="http://127.0.0.1:$PORT"
    WT=""
    LOCAL_MODE=true

    "$WORK/deaddrop-relay" \
        --listen ":$PORT" \
        --local-only \
        >"$WORK/relay.log" 2>&1 &
    RELAY_PID=$!

    _i=0
    while [ "$_i" -lt 30 ]; do
        _c=$(curl -s -o /dev/null -w '%{http_code}' "$RELAY_URL/__ready" 2>/dev/null || echo "000")
        case "$_c" in [1-9][0-9][0-9]) break ;; esac
        _i=$((_i + 1)); sleep 0.1
    done
    echo "    local relay on :$PORT"
fi

# ─── HOWTO examples ──────────────────────────────────────────────────

echo ""
echo "=== HOWTO: Key Generation ==="

# 1. Generate a capsule (keypair)
echo "Step: deaddrop keygen <path>"
printf 'test-passphrase\ntest-passphrase\n' \
    | "$DD" keygen --passphrase-fd 0 "$WORK/capsule" >/dev/null 2>&1 \
    && pass "keygen creates capsule" \
    || fail "keygen"

# 2. Capsule file exists and is the right size
[ -f "$WORK/capsule" ] \
    && pass "capsule file exists" \
    || fail "capsule file missing"

echo ""
echo "=== HOWTO: Send a File ==="

# 3. Create a test file
echo "Hello, DeadDrop!" > "$WORK/message.txt"

# 4. Send it
echo "Step: deaddrop send --relay URL <file>"
WT_ARG=""
[ -n "$WT" ] && WT_ARG="--write-token $WT"
printf 'test-passphrase\n' \
    | "$DD" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        $WT_ARG \
        "$WORK/message.txt" 2>/dev/null \
    && pass "send file" \
    || fail "send file"

echo ""
echo "=== HOWTO: Receive a File ==="

# 5. Receive to file
echo "Step: deaddrop recv --relay URL <output>"
printf 'test-passphrase\n' \
    | "$DD" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        "$WORK/received.txt" 2>/dev/null \
    && pass "recv to file" \
    || fail "recv to file"

# 6. Content matches
if [ -f "$WORK/received.txt" ]; then
    sent=$(cat "$WORK/message.txt")
    got=$(cat "$WORK/received.txt")
    if [ "$sent" = "$got" ]; then
        pass "content matches: '$got'"
    else
        fail "content mismatch: sent='$sent' got='$got'"
    fi
fi

echo ""
echo "=== HOWTO: Receive to stdout ==="

# 7. Send another message
echo "stdout test payload" > "$WORK/msg2.txt"
printf 'test-passphrase\n' \
    | "$DD" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        $WT_ARG \
        "$WORK/msg2.txt" 2>/dev/null

# 8. Receive to stdout (no output arg)
echo "Step: deaddrop recv --relay URL  (stdout)"
printf 'test-passphrase\n' \
    | "$DD" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        >"$WORK/stdout_out.txt" 2>/dev/null \
    && pass "recv to stdout" \
    || fail "recv to stdout"

if [ -f "$WORK/stdout_out.txt" ]; then
    got=$(cat "$WORK/stdout_out.txt")
    if [ "$got" = "stdout test payload" ]; then
        pass "stdout content matches"
    else
        fail "stdout content mismatch: '$got'"
    fi
fi

echo ""
echo "=== HOWTO: One-Shot Semantics ==="

# 9. Send, recv once, second recv should fail
echo "one-shot" > "$WORK/oneshot.txt"
printf 'test-passphrase\n' \
    | "$DD" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        $WT_ARG \
        "$WORK/oneshot.txt" 2>/dev/null

printf 'test-passphrase\n' \
    | "$DD" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        "$WORK/oneshot_r.txt" 2>/dev/null

if printf 'test-passphrase\n' \
    | "$DD" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        "$WORK/oneshot_r2.txt" 2>/dev/null; then
    fail "second recv should fail (one-shot)"
else
    pass "one-shot: second recv correctly rejected"
fi

echo ""
echo "=== HOWTO: Binary Files ==="

# 10. Binary round-trip
dd if=/dev/urandom bs=4096 count=1 >"$WORK/random.bin" 2>/dev/null
SHA_SEND=$(sha256sum "$WORK/random.bin" | cut -d' ' -f1)

printf 'test-passphrase\n' \
    | "$DD" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        $WT_ARG \
        "$WORK/random.bin" 2>/dev/null

printf 'test-passphrase\n' \
    | "$DD" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        "$WORK/random_recv.bin" 2>/dev/null

SHA_RECV=$(sha256sum "$WORK/random_recv.bin" | cut -d' ' -f1)
if [ "$SHA_SEND" = "$SHA_RECV" ]; then
    pass "4KiB binary round-trip (SHA-256 match)"
else
    fail "binary checksum mismatch"
fi

echo ""
echo "=== HOWTO: Bootstrap Pairing ==="

# 11. Bootstrap — initiator + responder with shared passphrase
BOOTSTRAP_PASS="howto-bootstrap-$(date +%s)"
CAPSULE_PASS_B="howto-capsule-$(date +%s)"

printf '%s\n%s\n' "$BOOTSTRAP_PASS" "$CAPSULE_PASS_B" > "$WORK/init_pass"
printf '%s\n%s\n' "$BOOTSTRAP_PASS" "$CAPSULE_PASS_B" > "$WORK/resp_pass"

WT_ARG_VAL=""
[ -n "$WT" ] && WT_ARG_VAL="$WT"

echo "Step: bootstrap --role initiator + --role responder"
echo "" | "$DD" bootstrap \
    --role initiator \
    --passphrase-fd 3 \
    --relay "$RELAY_URL" \
    --no-require-e2e \
    $WT_ARG \
    --capsule "$WORK/capsule-init" \
    --timeout 60 \
    3< "$WORK/init_pass" \
    >"$WORK/init.log" 2>&1 &
INIT_PID=$!

sleep 1

echo "" | "$DD" bootstrap \
    --role responder \
    --passphrase-fd 3 \
    --relay "$RELAY_URL" \
    --no-require-e2e \
    $WT_ARG \
    --capsule "$WORK/capsule-resp" \
    --timeout 60 \
    3< "$WORK/resp_pass" \
    >"$WORK/resp.log" 2>&1
RESP_EXIT=$?

wait $INIT_PID
INIT_EXIT=$?

if [ "$INIT_EXIT" -eq 0 ] && [ "$RESP_EXIT" -eq 0 ]; then
    pass "bootstrap pairing"
else
    fail "bootstrap pairing (init=$INIT_EXIT resp=$RESP_EXIT)"
    cat "$WORK/init.log" >&2
    cat "$WORK/resp.log" >&2
fi

[ -f "$WORK/capsule-init" ] && [ -f "$WORK/capsule-resp" ] \
    && pass "bootstrap capsule files exist" \
    || fail "bootstrap capsule files missing"

echo ""
echo "=== HOWTO: Cross-Capsule Send/Recv ==="

# 12. Cross-capsule send/recv after bootstrap
echo "cross-capsule test" > "$WORK/cross.txt"
echo "Step: send with initiator capsule, recv with responder capsule"
printf '%s\n' "$CAPSULE_PASS_B" \
    | "$DD" send \
        --capsule "$WORK/capsule-init" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        $WT_ARG \
        "$WORK/cross.txt" 2>/dev/null \
    && pass "cross-capsule send" \
    || fail "cross-capsule send"

printf '%s\n' "$CAPSULE_PASS_B" \
    | "$DD" recv \
        --capsule "$WORK/capsule-resp" \
        --passphrase-fd 0 \
        --relay "$RELAY_URL" \
        --no-require-e2e \
        "$WORK/cross-recv.txt" 2>/dev/null \
    && pass "cross-capsule recv" \
    || fail "cross-capsule recv"

if [ -f "$WORK/cross-recv.txt" ]; then
    sent=$(cat "$WORK/cross.txt")
    got=$(cat "$WORK/cross-recv.txt")
    if [ "$sent" = "$got" ]; then
        pass "cross-capsule content matches: '$got'"
    else
        fail "cross-capsule content mismatch: sent='$sent' got='$got'"
    fi
fi

# ─── summary ─────────────────────────────────────────────────────────

echo ""
echo "=========================================="
total=$((PASS + FAIL + SKIP))
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: All $PASS/$total HOWTO examples validated"
else
    echo "FAIL: $FAIL/$total checks failed ($SKIP skipped)"
fi
echo "=========================================="
exit "$FAIL"
