#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end tests through the full TLS stack (Caddy → relay).
# Builds the deaddrop client binary and exercises send/recv through
# HTTPS with real TLS certificates.
#
# Usage:
#   sh test/e2e/e2e-tls.sh
#
# Environment (reads from /etc/deaddrop/relay.env or override):
#   DEADDROP_RELAY          — relay base URL with CADDY_PREFIX
#   DEADDROP_DEPLOY_SECRET  — hex:... deploy secret
#   DEADDROP_WRITE_TOKEN    — hex:... write token
#
# Or just set RELAY_ENV to point at the env file:
#   RELAY_ENV=/etc/deaddrop/relay.env sh test/e2e/e2e-tls.sh
set -eu

# ─── configuration ───────────────────────────────────────────────────

RELAY_ENV="${RELAY_ENV:-/etc/deaddrop/relay.env}"

if [ -f "$RELAY_ENV" ] && [ -z "${DEADDROP_RELAY:-}" ]; then
    # shellcheck disable=SC1090
    . "$RELAY_ENV"
    export DEADDROP_DEPLOY_SECRET
    export DEADDROP_WRITE_TOKEN
    DEADDROP_RELAY="https://${SITE_ADDR}/${CADDY_PREFIX}"
    export DEADDROP_RELAY
fi

: "${DEADDROP_RELAY:?DEADDROP_RELAY not set — provide relay URL or RELAY_ENV}"
: "${DEADDROP_DEPLOY_SECRET:?DEADDROP_DEPLOY_SECRET not set}"
: "${DEADDROP_WRITE_TOKEN:?DEADDROP_WRITE_TOKEN not set}"

PASSPHRASE="e2e-tls-test-$(date +%s)"
PASS=0
FAIL=0
WORK=$(mktemp -d)
DEADDROP=""

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ─── helpers ─────────────────────────────────────────────────────────

hash256() {
    h=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$h" ]; then
        h=$(shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1)
    fi
    if [ -z "$h" ]; then echo "FAIL: cannot compute SHA-256" >&2; return 1; fi
    printf '%s\n' "$h"
}

pass() { PASS=$((PASS + 1)); echo "    PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "    FAIL: $1" >&2; }

send_file() {
    printf '%s\n' "$PASSPHRASE" \
        | "$DEADDROP" send \
            --capsule "$WORK/capsule" \
            --passphrase-fd 0 \
            --no-require-e2e \
            "$1" 2>/dev/null
}

recv_file() {
    printf '%s\n' "$PASSPHRASE" \
        | "$DEADDROP" recv \
            --capsule "$WORK/capsule" \
            --passphrase-fd 0 \
            --no-require-e2e \
            "$1" 2>/dev/null
}

recv_stdout() {
    printf '%s\n' "$PASSPHRASE" \
        | "$DEADDROP" recv \
            --capsule "$WORK/capsule" \
            --passphrase-fd 0 \
            --no-require-e2e \
            2>/dev/null
}

# ─── check tools ─────────────────────────────────────────────────────

for tool in curl go; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FATAL: $tool not found" >&2; exit 1
    }
done

# ─── build client ────────────────────────────────────────────────────

echo "==> building deaddrop client"
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop \
    || { echo "FAIL: go build" >&2; exit 1; }
DEADDROP="$WORK/deaddrop"

# ─── smoke test ──────────────────────────────────────────────────────

echo "==> smoke: HTTPS connectivity"
code=$(curl -s -o /dev/null -w '%{http_code}' "${DEADDROP_RELAY}/00000000000000000000000000000000/00000000000000000000000000000000" 2>/dev/null || echo "000")
if [ "$code" = "404" ]; then
    pass "HTTPS 404"
else
    fail "expected 404, got $code"
    echo "    TLS stack may not be ready — aborting" >&2
    exit 1
fi

# ─── keygen ──────────────────────────────────────────────────────────

echo "==> keygen"
printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
    | "$DEADDROP" keygen --passphrase-fd 0 "$WORK/capsule" >/dev/null 2>&1 \
    || { fail "keygen"; exit 1; }

# ─── test 1: 256-byte round-trip ─────────────────────────────────────

echo "==> test 1: 256B round-trip"
dd if=/dev/urandom bs=256 count=1 >"$WORK/p1.bin" 2>/dev/null
SHA1=$(hash256 "$WORK/p1.bin")
if send_file "$WORK/p1.bin" && recv_file "$WORK/r1.bin"; then
    R1=$(hash256 "$WORK/r1.bin")
    if [ "$SHA1" = "$R1" ]; then pass "256B SHA-256 match"
    else fail "256B checksum mismatch"; fi
else
    fail "256B send/recv"
fi

# ─── test 2: 1 MiB round-trip ────────────────────────────────────────

echo "==> test 2: 1MiB round-trip"
dd if=/dev/urandom bs=1048576 count=1 >"$WORK/p2.bin" 2>/dev/null
SHA2=$(hash256 "$WORK/p2.bin")
if send_file "$WORK/p2.bin" && recv_file "$WORK/r2.bin"; then
    R2=$(hash256 "$WORK/r2.bin")
    if [ "$SHA2" = "$R2" ]; then pass "1MiB SHA-256 match"
    else fail "1MiB checksum mismatch"; fi
else
    fail "1MiB send/recv"
fi

# ─── test 3: 10 MiB round-trip ───────────────────────────────────────

echo "==> test 3: 10MiB round-trip"
dd if=/dev/urandom bs=1048576 count=10 >"$WORK/p3.bin" 2>/dev/null
SHA3=$(hash256 "$WORK/p3.bin")
if send_file "$WORK/p3.bin" && recv_file "$WORK/r3.bin"; then
    R3=$(hash256 "$WORK/r3.bin")
    if [ "$SHA3" = "$R3" ]; then pass "10MiB SHA-256 match"
    else fail "10MiB checksum mismatch"; fi
else
    fail "10MiB send/recv"
fi

# ─── test 4: one-shot semantics ──────────────────────────────────────

echo "==> test 4: one-shot semantics"
dd if=/dev/urandom bs=64 count=1 >"$WORK/p4.bin" 2>/dev/null
if send_file "$WORK/p4.bin" && recv_file "$WORK/r4.bin"; then
    if recv_file "$WORK/r4b.bin" 2>/dev/null; then
        fail "second recv should have failed (one-shot)"
    else
        pass "second recv correctly rejected"
    fi
else
    fail "one-shot send/recv"
fi

# ─── test 5: recv to stdout ──────────────────────────────────────────

echo "==> test 5: recv → stdout"
dd if=/dev/urandom bs=128 count=1 >"$WORK/p5.bin" 2>/dev/null
SHA5=$(hash256 "$WORK/p5.bin")
if send_file "$WORK/p5.bin" && recv_stdout >"$WORK/r5.bin"; then
    R5=$(hash256 "$WORK/r5.bin")
    if [ "$SHA5" = "$R5" ]; then pass "stdout SHA-256 match"
    else fail "stdout checksum mismatch"; fi
else
    fail "stdout send/recv"
fi

# ─── test 6: wrong deploy-secret → auth failure ──────────────────────

echo "==> test 6: wrong deploy-secret"
dd if=/dev/urandom bs=32 count=1 >"$WORK/p6.bin" 2>/dev/null
if DEADDROP_DEPLOY_SECRET="hex:0000000000000000000000000000000000000000000000000000000000000000" \
    send_file "$WORK/p6.bin" 2>/dev/null; then
    fail "wrong deploy-secret should have failed"
else
    pass "wrong deploy-secret rejected"
fi

# ─── test 7: no write-token → auth failure ───────────────────────────

echo "==> test 7: missing write-token"
dd if=/dev/urandom bs=32 count=1 >"$WORK/p7.bin" 2>/dev/null
if DEADDROP_WRITE_TOKEN="" \
    printf '%s\n' "$PASSPHRASE" \
    | "$DEADDROP" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --write-token "" \
        "$WORK/p7.bin" 2>/dev/null; then
    fail "missing write-token should have failed"
else
    pass "missing write-token rejected"
fi

# ─── test 8: bootstrap + cross-capsule round-trip ────────────────────

echo "==> test 8: bootstrap pairing + cross-capsule send/recv"
BOOTSTRAP_PASS="bootstrap-e2e-$(date +%s)"
CAPSULE_PASS="capsule-e2e-$(date +%s)"

printf '%s\n%s\n' "$BOOTSTRAP_PASS" "$CAPSULE_PASS" > "$WORK/init_pass"
printf '%s\n%s\n' "$BOOTSTRAP_PASS" "$CAPSULE_PASS" > "$WORK/resp_pass"

echo "" | "$DEADDROP" bootstrap \
    --role initiator \
    --passphrase-fd 3 \
    --capsule "$WORK/capsule-init" \
    --timeout 60 \
    3< "$WORK/init_pass" \
    >"$WORK/init.log" 2>&1 &
INIT_PID=$!

sleep 1

echo "" | "$DEADDROP" bootstrap \
    --role responder \
    --passphrase-fd 3 \
    --capsule "$WORK/capsule-resp" \
    --timeout 60 \
    3< "$WORK/resp_pass" \
    >"$WORK/resp.log" 2>&1
RESP_EXIT=$?

wait $INIT_PID
INIT_EXIT=$?

if [ "$INIT_EXIT" -eq 0 ] && [ "$RESP_EXIT" -eq 0 ]; then
    pass "bootstrap pairing (initiator=$INIT_EXIT responder=$RESP_EXIT)"
else
    fail "bootstrap pairing (initiator=$INIT_EXIT responder=$RESP_EXIT)"
    cat "$WORK/init.log" >&2
    cat "$WORK/resp.log" >&2
fi

if [ -f "$WORK/capsule-init" ] && [ -f "$WORK/capsule-resp" ]; then
    pass "bootstrap capsule files created"
else
    fail "bootstrap capsule files missing"
fi

echo "==> test 9: cross-capsule send/recv"
echo "cross-capsule-e2e-test" > "$WORK/cross.txt"
if printf '%s\n' "$CAPSULE_PASS" \
    | "$DEADDROP" send \
        --capsule "$WORK/capsule-init" \
        --passphrase-fd 0 \
        "$WORK/cross.txt" 2>/dev/null; then
    pass "cross-capsule send"
else
    fail "cross-capsule send"
fi

if printf '%s\n' "$CAPSULE_PASS" \
    | "$DEADDROP" recv \
        --capsule "$WORK/capsule-resp" \
        --passphrase-fd 0 \
        "$WORK/cross-recv.txt" 2>/dev/null; then
    got=$(cat "$WORK/cross-recv.txt")
    if [ "$got" = "cross-capsule-e2e-test" ]; then
        pass "cross-capsule recv content match"
    else
        fail "cross-capsule content mismatch: '$got'"
    fi
else
    fail "cross-capsule recv"
fi

# ─── test 10: container security checks ──────────────────────────────

echo "==> test 10: container security posture"
if command -v docker >/dev/null 2>&1; then
    for cname in deaddrop-relay deaddrop-caddy; do
        info=$(docker inspect "$cname" 2>/dev/null) || continue

        ro=$(echo "$info" | grep -o '"ReadonlyRootfs": *true' | head -1)
        if [ -n "$ro" ]; then pass "$cname read-only rootfs"
        else fail "$cname NOT read-only"; fi

        nnp=$(echo "$info" | grep -o '"no-new-privileges:true"' | head -1)
        if [ -n "$nnp" ]; then pass "$cname no-new-privileges"
        else fail "$cname missing no-new-privileges"; fi
    done
else
    echo "    SKIP: docker not available (running remote?)"
fi

# ─── summary ─────────────────────────────────────────────────────────

echo ""
echo "=========================================="
total=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: All $total checks passed"
else
    echo "FAIL: $FAIL/$total checks failed"
fi
echo "=========================================="
exit "$FAIL"
