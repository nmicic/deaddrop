#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# QA round-trip: flat one-liner commands, copy-paste friendly.
# Each line is a standalone test step — no loops, no conditionals.
#
# v0.2.0: --deploy-secret on argv removed (D-72). All commands use
# $DEADDROP_DEPLOY_SECRET env var. --no-require-e2e is passed because
# this QA script uses keygen (no bootstrap / no identity entry).
set -eux

# --- config ---

SECRET=0101010101010101010101010101010101010101010101010101010101010101
PASS=test-passphrase
PORT=19876
WORK=/tmp/deaddrop-qa-$$

export DEADDROP_DEPLOY_SECRET="hex:$SECRET"

# --- setup ---

mkdir -p "$WORK"

go build -trimpath -o "$WORK/deaddrop"       ./cmd/deaddrop
go build -trimpath -o "$WORK/deaddrop-relay"  ./cmd/deaddrop-relay

"$WORK/deaddrop-relay" --listen ":$PORT" --local-only >"$WORK/relay.log" 2>&1 &
echo "$!" > "$WORK/relay.pid"
sleep 1

# --- keygen ---

printf '%s\n%s\n' "$PASS" "$PASS" | "$WORK/deaddrop" keygen --passphrase-fd 0 "$WORK/capsule"

# --- test 1: small file (256 bytes) ---

dd if=/dev/urandom of="$WORK/small.bin" bs=256 count=1 2>/dev/null
md5sum "$WORK/small.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/small.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/small-received.bin"

md5sum "$WORK/small-received.bin"

diff "$WORK/small.bin" "$WORK/small-received.bin"
echo "PASS: small file round-trip"

# --- test 2: 1 MiB file ---

dd if=/dev/urandom of="$WORK/medium.bin" bs=1048576 count=1 2>/dev/null
md5sum "$WORK/medium.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/medium.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/medium-received.bin"

md5sum "$WORK/medium-received.bin"

diff "$WORK/medium.bin" "$WORK/medium-received.bin"
echo "PASS: 1 MiB file round-trip"

# --- test 3: 10 MiB file (max size) ---

dd if=/dev/urandom of="$WORK/large.bin" bs=1048576 count=10 2>/dev/null
md5sum "$WORK/large.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/large.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/large-received.bin"

md5sum "$WORK/large-received.bin"

diff "$WORK/large.bin" "$WORK/large-received.bin"
echo "PASS: 10 MiB file round-trip"

# --- test 4: recv to stdout ---

dd if=/dev/urandom of="$WORK/stdout-test.bin" bs=4096 count=1 2>/dev/null
md5sum "$WORK/stdout-test.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/stdout-test.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e > "$WORK/stdout-received.bin"

md5sum "$WORK/stdout-received.bin"

diff "$WORK/stdout-test.bin" "$WORK/stdout-received.bin"
echo "PASS: recv to stdout"

# --- test 5: one-shot semantics (second recv gets 404) ---

dd if=/dev/urandom of="$WORK/oneshot.bin" bs=256 count=1 2>/dev/null

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/oneshot.bin"

DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/oneshot-received.bin"

set +e
DEADDROP_PASSPHRASE="$PASS" "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-env DEADDROP_PASSPHRASE --relay "http://127.0.0.1:$PORT" --no-require-e2e "$WORK/oneshot-double.bin" 2>/dev/null
SECOND_RECV=$?
set -e
test "$SECOND_RECV" -ne 0
echo "PASS: second recv correctly fails (one-shot semantics)"

# --- cleanup ---

kill "$(cat "$WORK/relay.pid")" 2>/dev/null || true
wait 2>/dev/null || true
rm -rf "$WORK"

echo ""
echo "ALL QA TESTS PASSED"
