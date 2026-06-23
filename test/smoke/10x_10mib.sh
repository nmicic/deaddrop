#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test: 10 back-to-back 10 MiB send/recv cycles.
# Verifies: round-trip integrity, RSS stability, SIGTERM graceful exit.
#
# v0.2.0: --deploy-secret on argv removed (D-72). All commands use
# $DEADDROP_DEPLOY_SECRET env var or --deploy-secret-fd. --no-require-e2e
# is passed because this smoke test uses keygen (no bootstrap / no
# identity entry).
#
# Portable sh — no bash-isms. Targets Linux.
set -eu

DEPLOY_SECRET_HEX="0101010101010101010101010101010101010101010101010101010101010101"
PASSPHRASE="smoke-test-passphrase"
CYCLES=10
PAYLOAD_BYTES=10485760  # 10 MiB

export DEADDROP_DEPLOY_SECRET="hex:$DEPLOY_SECRET_HEX"

RELAY_PORT=""
RELAY_PID=""
WORK=$(mktemp -d)

cleanup() {
  if [ -n "$RELAY_PID" ]; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- helpers ---

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
    || perl -e 'use Socket; socket(S,PF_INET,SOCK_STREAM,0) or die; bind(S,sockaddr_in(0,INADDR_ANY)) or die; my ($p)=sockaddr_in(getsockname(S)); print "$p\n"' 2>/dev/null \
    || echo "9876"
}

wait_ready() {
  _i=0
  while [ "$_i" -lt 30 ]; do
    _i=$((_i + 1))
    if command -v curl >/dev/null 2>&1; then
      _code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${RELAY_PORT}/__ready" 2>/dev/null || echo "000")
      case "$_code" in
        [1-9][0-9][0-9]) return 0 ;;
      esac
    elif command -v nc >/dev/null 2>&1; then
      if nc -z 127.0.0.1 "$RELAY_PORT" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 0.1
  done
  if ! command -v curl >/dev/null 2>&1 && ! command -v nc >/dev/null 2>&1; then
    sleep 2
    return 0
  fi
  return 1
}

hash256() {
  h=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)
  if [ -z "$h" ]; then
    h=$(shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1)
  fi
  if [ -z "$h" ]; then
    echo "FAIL: cannot compute SHA-256 for $1" >&2
    return 1
  fi
  printf '%s\n' "$h"
}

get_rss_kb() {
  ps -o rss= -p "$1" 2>/dev/null | tr -d ' '
}

# --- build ---

echo "==> building deaddrop + deaddrop-relay"
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop \
  || { echo "FAIL: go build deaddrop" >&2; exit 1; }
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop-relay" ./cmd/deaddrop-relay \
  || { echo "FAIL: go build deaddrop-relay" >&2; exit 1; }

# --- start relay ---

RELAY_PORT=$(free_port)
echo "==> relay port: $RELAY_PORT"

"$WORK/deaddrop-relay" \
  --listen ":${RELAY_PORT}" \
  --max-blob-bytes 11000000 \
  --local-only \
  >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!

if ! wait_ready; then
  echo "FAIL: relay did not become ready" >&2
  cat "$WORK/relay.log" >&2 || true
  exit 1
fi

# --- keygen ---

echo "==> keygen"
printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
  | "$WORK/deaddrop" keygen --passphrase-fd 0 "$WORK/capsule" >/dev/null \
  || { echo "FAIL: keygen" >&2; exit 1; }

# --- 10 MiB cycles ---

rss_values=""
cycle=1
while [ "$cycle" -le "$CYCLES" ]; do
  echo "==> cycle $cycle/$CYCLES: generating ${PAYLOAD_BYTES}-byte payload"
  dd if=/dev/urandom bs=1048576 count=10 of="$WORK/payload.bin" 2>/dev/null

  send_sha=$(hash256 "$WORK/payload.bin") || exit 1

  printf '%s\n' "$PASSPHRASE" \
    | "$WORK/deaddrop" send \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "http://127.0.0.1:${RELAY_PORT}" \
        --no-require-e2e \
        "$WORK/payload.bin" \
    || { echo "FAIL: send cycle $cycle" >&2; exit 1; }

  printf '%s\n' "$PASSPHRASE" \
    | "$WORK/deaddrop" recv \
        --capsule "$WORK/capsule" \
        --passphrase-fd 0 \
        --relay "http://127.0.0.1:${RELAY_PORT}" \
        --no-require-e2e \
        "$WORK/received.bin" \
    || { echo "FAIL: recv cycle $cycle" >&2; exit 1; }

  recv_sha=$(hash256 "$WORK/received.bin") || exit 1
  if [ "$send_sha" != "$recv_sha" ]; then
    echo "FAIL: checksum mismatch cycle $cycle" >&2
    echo "  sent: $send_sha" >&2
    echo "  recv: $recv_sha" >&2
    exit 1
  fi

  rss=$(get_rss_kb "$RELAY_PID")
  if [ -z "$rss" ]; then
    echo "FAIL: could not read RSS for relay (PID $RELAY_PID) at cycle $cycle" >&2
    exit 1
  fi
  echo "    cycle $cycle PASS (relay RSS: ${rss} KiB)"
  rss_values="${rss_values} ${rss}"

  rm -f "$WORK/payload.bin" "$WORK/received.bin"
  cycle=$((cycle + 1))
done

# --- RSS stability check ---

echo "==> checking RSS stability"
first_rss=""
last_rss=""
monotonic=true
prev_rss=0
for rss in $rss_values; do
  if [ -z "$first_rss" ]; then
    first_rss=$rss
  fi
  if [ "$rss" -le "$prev_rss" ] 2>/dev/null && [ "$prev_rss" -gt 0 ]; then
    monotonic=false
  fi
  prev_rss=$rss
  last_rss=$rss
done

if [ "$monotonic" = true ] && [ "$CYCLES" -gt 2 ]; then
  echo "WARN: RSS grew monotonically across all $CYCLES cycles (${first_rss} -> ${last_rss} KiB)" >&2
  echo "  This may indicate a memory leak." >&2
fi

# Allow up to 50% growth from first to last as normal variance
if [ -n "$first_rss" ] && [ -n "$last_rss" ] && [ "$first_rss" -gt 0 ]; then
  growth_limit=$(( first_rss + first_rss / 2 ))
  if [ "$last_rss" -gt "$growth_limit" ]; then
    echo "FAIL: RSS grew from ${first_rss} to ${last_rss} KiB (>50% growth)" >&2
    exit 1
  fi
fi
echo "    RSS stable: ${first_rss} -> ${last_rss} KiB"

# --- SIGTERM graceful shutdown ---

echo "==> cycle 11: SIGTERM with slot in store"
dd if=/dev/urandom bs=1048576 count=10 of="$WORK/payload.bin" 2>/dev/null
printf '%s\n' "$PASSPHRASE" \
  | "$WORK/deaddrop" send \
      --capsule "$WORK/capsule" \
      --passphrase-fd 0 \
      --relay "http://127.0.0.1:${RELAY_PORT}" \
      --no-require-e2e \
      "$WORK/payload.bin" \
  || { echo "FAIL: send cycle 11" >&2; exit 1; }

kill -TERM "$RELAY_PID"
wait "$RELAY_PID" 2>/dev/null
relay_exit=$?
RELAY_PID=""

if [ "$relay_exit" -eq 0 ]; then
  echo "    SIGTERM: relay exited 0 (graceful shutdown; zeroization verified by unit tests)"
else
  echo "FAIL: relay exited $relay_exit after SIGTERM (expected 0)" >&2
  exit 1
fi

echo ""
echo "PASS: 10x 10MiB smoke test (${CYCLES} cycles + SIGTERM)"
