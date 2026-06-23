#!/bin/sh
# Copyright (c) 2026 Nenad Mićić
# SPDX-License-Identifier: Apache-2.0
#
# E2E round-trip harness. Builds the deaddrop + deaddrop-relay
# binaries, starts the relay on a free port with --local-only, and
# exercises `deaddrop send` → `deaddrop recv` end-to-end — once writing
# to a file, once writing to stdout — verifying the SHA-256 of the
# received bytes matches the sent bytes on both paths.
#
# Portable sh — no arrays, no [[ ]], no process substitution, no seq.
# Targets Linux + macOS. `sleep 0.1` is a GNU/BSD extension (not strict
# POSIX) which both platforms support.

set -eu

# ---------------------------------------------------------------------------
# Setup. WORK is a private tempdir (do NOT reuse $TMPDIR, which is a
# POSIX-reserved env var consulted by mktemp/go build/etc.). The
# cleanup trap fires on ANY exit — including a failed build in step 1
# — so the tempdir is always removed.
# ---------------------------------------------------------------------------

DEPLOY_SECRET_HEX="0101010101010101010101010101010101010101010101010101010101010101"
PASSPHRASE="e2e-test-passphrase"
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

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

# free_port picks an unused TCP port. Falls back to a fixed port if
# neither python3 nor perl is available (CI images should have one).
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
    || perl -e 'use Socket; socket(S,PF_INET,SOCK_STREAM,0) or die; bind(S,sockaddr_in(0,INADDR_ANY)) or die; my ($p)=sockaddr_in(getsockname(S)); print "$p\n"' 2>/dev/null \
    || echo "9876"
}

# wait_ready polls the relay's listener — any valid HTTP status proves
# the socket is bound and the Handler is serving. The relay has no
# /health endpoint; an unknown path returns 404 which is fine here.
# Falls back to `nc -z` if curl is unavailable, then a fixed sleep.
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
  # Last-ditch: assume the relay is up after a 2-second grace period.
  if ! command -v curl >/dev/null 2>&1 && ! command -v nc >/dev/null 2>&1; then
    sleep 2
    return 0
  fi
  return 1
}

# hash256 computes the SHA-256 of $1 using sha256sum (Linux) or
# shasum -a 256 (macOS). Uses a capture-then-guard pattern because
# `cmd | cut` exits 0 even when cmd is absent — pipeline status is
# the final command's status, which `cut` happily returns.
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

# ---------------------------------------------------------------------------
# Steps.
# ---------------------------------------------------------------------------

# 1. Build binaries (static, trimpath) into $WORK.
echo "==> building deaddrop + deaddrop-relay"
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop \
  || { echo "FAIL: go build deaddrop" >&2; exit 1; }
CGO_ENABLED=0 go build -trimpath -o "$WORK/deaddrop-relay" ./cmd/deaddrop-relay \
  || { echo "FAIL: go build deaddrop-relay" >&2; exit 1; }

# 2. Pick a free port.
RELAY_PORT=$(free_port)
echo "==> relay port: $RELAY_PORT"

# 3. Start relay (background) — --local-only skips mlockall and
#    permits the empty write-token. v0.2.0: --deploy-secret on argv
#    removed (D-72); relay reads $DEADDROP_DEPLOY_SECRET from env.
echo "==> starting relay"
"$WORK/deaddrop-relay" \
  --listen ":${RELAY_PORT}" \
  --local-only \
  >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!

# 4. Wait for readiness.
if ! wait_ready; then
  echo "FAIL: relay did not become ready within 3s" >&2
  echo "--- relay.log ---" >&2
  cat "$WORK/relay.log" >&2 || true
  exit 1
fi

# 5. Keygen — passphrase read twice by ReadPassphraseConfirm. Go's
# flag package stops parsing at the first non-flag token, so flags
# must precede the positional <out-path>.
echo "==> keygen"
printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
  | "$WORK/deaddrop" keygen --passphrase-fd 0 "$WORK/capsule" >/dev/null \
  || { echo "FAIL: keygen" >&2; exit 1; }

# 6. Payload 1 — file round-trip.
dd if=/dev/urandom bs=256 count=1 >"$WORK/payload.bin" 2>/dev/null
SEND_SHA=$(hash256 "$WORK/payload.bin") || exit 1

# 7. Send payload 1. Flags precede the positional <file> for the
# same reason keygen does (stdlib flag package semantics).
echo "==> send (file → relay)"
printf '%s\n' "$PASSPHRASE" \
  | "$WORK/deaddrop" send \
      --capsule "$WORK/capsule" \
      --passphrase-fd 0 \
      --relay "http://127.0.0.1:${RELAY_PORT}" \
      --no-require-e2e \
      "$WORK/payload.bin" \
  || { echo "FAIL: send" >&2; exit 1; }

# 8. Recv payload 1 to file. Flags before the optional [output].
echo "==> recv (relay → file)"
printf '%s\n' "$PASSPHRASE" \
  | "$WORK/deaddrop" recv \
      --capsule "$WORK/capsule" \
      --passphrase-fd 0 \
      --relay "http://127.0.0.1:${RELAY_PORT}" \
      --no-require-e2e \
      "$WORK/received.bin" \
  || { echo "FAIL: recv to file" >&2; exit 1; }

# 9. Diff.
RECV_SHA=$(hash256 "$WORK/received.bin") || exit 1
if [ "$SEND_SHA" != "$RECV_SHA" ]; then
  echo "FAIL: file round-trip checksum mismatch" >&2
  echo "  sent: $SEND_SHA" >&2
  echo "  recv: $RECV_SHA" >&2
  exit 1
fi

# 10. Payload 2 — stdout round-trip. Do NOT capture binary stdout into
#     a shell variable ($() strips trailing newlines and truncates at
#     NUL). Redirect to a file and compare that.
dd if=/dev/urandom bs=128 count=1 >"$WORK/payload2.bin" 2>/dev/null
SEND2_SHA=$(hash256 "$WORK/payload2.bin") || exit 1

echo "==> send (file → relay, 2nd payload)"
printf '%s\n' "$PASSPHRASE" \
  | "$WORK/deaddrop" send \
      --capsule "$WORK/capsule" \
      --passphrase-fd 0 \
      --relay "http://127.0.0.1:${RELAY_PORT}" \
      --no-require-e2e \
      "$WORK/payload2.bin" \
  || { echo "FAIL: send (stdout test)" >&2; exit 1; }

echo "==> recv (relay → stdout → file)"
printf '%s\n' "$PASSPHRASE" \
  | "$WORK/deaddrop" recv \
      --capsule "$WORK/capsule" \
      --passphrase-fd 0 \
      --relay "http://127.0.0.1:${RELAY_PORT}" \
      --no-require-e2e \
      >"$WORK/received2.bin" \
  || { echo "FAIL: recv to stdout" >&2; exit 1; }

RECV2_SHA=$(hash256 "$WORK/received2.bin") || exit 1
if [ "$SEND2_SHA" != "$RECV2_SHA" ]; then
  echo "FAIL: stdout round-trip checksum mismatch" >&2
  echo "  sent: $SEND2_SHA" >&2
  echo "  recv: $RECV2_SHA" >&2
  exit 1
fi

# 11. Done.
echo "PASS: E2E round-trip (file + stdout)"
