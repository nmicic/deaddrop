#!/usr/bin/env bash
# TEST-ONLY — see tools/test-derive/derive.go header.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DERIVE="$SCRIPT_DIR/test-derive"
# Resolve deaddrop binary: $DEADDROP_BIN > ./deaddrop in cwd > PATH
DEADDROP="${DEADDROP_BIN:-}"
if [ -z "$DEADDROP" ]; then
    [ -x "./deaddrop" ] && DEADDROP="./deaddrop" || DEADDROP="deaddrop"
fi

if [ $# -lt 1 ]; then
    echo "Usage: quick-recv.sh <capsule-path> [extra deaddrop flags...] [output-file]" >&2
    echo "  Env: DEADDROP_SITE_ADDR (preferred) or DEADDROP_RELAY_URL" >&2
    echo "  Note: a keygen (non-bootstrap) capsule needs --no-require-e2e (before the" >&2
    echo "        output path, since recv stops flag parsing at the first positional)." >&2
    exit 2
fi

CAPSULE="$1"; shift   # remaining args (flags then optional output) forwarded verbatim

if [ -n "${DEADDROP_SITE_ADDR:-}" ]; then
    DERIVE_ARGS=(--phrase-stdin --site-addr "$DEADDROP_SITE_ADDR")
elif [ -n "${DEADDROP_RELAY_URL:-}" ]; then
    DERIVE_ARGS=(--phrase-stdin --relay-url "$DEADDROP_RELAY_URL")
else
    echo "error: set DEADDROP_SITE_ADDR or DEADDROP_RELAY_URL" >&2
    exit 2
fi

read -rsp "Passphrase: " PHRASE; echo >&2
eval "$("$DERIVE" "${DERIVE_ARGS[@]}" <<< "$PHRASE")"

"$DEADDROP" recv \
    --capsule "$CAPSULE" \
    --passphrase-env DEADDROP_CAPSULE_PASSPHRASE \
    "$@"
