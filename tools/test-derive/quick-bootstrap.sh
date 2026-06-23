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

if [ $# -lt 2 ]; then
    echo "Usage: quick-bootstrap.sh <capsule-path> --role={initiator|responder}" >&2
    echo "  Env: DEADDROP_SITE_ADDR (preferred) or DEADDROP_RELAY_URL" >&2
    exit 2
fi

CAPSULE="$1"
shift

ROLE=""
for arg in "$@"; do
    case "$arg" in
        --role=*) ROLE="${arg#--role=}" ;;
        --role)   shift; ROLE="$1" ;;
    esac
done

if [ -z "$ROLE" ]; then
    echo "error: --role={initiator|responder} required" >&2
    exit 2
fi

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

echo "" | "$DEADDROP" bootstrap \
    --role "$ROLE" \
    --capsule "$CAPSULE" \
    --passphrase-fd 3 \
    --timeout 60 \
    3< <(printf '%s\n%s\n' "$DEADDROP_BOOTSTRAP_PA" "$DEADDROP_CAPSULE_PASSPHRASE")
