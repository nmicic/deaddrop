#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Single-command deployment for deaddrop.
# Reads target configuration from deployment.yaml and deploys via SSH.
# Both relay and Caddy run in Docker with full security hardening.
#
# Usage:
#   ./scripts/deploy.sh vm          # deploy to KVM VM (self-signed TLS)
#   ./scripts/deploy.sh vps         # deploy to production VPS (Let's Encrypt)
#   ./scripts/deploy.sh vm --clean  # wipe containers first
#   ./scripts/deploy.sh vm --test   # deploy + smoke test
#
# Targets are defined in deployment.yaml (see deployment.yaml.example).
# This script runs entirely from the dev host — no manual SSH steps.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_YAML="$REPO_ROOT/deployment.yaml"

TARGET=""
CLEAN=false
RUN_TESTS=false

for arg in "$@"; do
    case $arg in
        --clean) CLEAN=true ;;
        --test)  RUN_TESTS=true ;;
        --help)  head -16 "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        -*)      echo "Unknown option: $arg" >&2; exit 1 ;;
        *)       TARGET="$arg" ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [--clean] [--test]" >&2
    echo "Targets: vm, vps (defined in deployment.yaml)" >&2
    exit 1
fi

if [ ! -f "$DEPLOY_YAML" ]; then
    echo "ERROR: $DEPLOY_YAML not found." >&2
    echo "Copy deployment.yaml.example to deployment.yaml and fill in." >&2
    exit 1
fi

# ─── Parse deployment.yaml ──────────────────────────────────────────
yaml_get() {
    awk -v section="$1" -v key="$2" '
        /^[^ #]/ { in_section = ($0 ~ "^" section ":") }
        in_section && $0 ~ "^  " key ":" {
            val = $0; sub(/^[^:]*: */, "", val)
            gsub(/["'"'"']/, "", val)
            print val
        }
    ' "$DEPLOY_YAML"
}

HOST=$(yaml_get "$TARGET" host)
USER=$(yaml_get "$TARGET" user)
TLS=$(yaml_get "$TARGET" tls)
DOMAIN=$(yaml_get "$TARGET" domain)
ENV_PATH=$(yaml_get "$TARGET" env_path)
DEPLOY_DIR=$(yaml_get "$TARGET" deploy_dir)

if [ -z "$HOST" ]; then
    echo "ERROR: target '$TARGET' not found in $DEPLOY_YAML" >&2
    exit 1
fi

SSH_TARGET="${USER:-root}@${HOST}"
DEPLOY_DIR="${DEPLOY_DIR:-/root/deaddrop}"
TLS="${TLS:-acme}"
SITE_ADDR="${DOMAIN:-$HOST}"

ts() { date '+%H:%M:%S'; }

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  deaddrop deploy → $TARGET"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Host:       $SSH_TARGET"
echo "  Deploy dir: $DEPLOY_DIR"
echo "  TLS:        $TLS"
echo "  Site addr:  $SITE_ADDR"
echo "  Git SHA:    $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
echo ""

# ─── 1. Verify SSH ──────────────────────────────────────────────────
echo "[$(ts)] Checking SSH to $SSH_TARGET..."
if ! ssh -o ConnectTimeout=5 $SSH_TARGET 'echo ok' >/dev/null 2>&1; then
    echo "ERROR: Cannot SSH to $SSH_TARGET" >&2
    exit 1
fi
echo "[$(ts)] SSH OK"

# ─── 2. Clean if requested ──────────────────────────────────────────
if [ "$CLEAN" = true ]; then
    echo "[$(ts)] Cleaning existing deployment..."
    ssh $SSH_TARGET "cd $DEPLOY_DIR 2>/dev/null && \
        docker compose down -v 2>/dev/null; \
        rm -rf $DEPLOY_DIR" 2>&1 || true
    echo "[$(ts)] Cleaned"
fi

# ─── 3. Sync code via git archive ────────────────────────────────────
echo "[$(ts)] Syncing code..."
git -C "$REPO_ROOT" archive --format=tar HEAD \
    | ssh $SSH_TARGET "mkdir -p $DEPLOY_DIR && cd $DEPLOY_DIR && tar xf -"
echo "[$(ts)] Code synced ($(git -C "$REPO_ROOT" rev-parse --short HEAD))"

# ─── 4. Set up .env ──────────────────────────────────────────────────
echo "[$(ts)] Setting up secrets..."
if [ -n "$ENV_PATH" ]; then
    # Target has a dedicated env file (e.g. /etc/deaddrop/relay.env on VPS).
    # Copy it to .env; if it doesn't exist yet, generate new secrets.
    ssh $SSH_TARGET "
        if [ -f '$ENV_PATH' ]; then
            cp '$ENV_PATH' '$DEPLOY_DIR/.env'
            chmod 600 '$DEPLOY_DIR/.env'
            echo '    .env copied from $ENV_PATH'
        else
            mkdir -p \$(dirname '$ENV_PATH')
            cat > '$DEPLOY_DIR/.env' <<ENVEOF
DEADDROP_DEPLOY_SECRET=hex:\$(openssl rand -hex 32)
DEADDROP_WRITE_TOKEN=hex:\$(openssl rand -hex 32)
CADDY_PREFIX=\$(openssl rand -hex 16)
SITE_ADDR=$SITE_ADDR
ENVEOF
            chmod 600 '$DEPLOY_DIR/.env'
            cp '$DEPLOY_DIR/.env' '$ENV_PATH'
            chmod 600 '$ENV_PATH'
            echo '    .env generated → $ENV_PATH'
        fi"
else
    # No dedicated env file — generate in deploy dir on first deploy.
    ssh $SSH_TARGET "
        if [ ! -f '$DEPLOY_DIR/.env' ]; then
            cat > '$DEPLOY_DIR/.env' <<ENVEOF
DEADDROP_DEPLOY_SECRET=hex:\$(openssl rand -hex 32)
DEADDROP_WRITE_TOKEN=hex:\$(openssl rand -hex 32)
CADDY_PREFIX=\$(openssl rand -hex 16)
SITE_ADDR=$SITE_ADDR
ENVEOF
            chmod 600 '$DEPLOY_DIR/.env'
            echo '    .env created (new secrets)'
        else
            echo '    .env exists (keeping secrets)'
        fi"
fi

# ─── 5. Patch for self-signed TLS (internal targets) ─────────────────
if [ "$TLS" = "internal" ]; then
    echo "[$(ts)] Patching for self-signed TLS..."
    ssh $SSH_TARGET "cd '$DEPLOY_DIR' && \
        awk '/SITE_ADDR/ && !/^#/ {
            print \"{\"
            print \"    default_sni \" \$0
            print \"}\"
            print \"\"
            print
            print \"tls internal\"
            next
        } 1' deploy/caddy/Caddyfile > /tmp/cf.tmp && \
        mv /tmp/cf.tmp deploy/caddy/Caddyfile && \
        sed -i '/seccomp:/d' docker-compose.yml"
fi

# ─── 6. Production hardening (ACME targets) ──────────────────────────
if [ "$TLS" = "acme" ]; then
    echo "[$(ts)] Applying production hardening..."
    ssh $SSH_TARGET "
        swapoff -a 2>/dev/null || true
        sed -i '/\\sswap\\s/d' /etc/fstab 2>/dev/null || true
        systemctl mask swap.target 2>/dev/null || true
        echo '    swap disabled'
    "
fi

# ─── 7. Install Docker if missing ────────────────────────────────────
echo "[$(ts)] Checking Docker..."
ssh $SSH_TARGET "
    if ! docker compose version >/dev/null 2>&1; then
        echo '    installing Docker...'
        apt-get update -qq
        apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
        systemctl enable --now docker
        echo '    Docker installed'
    else
        echo '    Docker OK'
    fi"

# ─── 8. Stop legacy systemd relay (pre-v0.2.0 migration) ────────────
ssh $SSH_TARGET "
    if systemctl is-active --quiet deaddrop-relay 2>/dev/null; then
        echo '[$(ts)] Stopping legacy systemd relay...'
        systemctl stop deaddrop-relay
        systemctl disable deaddrop-relay 2>/dev/null || true
        echo '    legacy relay stopped (migrated to Docker)'
    fi" 2>/dev/null || true

# ─── 9. Build and start containers ───────────────────────────────────
echo "[$(ts)] Building and starting containers..."
ssh $SSH_TARGET "cd '$DEPLOY_DIR' && \
    docker compose down 2>/dev/null; \
    docker stop deaddrop-relay deaddrop-caddy 2>/dev/null; \
    docker rm deaddrop-relay deaddrop-caddy 2>/dev/null; \
    docker compose up -d --build 2>&1 | tail -5"
echo "[$(ts)] Containers started"

# ─── 10. Wait for TLS health ─────────────────────────────────────────
echo "[$(ts)] Waiting for TLS health..."
_tries=0
while [ "$_tries" -lt 30 ]; do
    if [ "$TLS" = "internal" ]; then
        _code=$(ssh $SSH_TARGET "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/ 2>/dev/null" || echo "000")
    else
        _code=$(ssh $SSH_TARGET "curl -s -o /dev/null -w '%{http_code}' --resolve '${SITE_ADDR}:443:127.0.0.1' 'https://${SITE_ADDR}/' 2>/dev/null" || echo "000")
    fi
    case "$_code" in
        [1-9][0-9][0-9])
            echo "[$(ts)] TLS ready (HTTPS → $_code)"
            break
            ;;
    esac
    _tries=$((_tries + 1))
    sleep 2
done
if [ "$_tries" -ge 30 ]; then
    echo "[$(ts)] ERROR: TLS not ready after 60s"
    ssh $SSH_TARGET "docker logs deaddrop-caddy 2>&1 | tail -10; docker logs deaddrop-relay 2>&1 | tail -10"
    exit 1
fi

# ─── 11. Extract relay URL ───────────────────────────────────────────
CADDY_PREFIX=$(ssh $SSH_TARGET "grep '^CADDY_PREFIX=' '$DEPLOY_DIR/.env' | cut -d= -f2")
DEPLOY_SECRET=$(ssh $SSH_TARGET "grep -E '^(DEADDROP_)?DEPLOY_SECRET=' '$DEPLOY_DIR/.env' | head -1 | cut -d= -f2-")
WRITE_TOKEN=$(ssh $SSH_TARGET "grep -E '^(DEADDROP_)?WRITE_TOKEN=' '$DEPLOY_DIR/.env' | head -1 | cut -d= -f2-")

if [ "$TLS" = "internal" ]; then
    RELAY_URL="https://${HOST}/${CADDY_PREFIX}"
else
    RELAY_URL="https://${SITE_ADDR}/${CADDY_PREFIX}"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  DEPLOYMENT COMPLETE                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target:        $TARGET ($TLS)"
echo "  Relay URL:     $RELAY_URL"
echo "  Git SHA:       $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
echo ""
echo "  Client usage:"
echo "    export DEADDROP_RELAY='$RELAY_URL'"
echo "    export DEADDROP_DEPLOY_SECRET='$DEPLOY_SECRET'"
echo "    export DEADDROP_WRITE_TOKEN='$WRITE_TOKEN'"
echo ""

# ─── 12. Optional smoke test ─────────────────────────────────────────
if [ "$RUN_TESTS" = true ]; then
    echo "[$(ts)] Running smoke test from host..."
    export DEADDROP_RELAY="$RELAY_URL"
    export DEADDROP_DEPLOY_SECRET="$DEPLOY_SECRET"
    export DEADDROP_WRITE_TOKEN="$WRITE_TOKEN"

    WORK=$(mktemp -d)
    trap "rm -rf $WORK" EXIT
    PASSPHRASE="deploy-test-passphrase"

    # For self-signed TLS: extract Caddy root CA so Go trusts it.
    if [ "$TLS" = "internal" ]; then
        ssh $SSH_TARGET "docker exec deaddrop-caddy cat /data/caddy/pki/authorities/local/root.crt" \
            > "$WORK/caddy-root.crt" 2>/dev/null
        export SSL_CERT_FILE="$WORK/caddy-root.crt"
    fi

    (cd "$REPO_ROOT" && go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop)

    printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
        | "$WORK/deaddrop" keygen --passphrase-fd 0 "$WORK/capsule" 2>/dev/null

    echo "hello from $TARGET at $(git -C "$REPO_ROOT" rev-parse --short HEAD)" > "$WORK/msg.txt"

    printf '%s' "$PASSPHRASE" \
        | "$WORK/deaddrop" send --capsule "$WORK/capsule" --passphrase-fd 0 \
            --write-token "$WRITE_TOKEN" --no-require-e2e "$WORK/msg.txt" 2>/dev/null
    echo "    send: OK"

    printf '%s' "$PASSPHRASE" \
        | "$WORK/deaddrop" recv --capsule "$WORK/capsule" --passphrase-fd 0 \
            --no-require-e2e "$WORK/received.txt" 2>/dev/null
    echo "    recv: OK"

    if diff -q "$WORK/msg.txt" "$WORK/received.txt" >/dev/null; then
        echo "    round-trip: PASS"
    else
        echo "    round-trip: FAIL"
        exit 1
    fi
    echo "[$(ts)] Smoke test passed"
fi
