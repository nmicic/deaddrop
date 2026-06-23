#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Single-command deployment for deaddrop on a fresh Ubuntu 22.04/24.04 VPS.
# Both relay and Caddy run in Docker with full security hardening.
#
# Usage:
#   git clone https://github.com/nmicic/deaddrop.git
#   cd deaddrop
#   sudo sh deploy/vm/quickstart.sh
#
# Prerequisites:
#   - /etc/deaddrop/relay.env with secrets (see below)
#   - DNS A record pointing SITE_ADDR to this server
#
# Idempotent — safe to re-run after updates.
set -eu

RELAY_ENV="/etc/deaddrop/relay.env"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ─── helpers ─────────────────────────────────────────────────────────

die() { echo "FATAL: $*" >&2; exit 1; }

check_tool() {
    command -v "$1" >/dev/null 2>&1 || return 1
}

# ─── prerequisites ───────────────────────────────────────────────────

[ "$(id -u)" -eq 0 ] || die "must run as root"

grep -q '^ID=ubuntu' /etc/os-release 2>/dev/null \
    || die "Ubuntu required"
ubuntu_ver=$(. /etc/os-release && echo "${VERSION_ID}")
case "$ubuntu_ver" in
    22.04|24.04) ;;
    *) die "Ubuntu 22.04 or 24.04 required (got $ubuntu_ver)" ;;
esac

if [ ! -f "$RELAY_ENV" ]; then
    echo "FATAL: $RELAY_ENV not found." >&2
    echo "" >&2
    echo "Create it before running quickstart:" >&2
    echo "  mkdir -p /etc/deaddrop" >&2
    echo "  cat > $RELAY_ENV <<'ENVEOF'" >&2
    echo "DEADDROP_DEPLOY_SECRET=hex:\$(openssl rand -hex 32)" >&2
    echo "DEADDROP_WRITE_TOKEN=hex:\$(openssl rand -hex 32)" >&2
    echo "CADDY_PREFIX=\$(openssl rand -hex 16)" >&2
    echo "SITE_ADDR=deaddrop.example.com" >&2
    echo "ENVEOF" >&2
    echo "  chmod 600 $RELAY_ENV" >&2
    exit 1
fi

# Validate required keys in relay.env.
ds_ok=false; wt_ok=false
grep -q '^DEADDROP_DEPLOY_SECRET=' "$RELAY_ENV" && ds_ok=true
grep -q '^DEADDROP_WRITE_TOKEN=' "$RELAY_ENV"   && wt_ok=true
missing=""
[ "$ds_ok" = false ] && missing="$missing DEADDROP_DEPLOY_SECRET"
[ "$wt_ok" = false ] && missing="$missing DEADDROP_WRITE_TOKEN"
for key in CADDY_PREFIX SITE_ADDR; do
    grep -q "^${key}=" "$RELAY_ENV" || missing="$missing $key"
done
[ -z "$missing" ] || die "$RELAY_ENV missing required keys:$missing"

echo "==> prerequisites OK"

# ─── disable swap (D-39: all secrets in mlocked RAM) ─────────────────

echo "==> disabling swap"
swapoff -a 2>/dev/null || true
sed -i '/\sswap\s/d' /etc/fstab
systemctl mask swap.target 2>/dev/null || true
echo "    swap disabled"

# ─── install Docker ──────────────────────────────────────────────────

if docker compose version >/dev/null 2>&1; then
    echo "==> Docker already installed"
else
    echo "==> installing Docker"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl >/dev/null

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    echo "deb [arch=$(dpkg --print-architecture) \
signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-compose-plugin >/dev/null
    echo "    Docker installed"
fi

# ─── install required host tools ─────────────────────────────────────

echo "==> checking host tools"
for tool in curl openssl; do
    if ! check_tool "$tool"; then
        echo "    installing $tool"
        apt-get install -y -qq "$tool" >/dev/null
    fi
done
echo "    host tools OK"

# ─── harden Docker daemon ────────────────────────────────────────────

echo "==> hardening Docker daemon"
DAEMON_JSON="/etc/docker/daemon.json"
if [ ! -f "$DAEMON_JSON" ] || ! grep -q '"no-new-privileges"' "$DAEMON_JSON" 2>/dev/null; then
    cat > "$DAEMON_JSON" <<'DJEOF'
{
  "no-new-privileges": true,
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DJEOF
    systemctl restart docker
    echo "    daemon.json applied"
else
    echo "    daemon.json already hardened"
fi

# ─── volatile journald (no logs survive reboot) ──────────────────────

echo "==> configuring volatile journald"
install -d /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/deaddrop.conf <<'JEOF'
[Journal]
Storage=volatile
JEOF
systemctl restart systemd-journald
echo "    journald volatile"

# ─── create .env from relay.env ──────────────────────────────────────

echo "==> creating .env"
cp "$RELAY_ENV" "$REPO_ROOT/.env"
chmod 600 "$REPO_ROOT/.env"
echo "    .env created"

# ─── build and start containers ──────────────────────────────────────

echo "==> building and starting containers"
cd "$REPO_ROOT"

# Apply seccomp profiles if available.
SECCOMP_RELAY="$REPO_ROOT/deploy/security/seccomp/relay.json"
SECCOMP_CADDY="$REPO_ROOT/deploy/security/seccomp/caddy.json"

if [ -f "$SECCOMP_RELAY" ] && [ -f "$SECCOMP_CADDY" ]; then
    echo "    seccomp profiles found — deploying with hardened compose"
    # Generate security overlay with absolute paths.
    cat > "$REPO_ROOT/docker-compose.security.yml" <<SECEOF
services:
  relay:
    security_opt:
      - no-new-privileges:true
      - seccomp=$SECCOMP_RELAY
  caddy:
    security_opt:
      - no-new-privileges:true
      - seccomp=$SECCOMP_CADDY
SECEOF
    docker compose -f docker-compose.yml -f docker-compose.security.yml up -d --build
else
    docker compose up -d --build
fi

echo "    containers started"

# ─── verify ──────────────────────────────────────────────────────────

echo "==> verifying deployment"
sleep 3

ok=true

if docker ps --filter "name=deaddrop-relay" --filter "status=running" -q | grep -q .; then
    echo "    relay: running"
else
    echo "    relay: NOT RUNNING" >&2
    ok=false
fi

if docker ps --filter "name=deaddrop-caddy" --filter "status=running" -q | grep -q .; then
    echo "    caddy: running"
else
    echo "    caddy: NOT RUNNING" >&2
    ok=false
fi

# Wait for TLS to be ready.
SITE_ADDR=$(grep '^SITE_ADDR=' "$RELAY_ENV" | cut -d= -f2)
_tries=0
while [ "$_tries" -lt 15 ]; do
    _code=$(curl -s -o /dev/null -w '%{http_code}' "https://${SITE_ADDR}/" 2>/dev/null || echo "000")
    case "$_code" in
        [1-9][0-9][0-9])
            echo "    TLS: https://${SITE_ADDR}/ → ${_code}"
            break
            ;;
    esac
    _tries=$((_tries + 1))
    sleep 2
done
if [ "$_tries" -ge 15 ]; then
    echo "    TLS: NOT READY (DNS or cert issue)" >&2
    ok=false
fi

if [ "$ok" = true ]; then
    echo ""
    echo "==> quickstart complete"
    echo ""
    echo "Run E2E tests:"
    echo "  sh test/e2e/e2e-tls.sh"
else
    echo ""
    echo "==> quickstart finished with errors (see above)" >&2
    exit 1
fi
