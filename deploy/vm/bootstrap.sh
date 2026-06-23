#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Idempotent bootstrap for deaddrop relay on Ubuntu 22.04 or 24.04.
# Run from the repo root: sudo sh deploy/vm/bootstrap.sh
set -eu

RELAY_ENV="/etc/deaddrop/relay.env"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- prerequisites ---

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: must run as root" >&2
    exit 1
fi

if ! grep -q '^ID=ubuntu' /etc/os-release 2>/dev/null; then
    echo "FATAL: Ubuntu required" >&2
    exit 1
fi
ubuntu_ver=$(. /etc/os-release && echo "${VERSION_ID}")
case "$ubuntu_ver" in
    22.04|24.04) ;;
    *) echo "FATAL: Ubuntu 22.04 or 24.04 required (got $ubuntu_ver)" >&2; exit 1 ;;
esac

if [ ! -f "$RELAY_ENV" ]; then
    echo "FATAL: $RELAY_ENV not found." >&2
    echo "" >&2
    echo "Create it before running bootstrap:" >&2
    echo "  mkdir -p /etc/deaddrop" >&2
    echo "  cat > $RELAY_ENV <<EOF" >&2
    echo "DEADDROP_DEPLOY_SECRET=hex:\$(openssl rand -hex 32)" >&2
    echo "DEADDROP_WRITE_TOKEN=hex:\$(openssl rand -hex 32)" >&2
    echo "CADDY_PREFIX=\$(openssl rand -hex 16)" >&2
    echo "SITE_ADDR=deaddrop.example.com" >&2
    echo "EOF" >&2
    echo "  chmod 600 $RELAY_ENV" >&2
    echo "" >&2
    echo "(Legacy unprefixed DEPLOY_SECRET / WRITE_TOKEN are still accepted with a deprecation WARN; rename before v0.2.)" >&2
    exit 1
fi

# Accept either canonical (DEADDROP_*) or legacy unprefixed names.
# Legacy names trigger the relay's deprecation WARN at startup;
# bootstrap.sh accepts both so existing deployments keep working
# across the v0.1.1 → v0.2 migration window.
ds_present=false
wt_present=false
if grep -q '^DEADDROP_DEPLOY_SECRET=' "$RELAY_ENV" || grep -q '^DEPLOY_SECRET=' "$RELAY_ENV"; then
    ds_present=true
fi
if grep -q '^DEADDROP_WRITE_TOKEN=' "$RELAY_ENV" || grep -q '^WRITE_TOKEN=' "$RELAY_ENV"; then
    wt_present=true
fi

missing=""
[ "$ds_present" = false ] && missing="$missing DEADDROP_DEPLOY_SECRET"
[ "$wt_present" = false ] && missing="$missing DEADDROP_WRITE_TOKEN"
for key in CADDY_PREFIX SITE_ADDR; do
    if ! grep -q "^${key}=" "$RELAY_ENV"; then
        missing="$missing $key"
    fi
done
if [ -n "$missing" ]; then
    echo "FATAL: $RELAY_ENV missing required keys:$missing" >&2
    exit 1
fi

echo "==> prerequisites OK"

# --- disable swap (D-39) ---

echo "==> disabling swap"
swapoff -a || true
sed -i '/\sswap\s/d' /etc/fstab
systemctl mask swap.target 2>/dev/null || true

if [ "$(tail -n +2 /proc/swaps | wc -l)" -gt 0 ]; then
    echo "FATAL: swap still active after swapoff -a" >&2
    exit 1
fi
echo "    swap disabled"

# --- install Docker ---

if docker compose version >/dev/null 2>&1; then
    echo "==> Docker already installed, skipping"
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

# --- create deaddrop user ---

if id deaddrop >/dev/null 2>&1; then
    echo "==> user deaddrop already exists"
else
    echo "==> creating deaddrop user"
    useradd --system --no-create-home --shell /usr/sbin/nologin deaddrop
fi

# --- build and install relay binary ---

if [ -x /usr/local/bin/deaddrop-relay ]; then
    echo "==> relay binary already installed, skipping build"
elif command -v go >/dev/null 2>&1; then
    echo "==> building relay binary"
    (cd "$REPO_ROOT" && go build -trimpath -ldflags="-s -w" \
        -o /usr/local/bin/deaddrop-relay ./cmd/deaddrop-relay/)
    chmod 0755 /usr/local/bin/deaddrop-relay
    echo "    installed /usr/local/bin/deaddrop-relay"
else
    echo "FATAL: go not found on PATH and no pre-built binary at /usr/local/bin/deaddrop-relay." >&2
    echo "Install Go (https://go.dev/dl/) or copy a pre-built binary." >&2
    exit 1
fi

# --- install systemd files ---

echo "==> installing systemd files"

cp "$REPO_ROOT/deploy/systemd/deaddrop-relay.service" \
    /etc/systemd/system/deaddrop-relay.service

install -d /usr/local/lib/deaddrop
cp "$REPO_ROOT/deploy/systemd/preflight.sh" \
    /usr/local/lib/deaddrop/preflight.sh
chmod 0755 /usr/local/lib/deaddrop/preflight.sh

install -d /etc/systemd/journald.conf.d
cp "$REPO_ROOT/deploy/systemd/journald-deaddrop.conf" \
    /etc/systemd/journald.conf.d/deaddrop.conf

systemctl daemon-reload
systemctl restart systemd-journald
echo "    systemd files installed"

# --- set up Caddy Docker Compose ---

echo "==> setting up Caddy"

install -d /opt/deaddrop/caddy
install -m 0644 "$REPO_ROOT/deploy/caddy/Caddyfile" /opt/deaddrop/caddy/Caddyfile
cp "$REPO_ROOT/deploy/vm/docker-compose.yml" /opt/deaddrop/docker-compose.yml

grep '^SITE_ADDR=' "$RELAY_ENV" > /opt/deaddrop/.env
grep '^CADDY_PREFIX=' "$RELAY_ENV" >> /opt/deaddrop/.env
chmod 600 /opt/deaddrop/.env

echo "    Caddy files installed"

# --- start services ---

echo "==> starting services"

systemctl enable --now deaddrop-relay
(cd /opt/deaddrop && docker compose up -d)

echo "    services started"

# --- verify deployment ---

echo "==> verifying deployment"

_tries=0
while [ ! -S /run/deaddrop/app.sock ] && [ "$_tries" -lt 10 ]; do
    sleep 1
    _tries=$((_tries + 1))
done

ok=true

if systemctl is-active --quiet deaddrop-relay; then
    echo "    relay: active"
else
    echo "    relay: FAILED" >&2
    ok=false
fi

if [ -S /run/deaddrop/app.sock ]; then
    echo "    socket: /run/deaddrop/app.sock exists"
else
    echo "    socket: /run/deaddrop/app.sock NOT FOUND" >&2
    ok=false
fi

if docker ps --filter "name=deaddrop-caddy" --filter "status=running" -q 2>/dev/null | grep -q .; then
    echo "    caddy: running"
else
    echo "    caddy: NOT RUNNING" >&2
    ok=false
fi

if [ "$ok" = true ]; then
    echo ""
    echo "==> bootstrap complete"
else
    echo ""
    echo "==> bootstrap finished with errors (see above)" >&2
    exit 1
fi
