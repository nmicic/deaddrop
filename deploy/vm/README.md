# DeadDrop VM Deployment

Deploys the deaddrop relay on an Ubuntu 22.04/24.04 VM with Caddy (Docker) for TLS termination.

## Architecture

- **Relay binary** runs as a systemd service with full hardening (mlockall, no swap, no core dumps).
- **Caddy** runs in Docker (`caddy:alpine`) for TLS. Communicates with the relay via unix socket at `/run/deaddrop/app.sock`.

## Prerequisites

- Ubuntu 22.04 or 24.04 VM
- Go installed (for building), or a pre-built relay binary at `/usr/local/bin/deaddrop-relay`
- Root access

## 1. Provision Secrets

Create `/etc/deaddrop/relay.env` before running the bootstrap:

```sh
mkdir -p /etc/deaddrop

cat > /etc/deaddrop/relay.env <<EOF
DEADDROP_DEPLOY_SECRET=hex:$(openssl rand -hex 32)
DEADDROP_WRITE_TOKEN=hex:$(openssl rand -hex 32)
CADDY_PREFIX=$(openssl rand -hex 16)
SITE_ADDR=deaddrop.example.com
EOF

chmod 600 /etc/deaddrop/relay.env
```

Replace `deaddrop.example.com` with your actual domain.

**Legacy variable names (`DEPLOY_SECRET`, `WRITE_TOKEN`) are still
accepted** for backward compatibility with pre-v0.1.1 deployment
files; the relay emits a stderr deprecation WARN at startup when
the legacy names are used. Rename to the canonical
`DEADDROP_*`-prefixed names. The `--deploy-secret` argv flag was
removed in v0.2.0 (D-72); secrets reach the relay via the
`EnvironmentFile` or `--deploy-secret-fd` (D-43).

## 2. Bootstrap

```sh
git clone https://github.com/nmicic/deaddrop.git
cd deaddrop
sudo sh deploy/vm/bootstrap.sh
```

The script is idempotent — safe to run again after updates. Note: the build step is skipped if `/usr/local/bin/deaddrop-relay` already exists. Delete the binary before re-running to force a rebuild.

## 3. Verify

```sh
systemctl status deaddrop-relay
docker compose -f /opt/deaddrop/docker-compose.yml ps
curl -s -o /dev/null -w '%{http_code}' https://deaddrop.example.com/
# Should return 404 (uniform 404 for non-matching paths)
```

## CADDY_PREFIX Rotation

See `SECURITY.md` for the rotation procedure. After updating `CADDY_PREFIX` in `/etc/deaddrop/relay.env`:

```sh
# Update Caddy's .env (atomic, no temp file with secret)
new_prefix=$(grep '^CADDY_PREFIX=' /etc/deaddrop/relay.env)
sed -i '/^CADDY_PREFIX=/d' /opt/deaddrop/.env
printf '%s\n' "$new_prefix" >> /opt/deaddrop/.env

# Restart both services
systemctl restart deaddrop-relay
cd /opt/deaddrop && docker compose restart caddy
```

## Important: journald Storage=volatile

The bootstrap installs a journald drop-in (`/etc/systemd/journald.conf.d/deaddrop.conf`) that sets `Storage=volatile` for **all** services on the host. No logs survive reboot.

If other services on the VM need persistent logging, either:
- Remove the drop-in and use per-unit log filtering
- Use a separate systemd log namespace for deaddrop
