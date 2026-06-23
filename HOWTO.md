<!-- Copyright (c) 2026 Nenad Mićić -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HOWTO — deaddrop operator guide

Practical recipes for day-to-day use. Assumes Linux (amd64);
macOS differences are called out where they matter.

For protocol design, see `SPEC.md` and `PROTOCOL.md`.

---

## 1. Install

```bash
# build from source (requires Go 1.22+)
git clone https://github.com/<you>/deaddrop.git
cd deaddrop
go build -trimpath -o deaddrop ./cmd/deaddrop

# optional: install to PATH
sudo install -m 755 deaddrop /usr/local/bin/
```

No runtime dependencies.

### Linux

The Linux binary is statically linked (`CGO_ENABLED=0`). The repo
`Makefile` exports `CGO_ENABLED=0` for `make build`, which is the
right default on Linux: identity and passcache backends use the
kernel keyring via direct syscalls, no cgo needed.

### macOS

macOS builds require `CGO_ENABLED=1`. The identity and passcache
backends call `Security.framework` / `CoreFoundation.framework` via
cgo, so a `CGO_ENABLED=0` build fails with `undefined:
identitystore.New` / `undefined: passcache.New`.

```bash
# prerequisite: Xcode Command Line Tools (provides system headers + ld64)
xcode-select --install

# build (override the Makefile default)
CGO_ENABLED=1 go build -trimpath -o deaddrop ./cmd/deaddrop

# Apple Silicon (default on M1/M2/M3/M4):
GOARCH=arm64 CGO_ENABLED=1 go build -trimpath -o deaddrop ./cmd/deaddrop

# Intel Mac:
GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -o deaddrop ./cmd/deaddrop
```

Building from source is the recommended path. If you instead receive
a `deaddrop` binary downloaded from the internet (Safari, curl, etc.),
macOS will quarantine it on first run with a Gatekeeper warning. To
clear the quarantine attribute on a binary you trust:

```bash
xattr -d com.apple.quarantine ./deaddrop
```

`make build` from the repo Makefile will fail on macOS unless you
override `CGO_ENABLED`. Either run `go build` directly with cgo on, or
invoke `make build CGO_ENABLED=1`.

---

## 2. Set up env vars

Every command needs the relay URL and deploy secret.
Set them once in your shell profile or `.env`:

```bash
export DEADDROP_RELAY="https://relay.example.com/<prefix>"
export DEADDROP_DEPLOY_SECRET="hex:<64-char-hex>"
export DEADDROP_WRITE_TOKEN="hex:<64-char-hex>"   # needed for send/bootstrap only
```

`DEADDROP_DEPLOY_SECRET` requires a `hex:` or `b64:` prefix.
`DEADDROP_WRITE_TOKEN` is optional — only needed if the relay enforces write auth.

---

## 3. Create a capsule

### Option A: offline keygen (manual capsule transfer)

```bash
deaddrop keygen ~/.deaddrop/capsule
# prompts for passphrase twice (enter + confirm)
# prints capsule fingerprint — compare OOB with your peer
```

Copy the capsule file to the other laptop (USB, Signal, SCP).
Both sides share the same 109-byte file and the same passphrase.

> **Keygen capsules have no E2E identity.** A `keygen` capsule is a
> shared symmetric secret with no per-pair X25519 identity entry, so
> the default-on E2E check (`--require-e2e`, see §15) has nothing to
> bind to. Every `send`/`recv` against a keygen capsule must pass
> `--no-require-e2e`, otherwise it exits 22 (`IdentityMiss`):
>
> ```bash
> deaddrop send --no-require-e2e ~/file.txt
> deaddrop recv --no-require-e2e ~/out.txt
> ```
>
> For automatic content-layer E2E (no flag needed), use Option B
> instead — bootstrap provisions the identity entry the check requires.

### Option B: bootstrap pairing (no file transfer)

Both laptops need the same `DEADDROP_RELAY` and `DEADDROP_DEPLOY_SECRET`.

**Laptop A (initiator):**
```bash
deaddrop bootstrap --role=initiator
# generates a 6-word Diceware passphrase (~77 bits)
# read it aloud to your peer (voice, Signal, etc.)
```

**Laptop B (responder) — start within 60 seconds:**
```bash
deaddrop bootstrap --role=responder
# type the 6 words when prompted
```

Both sides:
1. Show a pairing fingerprint — compare OOB, press Enter to confirm
2. Prompt for a local capsule passphrase (can differ per side)
3. Write `~/.deaddrop/capsule` and store X25519 identity in OS keyring

After bootstrap, E2E is automatic — `send`/`recv` wrap payloads
with a content-layer AEAD the relay cannot read.

---

## 4. Send a file

```bash
deaddrop send ~/documents/report.pdf
# prompts for capsule passphrase (cached after first use)
```

The file is encrypted and uploaded. Maximum 10 MiB.
Exit code 0 means the relay accepted it.

The bare commands in §4–§6 assume a **bootstrap** capsule (Option B),
where E2E is automatic. With a **keygen** capsule (Option A), add
`--no-require-e2e` to every `send`/`recv` — see the callout in §3.

### Non-interactive (scripts, cron)

```bash
printf 'my-passphrase' | deaddrop send \
    --passphrase-fd 0 ~/documents/report.pdf
```

Or via env var (emits a warning — acceptable for automation):
```bash
deaddrop send --passphrase-env MY_PASS ~/documents/report.pdf
```

---

## 5. Receive a file

### Single-shot (receiver runs within ~3 minutes of send)

```bash
deaddrop recv ~/downloads/report.pdf
```

Or to stdout:
```bash
deaddrop recv | tar xz
```

Exit code 1 means no message found. The 3-minute window comes from
the blind-probe design — receiver checks the last 3 minute-buckets.

### Polling mode (`--watch`)

For "send now, recv whenever":

```bash
# poll for up to 1 hour (default), check every 60 seconds
deaddrop recv --watch ~/downloads/report.pdf

# poll for 30 minutes, check every 45 seconds
deaddrop recv --watch --duration 30m --watch-interval 45s ~/downloads/report.pdf

# poll indefinitely until message arrives or Ctrl-C
deaddrop recv --watch --duration 0 ~/downloads/report.pdf
```

- First probe runs immediately (no initial sleep)
- `--watch-interval` minimum is 30 seconds
- `--duration` maximum is 24 hours; `0` = unbounded
- Ctrl-C exits cleanly with code 130
- Auth/crypto errors are terminal (not retried)

---

## 6. One-shot guarantee

Every message is consumed on first `recv` — the relay deletes it atomically.
A second `recv` returns exit code 1:

```bash
echo "secret" | deaddrop send --passphrase-fd 3 /dev/stdin 3<<<'pass'
deaddrop recv --passphrase-fd 3 /tmp/first.txt 3<<<'pass'     # succeeds
deaddrop recv --passphrase-fd 3 /tmp/second.txt 3<<<'pass'    # exit 1
```

---

## 7. Verify capsule fingerprint

```bash
# capsule fingerprint (both sides should match)
deaddrop fingerprint

# pairing fingerprint (after bootstrap, includes identity keys)
deaddrop fingerprint --identity
# output: 6chars 6chars 6chars 6chars 8chars
```

---

## 8. Passphrase caching

After the first passphrase prompt, deaddrop caches it in the OS keyring.
Subsequent commands skip the prompt until the TTL expires.

```bash
deaddrop send ~/file1.txt       # prompts
deaddrop send ~/file2.txt       # uses cache — no prompt

# change TTL (default: 1 hour / 3600 seconds)
deaddrop send --passcache-ttl 7200 ~/file.txt   # 2 hours

# disable caching for one command
deaddrop send --passcache=none ~/file.txt

# forget cached passphrase and re-prompt
deaddrop send --forget-passcache ~/file.txt
```

### Linux: session keyring

Cache lives in the kernel session keyring. Survives tmux/screen
detach but is lost on logout.

```bash
# list cached entries
keyctl list @s | grep 'deaddrop:'

# manually clear all deaddrop cache entries
keyctl list @s | awk '/deaddrop:/ {print $1}' | while read id; do
    keyctl unlink "$id" @s
done
```

### macOS: Keychain Services

Cache lives in the login keychain. No per-item TTL — entries persist
until the login keychain locks (which rarely happens in practice;
the login keychain auto-unlocks at login and stays unlocked across
sleep, screen-lock, and reboot). `--passcache-ttl` is silently
ignored (note printed to stderr).

```bash
# list entries
security find-generic-password -s deaddrop

# delete one
security delete-generic-password -s deaddrop -a 'deaddrop:<hex>'
```

For full Keychain semantics — ACL prompts, persistence vs Linux,
locked-keychain handling, identity vs passcache services — see
section 9b below.

---

## 9. Linux kernel keyring deep-dive

deaddrop uses the Linux kernel keyring for two things:

1. **Passphrase cache** — session keyring, short-lived, auto-expires
2. **E2E identity keys** — UID-scoped persistent keyring, long-lived

### Persistent keyring (identity keys)

After `deaddrop bootstrap`, X25519 identity keys are stored in the
UID-scoped persistent keyring via `KEYCTL_GET_PERSISTENT`. This keyring:

- Survives logout (unlike the session keyring)
- Lives in kernel RAM — lost on reboot
- Has a 3-day idle expiry (default), reset on every access
- Configurable via `/proc/sys/kernel/keys/persistent_keyring_expiry`
- Requires `CONFIG_PERSISTENT_KEYRINGS=y` in the kernel

```bash
# check if your kernel supports persistent keyrings
grep PERSISTENT_KEYRINGS /boot/config-$(uname -r)
# → CONFIG_PERSISTENT_KEYRINGS=y

# after bootstrap, show the session keyring tree
# (persistent keyring appears as a linked sub-keyring)
keyctl show @s

# list identity entries
keyctl list @s | grep 'deaddrop-id-'

# check persistent keyring expiry (seconds)
cat /proc/sys/kernel/keys/persistent_keyring_expiry
# → 259200  (3 days)
```

### Session keyring fallback

On kernels without `CONFIG_PERSISTENT_KEYRINGS`, or in restricted
namespaces (EPERM), deaddrop falls back to the session keyring
and prints a warning:

```
WARN: persistent keyring unavailable, using session keyring (identity lost on logout)
```

If you see this, identity keys won't survive logout — you'll need
to re-run `deaddrop bootstrap` after logging back in. The capsule
file is unaffected.

### Inspecting keyring contents

```bash
# list all keys in session keyring
keyctl list @s

# read a specific key (raw bytes)
keyctl pipe <key-id> | xxd

# show key metadata (permissions, expiry)
keyctl describe <key-id>

# check remaining TTL on a cached passphrase
keyctl timeout <key-id>     # prints remaining seconds

# show full keyring hierarchy
keyctl show @s
```

### Troubleshooting keyring issues

```bash
# "key was rejected by service" — wrong passphrase cached
deaddrop send --forget-passcache ~/file.txt

# "disk quota exceeded" — too many keys
cat /proc/sys/kernel/keys/maxkeys     # per-user limit
cat /proc/sys/kernel/keys/maxbytes    # per-user byte limit

# increase if needed (as root)
echo 5000 > /proc/sys/kernel/keys/maxkeys

# "operation not permitted" inside container/namespace
# → use --passcache=none or ensure keyring syscalls are allowed
```

---

## 9b. macOS Keychain deep-dive

Counterpart to section 9 for macOS users. deaddrop uses the user's
**login keychain** (the default for `security` CLI) — never the
System keychain, never iCloud Keychain.

### Two services, two purposes

| Service name        | Purpose                                  | Account format                  |
|---------------------|------------------------------------------|---------------------------------|
| `deaddrop`          | Passphrase cache (short-lived)           | `deaddrop:<8-byte-hex>`         |
| `deaddrop-identity` | Per-pair X25519 identity (long-lived)    | `deaddrop:pair:<16-byte-hex>`   |

The two services are intentionally distinct so an operator running
`security delete-generic-password -s deaddrop` to clear the passcache
does NOT also wipe identity entries (would silently break the pair).

### Persistence model (different from Linux)

- **Survives logout:** yes (login keychain re-unlocks on next login).
- **Survives reboot:** yes (login keychain is on disk, encrypted at rest).
- **Migrated to a new Mac via Migration Assistant or restore:** no.
  Both services use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  which excludes the entry from device-to-device migration and from
  iCloud Keychain sync.
- **Available while screen is locked:** depends on whether keychain
  is locked. Default macOS behavior: lock screen alone does NOT lock
  the login keychain. The keychain only locks if you explicitly lock
  it via Keychain Access or via `security lock-keychain`, or if you
  set "Lock keychain when sleeping" in Keychain Access preferences.

This is a meaningful behavioral difference from Linux: on Linux the
persistent keyring is RAM-only and reboot wipes it (rebootstrap
needed). On macOS, identity entries survive reboot.

### First-access ACL prompt — pick "Always Allow"

The first time `deaddrop` reads or writes a Keychain item, macOS
shows an authorization dialog:

> "deaddrop wants to access your confidential information stored in
> [item-name] in your keychain. To allow this, enter the
> [keychain] password."

You will see this dialog **once per Keychain item** (so once after
first passcache write, plus once per pair after `deaddrop bootstrap`).
The dialog has three buttons:

- **Always Allow** — adds `deaddrop` to that item's ACL. Future
  reads/writes from the same binary path are silent. **This is what
  you want.**
- **Allow** — one-time grant. The dialog will appear again on the
  next access. Annoying for an interactive workflow, fatal for cron.
- **Deny** — `deaddrop` gets `errSecAuth` / `errSecItemNotFound`,
  which surfaces as `IdentityMiss` (exit 22) or a wrong-passphrase
  error.

Touch ID may replace the password prompt on Macs with a Secure
Enclave; the ACL semantics are identical.

If you change the binary path (e.g., move from `/usr/local/bin/`
to `~/bin/`) or rebuild with a different team-id signature, macOS
treats it as a new binary and re-prompts. Pick "Always Allow" again.

### Inspecting entries via `security` CLI

```bash
# list every passcache entry (returns the first match by default;
# use -g to print attributes, repeat queries to enumerate)
security find-generic-password -s deaddrop -g

# list identity entries for a specific pair
security find-generic-password -s deaddrop-identity \
    -a 'deaddrop:pair:<16-hex>'

# dump every deaddrop-related entry (pipe through grep)
security dump-keychain | grep -E 'deaddrop|deaddrop-identity'

# delete one passcache entry
security delete-generic-password -s deaddrop -a 'deaddrop:<hex>'

# delete one identity entry (forces rebootstrap for that pair)
security delete-generic-password -s deaddrop-identity \
    -a 'deaddrop:pair:<hex16>'

# nuke ALL passcache entries (one per call — repeat until ENOENT)
while security delete-generic-password -s deaddrop 2>/dev/null; do :; done
```

`security find-generic-password` returns only the first match per
invocation. To enumerate, narrow with `-a <account>` or use
`security dump-keychain` and filter.

### Locked keychain → IdentityMiss

If the login keychain is locked when `deaddrop send`/`recv` runs,
the identity store returns `ErrMiss` (D-62 graceful degradation):
the user-facing error is `IdentityMiss` (exit 22), not a cryptic
OSStatus number. The fix path is one of:

```bash
# unlock the login keychain (prompts for password)
security unlock-keychain ~/Library/Keychains/login.keychain-db

# or rebootstrap the pair (last resort)
deaddrop bootstrap --role=...
```

Same behavior applies if the keychain item exists but ACL denies
deaddrop's process. Re-run interactively, click "Always Allow."

### Troubleshooting

```bash
# every send/recv re-prompts for keychain password
# → first prompt got "Allow" instead of "Always Allow"; delete the
#   item and re-run, choosing "Always Allow" this time.

# "wrong passphrase" but you typed the right one
# → stale passcache entry; force-forget and retype:
deaddrop send --forget-passcache ~/file.txt

# bootstrap succeeded but next send shows IdentityMiss (exit 22)
# → keychain was locked between bootstrap and send; unlock and retry:
security unlock-keychain ~/Library/Keychains/login.keychain-db

# "deaddrop" is not in the ACL of an existing item (binary moved)
# → easiest fix is to delete and recreate:
security delete-generic-password -s deaddrop-identity \
    -a 'deaddrop:pair:<hex16>'
deaddrop bootstrap --role=...
```

### What is NOT used

- **iCloud Keychain** — deaddrop entries do not sync. The
  `ThisDeviceOnly` accessibility class blocks iCloud upload.
- **System keychain** — never written to. No sudo-elevated keychain
  prompts.
- **Time Machine** — login keychain *is* included in default Time
  Machine backups, but the backup is encrypted with the user's login
  password. Restoring to a new Mac does not migrate
  `ThisDeviceOnly` items, so the practical effect is zero. If you
  want explicit exclusion, add `~/Library/Keychains/` to Time Machine
  exclusions in System Settings.

---

## 10. Proxy configuration

deaddrop respects standard HTTP proxy environment variables.
Go's `net/http` handles this automatically — no flags needed.

```bash
# HTTPS traffic through a forward proxy
export HTTPS_PROXY=http://proxy.example.com:8080
deaddrop send ~/file.txt
deaddrop recv ~/received.txt

# lowercase also works
export http_proxy=http://proxy.example.com:8080

# bypass proxy for specific hosts
export NO_PROXY=relay.internal.example.com
deaddrop send ~/file.txt    # goes direct, not through proxy
```

### What gets proxied

All relay communication uses HTTPS. The proxy sees a `CONNECT`
request to the relay hostname:443 — it cannot see the request
path, headers, or body (TLS tunnel).

### Proxy through SSH tunnel

```bash
# on your workstation: tunnel local port to a remote proxy
ssh -L 8080:proxy.internal:3128 jumpbox

# then
HTTPS_PROXY=http://127.0.0.1:8080 deaddrop send ~/file.txt
```

### Self-signed proxy / corporate MITM

If the proxy terminates TLS with its own CA:

```bash
export SSL_CERT_FILE=/path/to/corporate-ca.pem
deaddrop send ~/file.txt
```

### Verifying proxy is used

Check your proxy logs for `CONNECT <relay-host>:443` entries.
With Squid:

```
TCP_TUNNEL/200 ... CONNECT deaddrop.example.com:443
```

### macOS specifics

Go's `net/http` reads `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`
environment variables on every platform — but it does **not** read
the macOS system proxy from `System Settings → Network → Proxies`.
If your Mac is configured to use a corporate proxy via System
Settings or a PAC file, deaddrop will bypass it and try to connect
direct (which will likely fail).

```bash
# inspect the macOS system proxy (informational; deaddrop won't read this)
scutil --proxy

# if you see HTTPS proxy / PAC, set the env var to match before running:
export HTTPS_PROXY=http://proxy.corp.example.com:8080
deaddrop send ~/file.txt
```

PAC (Proxy Auto-Config) files are not supported. Resolve the PAC to
a concrete proxy URL once and export it.

---

## 11. Self-signed TLS (internal relays)

For relays with self-signed certificates (e.g., `tls internal` in Caddy):

```bash
# extract Caddy's self-signed root CA (run on the relay host)
docker exec deaddrop-caddy cat /data/caddy/pki/authorities/local/root.crt > /tmp/caddy-root.crt

# scp it to your client machine (Linux or macOS), then:
export SSL_CERT_FILE=/tmp/caddy-root.crt
deaddrop send ~/file.txt
```

This also works for `--watch` mode and `bootstrap`.

### macOS: SSL_CERT_FILE vs System keychain trust

`SSL_CERT_FILE` is the recommended path on macOS too — Go's
`crypto/tls` honors it on every platform, no rebuild needed.

You *can* alternatively add the Caddy root to the macOS System
keychain trust roots, but the env-var approach is cleaner because
it scopes the trust to deaddrop only:

```bash
# only if you need the cert trusted system-wide (other tools, browsers)
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain /tmp/caddy-root.crt

# remove later:
sudo security delete-certificate -c "Caddy Local Authority" \
    /Library/Keychains/System.keychain
```

---

## 12. Deploy a relay

### Prerequisites

- A Linux server with SSH access and Docker installed
- A domain pointing to the server (for Let's Encrypt), or IP-only (self-signed)
- Create `deployment.yaml` from the example:

```bash
cp deployment.yaml.example deployment.yaml
# edit: fill in host, domain, user, tls mode
```

### Deploy

```bash
# production VPS with Let's Encrypt
./scripts/deploy.sh vps

# internal VM with self-signed TLS
./scripts/deploy.sh vm

# clean deploy (wipe containers first)
./scripts/deploy.sh vps --clean

# deploy + smoke test
./scripts/deploy.sh vps --test
```

The script:
1. Syncs code via `git archive | ssh tar xf`
2. Generates secrets on first deploy (or reuses existing `.env`)
3. Builds and starts Docker containers (relay + Caddy)
4. Waits for TLS health
5. Prints relay URL and env export commands

### deployment.yaml format

```yaml
vps:
  host: 203.0.113.10
  user: root
  domain: deaddrop.example.com
  tls: acme                        # Let's Encrypt
  env_path: /etc/deaddrop/relay.env
  deploy_dir: /root/deaddrop

vm:
  host: 192.168.122.254
  user: root
  tls: internal                    # self-signed
  deploy_dir: /root/deaddrop
```

### TLS renewal

Caddy handles Let's Encrypt certificate renewal automatically —
no cron job needed. Certificates are renewed ~30 days before expiry
via a background goroutine. Check status:

```bash
ssh root@relay docker logs deaddrop-caddy 2>&1 | grep -i cert
```

---

## 13. Running tests

### Unit tests

```bash
go test ./...
```

### Smoke test (local relay, no deploy needed)

```bash
sh test/smoke/qa-roundtrip.sh
```

### Performance test (against deployed relay)

```bash
eval "$(./scripts/deploy.sh vps 2>/dev/null | grep export)"
./test/perf/perf-roundtrip.sh
./test/perf/perf-roundtrip.sh --parallel 4 --cycles 10
./test/perf/perf-roundtrip.sh --sizes "1024 102400" --report /tmp/perf
```

### Proxy end-to-end test (requires local Squid)

```bash
eval "$(./scripts/deploy.sh vps 2>/dev/null | grep export)"
./test/proxy/proxy-e2e.sh
./test/proxy/proxy-e2e.sh --proxy http://127.0.0.1:8080
./test/proxy/proxy-e2e.sh --skip-large
```

Tests: HTTPS_PROXY round-trip, http_proxy lowercase, invalid proxy
clean error, NO_PROXY bypass, recv --watch through proxy, 5 MiB
payload, bad relay clean error.

---

## 14. Exit codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | OK | Success |
| 1 | NotFound | No message (single-shot miss or watch deadline) |
| 2 | Usage | Bad flags, missing args, passphrase on argv |
| 10 | CryptoLocal | Local crypto failure |
| 11 | RelayUnreachable | Network error (DNS, TCP, TLS) |
| 12 | Collision | Bootstrap slot collision |
| 13 | Auth | Relay rejected write token (401/403) |
| 14 | SizeCap | File exceeds 10 MiB |
| 15 | CapsuleUnwrap | Wrong passphrase or corrupt capsule |
| 16 | RelayOverloaded | Relay returned 429 or 503 |
| 17 | BootstrapMITM | Bootstrap AEAD open failed |
| 18 | BootstrapAuthFail | Bootstrap auth failure |
| 19 | BootstrapTimeout | Timeout waiting for peer |
| 20 | Internal | Unclassified internal error |
| 21 | E2EUnwrap | Content-AEAD open failed |
| 22 | IdentityMiss | No E2E identity entry for pair |
| 23 | IdentityStore | OS identity store backend error |
| 24 | PlatformUnsupported | No identity store on this OS |
| 130 | Interrupted | Ctrl-C during `--watch` |

Use in scripts:
```bash
deaddrop recv /tmp/out.txt
case $? in
    0)   echo "got it" ;;
    1)   echo "no message yet" ;;
    11)  echo "relay unreachable" ;;
    15)  echo "wrong passphrase" ;;
    130) echo "interrupted" ;;
    *)   echo "error: $?" ;;
esac
```

---

## 15. Gotchas and platform notes

### Timing: 3-minute window vs. relay TTL

Single-shot `recv` probes the last 3 minute-buckets. The relay's
slot TTL (default 1 hour) is a cleanup safety net, not a delivery
window. If the receiver runs `recv` more than ~3 minutes after
`send`, single-shot will miss — use `--watch` instead.

### Passphrase on argv is forbidden

`--passphrase=foo` or `--passphrase foo` on the command line exits
with code 2. Passphrases leak into `ps`, `/proc/*/cmdline`, shell
history. Use `--passphrase-fd` or `--passphrase-env`.

### --deploy-secret on argv removed (v0.2.0)

Same reasoning. Use `$DEADDROP_DEPLOY_SECRET` env var or
`--deploy-secret-fd 3` with a heredoc:

```bash
deaddrop send --deploy-secret-fd 3 ~/file.txt 3<<<"hex:$SECRET"
```

### recv needs DEPLOY_SECRET but not WRITE_TOKEN

`DEADDROP_DEPLOY_SECRET` is needed by both send and recv (it
derives the slot address). `DEADDROP_WRITE_TOKEN` is only needed
for `send` and `bootstrap`.

### E2E after bootstrap is automatic

After `deaddrop bootstrap`, subsequent `send`/`recv` automatically
use E2E wrapping (wire version 0x04). No flags needed.

`--require-e2e` is **default-on** (D-71): any `send`/`recv` against a
capsule with no identity entry exits 22 (`IdentityMiss`). Two cases
have no identity entry and therefore require `--no-require-e2e`:

- **`keygen` capsules** (§3 Option A) — a shared symmetric secret,
  never paired, so there is no per-pair identity. This is a current,
  supported workflow, not legacy.
- **pre-v0.1.5 capsules** — created before the identity layer existed.

In both cases `--no-require-e2e` selects the legacy 0x01 wire path
(relay-opaque transport encryption, but no content-layer AEAD). It
prints a deprecation warning. For full E2E, rebootstrap (Option B).

### Capsule is 109 bytes — treat it like a key

The capsule file contains the wrapped PSK. Anyone with the capsule
AND the passphrase can decrypt your messages. Store it with
`chmod 600` (keygen does this automatically). Don't commit it to git.

### tmux/screen and keyring

Linux session keyring is inherited by tmux/screen child processes.
Cached passphrases and identity keys are accessible after
detach/reattach — this is intentional.

On macOS, tmux/iTerm/Terminal all run as the same user with access
to the same login keychain — no inheritance to worry about. The ACL
"Always Allow" choice you made for the deaddrop binary applies
regardless of which terminal launched it.

### Docker and kernel keyring (Linux)

Containers may not have access to the host keyring. If `deaddrop`
runs inside a container and needs passcache or E2E identity:
- Ensure the `keyctl` syscall is allowed (not blocked by seccomp)
- Or use `--passcache=none` and `--no-require-e2e`

### macOS: Gatekeeper / quarantine on downloaded binaries

A `deaddrop` binary downloaded via Safari, curl, or AirDrop is
quarantined by macOS. First run shows "deaddrop cannot be opened
because the developer cannot be verified." Either build from source
(no quarantine), or strip the attribute:

```bash
xattr -d com.apple.quarantine ./deaddrop
```

Building from source on the same Mac is cleaner because it avoids
the prompt entirely and Keychain ACL prompts will name the local
build path consistently.

### macOS: every send/recv re-prompts for keychain password

You clicked "Allow" on the first ACL prompt instead of "Always
Allow." The fix is to delete the entry and re-run, then pick "Always
Allow":

```bash
# passcache:
security delete-generic-password -s deaddrop
# identity (per pair):
security delete-generic-password -s deaddrop-identity \
    -a 'deaddrop:pair:<hex16>'
```

### macOS: PlatformUnsupported (exit 24) cannot occur

Exit code 24 is reserved for platforms with no identity store
backend (FreeBSD, OpenBSD, etc.). macOS Keychain is always present;
if you see exit 24 on a Mac, something else is wrong (binary built
with the wrong build tags?). On macOS the relevant identity-related
errors are 22 (`IdentityMiss` — locked keychain or no entry) and 23
(`IdentityStore` — Keychain backend error).

### File size limit

Maximum 10 MiB per message. For larger files, split first:

```bash
split -b 9M largefile.tar.gz part_
for f in part_*; do deaddrop send "$f"; done
```

### Clock skew

Sender and receiver clocks must agree within ~3 minutes for
single-shot `recv` (they derive minute-bucket addresses from wall
clock). Use NTP. The `--watch` mode is immune to moderate skew
since it polls continuously.

---

## 16. Quick reference

```
deaddrop keygen <path>                    create capsule
deaddrop fingerprint [--identity]         print fingerprint
deaddrop send <file>                      encrypt + upload
deaddrop recv [file]                      download + decrypt (stdout if no file)
deaddrop recv --watch [file]              poll until message arrives
deaddrop bootstrap --role=initiator       start pairing handshake
deaddrop bootstrap --role=responder       join pairing handshake
```

**Environment variables:**
```
DEADDROP_RELAY              relay base URL
DEADDROP_DEPLOY_SECRET      anti-enumeration secret (hex: or b64: prefix)
DEADDROP_WRITE_TOKEN        relay write auth token
DEADDROP_CAPSULE            capsule file path (default: ~/.deaddrop/capsule)
HTTPS_PROXY / http_proxy    HTTP proxy for all relay traffic
NO_PROXY                    comma-separated hosts to bypass proxy
SSL_CERT_FILE               custom CA bundle (for self-signed relay TLS)
```
