# deaddrop — Future / Deferred / Nice-to-Have

Items here are tracked, not promised. Add freely. Promote to `DECISIONS.md`
as a new D-XX entry when an item is committed to.

Parked variant specs (B′, C, D, E, G) live in `experimental/` rather
than being summarized here — they are larger than an F-entry and have
their own design documents. Variant A is **rejected on threat model
as a general-purpose send primitive** (D-37): a user-chosen
passphrase is the confidentiality budget, and that does not reliably
meet the offline-brute-resistance target variant B gets from a
32-byte capsule PSK. D-41 narrows D-37 on scope: A's Argon2id envelope
shape is revived for `deaddrop bootstrap` only (three-leg handshake;
PSK never travels under passphrase-derived keying). `send --mode=A`
remains rejected. Variant F graduated out of `experimental/` to
become the VM deployment (see `BACKEND_VM.md`, D-24 → D-33). The
parallel Cloudflare backend was considered in D-24 and parked in
D-33 — see `experimental/BACKEND_CLOUDFLARE_parked.md`.

---

## Committed (pending implementation) / superseded

> The repo is spec-only as of 2026-04. "Committed" here means the
> decision is locked and the design is normative — not that Go code
> exists in this repository.

- **F-3 (Go reference client)** — committed; normative per D-25.
  The bash client is diagnostic-only and explicitly non-normative.
  Code has not yet landed in this repo (see F-16 `DEPLOY-VM`).
- **F-9 (authenticated DELETE)** — committed; normative per D-26.
  The relay stores `SHA-256(delete_token)`; the raw token is
  sender-memory-only (D-35). Receive-side has no DELETE capability.
  Not yet implemented in this repo.

---

## Parked with Cloudflare (D-33)

Items that existed only to rescue the parked Cloudflare backend are
collapsed here. They do not constitute a roadmap — reopening any of
them means reopening D-33 first.

- **F-4 (Durable Objects)** — was the path to strict one-shot on
  Cloudflare; moot on VM/Go where one-shot is already strict.
- **F-7 (CF Access mTLS alternative)** — moot; the VM deployment
  already supports operator-provisioned mTLS via
  `experimental/SPEC_DRAFT_D_private_CA.md` (referenced by
  `BACKEND_VM.md §5`).
- **F-17 (DEPLOY-WORKER artifacts)** — Worker-side `wrangler.toml`
  template, secret helpers, DNS guidance. Moot.
- **F-24 (KV quota budgeting)** — Cloudflare-specific free-tier
  write-cap tracking. Moot.
- **F-26 (Durable Objects graduation checklist)** — moot.

Historical design that would need to be revisited to reopen any of
the above: `experimental/BACKEND_CLOUDFLARE_parked.md`.

---

## F-1  Chunked large files

10 MiB is fine for configs, capsules, recovery phrases, small media.
DB dumps, firmware images, movies need chunking.

Design outline:

- Client splits plaintext into N chunks of ≤ `MAX_BLOB_BYTES`.
- Each chunk gets `slot_id = HMAC(slot_key, "chunk" || bucket || idx)`.
- A manifest slot (label `"manifest"`) lists the N chunk slot_ids and
  per-chunk auth tags.
- Receiver fetches manifest, verifies, then fetches chunks
  (parallelizable).

Open questions: manifest format (CBOR? length-prefixed?), per-chunk
retry, resumable receivers, partial-fetch security, how AEAD AD binds
chunk index without enabling a truncation oracle.

---

## F-2  Multi-recipient fanout

Send once, N recipients read. Today `reads_left=N` allows N reads
total, not "N distinct recipients, each exactly once." Approaches:

- Per-recipient slot: sender posts N times, each recipient has a
  distinct `slot_key`. Simple, O(N) work for sender.
- Group key: one slot, body contains N recipient-wrap blobs + one
  shared session key (age-style). Worth considering for small N (≤10).
  D-32 rejected age as the crypto *core*; age-style multi-wrap as an
  optional inner format is separately defensible.

---

## F-5  Public service hardening (if ever — currently NOT planned)

Position today (D-13): single-tenant per deployment. If that ever
changes:

- Captcha on first POST per IP.
- Global rate limit across the tenant.
- Size-cap tightening.
- Abuse-report endpoint (out-of-band; relay cannot decrypt).
- Tor exit detection (not block — note for rate-limit policy).
- Blocklist of known-abuse content is genuinely hard on a
  zero-knowledge service; probably unachievable.

---

## F-6  PQC hybrid upgrade

XChaCha20-Poly1305 is symmetric PQC-safe. Any future DH variant (B′,
parked C/E) would not be. Plan:

- Replace any X25519 with X25519 + ML-KEM-768 hybrid.
- Concatenate shared secrets, feed to HKDF.
- Body grows by ≈1088 bytes.
- Flag-day wire bump (`deaddrop-v2`, version byte `0x02`). See D-23
  and `PROTOCOL.md §12`: KDF / AEAD changes MUST bump the wire
  version byte.

URTB tracks the parallel upgrade in its `FUTURE.md`.

---

## F-8  Web client

A pure-browser client (WebCrypto) for variant B, served from the same
VM (separate vhost). Paste file, unlock capsule in-browser, get URL —
same wire protocol, different runtime.

Security considerations (see also F-22):

- Host the page at a version-pinned URL.
- Subresource Integrity (SRI) on every script tag.
- No third-party scripts. No analytics. Strict CSP
  (`default-src 'self'`).
- Document clearly that a browser client has more supply-chain
  surface than the CLI and is intended for convenience, not
  high-security use.

---

## F-10  B′ steady-state — forward secrecy upgrade path

Variant B does not provide forward secrecy: capsule compromise plus
captured on-wire ciphertext = plaintext recovery (`SECURITY.md`). B′
adds per-send ephemeral DH over pinned peer pubkeys on top of the
existing capsule (`experimental/SPEC_DRAFT_Bprime_bootstrap.md`).

**Status after D-41 / D-42 (2026-04):** D-41's `deaddrop bootstrap`
already exchanges the pubkeys B′ would need, but ships with
`--burn` default — identity X25519 keypairs are ephemeral to the
bootstrap process only, not persisted. D-42 was drafted to promote
B′ to normative end-state but **withdrawn before commit** (see D-42's
withdrawal banner): without agent-style identity-key protection,
persisting long-term X25519 private keys as plaintext-readable files
would be a regression vs plain B's symmetric-PQC-safe posture.

Graduation therefore gates on:

1. **F-34 (agent-style identity-key protection)** — load-bearing.
   Until long-term X25519 private keys can be held in an
   ssh-agent-style process (or a hardware token per F-14), B′
   steady-state is strictly worse than plain B on at-rest surface.
2. A `--keep-keys` opt-in on `deaddrop bootstrap` (parked in D-41,
   gated on F-34).
3. Go client being the only supported reference (D-25).
4. Explicit wire-version bump if the body format grows (KDF / AEAD AD
   both may need extension per `PROTOCOL.md §12`).

Promote by opening a `DECISIONS.md` entry D-XX and graduating the
spec out of `experimental/`. D-42's slot is WITHDRAWN and must not be
reused — allocate D-43 or later.

---

## F-11  Noise_IK formal upgrade (for B′, if promoted)

If B′ graduates, its per-send ephemeral DH should use the Noise_IK
handshake via a proper library (flynn/noise for Go) rather than hand-
rolling the structural moves. Tradeoff: adds a dependency. Bash client
cannot implement Noise cleanly — another reason the Go binary is the
single normative reference (D-25).

---

## F-12  Tamper-evident deployment logs

Emit hash-chained logs so an operator can prove "the relay was not
tampered with" to users. journald integration on the VM.

---

## F-13  CSR / CA fleet PKI on top of B′

B′ pins peer pubkeys one-by-one. That scales poorly beyond ~5 nodes
and has no revocation story. Promote one node to CA, issue
signed-blob identity certs over the B channel:

- `deaddrop ca-init` designates this node as CA (self-signed root).
- New nodes: `deaddrop csr | send over B` → CA node validates and signs
  → signed cert returned over B.
- Peers validate incoming pubkeys against the embedded CA root.
- CRL distributed as a normal blob.

Client-side only; relay does not change.

---

## F-14  Identity key storage: keyring / Keychain / hardware

B′'s `identity.key` is the one long-term secret that rides on the
device. v1 would store it as a flat file at `~/.deaddrop/identity.key`
(mode 0600, relies on full-disk encryption).

**Bypassed for the bootstrap flow (D-41, 2026-04).** `deaddrop
bootstrap` runs with `--burn` by default: identity X25519 keypairs
are ephemeral to the bootstrap process and zeroized at exit, so no
on-disk `identity.key` artifact exists after v1. F-14 re-enters the
picture only when B′ steady-state graduates (see F-10, gated on
F-34) — at which point persisted identity keys resurface as a real
design question, and F-34's agent-style protection is the
hardware-minus tier that must land before K3 / K4.

Staged migration (applies to a future B′ steady-state, not v1):

- **K2.** Linux keyutils (session keyring, wiped on logout).
- **K3.** macOS Keychain (OS-gated access).
- **K4.** Hardware-backed — YubiKey PIV, TPM 2.0, Apple Secure
  Enclave, GnuPG smartcard. X25519 ops in hardware; private key never
  touches userland.

All plugins of a single `KeySource` interface — main send/recv path
does not branch on source. Bash client is frozen at K1; Go client
adopts K2–K4 incrementally.

---

## F-15  Slot reservation / claim-then-upload

Today sender POSTs full ciphertext in one shot. Collision on a slot
(409) is a terminal error per D-36: the client exits with
`EDDCollision` (exit 12) and the user retries at the next minute
boundary with a freshly-derived slot. (Earlier wording said 409
triggered an in-process retry with a new nonce; D-36 explicitly
removed retries.) A future two-phase POST could replace the minute-
boundary wait with an in-session reservation handshake:

1. `POST /{service}/{slot}?claim=1` with empty body → 201 reserves
   slot for 10 s.
2. `PUT  /{service}/{slot}` with body → 200.

Probably not worth the added complexity unless contention is observed
in a real deployment.

---

## F-16  Operational artifacts (`DEPLOY-VM`)

Ship under `deploy/vm/`:

- `caddy.conf` fragment (unix-socket upstream, TLS, HSTS).
- `systemd/deaddrop.service` with hardening directives
  (`ProtectSystem=strict`, `NoNewPrivileges`,
  `CapabilityBoundingSet=`).
- `nftables.conf` with inbound 443 / 22 only, outbound whitelist
  53 / 80 / 443.
- `scripts/install-vm.sh user@host` — copies binary, drops service
  file, creates `deaddrop` user + directories, renders Caddyfile
  fragment, enables services, runs smoke test, rolls back on failure.
- `scripts/vm-firewall-check.sh` — asserts expected rules present
  (used by `TESTING.md firewall-audit`).

Tracked under the umbrella handle `DEPLOY-VM`.

---

## F-18  Rotation runbook tooling

`SECURITY.md §Rotation runbook` describes the steps; ship helpers:

- `deaddrop rotate-deploy-secret` — generates new secret, prints the
  `systemctl reload deaddrop` command, and updates
  `~/.deaddrop/config` atomically.
- `deaddrop rotate-capsule` (shipped in D-31; this is the deploy-side
  equivalent).

---

## F-19  Traffic-analysis mitigations

Optional size padding (bucket plaintext to nearest 4 KiB / 64 KiB /
1 MiB) and configurable send delay. Leaks less plaintext size class
at the cost of bandwidth and latency. Opt-in via CLI flags; off by
default.

---

## F-20  LICENSE + SPDX hygiene

Add a top-level `LICENSE` file (Apache-2.0) and ensure every tracked
source file carries an `SPDX-License-Identifier` header. `README.md`
references `LICENSE` but the file is not yet in the repo.

---

## F-21  Release signing + reproducible builds

Sign release binaries (Sigstore / cosign or minisign) and publish
SBOMs. Reproducible-build note in the release checklist — the Go
binary has a fighting chance here given minimal dependencies.

---

## F-22  Web client hardening track

Expansion of F-8 once it ships:

- Version-pinned asset URLs with SRI for every script.
- Strict CSP (`default-src 'self'`, no `unsafe-inline`).
- SBOM for browser deps.
- Timing-side-channel analysis of WebCrypto usage (not all UAs make
  constant-time guarantees).
- Explicit documentation that browser client is a convenience
  surface, not a high-assurance one.

---

## F-23  Operator-observable health endpoint

`GET /_health` returning a signed build-id + a rolling timestamp.
Lets an operator confirm which binary is actually deployed and detect
silent rollbacks. Returns 404 if the request path is not within the
rolling `service_id` window — preserves the anti-enumeration property.

---

## F-25  Mobile / TUI adapters (long-term)

iOS / Android clients — full native crypto, not a WebView over the
web client. Long-term; out of scope for v1. Also consider a
first-class TUI (`deaddrop tui`) for ergonomics on headless boxes.

---

## F-27  `kvm/` disposable test-VM harness

Ship under `kvm/` three bash scripts adapted to deaddrop from the public
KVM harness at github.com/nmicic/compartment (compartment-bpf/kvm):

- `ubuntu-alpine.sh` — **TESTING-ONLY.** Boots a disposable
  cloud-init KVM guest on a dev host, installs the deaddrop Go
  binary + caddy, enables SSH-as-root so a test operator
  can SSH in and run the full e2e test battery from
  `TESTING.md §deployed-vm` against a realistic OS stack. Not a
  production install script. Real deployments go to a separate,
  operator-managed VPS; the disposable VM exists only to validate
  that the code passes e2e before anything touches the VPS.
- `ubuntu-alpine_watcher.sh` — 60s polling daemon that reloads /
  rebuilds the guest when the dev-host repo state changes, so
  a test run starts from a fresh VM without manual rebuild.
  Integrity of the reload trigger is verified via HMAC-SHA256
  against a secret in `/root/.watch_secret`.
- `ubuntu-alpine_sign.sh` — HMAC signer used by the watcher's
  trigger channel.

Explicit non-goals:

- This is not the production install path. `scripts/install-vm.sh`
  (F-16) is that; it targets a VPS the operator provisions and
  hardens separately.
- The disposable VM's "SSH as root" posture is a convenience for the
  test loop and is NEVER a model for the VPS. The VPS runs the
  `deaddrop` user, no login shell, no SSH key — per `BACKEND_VM.md §5`.

Adaptations from the source KVM harness:

- Drop LUKS on the test VM. deaddrop stores only ciphertext; the
  at-rest property is provided by the protocol, not the disk. A LUKS
  layer on a disposable test VM adds noise without adding test
  coverage. The VPS may still use LUKS if the operator wants it; the
  test harness does not.
- The e2e suite invoked inside the guest is `make test-vm`
  (`TESTING.md`), not a generic `make test`.

---

## F-28  Docker + compose base hardening

Ship `Dockerfile` (multi-stage → scratch) and `docker-compose.yml`
with the base hardening block below:

```yaml
services:
  deaddrop:
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    pids_limit: 100
    cpus: 1.0
    mem_limit: 3g
    memswap_limit: 3g
    tmpfs:
      - /tmp
  caddy:
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
      - /run
```

Dockerfile outline:

- Stage 1: `golang:alpine` builds a static `deaddrop-server`
  (`CGO_ENABLED=0`, `-ldflags='-s -w'`, `-trimpath`).
- Stage 2: `scratch` image containing the binary plus
  `/etc/ssl/certs/ca-certificates.crt`. Final image ≈ 7 MiB.
- Runs as a non-root UID baked at build time.
- Holds all ciphertext in mlocked process memory only (D-39). No
  writable on-disk data directory is declared; the container is
  `read_only: true` with `/run/deaddrop` the only writable tmpfs
  mount (socket only, not ciphertext).
- Exposes no TCP port; communicates with caddy via
  `/run/deaddrop/app.sock` on a shared tmpfs mount.

This is the baseline hardening. The runtime-policy overlay
(seccomp + AppArmor) is tracked separately under F-29.

---

## F-30  Sender back-channel retry negotiation

Strict one-shot (`BACKEND_VM.md §3.2`) means a TLS drop mid-download
loses the ciphertext permanently — the in-memory store mutex (D-39)
already committed the decrement and removed the map entry before the
body started streaming. The relay cannot help; by design, it has
nothing left to serve.

The missing piece is a pre-agreed **back-channel** between receiver
and sender so the receiver can signal "I did not successfully drain
slot S, please repost." deaddrop today is one-way: sender → relay →
receiver, with no receiver → sender path. The receiver's only
recourse is out-of-band ("Signal me that the download died").

Sketch (not committed, just a shape):

- Both sides derive a rolling nack_key from the capsule, parallel to
  `slot_key`:
  `nack_key = HMAC-SHA256(PSK, "nack-key-v1" ‖ pair_id)`
- On send, the sender posts the primary ciphertext to slot S as
  normal, AND stays online (or runs a lightweight watcher) for a
  window — say 2–5 minutes.
- If the receiver's GET fails mid-stream, the receiver posts a
  small authenticated marker to a derived
  `nack_slot = HMAC(nack_key, "nack" ‖ bucket ‖ S_ref)` — the relay
  sees only another opaque slot, no semantics.
- The sender watches `nack_slot` across the same skew window. If it
  sees the marker, it re-encrypts and reposts. If it sees nothing
  within the window, the send is presumed delivered.
- Structurally this is a receiver-originated micro-message back to
  the sender: deaddrop becomes a bidirectional pub/sub for control
  messages, which is exactly the direction variant G (messaging bus)
  was already heading. Could land as a subset of G or as a
  standalone protocol option behind a version-byte bump.

Open questions:

- Does this defeat strict one-shot? No — the primary slot S still
  drains exactly once. The nack_slot is a separate slot with its
  own `reads_left = 1`. The retry reposts to a new slot at the next
  minute boundary.
- Does the relay learn anything? It learns that two slots in two
  different derivation domains were posted from the same client IP
  — which it already learns today without the back-channel.
- Identity replay: a nack_slot can only be authored by someone
  holding the capsule. AEAD AD binding (`service_id ‖ slot_id ‖
  version`) on the nack marker prevents cross-deployment replay.
- How long does the sender watch? Coupled to MAX_TTL (so max
  ~10 min default). Past TTL, slot S is gone anyway.

Predecessor inspiration: HOTP-style counter (`URTB`) and the
message-bus / role-suffix patterns in
`experimental/SPEC_DRAFT_G_messaging_bus.md`. G's structure already
has the receiver posting to a derived slot; F-30 is a narrow
version of that for retry negotiation only.

Promotion path: likely graduates as part of G, not as a standalone
variant — G's multi-slot role-suffixed pattern is the natural home
for any receiver-originated message. If G is too big, a "G-retry
subset" could land first as its own D-XX.

---

## F-29  Security overlay — seccomp + AppArmor (LATER PHASE)

Runtime-policy overlay on top of F-28's base compose hardening.
Deliberately deferred.

**Phase gate:** do NOT start this work until:

1. All code is written and merged (relay, Go client, bash
   diagnostic, kvm/ harness).
2. The e2e suite in `TESTING.md` passes against the disposable KVM
   guest AND the staging VPS.
3. F-28's base compose hardening is live.

**Required before VPS-on-internet:** once the service faces the
public internet, this overlay is mandatory, not optional. The
disposable test VM can run without it; the VPS cannot.

Scope when promoted:

- Custom seccomp profile restricting the Go binary to the syscalls
  it actually uses (network, file, epoll, time). Generated by
  recording a clean e2e run under `strace -c` or `falco`, then
  hand-audited. Attached via `security_opt: [seccomp=...]`.
- AppArmor profile confining filesystem access to `/run/deaddrop`
  (socket dir, tmpfs) and `/etc/deaddrop` (read-only secrets). No
  `/var/lib/deaddrop` entry — the process has no writable on-disk
  data directory under D-39. Attached via
  `security_opt: [apparmor=...]`.
- Both profiles version-controlled under `deploy/vm/security/` and
  asserted by a CI test (container refuses to start without the
  named profiles loaded on the host).

Promotion criteria: open a `DECISIONS.md` D-XX when ready to
graduate this out of `FUTURE.md`.

---

## F-31  Admin control-plane (PARKED — for deployment-shape reasons, not security-principle reasons)

Operator needs an alternative to "SSH in and `systemctl restart`" for
stats and bulk wipe. Under D-39 restart *is* the wipe (the in-memory
store is thrown away), but there is no equivalent for "show me how
many slots are live and how much memory they're holding" short of
parsing `/proc/<pid>/status`. A sibling Go service has a rich `/admin/*` surface
guarded by `ADMIN_TOKEN`. The analogous
deaddrop surface would be:

```
GET    /_admin/stats            { slots_count, bytes_used, oldest_expires_at }
GET    /_admin/slots            paged list of sha256(slot_id) + expiry + reads_left
POST   /_admin/purge-expired    run TTL sweep now; returns count deleted
POST   /_admin/purge-all        wipe all rows; requires X-Confirm: wipe-all
DELETE /_admin/slot/{sha256}    remove one slot by *hash* (not raw id)
```

### The real driver: DMZ risk reduction

A typical `/admin/*` surface exists specifically to **avoid needing
SSH on an internet-facing DMZ VM**. The trade-off is NOT "admin
endpoint vs. nothing"; it is:

- **SSH to root / sudoer on a DMZ VPS** — if the credential leaks,
  attacker owns the entire box: `DEPLOY_SECRET`, `WRITE_TOKEN`,
  `CADDY_PREFIX`, journal, TLS private key, can read the running
  relay's memory via `/proc/<pid>/mem` and exfiltrate every live
  slot (D-39 does not protect against on-box root), any other
  services on the host, can modify the Go binary in place, can
  pivot to LAN if the VM has one.
- **Scoped admin token on an HTTPS endpoint** — if the credential
  leaks, attacker can list stats, wipe slots, and nothing else.
  No key material, no plaintext, no host escape, no binary modify.

For an internet-facing VPS, the scoped admin token is **strictly
narrower blast radius** than leaving SSH reachable. "Dumb relay"
framing is real, but it has to be weighed against "what does the
alternative operational path cost?" — and on a DMZ VPS, the
alternative costs more than the admin endpoint.

### Why still PARKED for v1

Not because the admin surface is wrong — because the deployment
shape that needs it isn't v1's target:

- **v1 target is Tailscale / LAN** (`BACKEND_VM.md §6`, "just me"
  single-user knobs). SSH on a private network has a narrower
  exposure than SSH on the public internet — the admin-vs-SSH
  calculus tips the other way.
- **No Go binary exists yet.** Adding a control-plane before the
  data-plane is built is premature.
- **Transport / auth design needs real work.** The common model
  ships `ADMIN_TOKEN` on the same caddy listener as data traffic
  (two-layer: IP allowlist on `@admin` block + bearer). deaddrop's
  `CADDY_PREFIX` shape-match filter (D-34) complicates that: the
  admin path would have to either share the prefix (and then
  senders can enumerate admin paths), or live behind a second
  caddy block with its own IP allowlist or mTLS.

### Current v1 "admin" path

SSH to the VM as a human operator (fine on Tailscale; not fine on
a public-internet VPS). Under D-39 there is no on-disk store to
remove — bulk wipe is simply a restart:

```
systemctl restart deaddrop
```

The in-memory map is thrown away at process exit and rebuilt empty
on start. There is no `bbolt stats` equivalent in v1; operator
visibility for live-slot count / store bytes is deferred to a future
stats surface (either `_admin/stats` once this item promotes, or the
health endpoint in F-23).

### Promotion criteria — revisit F-31 when

1. **Deployment target becomes internet-facing VPS.** At that point
   the DMZ-risk-reduction driver is the primary motivation and
   parking is no longer defensible on "principle."
2. **Transport decision** — pick ONE of:
   - (a) Unix socket + on-host `deaddrop-admin` CLI (no network
     surface; operator still SSHs but the admin capability is
     scoped to the shell account, not root).
   - (b) Separate caddy block with `remote_ip` allowlist
     (Tailscale / bastion IP) + `ADMIN_TOKEN` bearer — a
     standard pattern.
   - (c) Separate caddy block with mTLS (SPEC_DRAFT_D) +
     `ADMIN_TOKEN` bearer — strongest, requires CA work.
3. **Scope hard-pinned: admin MUST NOT read ciphertext.** Listing
   uses `sha256(slot_id)` only; there is no `/_admin/read/{id}`
   endpoint and no admin flag that exposes raw bodies. A compromised
   admin token can observe + wipe but cannot exfiltrate.
4. **`ADMIN_TOKEN` unset → 503 on every admin path** (mirrors
   a standard `e2e-admin` test). Covered by a new `TESTING.md` row.
5. **A `DECISIONS.md` D-XX** records the transport choice and the
   "admin can observe + wipe but not read" invariant as normative.

Until all of these hold, treat any PR that adds `/_admin/*` or
`deaddrop serve --admin-token=...` as premature — but the parking
is "not yet built," not "wrong in principle."

---

## F-32  Hot-standby replication (memory-to-memory only)

D-39 makes process crash = total data loss. That is an explicit
design choice, not a bug — but for operators who want better
availability than "restart costs you every in-flight slot," a
hot-standby relay holding a mirror of the in-memory store would let
the standby take over without replay.

**Hard constraint (inherits from D-39 + D-40): replication MUST be
memory-to-memory AND end-to-end encrypted on the wire. No disk, no
tmpfs, no WAL, no snapshot files, no plaintext-on-wire replication.**
Both primary and standby inherit the full D-39 posture (mlockall,
no swap, no core dumps) and the full D-40 posture (read-only
filesystem, no disk-backed logs). Any persistence or plaintext-
on-wire anywhere in the replication path re-introduces the
"seize the box, get ciphertext" / "snapshot the wire, get
ciphertext" properties D-39 / D-40 were written to eliminate.

Sketch (not committed, just a shape):

- Primary + standby run the same Go binary; standby is read-only
  for the data plane and refuses sender POSTs.
- Replication transport is a mutually-authenticated TCP or unix-
  socket stream (shared secret derived from `DEPLOY_SECRET`, or mTLS
  over SPEC_DRAFT_D). Replication MUST NOT ride the public caddy
  listener.
- On each POST commit in the primary, the store mutex critical
  section is extended to synchronously write `(slot_id, ct, meta)`
  to the replication socket. Standby ACKs before primary returns
  201 to the sender, so one-shot semantics survive primary death.
- On each transactional delete (GET drain or DELETE), primary sends
  a delete record; standby removes + zeroizes the slice.
- Failover is operator-driven (health check + DNS / caddy-upstream
  swap). No automatic leader election in v1 of this design.
- Standby MUST enforce the same mlockall + LimitMEMLOCK=infinity +
  LimitCORE=0 + swap-disabled discipline as primary (D-39). A
  misconfigured standby is a hole in the no-disk property.

Open questions:

- Does synchronous replication turn the store mutex into a latency
  bottleneck? Probably yes under contention; may need a bounded
  async queue with a back-pressure mode that degrades to 503 rather
  than dropping replication lag.
- Split-brain after network partition: the strict-one-shot guarantee
  has to survive both nodes being promoted. Simplest answer is
  operator-driven failover only; no automatic promotion.
- Does replication leak `(slot_id, ct)` tuples anywhere outside the
  two Go processes? The socket endpoints MUST be local to the
  hardened hosts; the wire MUST use the same AEAD-bound framing so
  a passive observer on the replication link learns nothing the
  public relay wouldn't already leak.

Promotion criteria:

1. D-25 Go reference relay is actually built and passing all
   `TESTING.md` rows, including `AC-CRASH-01` (D-39).
2. A `DECISIONS.md` D-XX records:
   - the transport (unix socket vs. authenticated TCP vs. mTLS),
   - the synchronous-vs-async model,
   - the "no disk anywhere in the replication path" invariant,
   - the failover model (operator-driven for v1).
3. The standby-host hardening in `BACKEND_VM.md §5` is extended to
   cover the replication listener (no internet exposure).

Until then, operators who need availability should accept the
D-39 tradeoff: restart is cheap, data loss on crash is the price.

---

## F-33  `deaddrop bootstrap --generator={initiator|responder}`

D-41 ships `deaddrop bootstrap` with "responder generates the PSK"
fixed (back-to-back leg-2 + leg-3 POSTs shave one polling cycle
off the initiator). The choice works for the common case but is
sometimes the wrong side from a trust-surface perspective: when
the operator reached one of the two machines via a jump host, the
PSK's fresh-random moment is cleaner if it happens on the console-
access side regardless of who initiates.

Sketch:

- New flag `--generator={initiator|responder}` on both processes,
  defaulting to `responder` (current behavior).
- If set to `initiator`, leg 3 flips direction (initiator POSTs the
  PSK envelope to the responder after legs 1–2 complete).
  Initiator can no longer pipeline leg 3 with an earlier leg, so
  the total polling cost rises by roughly one polling cycle
  (~1–2 s), well within the bootstrap window.
- Both sides must agree on the value — a mismatch is an
  `EDDBootstrapFlagMismatch` with a clear remediation message. One
  option to avoid mismatch-by-typo: have one side announce its
  generator choice in leg 1 (as an extra field inside the A
  envelope) and have the other side validate before proceeding.
- Spec impact: asymmetric flow diagrams in `SPEC_BOOTSTRAP.md`;
  an extra exit code in `D-38`.

Parked for v1 because the additional CLI + spec surface is real
(responder-generates is a simpler story to test and document) and
the trust-surface win is a power-user concern. Revisit once the
rest of the stack is stable and real deployments report needing
the asymmetric flow.

---

## F-34  Agent-style identity-key protection (ssh-agent analogue)

Graduation gate for F-10 (B′ steady-state) and for D-41's parked
`--keep-keys` opt-in. Until this item lands, deaddrop does not
persist long-term X25519 private keys — see D-42 (WITHDRAWN) for
the full PQC / on-disk-surface regression argument, summarized:

- Plain B's capsule file is symmetric-PQC-safe and Argon2id-wrapped
  under `P_B`. Capture alone yields nothing without the passphrase,
  and even a future quantum adversary cannot shortcut the symmetric
  crypto.
- A persisted X25519 private key (classic crypto) is harvestable
  now, decryptable later — a posture regression deaddrop should not
  accept as a default.

Sketch:

- `deaddrop-agent` long-running process holding identity X25519
  private keys in mlocked memory (parallel to D-39's posture for
  the relay); exposes a local unix socket for sign / DH operations.
- Key material enters the agent via `deaddrop bootstrap
  --keep-keys` (hands the fresh identity secret to the agent before
  zeroizing process-local copies) or explicit import.
- Agent-side access control: PID-matching on the socket + optional
  policy (confirm-on-use, timeout-to-lock, etc.), modeled on
  ssh-agent's `-c` / `-t` semantics.
- Integration path: main `deaddrop send` / `recv` grows an
  optional `KeySource` implementation that talks to the agent
  socket instead of reading `identity.key` from disk. Direct
  `identity.key` file access is **never** added to v1; if F-34 does
  not land before F-10 is promoted, F-10 stays parked.
- Hardware token path (F-14 K4 — YubiKey PIV / TPM / Secure Enclave)
  is the strong form of this item: F-34 is the "no hardware
  required" baseline, F-14 K3 / K4 are progressively stronger
  backings of the same `KeySource` interface.

Promotion criteria:

1. A `DECISIONS.md` D-XX records the agent's protocol, socket
   discipline, and the mlockall / no-swap posture (inheriting
   D-39's framing for relay → agent).
2. `SPEC_DRAFT_Bprime.md` graduates out of `experimental/` with
   normative `KeySource` binding.
3. `deaddrop bootstrap --keep-keys` becomes a supported flag with
   an agent-import codepath, superseding the "parked opt-in" note
   in D-41.
