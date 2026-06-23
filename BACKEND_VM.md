# deaddrop — VM deployment

Self-hosted VM running the Go relay server with an **in-memory
transactional store** (D-39). No disk persistence. This is the
deployment target for deaddrop; there is no parallel "other backend"
after D-33.

---

## 1. When deaddrop is the right fit

- You want strict one-shot semantics: exactly one 200 per `reads=1`
  slot, even under concurrent reads. A single mutex-protected
  `map[slot_id]*slot` critical section covers decrement + delete +
  response staging (D-39).
- You want blobs up to 10 MiB (default) without extra thought.
- You want LAN-only or Tailscale-only deployment, OR internet-facing
  with standard ops hardening.
- You want operator-provisioned mTLS as an option.
- You want ordinary ops tooling (journald, nftables, fail2ban) on a
  Linux VM you already run.
- You want "seize the VM, get nothing" as a threat-model property —
  no bbolt file, no sqlite, no LUKS volume to attack (D-39).

## 2. When deaddrop is NOT the right fit

- You want zero operational work. deaddrop requires patching an
  internet-facing Linux box on an ordinary ops cadence.
- You want global edge distribution from a single deployment.
- You want the relay's in-flight slots to survive a crash or a
  restart (patching, kernel update, power loss). Process restart =
  total data loss, by design (D-39). Slots are ephemeral by spec
  (TTL ≤ 1 hour); a sender that needs delivery confirmation MUST
  obtain it out-of-band.
- You want disk-backed durability or backup/restore. Neither exists
  and neither is coherent with the design — any proposal that adds
  one reopens D-39.

---

## 3. Reference stack

```
           internet (or Tailscale / LAN)
              │
         ┌────┴────┐
         │  caddy  │   TLS 1.2+, Let's Encrypt, optional mTLS
         └────┬────┘
              │ unix domain socket  /run/deaddrop/app.sock
         ┌────┴────┐
         │deaddrop │   Go static binary (D-25)
         │ -server │   mlockall(MCL_CURRENT|MCL_FUTURE)
         └────┬────┘   RLIMIT_CORE=0; PR_SET_DUMPABLE=0
              │
         ┌────┴────┐
         │  map    │   in-memory slot store (D-39):
         │storeKey │     map[storeKey]*slot + sync.Mutex
         │ →*slot  │     key = (service_id_at_post, slot_id)
         └─────────┘     bounded by MAX_STORE_BYTES
                        VM boots with swap DISABLED.
                        Process crash / restart = data loss,
                        by design. No disk persistence.
```

### 3.1 Storage schema (in-memory map `slots`)

```go
// In-memory only; no disk, no WAL, no snapshot. See D-39.
type slot struct {
    ct         []byte    // ciphertext (Go heap; mlocked via mlockall)
    expiresAt  time.Time
    readsLeft  uint32
    deleteHash [32]byte  // SHA-256(delete_token); D-26
}

// storeKey binds service_id_at_post with slot_id. A GET/DELETE under
// a different service_id cannot resolve the slot even if slot_id
// matches — this closes the destructive wrong-hour read at the hour-
// boundary seam (PROTOCOL.md §2 write-vs-read asymmetry).
type storeKey struct {
    svc  [16]byte   // service_id the slot was stored under at POST
    slot [16]byte
}

type store struct {
    mu    sync.Mutex
    bytes int64              // total ciphertext bytes resident (vs MAX_STORE_BYTES)
    m     map[storeKey]*slot // key = (service_id_at_post, slot_id)
}
```

POST acceptance at the hour boundary: the relay recomputes
`service_id(current_hour)` and `service_id(current_hour - 1)` and
accepts the POST if the URL's `service_id` matches either
(write-side skew tolerance per `PROTOCOL.md §2`). The slot is stored
under whichever `service_id` the client actually presented — so
GET/DELETE, which require exact match, will hit the stored entry
when the receiver computes the per-bucket `service_id` using
`hour_of(b)` (`PROTOCOL.md §9`).

A background goroutine sweeps expired entries every 60 s — under
`store.mu`, zeroing each victim's ciphertext before removing its
map entry (same hygiene as the clean-shutdown path).

### 3.2 One-shot semantics (strict)

GET on an entry with `readsLeft == 1` runs in a single critical
section on `store.mu`:

1. Compute `k = storeKey{svc: service_id_from_url, slot: slot_id_from_url}`.
2. Acquire `store.mu`.
3. Look up `m[k]`. If missing or expired → release, 404.
   (A GET whose `service_id` does not match the one the slot was
   stored under at POST produces a miss here — the wrong-hour read
   never reaches the decrement path.)
4. Copy the ciphertext into a fresh per-request `[]byte` (the caller
   streams from this copy outside the lock).
5. Decrement `readsLeft`. If `readsLeft == 0`: zeroize the stored
   ciphertext byte-by-byte, decrement `store.bytes`, and
   `delete(m, k)`.
6. Release `store.mu`.
7. Stream the per-request copy on the response body via `io.Copy`
   (or `http.ResponseWriter.Write` on the slice).

The mutex is released at step 6. The network write in step 7 happens
**outside** any store lock so a slow client does not block concurrent
writes. This serialises every winner on a short critical section and
releases the lock before doing the slow thing — identical reasoning
to the previous bbolt design, with a lighter primitive (D-39).

Concurrent GETs serialize on `store.mu`. Exactly one GET wins → 200
response with the body. All others see a 404 from the uniform-404
class. This is the protocol's one-shot guarantee, not a
deployment-conditional attribute.

**Network drop during step 6 → ciphertext is lost.** This is the
strict-one-shot tradeoff stated explicitly: once the critical section
commits the delete, the map entry is gone AND the original bytes are
zeroed. A TLS drop at 5 MiB into a 10 MiB download cannot be resumed
at the protocol layer. This is a DESIGN property, not a bug —
relaxing it would require a soft-lock window and that reopens the
single-reader guarantee to a race with on-wire observers. Recovery
from mid-transfer drop is the domain of a sender-side back-channel
(see `FUTURE.md F-30`), not the relay.

**Process crash → all slots lost.** The store is memory-only (D-39).
Planned restart (patching, systemd reload), kernel panic, OOM-kill,
host power loss — all produce the same outcome: every in-flight slot
is gone, the new process comes up with an empty map. This is
deliberate and is the same class of event as the TLS-drop case above.
A sender that requires delivery confirmation MUST obtain it
out-of-band (receiver acks via a separate channel). The relay is
not the durability layer.

**Memory / back-pressure constraints.** Two caps apply:

1. **Per-request RSS cap.** The ciphertext copy in step 3 is
   `MAX_BLOB_BYTES`-bounded (10 MiB default). The relay caps
   concurrent in-flight GETs so that
   `MAX_BLOB_BYTES × max_concurrent` fits in RSS with head-room for
   caddy, the Go runtime, and the resident slot store. A
   `semaphore.Weighted(max_concurrent)` gate on GET is the minimum
   acceptable primitive.
2. **Total-store cap (D-39, new).** `store.bytes` MUST NOT exceed
   `MAX_STORE_BYTES` (default `512 × MAX_BLOB_BYTES` ≈ 5 GiB at
   defaults; operator-tunable down to fit `MemoryMax=`). A POST
   that would push `store.bytes` above the cap is rejected.

The HTTP handler MUST stream via `io.Copy` (or
`http.ResponseWriter.Write` on the slice); it MUST NOT build a larger
intermediate buffer (no `bytes.Buffer`-then-`Write`, no multi-pass
encode).

**413 / request-body size enforcement.** `MAX_BLOB_BYTES` is enforced
at **two layers**, both of which MUST be present:

1. **caddy** — `request_body { max_size <MAX_BLOB_BYTES> }` in the
   deaddrop site block. Caddy rejects oversized uploads with 413
   **before streaming any payload to the unix socket**, so the Go
   app never allocates heap for a 1 GiB upload attempt. This is the
   primary defense; without it, an attacker can force the relay to
   buffer up to its configured caddy body limit before the Go app
   sees one byte.
2. **Go app** — `http.MaxBytesReader(w, r.Body, MAX_BLOB_BYTES + 1)`
   at the top of the POST handler. Belt-and-suspenders against a
   misconfigured caddy (missing directive, layer swap, direct unix-
   socket access from an on-host process). Go returns 413 if the
   reader exceeds the cap. The `+1` is intentional: the app reads
   exactly one byte past the cap to distinguish "at the limit"
   (accept) from "over the limit" (reject 413).

Both layers produce HTTP 413 → client exit code 14 `EDDSizeCap`
(D-38). A 413 from either layer is indistinguishable to the client.

**Trusted client-IP handoff from caddy.** Rate limits and abuse
counters are keyed by source IP, but the Go app never sees the
peer's TCP address (it speaks to caddy over a unix socket).
Normative:

- Caddy SHALL **strip** any client-supplied `X-Forwarded-For`,
  `X-Real-IP`, `X-Client-IP`, or `Forwarded` header from the
  inbound request before proxying. Never merge; always replace.
- Caddy SHALL then set `X-DeadDrop-Client-IP: <peer ip>` on the
  proxied request, using caddy's own `{http.request.remote.host}`
  placeholder.
- The Go app SHALL read `X-DeadDrop-Client-IP` only (not
  `X-Forwarded-For`) for rate-limit keying. Requests missing this
  header MUST be rejected with 500 — that means caddy is
  misconfigured or bypassed, and the failure surface should be
  loud, not silent.
- The header name `X-DeadDrop-Client-IP` is deaddrop-namespaced
  deliberately; reusing `X-Forwarded-For` creates confusion with
  any upstream proxy chain in unusual deployments.

**Back-pressure response.** When the semaphore gate is full on GET,
OR when the total-store cap would be exceeded on POST, the relay
returns **503** (NOT the uniform 404 class). Justification: requests
that reach these gates have already passed caddy's shape-match
filter (D-34) and carry a valid `CADDY_PREFIX` + rolling
`service_id`; they are from legitimate clients. Responding 404 to a
legitimate receiver under load would silently corrupt the
strict-one-shot contract — the receiver would exit as "slot not
found" and the sender's guarantee that "receiver got it once" is
violated. 503 maps to client exit code 16 `EDDRelayOverloaded`
(D-38) so wrapper scripts can distinguish transient-retry-later
from permanent classes and back off appropriately. Scanner /
unauthorized traffic is absorbed at caddy and never reaches the
semaphore, so 503 here is NOT an oracle visible to probes.

---

## 4. Operational parameters (defaults)

```
MAX_BLOB_BYTES    = 10_485_760     (10 MiB, per-slot cap)
MAX_STORE_BYTES   = 5_368_709_120  (≈ 5 GiB total resident; D-39)
MAX_TTL_SECONDS   = 3600           (1 hour)
MAX_READS         = 10
DEFAULT_READS     = 1
WRITE_TOKEN       = REQUIRED       (internet-facing; --local-only opt-out)
```

`MAX_STORE_BYTES` MUST be sized beneath the systemd unit's
`MemoryMax=` with head-room for the Go runtime, caddy, and the
per-request copy path (§3.2). Bumping `MAX_BLOB_BYTES` above 10 MiB
is operator-allowed; pair it with a `MemoryMax=` / `MAX_STORE_BYTES`
audit, NOT a disk-quota audit (there is no disk store — D-39).

---

## 5. Security posture — deaddrop-specific

A general self-hosted-service security architecture is a useful companion
read for the layer-by-layer attacker walk (the mental model transfers),
but the list below is deaddrop's own hardening, and several items diverge
deliberately from typical shipped configurations. The divergences are
called out inline.

- **Firewall inbound** (nftables, deaddrop-specific): 443 + 22 only.
  SSH rate-limited to 5 new conns/min. HTTPS rate-limited to 200
  conns/s with burst 50. (A common pattern ships an `iptables`
  script; deaddrop chooses nftables for cleaner rule composition,
  not ported from any existing script.)
- **Firewall outbound**: whitelist 53 / 80 / 443 only. Contains the
  blast radius if the relay binary is ever RCE'd.
- **TLS**: 1.2+ only, HSTS, modern ciphers only.
- **Caddy edge filter** (D-34, deaddrop-specific): caddy accepts only
  `/<CADDY_PREFIX>/<32hex>/<32hex>$`; everything else is 404ed at the
  edge and never reaches the unix socket or the Go binary. The
  `CADDY_PREFIX` is a second, operator-layer secret independent of
  `DEPLOY_SECRET`. Rotated via caddy reload; runbook in `SECURITY.md`.
  Caddy applies `uri strip_prefix /{CADDY_PREFIX}` before
  `reverse_proxy`, so the Go binary sees only the wire-level path
  `/{service_id_hex}/{slot_id_hex}` — the operator-layer prefix never
  enters app logs or error messages. (A typical Caddyfile uses a
  path-whitelist plus `remote_ip` allowlist on an `@admin` block; it
  does NOT use the shape-match-regex + static-prefix pattern. The
  regex-match-then-strip pattern is deaddrop-specific and motivated
  by the need to absorb internet scanner traffic before the Go
  binary sees it.)
- **Unix-socket between caddy and the Go server**: no TCP listener on
  the Go app. Nothing on the host reaches the relay without filesystem
  permission.
- **systemd hardening** (deaddrop-specific, not carved out for
  Docker): `PrivateTmp`, `ProtectSystem=strict`, `NoNewPrivileges`,
  `CapabilityBoundingSet=`, dedicated `deaddrop` user with no login
  shell, no SSH key. (A Docker-oriented hardening config typically
  OMITS `PrivateTmp` / `ProtectSystem` because they break
  the Docker daemon. deaddrop runs as a plain systemd unit, not under
  dockerd, so it CAN apply these — and it does. This is a
  deliberate divergence, not inherited.)
- **Memory-only data plane** (D-39, deaddrop-specific): the Go
  binary stores all ciphertext in process memory; there is no
  `/var/lib/deaddrop` data directory and no disk-backed store.
  Mandatory systemd unit hardening:
    - `LimitMEMLOCK=infinity` — permits `mlockall(MCL_CURRENT |
      MCL_FUTURE)` at startup. The binary refuses to accept traffic
      if `mlockall` fails.
    - `LimitCORE=0` and `PR_SET_DUMPABLE=0` (the latter set by the
      binary via `prctl`) — no core dumps, so a crash cannot drop
      ciphertext to disk.
    - `MemoryMax=` set just above `MAX_STORE_BYTES` + runtime
      overhead; cgroup OOM-kills the binary before the kernel
      starts paging pressure-evicted pages toward swap.
    - `ProtectSystem=strict` + `ReadWritePaths=/run/deaddrop`
      (the socket path only).
  Mandatory VM host config: **swap disabled** (`swapoff -a` and no
  swap partition / zram). Without this, mlock's guarantee weakens
  at the kernel level. Tracked as an install-time assertion in the
  deploy script (F-16).
- **Optional mTLS**: operator-provisioned private CA; clients present
  certs; 4xx on invalid cert at caddy layer. See
  `experimental/SPEC_DRAFT_D_private_CA.md`.
- **Later phase — runtime policy overlay**: custom seccomp + AppArmor
  profiles for the relay container. Tracked as `FUTURE.md` F-29;
  mandatory for any VPS facing the public internet, deferred until
  after all code and e2e tests pass.

---

## 6. "Just me" single-user knobs

For a two-laptop personal deployment:

```
MAX_BLOB_BYTES    = 10_485_760
MAX_TTL_SECONDS   = 600            (10 min)
MAX_READS         = 1              (strict one-shot; no distribution use case)
WRITE_TOKEN       = enabled
ALLOWED_IPS       = (optional) Tailscale ACL only; skip if you use mTLS
```

---

## 7. Build and deploy

Not yet shipped (tracked in `FUTURE.md` F-16 `DEPLOY-VM`). Planned
shape:

```
make build                                     # produces ./deaddrop-server (Go)

./scripts/install-vm.sh user@vm.example.com
  # - copies binary to /usr/local/bin/deaddrop-server
  # - drops /etc/systemd/system/deaddrop.service with LimitMEMLOCK=infinity,
  #   LimitCORE=0, MemoryMax=, ProtectSystem=strict,
  #   ReadWritePaths=/run/deaddrop
  # - creates deaddrop user, /run/deaddrop (socket dir only — there is
  #   NO /var/lib/deaddrop; the store is in-memory per D-39)
  # - asserts swap is off (fails the install if `swapon --summary`
  #   returns non-empty) and emits a one-liner to disable it if set
  # - renders /etc/caddy/Caddyfile fragment
  # - runs: systemctl enable --now deaddrop && systemctl reload caddy
```

Secrets (not baked into the image):

```
/etc/deaddrop/deploy_secret      # mode 0600, owned by deaddrop user
/etc/deaddrop/write_token        # mode 0600, owned by deaddrop user
/etc/deaddrop/caddy_prefix       # mode 0640, owned by caddy (D-34)
/etc/deaddrop/ca.pem             # (optional, mTLS) CA bundle
```

Operational artifacts `deploy/vm/{caddy.conf, systemd/deaddrop.service,
nftables.conf}` are tracked under `FUTURE.md` F-16; none shipped yet.

---

## 8. Testing

See `TESTING.md`:

- `check-vm` smoke target — self-signed cert, local Go server, full
  send/recv round-trip.
- `deployed-vm` — smoke against a running VM.
- Firewall audit — `./scripts/vm-firewall-check.sh` (expected nftables
  rules present).
- `AC-RACE-VM` — 100 concurrent GETs on a `reads=1` slot; expects
  exactly one 200 and the rest 404. This is the canonical one-shot
  race test.

---

## 9. References

- `DECISIONS.md` — D-25 (Go reference client), D-26 (authenticated
  DELETE), D-31 (CLI contract), D-33 (VM/Go as sole deployment
  target), D-34 (caddy edge filter).
- `PROTOCOL.md §10` — delete-on-read semantics.
- `SECURITY.md` — threat model and properties.
- `experimental/SPEC_DRAFT_F_self_hosted_vm.md` — frozen historical
  snapshot of this design before it graduated to the root of the repo.
- `experimental/SPEC_DRAFT_D_private_CA.md` — optional mTLS layer.
- `experimental/BACKEND_CLOUDFLARE_parked.md` — parked Cloudflare
  Worker design (D-33).
