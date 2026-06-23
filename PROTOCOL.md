# deaddrop — Wire Protocol

deaddrop runs on a self-hosted VM with the Go reference binary and an
in-memory transactional store (D-39); see `BACKEND_VM.md` for the
operational story. Cloudflare was considered as a parallel backend in D-24 and
parked in D-33 — its historical design lives under
`experimental/BACKEND_CLOUDFLARE_parked.md` and is not part of this
protocol as shipped.

Variant B is the shipped steady-state payload mode (D-22). The
shipped surface also includes the `deaddrop bootstrap` provisioning
protocol (D-41 / `SPEC_BOOTSTRAP.md`); bootstrap is not a payload
mode but it rides this same wire (see §7 and §12). Parked payload
modes (B′, C, D, E, G) live in `experimental/`;
`experimental/SPEC_DRAFT_A_passphrase.md` documents the rejected
general-purpose variant A (D-37).

**Normative precedence** when two root docs disagree: `PROTOCOL.md`
owns HTTP semantics and URL construction; `SPEC_DRAFT_B_capsule.md`
owns variant-B crypto (capsule format, key derivations, AD binding);
`DECISIONS.md D-31` is the sole normative source of CLI syntax
(flag names, passphrase-entry paths, capsule-path resolution) —
`SPEC_DRAFT_B_capsule.md` and `SPEC.md` mirror D-31 by command name
only and MUST NOT re-specify flag shape. `SPEC.md` is high-level and
MUST NOT restate low-level semantics imprecisely. `DECISIONS.md
D-38` is the sole normative source of CLI exit codes and error names.

---

## 1. URL structure

```
/{service_id}/{slot_id}
```

Where:

```
service_id = HMAC-SHA256(DEPLOY_SECRET, "svc" ‖ enc_u64_be(h))[:16]
                where h = floor(unixtime / 3600)
slot_id    = HMAC-SHA256(slot_key,     "slot" ‖ enc_u64_be(b) ‖ enc_u32_be(attempt))[:16]
                where b = floor(unixtime / 60), attempt ∈ {0, 1, 2, ...}
```

`[:N]` means the first `N` **raw bytes** of the HMAC output (not hex
chars), hex-encoded to `2N` lowercase characters in the URL. So
`service_id` is 16 raw bytes → 32 hex chars; `slot_id` is 16 raw bytes
→ 32 hex chars. Clients MUST emit lowercase hex; uppercase or
mixed-case paths are rejected at the caddy edge (D-34 regex is
`[0-9a-f]{32}`) and never reach the Go relay. Normative: Go's
`hex.EncodeToString` output is the canonical on-wire form.

**Canonical HMAC input encoding** (the `‖` operator):
- ASCII label fields ("svc", "slot", "slot-key-v1") — raw ASCII bytes,
  no length prefix, no null terminator.
- Integer fields — `enc_u64_be` is unsigned 64-bit big-endian; `enc_u32_be`
  is unsigned 32-bit big-endian. No textual decimal encoding ever.
- Concatenation is byte-level with no separator byte.

Any two implementations following this encoding produce byte-identical
HMAC inputs. See `testdata/derive/*.json` (TESTING.md
AC-DER-FIXTURES) for check-in vectors once the reference client
exists.

`slot_key` derivation is specified in `SPEC_DRAFT_B_capsule.md`; the
slot_key is not the capsule PSK directly (defense in depth per D-17
and D-27).

---

## 2. Rolling service prefix

Write-vs-read asymmetry (per §9):

- **POST** — the relay accepts `service_id` matching HMAC for the
  current hour OR the previous hour. This absorbs sender-vs-relay
  clock skew around the hour boundary (sender may be a few seconds
  behind the relay's wall clock and still land in the relay's
  previous-hour bucket).
- **GET / DELETE** — the relay requires an **exact match** against
  the `service_id` the slot was stored under at POST time. The
  in-memory store is keyed by `(service_id_at_post, slot_id)` per
  D-39; a GET/DELETE under a different `service_id` cannot resolve
  the slot even if `slot_id` is correct. This closes a wrong-hour
  read that would otherwise consume a live blob.

Comparisons are constant-time on the relay. Anything else → 404,
empty body (indistinguishable from "no such slot" per D-14).

What the rolling prefix buys:
- **Scanner resistance**: probes from attackers who do not hold
  `DEPLOY_SECRET` land on a byte-identical 404 regardless of what
  path they guess.
- **Log-binding friction**: a log that retains full URLs eventually
  stops pointing at any one live prefix. Hourly rotation combined
  with per-minute `slot_id` means no single URL from a log six hours
  old is still resolvable.

What the rolling prefix does **not** buy (D-30):
- It does not hide the relay's existence. A VM is discoverable via
  Certificate Transparency on its TLS cert.
- It is not an access control mechanism. Access control is
  `WRITE_TOKEN` (§4), plus optional operator-provisioned mTLS
  (`experimental/SPEC_DRAFT_D_private_CA.md`).

`DEPLOY_SECRET` is a deployment-level secret shared by all clients of
one relay; the per-send capsule PSK is separate (see
`SPEC_DRAFT_B_capsule.md`).

---

## 3. Endpoints

### POST /{service_id}/{slot_id}

Upload ciphertext to a slot.

```
Body:    application/octet-stream, max MAX_BLOB_BYTES
Query:   ?ttl=<seconds>     default 600, max 3600 (clamped)
         ?reads=<N>         default 1,  max 10   (clamped)
Headers: X-DeadDrop-Write:       <WRITE_TOKEN>         (required on internet-facing)
         X-DeadDrop-Delete-Hash: hex(SHA-256(delete_token))  (optional; enables DELETE)
```

Response codes:

| Code | Meaning                                  | Body |
|------|------------------------------------------|------|
| 201  | Created                                  | empty |
| 401  | Missing/wrong `X-DeadDrop-Write` token   | empty |
| 404  | Invalid `service_id` (uniform-404 class) | empty |
| 409  | Slot already exists (no overwrite)       | empty |
| 413  | Body too large                           | empty |
| 429  | Rate limited (may carry `Retry-After`)   | empty |
| 503  | Relay overloaded (semaphore gate full; see `BACKEND_VM.md §3.2`) | empty |

All responses on POST have empty bodies. No JSON. The client learns
`reads_left` and clamped `ttl` implicitly — those are operator-fixed
and the client already passed them in the query string.

### GET /{service_id}/{slot_id}

Retrieve a slot's ciphertext. On the read that drains `reads_left` to
0, the relay deletes the slot transactionally before returning
(decrement + delete + stage body + zeroize all inside one mutex-
guarded in-memory critical section; see §10 and D-39).

```
Response 200: application/octet-stream, the stored blob
              Header: X-DeadDrop-Reads-Left: <N>
Response 404: invalid service_id OR slot not found / expired / exhausted
              (all indistinguishable — uniform-404 per D-14)
```

The 200 response carries exactly one custom header
(`X-DeadDrop-Reads-Left`); 404 responses carry none. This asymmetry
is itself a signal (200 vs. 404), which is unavoidable and matches
the protocol contract.

GET requests MUST NOT carry the `X-DeadDrop-Write` header. The
write-token is a write-path credential only; sending it on GET
leaks the credential into relay access logs, proxy logs, and
traffic-capture tooling for zero authorization benefit. This
applies to all GET sites: client `recv`, bootstrap leg-1 / leg-2 /
leg-3 polling, and any future GET path. Relays MUST NOT inspect
`X-DeadDrop-Write` on GET (D-45).

### DELETE /{service_id}/{slot_id}

Client-initiated early expiry, authenticated per D-26.

```
Headers: X-DeadDrop-Delete-Token: hex(delete_token)   (required)
```

The relay computes `SHA-256(hex-decoded delete_token)` and compares
constant-time against the hash stored at POST time.

| Outcome | Response |
|---------|----------|
| Valid `service_id` AND stored hash matches provided token | 204, empty body, slot removed |
| Valid `service_id` AND (no slot / hash mismatch / slot had no delete-hash registered) | 404, empty body |
| Invalid `service_id` | 404, empty body (uniform-404 class) |

204 is only reachable with a correct token. The 404 cases are
byte-identical to the GET 404, so DELETE is not a correlation oracle.

If a client posted without `X-DeadDrop-Delete-Hash`, DELETE on that
slot is always 404 (there is no stored hash to match against).

### Any other path or method

Response 404, empty body, uniform with D-14. This includes `HEAD /`,
`GET /`, and any unrecognized method on a valid slot path. There is
no public liveness endpoint in v1 (D-28); operator liveness probes
live on a non-public path (see `BACKEND_VM.md`).

---

## 4. Write authentication

`WRITE_TOKEN` is mandatory by default on internet-facing deployments
(`--local-only` opt-out exists for LAN/Tailscale deployments).

```
Header: X-DeadDrop-Write: <WRITE_TOKEN>
```

`WRITE_TOKEN` is compared constant-time on the relay. Mismatch or
absence → 401 (empty body). `WRITE_TOKEN` is distinct from
`DEPLOY_SECRET` and from the per-send capsule PSK.

Without write-auth, any party who learns `DEPLOY_SECRET` can fill
slots and exhaust disk. `WRITE_TOKEN` raises the required secret set
for write-side abuse from one to two.

Rotation: see `SECURITY.md` "Rotation." Dual-acceptance during
rotation is tracked in `FUTURE.md`.

---

## 5. Error responses

All non-200 responses have empty bodies and only the minimum headers
the HTTP layer requires (status, `Content-Length: 0`, platform
headers). No JSON error messages, no `X-Error-Code`, no diagnostic
text. Status codes only.

Test coverage: `TESTING.md` AC-404-* and S-03 enforce byte-identical
404 responses across the five no-oracle classes (AC-404-WRONGSVC,
AC-404-NOSLOT, AC-404-EXPIRED, AC-404-EXHAUSTED, AC-404-WRONGTOKEN).

---

## 6. Headers the relay reads

| Header                      | Purpose                                  | Required |
|-----------------------------|------------------------------------------|----------|
| `X-DeadDrop-Write`          | Write token                              | Yes on internet-facing deployments |
| `X-DeadDrop-Delete-Hash`    | `hex(SHA-256(delete_token))` (POST-only) | No (omitting disables DELETE) |
| `X-DeadDrop-Delete-Token`   | `hex(delete_token)` (DELETE-only)        | Yes on DELETE |

All other headers are ignored. `User-Agent` is not logged by default;
operators may enable logging per `BACKEND_VM.md` guidance.

`X-DeadDrop-Content-Type` from prior drafts is removed (D-28). Any
content-type hint belongs inside the AEAD plaintext in the v2 prelude
(D-23).

---

## 7. Body format

The body is an opaque ciphertext blob. The relay stores it byte-for-byte
and does not parse or validate it.

Wire format (plain B, `version = 0x01` — steady-state payload):

```
body = version(1) ‖ nonce(24) ‖ aead_ct(N) ‖ tag(16)
```

- `version` — one byte. Parser dispatches on this byte before any
  cryptographic operation. Unknown version → reject. See §12 for
  the full shipped-body-version table (bootstrap legs use `0x02`
  and `0x03`; bootstrap wire detail lives in `SPEC_BOOTSTRAP.md`).
- `nonce` — 24 random bytes per POST (IETF XChaCha20-Poly1305). See
  `SPEC_DRAFT_B_capsule.md` for the nonce-freshness requirement on retries.
- `aead_ct` + `tag` — XChaCha20-Poly1305 ciphertext and 16-byte tag.

AEAD associated data (D-27):

```
AD = service_id_bytes(16) ‖ slot_id_bytes(16) ‖ version(1)
```

Binding `service_id` prevents cross-deployment replay; binding `slot_id`
prevents cross-slot replay; binding `version` prevents a downgrade
attack across wire-version dispatch.

Algorithm: XChaCha20-Poly1305 (IETF). `SPEC_DRAFT_B_capsule.md`
specifies the key derivation that produces `aead_key`.

### Forward compatibility

A future wire version (v4+, `0x04…`) MAY introduce a metadata
prelude inside the encrypted plaintext, carrying fields such as
`sent_at`, `filename`, `content_type`. v1 plaintext is raw user
bytes; no prelude. A receiver parses the version byte first, then
decrypts according to that version's rules. See `DECISIONS.md`
D-23 and §12 below.

Parked variant body shapes (C, D, E, G) are documented in
`experimental/`. `experimental/SPEC_DRAFT_A_passphrase.md` describes
the rejected general-purpose variant A; bootstrap is a provisioning
protocol, not a variant-A revival. The wire version byte is reserved
for B's evolution, for the shipped bootstrap legs (§12), and for any
variant that graduates out of `experimental/`.

---

## 8. Operational parameters

Set on the relay:

```
DEPLOY_SECRET       32+ raw bytes, stored with a "hex:" or "b64:" prefix (see note below)
WRITE_TOKEN         32+ raw bytes, stored with a "hex:" or "b64:" prefix (see note below)
MAX_BLOB_BYTES      10485760 (10 MiB), operator-tunable
MAX_TTL_SECONDS     3600
MAX_READS           10
```

Set on every client (e.g. `~/.deaddrop/config`):

```
DEPLOY_SECRET       same as relay (deployment-shared secret)
WRITE_TOKEN         same as relay (deployment-shared secret)
RELAY_BASE_URL      opaque operator base URL including caddy prefix,
                    e.g. https://deaddrop.my.vm/<CADDY_PREFIX>  (D-34)
                    — the client appends /{service_id}/{slot_id} to this.
                    The Go relay only sees the path AFTER caddy strips
                    /<CADDY_PREFIX>, so <CADDY_PREFIX> does NOT appear
                    in the wire paths defined in §3.
DEADDROP_CAPSULE    optional path override (default ~/.deaddrop/capsule)
```

Encoding note on `DEPLOY_SECRET` and `WRITE_TOKEN`: all values are
stored with a leading `hex:` or `b64:` prefix so the client cannot
misparse a 32-character ASCII string that happens to be valid base64.
Values without a prefix are rejected.

`b64:` values are standard, padded base64 per RFC 4648 §4 (Go:
`encoding/base64.StdEncoding`). URL-safe (`base64url`, RFC 4648 §5)
and unpadded variants are reserved and MUST be rejected by both
client and relay parsers. The unified parser lives at
`internal/secretparse/`.

### 8.1 DEPLOY_SECRET / WRITE_TOKEN delivery (D-43)

Per D-43, the argv path is deprecated in v0.1.x and removed in v0.2.
All four binaries (`deaddrop send`, `deaddrop recv`,
`deaddrop bootstrap`, `deaddrop-relay`) accept the secret via:

1. `--deploy-secret-fd <n>` — read from an open file descriptor.
   The fd is read until first LF or EOF (≤1024 bytes); one trailing
   LF (and one preceding CR) are stripped, then the value flows
   through `internal/secretparse.Parse` unchanged. Same shape for
   `--write-token-fd <n>` on the relay binary.
2. `$DEADDROP_DEPLOY_SECRET` — canonical client / relay env-var.
   Symmetric `$DEADDROP_WRITE_TOKEN` for the relay's write-token.
3. `--deploy-secret <value>` on argv — DEPRECATED. Emits a stderr
   WARN at startup; removed in v0.2. The relay version of the WARN
   notes that the relay is long-lived and the exposure persists in
   `ps` for the entire process lifetime, not a brief one-shot.

Precedence (highest first):
`-fd` > `$DEADDROP_*` > legacy `$DEPLOY_SECRET` / `$WRITE_TOKEN` (relay only) > argv.

Legacy unprefixed env-vars (`DEPLOY_SECRET`, `WRITE_TOKEN`) are
accepted by the relay binary only, with a deprecation WARN; they
exist for backward compatibility with the existing
`/etc/deaddrop/relay.env` shape and are removed in v0.2.

When more than one source is set, the relay / client emits a
stderr WARN naming the precedence winner, in addition to any
argv-deprecation warning that may apply.

The `hex:` / `b64:` prefix discipline (above) applies to all
delivery paths uniformly — fd does not bypass parsing.

---

## 9. Clock skew — receiver probing

Senders derive with the current time bucket. Receivers probe backwards
only (the sender cannot post to a future bucket the receiver will never
probe — the receiver's clock is authoritative for past buckets only).

Each minute-bucket has its own hour. For a minute-bucket `b`, the
hour-bucket is computed deterministically:

```
hour_of(b) = b / 60        # integer division; b = floor(unixtime/60)
```

The receiver derives one `service_id` per minute-bucket using that
bucket's own hour, eliminating the hour-boundary seam:

```
K = 3  # fixed; no env override (D-05 superseded on configurability)
for b in [now_bucket, now_bucket-1, now_bucket-2]:
    h    = b / 60
    svc  = HMAC-SHA256(DEPLOY_SECRET, "svc"  ‖ enc_u64_be(h))[:16]
    slot = HMAC-SHA256(slot_key,      "slot" ‖ enc_u64_be(b) ‖ enc_u32_be(0))[:16]
    GET /{svc}/{slot}
    if 200: decrypt; if decrypt success: return
```

Three GETs, each under the `service_id` matching that minute-bucket's
hour. No "try both hours" ambiguity, AD binding intact, always
exactly three requests per `recv`.

The POST-time relay still accepts `service_id(current_hour)` OR
`service_id(current_hour - 1)` (§2) — that absorbs sender-vs-relay
clock skew on the write side. On the read side, `hour_of(b)` is
exact and the relay store requires exact service_id match for
retrieval (D-39 store keying). Different rules on write vs read
by design.

`attempt = 0` is fixed on both sides (D-36). Sender posts once at
`attempt = 0` and does not retry on 409. Receiver probes `attempt = 0`
only. The minute-bucket in the `slot_id` derivation is itself the
hold-timer on the slot address: within one minute, the derived
`slot_id` is occupied; at the next minute rollover, a fresh address
is available. This mirrors the idle-timeout + IP-hold-timer pattern
used in mobility networks to prevent same-address reuse within a
window.

Sender attempt policy: `MAX_SEND_ATTEMPTS = 1`. A 409 response
(slot already exists in this minute) is a terminal error — the
sender returns the stable error code `EDDCollision` and exits with
shell exit code 12 (`DECISIONS.md D-38`). The user retries at the
next minute boundary. 128-bit `slot_id` collisions across distinct
capsules have vanishing probability (birthday ≈ 2^64 same-minute
sends); 409 in practice means the same capsule posted twice in one
minute.

Other relay responses map to the stable shell exit codes in D-38:
401 / 403 → `EDDAuth` (13), 413 → `EDDSizeCap` (14), 503 →
`EDDRelayOverloaded` (16), other 5xx / network → `EDDRelayUnreachable`
(11). `EDDRelayOverloaded` is split out from `EDDRelayUnreachable`
so wrappers can treat it as transient-retry-later (the relay is up
but back-pressured — see `BACKEND_VM.md §3.2`) rather than
permanent-unreachable. Clients MUST emit the single-line
`ERROR: <EDDName>: <detail>` stderr prefix on every non-zero exit
so wrapper scripts can branch on `$?` without parsing English.

Legitimate multi-slot operations do NOT use `attempt` to
disambiguate — they use domain-separated `slot_id` derivations:

- Chunked send (`FUTURE.md F-1`):
  `slot_id = HMAC(slot_key, "chunk" ‖ bucket ‖ idx)`.
- Multi-recipient fanout (`FUTURE.md F-2`): per-recipient
  `slot_key` (different capsule per recipient).

The `attempt` field remains in the derivation formula as a reserved
value (fixed at 0 in v1); a future wire-version bump may reintroduce
nonzero attempts with matching receiver-side probing.

Effective end-to-end reach: up to ~3 minutes (three minute-buckets
back from the receiver's wall clock). This is the user-visible
delivery window. It is **not** the relay's TTL — TTL is retention
(`MAX_TTL = 600 s`), a safety-net for relay-side expiry of
unclaimed blobs, not a user-visible reach guarantee. The two
numbers are separate by design. Run `deaddrop recv` when you
expect a message to have arrived within the last ~3 minutes;
beyond that, re-coordinate and retry.

---

## 10. Delete-on-read semantics

On the GET that drains `reads_left` to 0, the relay runs a single
mutex-guarded in-memory critical section (D-39): decrement
`reads_left`, remove the map entry, stage the response body (the
ciphertext just read), zeroize the backing slice. Concurrent GETs
serialize on the store mutex — exactly one wins → 200 with body; all
others see the uniform 404. Process crash mid-transaction loses the
slot entirely and is the accepted failure mode; see D-39 and
`SECURITY.md §Subpoena / compromise response`.

This is **strict** one-shot, not best-effort. It is a protocol
guarantee, not a deployment-conditional one.

---

## 11. Metrics (relay records, without leaking content)

- Count of POST by outcome (201/401/409/413/429).
- Count of GET by outcome (200/404).
- Count of DELETE by outcome (204/404).
- Bytes stored, bytes served.
- Slot count, expired-vs-drained ratio (abuse signal).
- Rate-limiter counters per source IP (not per `service_id`).

Relay MUST NOT log:
- Body bytes.
- `slot_id` beyond a rolling salted hash (rotated on capsule-
  rotation cadence).
- `service_id` with per-hour granularity (would tie logs to a future-
  exfiltrated `DEPLOY_SECRET`); hash-through-salt if retained.
- `DEPLOY_SECRET` or `WRITE_TOKEN`.
- Client capsule PSK (the relay does not have it; this is a
  defensive check against accidental header logging).
- Full `User-Agent` strings.

Uniform-404 (D-14) applies to the external HTTP response. Internal
metrics MAY distinguish the four 404 classes (wrong-prefix, no-slot,
expired, exhausted) for operator debugging; those counters MUST NOT
feed any externally-observable header.

---

## 12. Versioning

Two versioning surfaces:

**Wire body version** — the leading byte of the encrypted body (§7).
Identifies the on-the-wire framing (nonce layout, AD composition,
whether a metadata prelude is present inside the plaintext, whether
a cleartext key-material prefix precedes the nonce).

**KDF / protocol version** — embedded in HKDF `info` strings as
`"deaddrop-v1-<variant>"` and bound into AD per D-27. Bumped when the
key-derivation rules change (new KDF, new domain-separation scheme,
new variant-letter semantics).

### Shipped wire-body versions

| `version` | Meaning                                         | Body shape                                                   | Spec owner                  |
|-----------|-------------------------------------------------|--------------------------------------------------------------|-----------------------------|
| `0x01`    | Plain B — steady-state payload                  | `version ‖ nonce ‖ aead_ct ‖ tag`                            | `SPEC_DRAFT_B_capsule.md §3`|
| `0x02`    | Bootstrap leg 1 / leg 2 (pubkey exchange)       | `version ‖ nonce ‖ aead_ct ‖ tag` (Argon2id(P_A)-keyed)      | `SPEC_BOOTSTRAP.md §2.4`    |
| `0x03`    | Bootstrap leg 3 (PSK delivery, two-DH-keyed)    | `version ‖ eph_pk ‖ nonce ‖ aead_ct ‖ tag`                   | `SPEC_BOOTSTRAP.md §5`      |
| `0x04…`   | Reserved for future suite changes (F-6 PQC)     | —                                                            | `FUTURE.md` F-6             |

Parser dispatch is **by version byte** — full stop. There is no
"dispatch by slot-derivation domain" special rule; a client that
fetches a slot it derived itself still MUST check the version byte
against the body shape it expects for that slot's role, and reject
with `EDDCryptoLocal` (exit 10) on mismatch.

**Coupling rule (D-23 clarification):** a KDF bump MUST coincide with
a wire-body version bump. Receivers dispatch on the wire-body version
byte first; that byte determines which HKDF info string they use.
A KDF change that was invisible to the receiver (same wire byte, new
info string) would cause silent tag failure, not a helpful error.
Hence the requirement: version evolution is single-surface at the
wire byte, with the KDF info string following along.

Breaking changes on `0x01` (plain B) → bump to the next unused
version in `0x04…` and run both versions for a transition period.
`0x02` / `0x03` are bootstrap-only and have no deployment-side
transition concern (bootstrap is short-lived per-pair).
