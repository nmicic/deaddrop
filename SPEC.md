# deaddrop — System Specification

---

## What deaddrop is

A single-file ephemeral relay for sending small encrypted blobs between
two laptops over the internet, using an untrusted self-hosted HTTP relay
that stores ciphertext only and deletes it on first read.

Common shape (single-process CLI — D-31 is the sole normative source;
this file mirrors by name, not by re-specifying flag shape):

```
deaddrop keygen <out-path>      # one-time, out-of-band transfer
deaddrop bootstrap --role={initiator|responder}
                                # interactive three-leg pairing over
                                # the relay; replaces OOB capsule-file
                                # transfer. See SPEC_BOOTSTRAP.md.
deaddrop send <file>            # encrypt + POST
deaddrop recv [output]          # blind-probe last ~3 min; GET + decrypt (strict one-shot)
deaddrop fingerprint            # print capsule fingerprint (HKDF-PSK-derived)
deaddrop rotate-capsule         # re-wrap same PSK under a new passphrase;
                                # fingerprint UNCHANGED; no OOB re-transfer.
                                # (Full PSK replacement = `keygen` + OOB
                                # re-transfer of the new capsule.)
```

Capsule path resolution and passphrase entry are specified exactly once
in D-31 (`DEADDROP_CAPSULE` env var or `--capsule <path>`; default
`~/.deaddrop/capsule`). Any re-specification in other docs is an error.

`bootstrap` is the **primary** one-time pairing path (D-41): both
sides run it interactively, a short Diceware passphrase is
transferred OOB (voice / Signal), and the capsule file materializes
on both laptops without a file-copy step. Offline capsule-file
transfer (`keygen` + USB / Signal / existing SSH of the capsule
file) remains as a **backup** for paranoid-mode operators or when a
pre-existing side channel is already present. Steady state after
bootstrap is **plain B**, identical to a capsule produced by
`keygen` + OOB transfer — `send` / `recv` do not branch on pairing
origin. Under the default `--burn` mode, the only on-disk artifact
bootstrap produces is the capsule file; identity X25519 keypairs
are ephemeral to the bootstrap process.

Authenticated DELETE is a **sender-side in-process primitive only**
(D-26 relay-side hash storage; D-35 sender-side in-memory-only
handling). `recv` never holds a delete_token; the default
`reads = 1` drains the slot via strict one-shot. Batch senders use
DELETE to roll back in-process partial failures — see D-35.

The relay never holds passphrases, PSKs, private keys, or plaintext.
The relay holds only `(slot_id → ciphertext, ttl, reads_left, delete_hash)` rows.

---

## What deaddrop is NOT

- NOT a multi-recipient fanout (see `FUTURE.md` F-2)
- NOT a chunked large-file transfer (size-capped; see `FUTURE.md` F-1)
- NOT a chat or sync protocol (one blob per invocation)
- NOT anonymous (relay sees IPs; use Tor/VPN for anonymity)
- NOT a replacement for Signal over LAN
- NOT a hosted service — each user runs their own VM
- NOT a browser-native tool in v1 (web client deferred to `FUTURE.md` F-8)
- NOT forward-secret — a capsule compromise exposes PAST ciphertext that
  was captured on the wire. See `SECURITY.md` and `FUTURE.md` F-10.

---

## Scope of this build cycle

deaddrop ships variant **B** (shared PSK capsule, URTB-style) for
steady-state payload transfer, plus the `deaddrop bootstrap`
provisioning protocol (D-41 / `SPEC_BOOTSTRAP.md`) for first-exchange
pairing. Both target a self-hosted VM with the Go reference binary
(D-25) and an in-memory transactional store (D-39). Cloudflare was
considered as a parallel backend in D-24 and parked in D-33; its
historical design lives under
`experimental/BACKEND_CLOUDFLARE_parked.md`. Parked variant sketches
(B′, C, D, E, G) live in `experimental/`;
`experimental/SPEC_DRAFT_A_passphrase.md` documents the rejected
general-purpose variant A (threat-model finding in D-37) — bootstrap
is NOT a revival of it. See `DECISIONS.md` D-22 for the scoping
decision and D-32 for age being rejected as the crypto core.

### Deployment target (D-33)

| Component | Choice                                              | Reference       |
|-----------|-----------------------------------------------------|-----------------|
| Relay     | Go static binary behind caddy, in-memory mlocked store (D-39) | `BACKEND_VM.md` |
| Blob cap  | 10 MiB plaintext default, operator-tunable          | `BACKEND_VM.md` |
| One-shot  | Strict — single in-memory critical section for decrement + delete + stage body | `BACKEND_VM.md §3.2` |
| Transport | TLS 1.2+ via caddy, optional operator-provisioned mTLS | `experimental/SPEC_DRAFT_D_private_CA.md` |

### Reference client

Go static binary (D-25). Differential testing rides on committed
golden vectors under `testdata/derive/` and `testdata/aead/`, computed
with an independent crypto library at fixture-generation time; no
runtime cross-language oracle ships with v1.

---

## Relay invariants

1. Relay never holds decryption material (passphrase, PSK, private keys).
2. Relay deletes ciphertext transactionally when `reads_left` reaches 0.
3. Relay enforces a maximum TTL even if the client requests longer.
4. Relay refuses POST to an existing slot — no overwrite.
5. Relay enforces a maximum blob size.
6. Relay returns opaque error codes — never leaks slot existence on GET.
   A GET for a non-existent slot and an expired slot return identical
   byte-for-byte responses.
7. Relay validates that the URL path is within the rolling service_id
   window (current hour or previous hour). All other paths: 404, empty body.
8. Relay honors authenticated DELETE: a request carrying a token whose
   SHA-256 hash matches `delete_hash` removes the slot early (D-26).
9. `WRITE_TOKEN` is mandatory on any deployment reachable from the
   internet; `--local-only` is available for LAN / Tailscale.

---

## Default sizing and timing

| Parameter         | Default    | Max            | Notes                                               |
|-------------------|------------|----------------|-----------------------------------------------------|
| MAX_BLOB_BYTES    | 10 MiB     | operator-set   | Default chosen for configs, capsules, small media   |
| TTL (retention)   | 600 s      | 3600 s         | Relay-side retention ceiling. NOT user-visible reach |
| Effective reach   | ~3 min     | ~3 min         | 3 minute-buckets back from receiver's clock — the true end-to-end delivery window |
| reads_left        | 1          | 10             | Normative default is 1; raise only for distribution |
| slot rotation     | 60 s       | —              | `floor(unixtime/60)` time bucket                    |
| service rotation  | 3600 s     | —              | `floor(unixtime/3600)` hour bucket                  |
| skew tolerance    | 3 buckets  | 3 buckets      | Fixed; receiver probes current, −1, −2 (past-only)  |

TTL and effective reach are **two separate numbers, by design**. TTL is
the relay-side retention ceiling — a safety-net that garbage-collects
unclaimed blobs. Effective reach is the user-visible delivery window: the
receiver only probes the last three minute-buckets, so a blob posted
more than ~3 minutes before `recv` ran is unreachable even if it is
still live on the relay. Guidance: run `recv` when you expect a message
to have arrived within the last ~3 minutes; beyond that, re-coordinate
and retry.

Skew is pinned at 3 buckets. The probe is past-only — the receiver
assumes the sender posted **at or before** the receiver's wall clock.
Required clock discipline: the receiver's clock MUST NOT lead the
sender's by more than ~3 min, otherwise the sender's minute-bucket
falls outside the probe window and `recv` returns uniform 404 with no
recourse. Senders ahead of receivers are tolerated only at the
POST-time hour-boundary seam (§2 write-vs-read asymmetry); within a
minute they are not. Operators cannot widen the probe window without a
protocol bump (D-05 superseded on configurability / `PROTOCOL.md §9`).

---

## Two-level rolling URL — core derivation

```
service_id = HMAC-SHA256(DEPLOY_SECRET, "svc"  || enc_u64_be(h))[:16]    (32 hex chars)
slot_id    = HMAC-SHA256(slot_key,      "slot" || enc_u64_be(b)
                                                || enc_u32_be(attempt))[:16] (32 hex chars)

wire path   = /{service_id_hex}/{slot_id_hex}         (what the Go server sees)
full URL    = {RELAY_BASE_URL}/{service_id_hex}/{slot_id_hex}
```

`RELAY_BASE_URL` is the opaque deployment base URL the operator gives
clients. On the normative VM deployment (D-34) it has the form
`https://<host>/<CADDY_PREFIX>`, where `<CADDY_PREFIX>` is an
operator-layer secret stripped by caddy before the Go server is
invoked — so the Go binary only ever observes the wire path
`/{service_id_hex}/{slot_id_hex}` above. `RELAY_BASE_URL` is the
SINGLE source of the host + prefix; examples elsewhere that look like
`https://deaddrop.my.vm/...` omit `<CADDY_PREFIX>` purely for
illustration and are NOT normative.

where `h = floor(ts/3600)`, `b = floor(ts/60)`, and `slot_key` is the
per-capsule value defined in `SPEC_DRAFT_B_capsule.md`.

- `DEPLOY_SECRET` is a per-deployment secret shared by all clients of this
  relay and baked into the relay (VM config).
- `slot_key` is derived from the capsule PSK and `pair_id` — two capsules
  for the same relay never collide on the same minute (D-27).
- Only clients holding BOTH `DEPLOY_SECRET` and the per-capsule material
  can address a slot.
- The relay accepts POSTs under `service_id(current_hour)` OR
  `service_id(current_hour-1)` (absorbs sender-vs-relay skew on write).
  GET/DELETE requires an **exact match** against the `service_id` the
  slot was stored under at POST time — the in-memory store is keyed by
  `(service_id_at_post, slot_id)` per D-39. The relay still cannot
  decrypt the body.
- `service_id` was widened from 8 bytes (16 hex) to 16 bytes (32 hex) per
  D-29 — security-first: 128-bit search space against enumeration.

See `PROTOCOL.md` for encodings, endpoints, error codes, and skew probing,
and `SPEC_DRAFT_B_capsule.md` for capsule-derived keys.

### Honest framing of the rolling prefix (D-30)

The rolling `service_id` is an anti-enumeration mechanism, not an identity
layer. A passive observer on the wire sees:

- The IP / SNI of the relay (TLS does not hide the destination host).
- The exact `service_id` and `slot_id` on every GET and POST (path is
  cleartext above TLS termination).

What the rolling prefix does:

- Makes internet-wide scans for known relay IP ranges infeasible (a
  scanner needs the current `service_id` to get anything other than a
  uniform 404).
- Bounds how long any single observed URL remains resolvable (one hour
  for the prefix, one minute for the slot under current-bucket probe).

What it does NOT do:

- Hide the relay from anyone who sees your TLS traffic.
- Rotate identities against a relay operator who logs full URLs — they
  see every `(service_id, slot_id)` pair regardless of rotation cadence.

---

## Threat model summary

See `SECURITY.md`. Assume:
- Relay is untrusted (subpoena-ready, log-hungry) — even though the
  operator owns it, treat it as compromised for design purposes.
- Network path is observed (TLS hides body, not endpoints / URL paths).
- Adversary may brute-force captured ciphertext offline.
- Laptops may be stolen — capsules must be Argon2id-encrypted at rest.
- Forward secrecy is NOT provided by variant B: if the capsule is
  compromised and ciphertext was captured on the wire, plaintext is
  recoverable.

Do NOT assume:
- Clocks are synchronized (expect skew; receiver probes current and two
  prior buckets).
- Passphrases are strong unless generated by the tool.
- Shared hosting is acceptable — it is not.
