# deaddrop — Cloudflare Worker backend profile (`worker-kv`)

> **Status: PARKED (D-33).** Cloudflare is no longer a supported
> deployment target for deaddrop. The shipped backend is VM/Go
> (`../BACKEND_VM.md`). This document is a frozen snapshot of the
> Cloudflare design that was considered alongside the VM backend in
> D-24. It is retained for history, to preserve the backend comparison,
> and so that anyone who wants to reopen the
> question has the full context without reconstructing it from scratch.
> Do not edit — reopening the decision goes through a new D-XX entry
> that supersedes D-33. Root docs may still reference Cloudflare only
> to say it is parked; they do not depend on any content here.

Cloudflare Worker with KV storage. Zero-ops, global edge, free-tier-
friendly. Same wire protocol as `vm-tx` (`PROTOCOL.md`), different
one-shot guarantee. Added per D-24.

---

## 1. When `worker-kv` is the right backend

- You want a personal deaddrop relay with zero VM operations.
- Global edge distribution matters (receiver latency varies widely).
- You accept **best-effort** one-shot semantics (see §3).
- 1 MiB default blob cap is sufficient (capsules, config files,
  recovery phrases, small credentials).

## 2. When `worker-kv` is NOT the right backend

- You need strict one-shot. Use `vm-tx` instead, or wait for the
  Durable Objects profile (`FUTURE.md` F-4).
- You need blobs ≥ 1 MiB regularly.
- You don't want a Cloudflare account or a Cloudflare dependency.
- You want mTLS-based access control without paying for Cloudflare
  Access.

---

## 3. One-shot semantics — best-effort on KV

Cloudflare KV is eventually consistent across regions. A GET that
drains `reads_left` to 0 issues the KV delete and returns the body;
a concurrent GET arriving at a different region (or the same region
before the delete propagates) can also read the body.

This is the **fundamental tradeoff** of `worker-kv`: operational
simplicity in exchange for a rare but real double-read window. The
window is typically sub-second but is not bounded by the protocol.

**Operator-facing claim:** on `worker-kv`, "delete-on-read" is a
best-effort property, not a guarantee against a race. A sender whose
threat model requires strict single-read MUST deploy `vm-tx`.

**Mitigation paths:**
1. Durable Objects — strict one-shot on Cloudflare, tracked as
   `FUTURE.md` F-4. Adds cost (DO is billed; KV free tier is
   generous). Not shipped in v1.
2. `vm-tx` for any content whose re-read would matter.
3. Short TTL + short-lived sender/receiver window — reduces the
   chance of a concurrent GET in practice without changing the
   underlying property.

Test coverage: `TESTING.md AC-RACE-KV` documents the expected
behavior on KV (may return 2× 200 on concurrent GET); this is the
profile's documented contract, not a bug.

---

## 4. Operational parameters (defaults)

```
MAX_BLOB_BYTES    = 1_048_576    (1 MiB)
MAX_TTL_SECONDS   = 3600
MAX_READS         = 10
DEFAULT_READS     = 1
WRITE_TOKEN       = REQUIRED     (no --local-only opt-out; CF is internet-facing)
```

The 1 MiB cap is 25× below Cloudflare KV's value size limit
(25 MiB), leaving headroom for the 1-byte version + 24-byte nonce +
16-byte AEAD tag wrapping without bumping against KV's edge.

KV free tier: 1000 writes / day. `TESTING.md AC-QUOTA-KV` asserts
the client surfaces a 5xx or 429-style error cleanly when KV write
quota is exhausted.

---

## 5. Cloudflare-as-adversary posture

Unlike `vm-tx` (which the operator owns end-to-end), `worker-kv` puts
Cloudflare in the trust path. Honest accounting:

- **CF terminates TLS** and sees the full URL path (both `service_id`
  and `slot_id` HMACs). Ciphertext is end-to-end encrypted; URL
  metadata is not.
- **CF stores ciphertext in KV** with global replication. The
  ciphertext is AEAD-sealed under a key never shared with CF, but
  the bytes persist in CF's storage for the TTL plus replication lag
  (and potentially longer if CF retains access-log / blob-metadata
  state beyond stated TTL).
- **CF holds `DEPLOY_SECRET` and `WRITE_TOKEN`** as Worker Secrets.
  Under compulsion (legal subpoena, state actor) CF staff can read
  these. An adversary who exfiltrates `DEPLOY_SECRET` can derive
  future URL paths but still cannot decrypt; an adversary who
  exfiltrates `WRITE_TOKEN` can POST DoS traffic but still cannot
  decrypt.
- **CF can perform silent GET races** against freshly-arrived
  `slot_id`s within the TTL window. deaddrop's threat model includes
  this possibility; the AEAD key and the capsule PSK are never
  within CF's reach.
- **Access logs** may retain full URLs at the edge even if the relay
  code does not. Per-minute `slot_id` rotation bounds how long any
  single URL is resolvable; per-hour `service_id` rotation does the
  same for the prefix.

If CF is an active adversary in your threat model, deploy `vm-tx`
with mTLS (`experimental/SPEC_DRAFT_D_private_CA.md`). If CF is a
passive observer with no interest in your traffic, `worker-kv` is
sufficient for the "send my URTB capsule to my other laptop" use case
that motivates deaddrop.

---

## 6. Deployment

Not yet shipped (tracked in `FUTURE.md`, new item DEPLOY-WORKER).
Planned shape:

```
# One-time setup
npm install -g wrangler
wrangler login
wrangler kv namespace create deaddrop-slots

# Secrets (never checked in)
wrangler secret put DEPLOY_SECRET    # paste hex:<32-byte-hex>
wrangler secret put WRITE_TOKEN      # paste hex:<32-byte-hex>

# Deploy
wrangler deploy
```

`wrangler.toml` template, secret-generation helper
(`openssl rand -hex 32` with `hex:` prefix), and DNS / custom-domain
guidance are tracked as `FUTURE.md` `DEPLOY-WORKER`.

---

## 7. Compatibility guarantee

Identical to `vm-tx` at the client: a client built for variant B
speaks to either backend with `RELAY_BASE_URL` as the only
configuration difference. Wire protocol (`PROTOCOL.md`) is the
authority; backend-specific deviations are enumerated in §3 of this
file and `BACKEND_VM.md`.

---

## 8. Testing

`worker-kv`-specific tests (see `TESTING.md`):

- `check-worker` — spin up `wrangler dev`, full send/recv round trip.
- `deployed-worker-smoke` — against a real deployed Worker +
  real KV namespace (required for the race test below; `wrangler dev`
  uses local SQLite and will not exhibit KV's consistency model).
- `AC-RACE-KV` — 100 concurrent GETs on a `reads=1` slot, multi-
  region; asserts documented best-effort behavior (may 2× 200, does
  not crash, delete eventually propagates).
- `AC-QUOTA-KV` — free-tier write quota exhaustion surfaces a clean
  429 / 5xx, no partial state.

---

## 9. References

- `DECISIONS.md` — D-24 (backend profiles), D-26 (authenticated
  DELETE), D-27 (AD binds service_id — closes cross-deployment
  replay between `worker-kv` and `vm-tx` using the same capsule),
  D-29 (service_id 16 bytes), D-30 (rolling-prefix honest framing).
- `PROTOCOL.md §10` — delete-on-read semantics per backend.
- `SECURITY.md` — backend security matrix and CF-as-adversary
  subsection.
- `FUTURE.md` F-4 — Durable Objects for strict one-shot on CF.
- `BACKEND_VM.md` — sibling profile (strict one-shot, higher ops).
