# Architectural Principle: Generic Relay, Smart Clients

Adapted from a generic-pipeline architecture principle.
Applied to deaddrop.

---

## Core idea

Keep the relay dumb. Put all cryptographic and protocol cleverness in the
client. The relay is a content-addressed byte bucket with TTL and a read
counter.

---

## The three principles

### 1. The relay speaks one protocol, forever

`PROTOCOL.md` is the contract. It does NOT change per variant. The relay
does not know whether a body is passphrase-encrypted (A, parked),
PSK-encrypted (B — shipped), or Noise-encrypted (C, parked). It stores
bytes. Every variant produces different bodies; the relay API is
identical.

### 2. All security properties are derivable from the client

The relay never:

- holds a decryption key
- computes an HMAC that a client could not compute itself
- knows who the sender or receiver is (beyond IP + TLS cert)
- distinguishes variants

The relay always:

- validates the rolling `service_id`
- enforces size, TTL, `reads_left` limits
- deletes on read
- returns opaque errors (404 for anything "not found" or "forbidden")

### 3. Swap the relay, keep the client

The protocol does not hard-code the backend. The shipped deployment is
VM/Go (D-33), but anything that correctly implements `PROTOCOL.md`
serves as a drop-in relay with only `RELAY_BASE_URL` changing on the
client. This is the reason there is one `PROTOCOL.md`, not one per
variant, and one `SPEC.md` describing what deaddrop is overall, not
one per deployment target. The parked Cloudflare Worker design under
`experimental/BACKEND_CLOUDFLARE_parked.md` is preserved precisely
because the protocol was built to not rule it out.

---

## Why this matters

### Abuse resistance

A dumb relay cannot be weaponized into "leak who sent what to whom" because
it never knew in the first place. If subpoenaed, the relay can only show:

> someone POSTed ciphertext at 12:03:04 from IP X, someone GETed it at
> 12:05:41 from IP Y, the slot is gone now.

No content. No sender/receiver identity. No passphrase. No capsule. No key.

### Swap-in future relays

Want to move the VM/Go relay to Deno Deploy, Fly.io, a Raspberry Pi on
Tailscale, or back to an edge platform? Rewrite the relay in ~100 lines.
The client is untouched. The protocol already supports it because it
never assumed a specific backend.

### Audit surface stays small

The relay is the part exposed to the internet. A small, dumb relay is
auditable in an hour. The client is local; its audit surface, while larger,
is not internet-exposed.

### Future cryptographic changes do not touch the relay

Want to add post-quantum hybrid key exchange? That is a client-side change
to variant C. The relay does not notice.

Want to add a browser client? New client, same relay.

---

## What goes in the relay

- URL parsing
- `service_id` validation (hour ± 1 skew window)
- slot existence check
- TTL + `reads_left` accounting
- size cap enforcement
- delete-on-read
- HTTP status mapping
- rate limiting
- metrics and structured logs (no content)

---

## What stays in the client

- passphrase handling / capsule unlock
- key derivation (HKDF, HMAC)
- AEAD encrypt / decrypt
- X25519 / Noise handshakes (variant C / E)
- mTLS cert handling (variant D / E)
- slot_id probing with clock skew
- capsule memory protection (mlock, MADV_DONTDUMP)
- passphrase entropy estimation

---

## Anti-patterns (do not)

- **Relay-side encryption.** "Let the relay AES-encrypt it for them." No —
  then the relay holds the key. Unfixable.

- **Relay-side deduplication.** "Detect when two users POST the same
  content." No — the relay sees ciphertext; two identical bodies indicate
  a nonce-reuse bug in the client, which is the client's problem.

- **Relay-side rate-limiting by "user".** The relay has no users.
  Rate-limit by IP, by `service_id`, by `WRITE_TOKEN` — not by identity.

- **Per-variant endpoints.** `/v1/passphrase/upload` vs `/v1/pki/upload`.
  No — the body is opaque; the endpoint does not need to know.

- **Variant-specific metadata headers.** `X-Variant: C`. No — defeats
  the abuse-resistance story by telling the relay what to look for.

- **Relay-side slot enumeration.** A `/list` endpoint for "my slots." No —
  the relay has no notion of "you." Clients that want this track slots
  themselves.

---

## Design test

When adding a new feature, ask:

1. Does the client already have enough information to do this itself?
2. Would doing this on the relay require the relay to know something it
   currently does not know (a key, an identity, a variant)?

If (1) is yes OR (2) is yes, do it in the client.

If the answer is "no, the relay really needs a new primitive," then this
is a protocol change. Bump `PROTOCOL.md` version, not a variant.

---

## Long-term payoff

If the cryptographic primitives change in 2030 (post-quantum, different AEAD,
different KDF), the relay does not need a rebuild. The protocol and the
relay stay; the client evolves.

This is the same payoff a generic pipeline gives for request
handlers: one shared path, many specific definitions, cheap future change.

---

## Reusable principle

Prefer:

- metadata-driven definitions over hand-wired per-variant logic
- opaque body formats over server-parsed payloads
- one protocol over one-endpoint-per-feature
- client-side cryptographic policy over server-side crypto helpers
- uniform 404 responses over helpful error bodies (no oracles)

Hard-code the storage/TTL/size primitives. Do not hard-code variants.
