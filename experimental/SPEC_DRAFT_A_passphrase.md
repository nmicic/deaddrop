# SPEC DRAFT A — Passphrase Variant

> **Status: REJECTED on threat model** (see `../DECISIONS.md` D-37,
> which supersedes the earlier "parked for scope" framing in D-22).
>
> The confidentiality budget of A equals the entropy of the user-chosen
> passphrase, funneled through Argon2id. That does NOT reliably meet
> the offline-brute-resistance target variant B gets from a 32-byte
> capsule PSK: users pick weak passphrases, and a passive wire
> observer who later captures the rolling URL has all the material
> needed to run offline Argon2id guesses against captured ciphertext.
>
> A future "forced strong passphrase" variant (tool-generated,
> ≥77-bit, never user-typed) would be a separate design, NOT a
> revival of A. Reopening would require a new D-XX that supersedes
> D-37.
>
> Kept here for historical reference and traceability only.
> Not on any roadmap.

> **Narrowed on scope by D-41 (2026-04): `deaddrop bootstrap` ships
> as a provisioning protocol, not a revival of this payload variant.**
> D-41 does reuse the `Argon2id(passphrase) → HKDF →
> XChaCha20-Poly1305` construction in legs 1–2 of the three-leg
> handshake — but the PSK never travels under passphrase-derived
> keying (leg 3 is encrypted under a two-DH body key combining a
> fresh ephemeral X25519 with a static X25519 to the pinned peer
> identity pubkey). Offline brute of a captured bootstrap envelope
> therefore yields only pubkeys, which are non-secret by
> construction. The threat-model finding above still rejects
> general-purpose variant A; `send --mode=A` is not reachable and
> bootstrap is NOT described as "variant A revived."
> See `../SPEC_BOOTSTRAP.md` for the normative bootstrap spec.
> This file continues to describe the rejected general-purpose
> variant and is retained for design history only.

The simplest variant. Zero setup beyond sharing a passphrase out-of-band
(voice, Signal, in person). Reference implementation fits in a bash script.

---

## Client flow

### Sender

```
1.  read passphrase from -s argument or stdin
2.  ts = unixtime
3.  for attempt in 0, 1, 2, ...:
      slot = HMAC-SHA256(passphrase, "slot" || floor(ts/60) || attempt)[:16]
      POST /{service_id(ts)}/{slot}  (empty body probe OR direct POST)
      if 409: attempt++, continue
      break
4.  aead_key = HKDF-SHA256(passphrase, salt=slot_bytes, info="deaddrop-v1-A", len=32)
5.  nonce    = random(24)
6.  body     = nonce || XChaCha20-Poly1305_Seal(aead_key, nonce, plaintext, ad=slot_bytes)
7.  POST body to /{service_id}/{slot}?ttl=600&reads=1
8.  print slot, expiry
```

### Receiver

```
1.  read passphrase from -r argument or stdin
2.  ts = unixtime
3.  for b in [floor(ts/60), floor(ts/60)-1, floor(ts/60)-2]:
      for attempt in [0 .. K-1]:
        slot = HMAC-SHA256(passphrase, "slot" || b || attempt)[:16]
        body = GET /{service_id(ts)}/{slot}
        if 404: continue
        aead_key  = HKDF-SHA256(passphrase, salt=slot_bytes, info="deaddrop-v1-A", len=32)
        plaintext = XChaCha20-Poly1305_Open(aead_key, body.nonce, body.ct, ad=slot_bytes)
        if OK: write plaintext to output; return 0
4.  if nothing found: return 1 (exit code — no match in skew window)
```

---

## Security

```
[X] Confidentiality  — AEAD with passphrase-derived key
[X] Integrity        — Poly1305 tag
[X] One-shot read    — relay deletes on read (default reads=1)
[X] URL unpredictable without passphrase — HMAC + time bucket + attempt
[ ] Offline dictionary resistance — weak passphrase → offline brute-force
    of captured ciphertext. MUST use a high-entropy passphrase.
[ ] Forward secrecy  — none; same passphrase reused across sends
[ ] Sender authenticity — any holder of the passphrase can produce messages
```

### Threat: captured ciphertext

An adversary who captured the ciphertext before delete-on-read (Cloudflare
subpoena, on-path TLS break, compromised relay) can mount an offline
dictionary attack against the passphrase. For 80-bit passphrases (diceware
6-word) this is computationally infeasible with current hardware. For short
phrases it is trivial.

Recommendation: use

```
./deaddrop gen-phrase      # prints 6-word diceware (≈77 bits entropy)
```

and refuse to send if `gen-phrase`'s estimator flags the passphrase as
below 60 bits.

---

## Dependencies

- `openssl` 3.x  — HMAC-SHA256, HKDF, XChaCha20-Poly1305
- `curl`         — HTTPS
- `jq`           — JSON parsing (optional; bash can parse POST response)
- `bash` 4+      — the script itself

Reference client is bash. Go port planned (see `FUTURE.md` F-3).

---

## Configuration

```
~/.deaddrop/config
    RELAY_BASE_URL=https://deaddrop.example.workers.dev
    DEPLOY_SECRET=<32-byte hex>
    WRITE_TOKEN=<32-byte hex>        # optional
```

---

## Pros / Cons

```
+  Zero persistent setup beyond the passphrase exchange.
+  No files to lose.
+  Reference implementation is ~150 lines of bash.
-  Passphrase must be high-entropy OR transmitted via a trusted channel.
-  No forward secrecy.
-  No sender authenticity — anyone who knows the passphrase can impersonate.
-  Each send re-proves knowledge of the passphrase; no cryptographic pinning.
```

---

## When to choose A

- Quick one-off transfer, passphrase generated by the tool.
- Receiver side will not live long enough to justify capsule exchange.
- Simplicity more important than forward secrecy.

## When NOT to choose A

- You send sensitive material regularly — use B or C.
- You cannot trust the channel that transmits the passphrase — use B.
