# SPEC DRAFT C — Capsule with X25519 Keypairs (Forward Secrecy)

> **Status: SUPERSEDED by B′** (see `../DECISIONS.md` D-21). Not on any
> current roadmap; reopened only if a concrete property emerges that B′
> cannot deliver. Kept for the Noise_IK lineage notes. For new 2-party
> deployments prefer `SPEC_DRAFT_Bprime_bootstrap.md` — B′ delivers the
> same cryptographic properties (Noise_IK-shaped body, ephemeral DH,
> sender authenticity) and
> additionally keeps the private key local to the device that generated it,
> allows re-key without reshipping a capsule, and migrates cleanly to
> keyring / hardware storage. See `DECISIONS.md` D-21 for the rationale.
> C is preserved for its Noise_IK lineage and for the niche case where a
> single capsule should carry everything needed to decrypt with no bootstrap
> round trip.

Extends variant B. The capsule carries each peer's long-term X25519 identity
keypair and the peer's public key. Each send uses a fresh ephemeral X25519
key for forward secrecy and sender authenticity.

Pattern: Noise_IK-lite (sender's long-term auth + ephemeral DH). Reference:
URTB `FUTURE.md` C-1 — the same upgrade URTB plans for its session keys.

---

## Capsule contents (extended)

```
magic(4 "DDC1") ‖ version(1="C") ‖ argon2_salt(16) ‖ argon2_params(9) ‖
nonce(24) ‖ AEAD_Seal(passphrase_key,
    PSK(32)                 ‖   # URL slot derivation, as in B
    pair_id(8)              ‖
    my_identity_priv(32)    ‖   # X25519 scalar
    my_identity_pub(32)     ‖
    peer_identity_pub(32)   ‖
    role(1)                 ‖   # 0x00 = Alice, 0x01 = Bob (domain separation)
) ‖ tag(16)
```

Two capsules are generated as a pair by `./deaddrop keygen-pair`:

- Alice's capsule: `{Alice priv, Alice pub, Bob pub, role=Alice}`
- Bob's capsule:   `{Bob priv,   Bob pub,   Alice pub, role=Bob}`

Each is encrypted with the holder's own passphrase. Out-of-band transfer is
still required, but the keypair split means each side keeps its own private
key — a stolen capsule is less catastrophic than in variant B.

---

## Send flow

```
1.  eph_priv, eph_pub = X25519_keypair()             # fresh per send
2.  ss_eph    = X25519(eph_priv,         peer_identity_pub)
3.  ss_static = X25519(my_identity_priv, peer_identity_pub)
4.  aead_key  = HKDF-SHA256(ss_eph ‖ ss_static,
                              salt  = slot_bytes,
                              info  = "deaddrop-v1-C" ‖ role,
                              len   = 32)
5.  nonce = random(24)
6.  body  = eph_pub(32) ‖ nonce(24) ‖ AEAD_Seal(aead_key, nonce, plaintext, ad=slot_bytes)
7.  slot derived from PSK as in variant B (URL unpredictability only)
8.  wipe(eph_priv, ss_eph, ss_static, aead_key)
```

---

## Recv flow

```
1.  body = GET /{service}/{slot}
2.  parse eph_pub(32), nonce(24), ct
3.  ss_eph    = X25519(my_identity_priv, eph_pub)
4.  ss_static = X25519(my_identity_priv, peer_identity_pub)
5.  aead_key  = HKDF-SHA256(ss_eph ‖ ss_static,
                              salt  = slot_bytes,
                              info  = "deaddrop-v1-C" ‖ peer_role,
                              len   = 32)
6.  plaintext = AEAD_Open(aead_key, nonce, ct, ad=slot_bytes)
7.  wipe(ss_eph, ss_static, aead_key)
```

`peer_role` is the *other* value (if I am Alice, peer_role = 0x01). This
prevents self-pair confusion.

---

## Security

```
[X] All of variant B
[X] Forward secrecy (post-compromise of capsule): ss_eph used an ephemeral
    key that was destroyed after send. Captured past ciphertext cannot be
    decrypted even if the capsule is later stolen.
[X] Sender authenticity: ss_static mixes sender's long-term private key.
    A third party cannot forge a ciphertext even with the receiver's capsule.
[X] Receiver authenticity: only the receiver holds the private key needed
    to derive ss_eph (and ss_static from their side).
[ ] Post-quantum: X25519 is not PQC. See FUTURE.md F-6 (ML-KEM hybrid).
```

---

## Pros / Cons

```
+  Forward secrecy — past sessions stay confidential after capsule theft.
+  Sender authenticity — not just "someone with the capsule," but "this peer."
+  Capsule ergonomics identical to variant B at the user level.
-  Capsule generation is a pair operation — both sides present, or one side
   generates both and transfers the other capsule securely.
-  Slightly more code to audit. Ephemeral key must be properly destroyed.
-  Body grows by 32 bytes (ephemeral public key).
```

---

## When to choose C

- You send sensitive material repeatedly.
- You want the capsule file to NOT be a one-shot decryptor of history.
- You want cryptographic proof of "who sent this."

## When NOT to choose C

- You only need one-off transfer — variant A.
- You cannot afford the pair-keygen setup complexity — variant B.
- You need transport-layer access control too — add D (gives variant E).

---

## Reference

- URTB `FUTURE.md` C-1 — planned X25519 upgrade (same pattern)
- URTB `DECISIONS.md` D-30 — Monocypher X25519 interface
- Noise Protocol Framework (https://noiseprotocol.org/) — IK pattern
