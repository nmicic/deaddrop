# SPEC DRAFT B′ — B with Bootstrap Pubkey Pinning

> **Status: DESIGNATED POST-B UPGRADE PATH.** B′ is the planned
> forward-secrecy upgrade to variant B. Gated on: (1) the Go client
> being the only normative reference (D-25), (2) consensus that FS is
> worth the extra state, (3) an explicit wire-version bump (KDF + AEAD
> AD change). Tracked as `../FUTURE.md` F-10. Graduation goes via a new
> D-XX decision and a move out of `experimental/`, not by editing B in
> place.
>
> **Inheritance banner:** any construction in this draft that predates current B
> MUST be read as "inherits current B hardening." Specifically:
>
> - `ad = slot_bytes` in pre-D-27 sketches → read as
>   `ad = service_id(16) ‖ slot_id(16) ‖ version(1)` per D-27/D-29.
> - `slot_key = HMAC(PSK, "slot-key-v1")` in pre-D-27 sketches → read
>   as `slot_key = HMAC(PSK, "slot-key-v1" ‖ pair_id)` per D-27
>   (pair_id folding).
> - Fingerprint construction follows the post-cleanup unified form
>   per `../SPEC_DRAFT_B_capsule.md §1.6` (v2: 128-bit output, pair_id
>   folded into HKDF `info`), NOT `sha256(capsule)[:8]` and NOT the
>   retired v1 `HKDF-SHA256(PSK, "deaddrop-fingerprint-v1", "", 8)`
>   shape. Graduation edit MUST adopt §1.6 verbatim.
>
> When B′ is promoted, the graduation edit MUST rewrite these
> constructions in place rather than rely on this banner. The banner
> exists so a reader of the frozen draft does not implement the
> pre-D-27 shapes literally.

B′ extends variant B with a one-time pubkey bootstrap over the B channel.
After bootstrap, each device holds:
- its own locally-generated X25519 identity keypair (private key never leaves),
- a pinned public key for each peer it has bootstrapped with.

Subsequent sends use ephemeral DH for forward secrecy and sender
authenticity. The wire protocol and the capsule format from B are unchanged.

---

## Relationship to B, C, and URTB

- Starts as a plain B deployment (shared PSK capsule).
- Adds one bootstrap step the first time a device pair communicates.
- After bootstrap, the body format matches variant C exactly.
- Slot derivation still uses B's `slot_key` (no change).
- Capsule file is unchanged from B (identical on both sides).
- Private keys generated **locally** on each device; never transferred.

URTB analogue: the capsule is the PSK layer (URTB D-05). B′'s per-send
ephemeral DH is the same upgrade URTB plans in `FUTURE.md` C-1 (X25519
ephemeral key exchange for PFS). Deaddrop B′ delivers URTB's C-1 out of
the box, client-side only, with no relay changes.

---

## Files on each device

```
~/.deaddrop/capsule              identical on both sides — B's PSK capsule,
                                 Argon2id-wrapped, transferred once OOB
~/.deaddrop/identity.key         LOCAL — X25519 private key, generated here,
                                 mode 0600, never leaves this device
~/.deaddrop/identity.pub         LOCAL — matching public key
~/.deaddrop/peers/<pair_id>.pub  pinned peer public key (one file per peer,
                                 created at successful bootstrap)
~/.deaddrop/peers/<pair_id>.fp   confirmed fingerprint (for audit trail)
```

`capsule` is portable. `identity.key` is not — each device has its own.

See "Key storage options" below for migrating `identity.key` to the kernel
keyring, macOS Keychain, or hardware tokens.

---

## Bootstrap (one-time per peer)

First run after a capsule has been exchanged:

```
./deaddrop bootstrap
  1. Generate X25519 keypair if identity.key does not exist
     (mlock, mode 0600).
  2. Pack bootstrap payload:
        magic(4 "DDBP") || my_pubkey(32) || my_fingerprint(10)
  3. Send via B (standard B slot derivation, standard B AEAD) with a
     well-known tag bucket: reads=1, ttl=300, slot_salt="bootstrap".
  4. Wait for peer's bootstrap blob (up to 5 min).
  5. Print local fingerprint + received fingerprint as 7-word diceware.
  6. Prompt: "Confirm peer's fingerprint matches out-of-band: [y/N]"
  7. On y:
        pin peer pubkey to ~/.deaddrop/peers/<pair_id>.pub
        write ~/.deaddrop/peers/<pair_id>.fp
     On N:
        discard, abort, exit non-zero.
```

Either side can initiate. Both sides run `bootstrap` once and confirm each
other's fingerprint via a trusted OOB channel (phone call, in person,
Signal, URTB session).

Fingerprint derivation:

```
fp = HKDF-SHA256(peer_pubkey, salt="", info="deaddrop-fp-v1", len=10)
words = diceware_encode(fp)            # ~90 bits as 7 diceware words
```

90 bits is overkill against a live collision attack, comfortable for
human verification.

---

## Send (post-bootstrap)

Identical to variant C's send flow, with the peer's pubkey read from
`~/.deaddrop/peers/<pair_id>.pub` (pinned at bootstrap):

```
1.  eph_priv, eph_pub = X25519_keypair()           # fresh per send
2.  ss_eph    = X25519(eph_priv,      peer_pubkey)
3.  ss_static = X25519(identity_priv, peer_pubkey)
4.  aead_key  = HKDF-SHA256(ss_eph || ss_static,
                              salt = slot_bytes,
                              info = "deaddrop-v1-Bprime" || pair_id,
                              len  = 32)
5.  nonce = random(24)
6.  body  = eph_pub(32) || nonce(24) ||
            AEAD_Seal(aead_key, nonce, plaintext, ad=slot_bytes)
7.  POST body as in PROTOCOL.md
8.  wipe(eph_priv, ss_eph, ss_static, aead_key)
```

Slot derivation is unchanged from B:

```
slot_key = HMAC-SHA256(PSK, "slot-key-v1")
slot     = HMAC-SHA256(slot_key, "slot" || floor(ts/60) || attempt)[:16]
```

---

## Recv (post-bootstrap)

```
1.  body = GET /{service}/{slot}
2.  parse eph_pub(32), nonce(24), ct
3.  ss_eph    = X25519(identity_priv, eph_pub)
4.  ss_static = X25519(identity_priv, peer_pubkey)
5.  aead_key  = HKDF-SHA256(ss_eph || ss_static,
                              salt = slot_bytes,
                              info = "deaddrop-v1-Bprime" || pair_id,
                              len  = 32)
6.  plaintext = AEAD_Open(aead_key, nonce, ct, ad=slot_bytes)
7.  wipe(ss_eph, ss_static, aead_key)
```

---

## Security properties

```
[X] All of variant B (offline-brute resistance, URL unpredictability,
    at-rest encryption of the PSK).
[X] Forward secrecy post-bootstrap — ephemeral DH per send. Capsule theft
    after session N does not decrypt sessions 1..N-1.
[X] Sender authenticity — ss_static binds the sender's long-term private key.
[X] Receiver authenticity — ss_eph requires the receiver's private key.
[X] Private key never leaves the device that generated it — unlike variant C.
[X] Identity re-key without re-sharing capsule — regenerate identity.key,
    re-bootstrap.
[X] Hardware-backed identity possible — identity.key can migrate to
    keyring or secure enclave (FUTURE.md F-14) without protocol change.
[ ] Bootstrap has a TOFU window — see threat below.
```

---

## Threat: Live MitM during bootstrap

If an adversary holds the PSK AND is positioned to intercept or replace
the first bootstrap exchange, they can pin themselves as "the peer" on
both sides and become a permanent MitM.

Preconditions:
- Attacker has the PSK (capsule intercepted in transit OR wrap passphrase
  leaked) AND
- Attacker controls the network path OR the relay AND
- Bootstrap happens over the relay, not out-of-band.

Mitigations (pick at least one):

- **M1. OOB fingerprint check (default).** Script refuses to pin the peer
  until the user confirms the 7-word fingerprint matches via phone, in
  person, URTB, Signal, or any trusted side channel. Strongest, simplest.
- **M2. LAN or USB bootstrap.** `./deaddrop bootstrap --transport lan` or
  `--transport file` exchanges pubkeys without the relay.
- **M3. Physical bootstrap.** Run `bootstrap` while both laptops are next
  to each other, before the capsule ever transits.

M1 is the default and always runs unless `--skip-fingerprint` is passed
(discouraged, prints a prominent warning).

After bootstrap, a later PSK compromise does NOT break confidentiality of
new sessions. The ephemeral DH carries that.

---

## What the PSK does in B′

- Gates `slot_id` derivation — attackers without PSK cannot even probe
  URLs (unchanged from B).
- Encrypts the bootstrap exchange — this is its one job for body
  confidentiality.
- After bootstrap, it is effectively vestigial for body confidentiality.
  Forward secrecy is carried by ephemeral DH + pinned pubkeys.

This is desirable: PSK theft post-bootstrap reduces to "attacker can now
address slots and attempt to fill them, still cannot decrypt anything."

---

## Key storage options (identity.key)

`identity.key` is the one long-term secret that rides on the device. From
simplest to strongest:

- **K1. Flat file** at `~/.deaddrop/identity.key`, mode 0600.
  Default. Relies on full-disk encryption (FileVault / LUKS / APFS).
- **K2. Linux kernel keyring (`keyutils`).**
  Lives in the user's session keyring; wiped on logout. Invoke with
  `--key-source=keyring`.
- **K3. macOS Keychain.**
  Stored as a Keychain item; OS-gated access. `--key-source=keychain`.
- **K4. Hardware-backed** (YubiKey PIV, TPM 2.0, Secure Enclave, GnuPG
  smartcard). X25519 operations delegated to the hardware; private key
  never exposed to userland. `--key-source=yubikey`.

K1 is v1. K2–K4 are tracked in `FUTURE.md` F-14. The abstraction is a
pluggable `KeySource` interface — later additions do not touch the main
send/recv path.

---

## Further expansion — client-side CSR / CA (FUTURE.md F-13)

B′'s local identity keypair is a foundation for fleet-scale PKI without
touching the relay:

- Designate one node as CA (self-signed identity cert).
- New nodes generate CSRs and submit them over the B channel.
- CA signs and returns certificates over the B channel.
- Peers validate against the embedded CA root instead of pinning raw pubkeys.
- Revocation list distributed through the relay like any other blob.

Use cases:
- LoRa-box fleets bootstrapped in a safe environment, then deployed.
- Small teams where manual pubkey pinning scales poorly (>5 nodes).
- URTB-style capsule distribution across many paired devices.

The relay stays dumb. Enrollment choreography is a client feature, not a
protocol change. See `FUTURE.md` F-13.

---

## Pros / Cons

```
+  All of B's simplicity for slot derivation and capsule management.
+  Forward secrecy and sender authenticity (C's properties, delivered
   after a one-time bootstrap).
+  Private keys never transit between devices (SSH model).
+  Identity re-key without reshipping the capsule.
+  Clean migration path to keyring / hardware-backed keys.
+  Clean expansion path to CSR / CA fleet PKI.
-  One-time bootstrap step per peer pair.
-  TOFU window at bootstrap — mitigated by OOB fingerprint check.
-  Slightly more client code than B (still pure userspace, still bash-doable).
```

---

## When to choose B′

- **Default recommendation for 2 personal laptops** where you send regularly.
- When you plan to grow to more devices later (B′ scales cleanly to CSR/CA).
- When you want the "private key never travels" property from day one.

## When plain B is enough (do not upgrade)

- One-off transfers where bootstrap friction exceeds the gain.
- When the inner payload is already strongly encrypted (e.g. URTB capsules,
  age-encrypted files) — transport PFS adds little marginal value.

## When to stay on plain B (do NOT upgrade)

- You cannot reliably do the OOB fingerprint check (no trusted side
  channel). In that specific case, plain B or pre-GPG'd content is safer
  than blind TOFU.

---

## Reference

- URTB `DECISIONS.md` D-03 — firmware is a blind modem. B′ keeps the
  deaddrop relay in the same role: no crypto, no pubkey awareness, just
  opaque bytes + TTL.
- URTB `FUTURE.md` C-1 — planned X25519 PFS upgrade. B′ is the same
  structure, delivered today in userland.
- Noise Protocol Framework IK pattern — B′'s body is Noise_IK-shaped.
- SSH identity model — B′'s local-only private key matches the SSH
  `ssh-keygen` + `authorized_keys` workflow.
- Deaddrop `DECISIONS.md` D-20 — B is default; security upgrades are
  client-side.
- Deaddrop `DECISIONS.md` D-21 — B′ supersedes C for 2-party use.
