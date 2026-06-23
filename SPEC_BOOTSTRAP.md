<!-- Copyright (c) 2026 Nenad Mićić -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SPEC — Bootstrap (`deaddrop bootstrap`)

Normative client-side specification for the `deaddrop bootstrap`
subcommand (D-41). Peer document to `SPEC_DRAFT_B_capsule.md`; the
relay-side specification is unchanged (`PROTOCOL.md` / `BACKEND_VM.md`
still describe a variant-agnostic POST/GET wire).

This spec is the sole normative source of bootstrap KDF inputs,
envelope formats, slot derivation, flow, and exit codes. The CLI
contract lives in `DECISIONS.md` D-31 (bootstrap subcommand row);
this document MUST NOT restate flag shape beyond what's needed to
disambiguate the flow.

---

## 1. Role and scope

`deaddrop bootstrap` is a **one-time provisioning protocol**. It
delivers a plain-B capsule (`PSK(32)`, `pair_id(8)`) to two laptops
via an interactive two-sided handshake keyed by a shared short-lived
passphrase `P_A`. It is the **primary** pairing path for deaddrop;
offline capsule-file transfer (`deaddrop keygen` + USB / Signal /
existing SSH) remains available as a **backup** for paranoid-mode
operators or when a pre-existing side channel is already present, but
is not co-equal (`README.md` Quickstart leads with bootstrap).

After `deaddrop bootstrap` exits 0, the system is indistinguishable
from `keygen` + offline capsule transfer: steady-state `send` / `recv`
is **plain B, unchanged** from `SPEC_DRAFT_B_capsule.md`, and
`~/.deaddrop/capsule` is bit-compatible with a capsule produced by
`keygen`.

Scope limits (normative):

- Bootstrap is a **provisioning protocol** only, not a steady-state
  transfer mode. Generic variant A (send-mode) remains rejected
  (D-37 / D-41); do not read this spec as reviving a parked payload
  variant. `experimental/SPEC_DRAFT_A_passphrase.md` is retained for
  design history only.
- v1 ships `--burn` default only. Identity X25519 keypairs generated
  during bootstrap are ephemeral to the process and MUST be zeroized
  at exit. `--keep-keys` is parked pending `FUTURE.md` F-34
  (agent-style identity-key protection) and MUST be rejected at
  CLI parse in v1 with a message pointing to F-34.
- The relay is untouched. All three legs ride the existing
  `POST /{service_id}/{slot_id}` wire; the server remains variant-
  agnostic (D-02, D-20, D-34).

---

## 2. Legs 1 and 2 — passphrase-keyed pubkey exchange

Legs 1 and 2 carry each side's X25519 identity pubkey under an AEAD
envelope derived from the shared passphrase `P_A`. **No secret
material other than a non-secret pubkey ever travels inside legs 1 or
2.** This is the load-bearing property distinguishing bootstrap from
the rejected general-purpose variant A (D-37 / D-41 rebuttal point 1).

### 2.1 Passphrase and Argon2id derivation

```
P_A            = UTF-8 bytes, NFC-normalized, of the shared bootstrap passphrase.
                 Default: 6-word Diceware (≈77 bits, per D-37 infeasible-brute floor).

bootstrap_salt = first 16 bytes of SHA-256(b"deaddrop-bootstrap-v1")
                 (pinned constant, domain-separated from capsule_salt).

passphrase_key = Argon2id(
                   password     = P_A,
                   salt         = bootstrap_salt,
                   m_cost_kib   = 1 << 17,    // 128 MiB
                   t_cost       = 3,
                   p_cost       = 4,
                   output_len   = 32
                 )
```

The Argon2id parameter tuple is identical to the capsule's normative
default profile (`SPEC_DRAFT_B_capsule.md §1.1`). This is deliberate:
single tuning surface for the project.

Passphrase entry follows D-31's universal rule — **argv passphrase
is forbidden**. Allowed surfaces:

- TTY prompt (default; interactive terminal)
- `--passphrase-fd <n>` (scripted; reads single line from fd n)
- `--passphrase-env VAR` (scripted; warning emitted on stderr)

`--passphrase "$P"` on argv is rejected with `EDDUsage` (exit 2).
This holds for both the initiator (who generated the Diceware
passphrase and reads it OOB) and the responder (who types it in).

### 2.2 Direction bit and per-leg key derivation

```
direction = 0x00   for leg 1 (initiator → responder)
          = 0x01   for leg 2 (responder → initiator)

leg_key   = HKDF-SHA256(
              ikm     = passphrase_key,
              salt    = b"",
              info    = b"deaddrop-bootstrap-leg12" ‖ direction(1),
              length  = 32
            )

slot_key_A = HKDF-SHA256(
              ikm     = passphrase_key,
              salt    = b"",
              info    = b"deaddrop-bootstrap-slot" ‖ direction(1),
              length  = 32
            )
```

The direction byte is the mechanism that makes legs 1 and 2 land at
**distinct slot addresses** from a single passphrase — preventing the
two legs from colliding on the same slot in the same minute-bucket.

### 2.3 Leg-1/2 slot derivation

```
slot_id_A = HMAC-SHA256(
              key   = slot_key_A,
              data  = b"slot" ‖ enc_u64_be(b) ‖ enc_u32_be(0)
            )[:16]
```

Where `b = floor(unixtime / 60)` matches the rolling minute-bucket
used by plain B. The trailing `enc_u32_be(0)` is the canonical slot
HMAC form from `PROTOCOL.md §1` (attempt counter pinned to 0 for
bootstrap; bootstrap does not retry within a single minute bucket).
Rolling window discipline is inherited from `PROTOCOL.md §2`: the
sender writes under the current bucket; the receiver probes current,
−1, −2.

**Honest framing of leg-1 collision floor.** The leg-1 slot space is
effectively keyed by `H(P_A)` alone (the responder has not yet
contributed any material on leg 1). Two pairs who happen to reuse the
same Diceware passphrase in the same minute bucket will collide on
leg 1. With a 6-word Diceware pool (~77 bits), the collision
probability is negligible per-pair; but if operator policy reuses a
fixed passphrase across pairs, the leg-1 floor degrades toward "no
floor at all." The remediation is exit 12 (`EDDCollision`) and
operator re-coordination — not a silent retry.

### 2.4 Leg-1/2 wire format

```
body = version(1) ‖ nonce(24) ‖ aead_ct(N) ‖ tag(16)

version  = 0x02   (bootstrap leg 1 / leg 2 body shape; see §5.1 for
                   the full shipped-body-version table)

plaintext = identity_pubkey(32)   // exactly 32 bytes, no header, no padding

N        = 32    (XChaCha20 is a stream cipher: ciphertext length
                  equals plaintext length)

AD       = service_id_bytes(16) ‖ slot_id_bytes(16) ‖ version(1)
           ‖ direction(1) ‖ b"leg12"

nonce    = 24 random bytes per POST (per-POST nonce freshness
           per SPEC_DRAFT_B_capsule.md §3.2)

aead_ct, tag = XChaCha20-Poly1305.Seal(
                 key       = leg_key,
                 nonce     = nonce,
                 plaintext = identity_pubkey(32),
                 ad        = AD
               )
```

Total body length: `1 + 24 + 32 + 16 = 73 bytes`. Fits trivially
within `MAX_BLOB_BYTES`.

**Why direction binds the AD even though `leg_key` already differs
per direction.** §2.2 derives `leg_key = HKDF(..., info =
b"deaddrop-bootstrap-leg12" ‖ direction(1), ...)`, so legs 1 and 2
use distinct AEAD keys; an attacker who captures a leg-1 ciphertext
cannot open it as leg 2 because the wrong `leg_key` will fail to
decrypt. **Key separation is the primary defense.** The `direction`
byte in AD is **redundant defense-in-depth**: it makes the wire shape
self-describing so a re-implementer who forgets the direction byte
in HKDF info — or whose KDF library silently succeeds on a malformed
info string — still gets a clean authentication failure rather than
a confusable handshake. See `DECISIONS.md` D-41 and §2.2 for the
full per-direction derivation chain.

The AD binding of `direction ‖ "leg12"` prevents a leg-1 envelope from
being replayed as leg 2 or as a plain-B body (and vice versa); the
receiver MUST compute AD with the direction byte matching the leg it
is currently consuming.

**Direction codepoint reservation.** Codepoints `0x00` and `0x01` are
defined in §2.2. All other values (`0x02..0xFF`) are reserved.
Receivers MUST reject any leg body whose AD encodes a reserved
direction codepoint with exit code `EDDCryptoLocal` (10) — without
attempting an AEAD open. (AEAD-open against a reserved codepoint
would be a silent decryption attempt against an undefined wire shape;
an explicit reject keeps the failure mode legible.)

**Reference implementation:** the AD construction is in
`internal/bootstrap/leg12.go`, function `leg12AD` (cited by symbol
name; line numbers drift). The pre-AEAD direction guard lives in
`OpenLeg12` in the same file and rejects any reserved codepoint
before the AEAD-open call.

**Conformance tests** (re-implementers MUST replicate):
`internal/bootstrap/leg12_test.go::TestLeg12_ADLayout` (verifies the
39-byte layout); `internal/bootstrap/leg12_test.go::TestOpenLeg12_WrongDirection`
(verifies cross-direction AEAD rejection); and
`internal/bootstrap/leg12_test.go::TestOpenLeg12_ReservedDirection`
(verifies reserved-codepoint pre-AEAD reject).

### 2.5 Receiver parse discipline

Receivers MUST:

1. Validate that the locally-supplied `direction` is in `{0x00, 0x01}`
   per §2.2. Any reserved codepoint (`0x02..0xFF`) is rejected with
   `EDDCryptoLocal` (exit 10) without attempting AEAD-open; the wire
   shape for reserved codepoints is undefined. (Defense-in-depth
   guard against an implementation bug; legitimate callers always
   pass either `DirInitiatorToResponder` or `DirResponderToInitiator`.)
2. Verify `version == 0x02` as the next parse step
   (`SPEC_DRAFT_B_capsule.md §3` discipline); any other value rejects
   with `EDDCryptoLocal` (exit 10), no AEAD open attempted.
3. AEAD-open with AD computed from the expected direction for the
   leg being consumed. AEAD failure on leg 1 or leg 2 is
   `EDDBootstrapAuthFail` (exit 18) — i.e., wrong `P_A` typed on the
   consuming side, or genuine envelope tampering.
4. Enforce `plaintext length == 32`. Any other length is
   `EDDCryptoLocal` (exit 10) with detail `leg12-plaintext-length`.
5. Enforce that the decrypted pubkey is a valid X25519 pubkey. The
   validator MUST reject:
   - the all-zero pubkey,
   - the twelve low-order points enumerated in RFC 7748 §5 / Curve25519
     small-subgroup literature (0, 1, and the ten additional points
     whose order divides the cofactor).
   Invalid → exit 18 with detail `pubkey-invalid`. A low-order peer
   pubkey would force `dh_shared` in §4.3 to a predictable value and
   enable downgrade attacks; rejecting these inputs keeps the 2DH
   construction load-bearing.

---

## 3. Pubkey pinning (in-memory)

Each side generates its X25519 keypair at bootstrap start:

```
(identity_sk, identity_pk) = X25519.KeyPair()
```

Both keys live **only in process memory** under `--burn`. The
private key MUST be held in an mlocked region (parity with D-39's
relay posture for secrets). It MUST be zeroized at process exit
(see §8).

After leg 1 decrypts successfully on the responder side, the
responder pins `initiator_pk` in-memory. After leg 2 decrypts on the
initiator side, the initiator pins `responder_pk`.

Leg-3 slot derivation (§4.2), leg-3 body_key derivation (§4.3), and
the unified pairing fingerprint (§10) all depend on both pinned
pubkeys. An MITM that swapped pubkeys in legs 1/2 will cause leg-3
AEAD open to fail on the initiator side, AND will cause the two
sides' printed fingerprints to diverge — **the OOB fingerprint voice
compare in §10 is the real MITM defense, and leg-3 AEAD failure is a
complementary tamper signal, not the whole MITM story.** See
`SECURITY.md` bootstrap subsection.

---

## 4. Leg 3 — PSK delivery under ephemeral + static DH

Leg 3 is the PSK-carrying leg. By default the **responder generates
the fresh `{pair_id, PSK}`** and posts leg 3 back-to-back with leg 2
(see §6 for why). The payload is encrypted under a body key derived
from **two Diffie-Hellman shared secrets** — one ephemeral, one
static — so that forging leg 3 requires either `initiator_sk` or
`responder_sk`, not merely `P_A`. This prevents anyone who learns
`P_A` from minting a leg 3 that substitutes their own PSK.

### 4.1 Ephemeral sender key

```
(eph_sk, eph_pk) = X25519.KeyPair()   // fresh per bootstrap run
```

`eph_sk` MUST be zeroized immediately after computing the leg-3 body
(the sender has no further use for it). Under `--burn` the two
long-term identity secrets are also zeroized at process exit (§8).

### 4.2 Leg-3 slot derivation

Derived deterministically from the exchanged pubkeys so both sides
can compute it without additional negotiation:

```
leg3_root    = HKDF-SHA256(
                 ikm     = initiator_pk(32) ‖ responder_pk(32),
                 salt    = b"",
                 info    = b"deaddrop-bootstrap-leg3",
                 length  = 32
               )

leg3_slot_id = HMAC-SHA256(
                 key   = leg3_root,
                 data  = b"slot" ‖ enc_u64_be(b) ‖ enc_u32_be(0)
               )[:16]
```

Concatenation order is fixed: **initiator pubkey first, responder
pubkey second**, regardless of which side is sending leg 3. Both
sides know which role they hold, so both compute the same value.
The trailing `enc_u32_be(0)` matches `PROTOCOL.md §1` canonical slot
HMAC.

### 4.3 Leg-3 body key (two-DH construction)

```
dh_eph      = X25519(eph_sk,       initiator_pk)   // sender side
            = X25519(initiator_sk, eph_pk)         // receiver side

dh_static   = X25519(responder_sk, initiator_pk)   // sender side
            = X25519(initiator_sk, responder_pk)   // receiver side

body_key    = HKDF-SHA256(
                ikm     = dh_eph(32) ‖ dh_static(32),
                salt    = b"",
                info    = b"deaddrop-bootstrap-leg3-body"
                          ‖ initiator_pk(32) ‖ responder_pk(32),
                length  = 32
              )
```

Both sides MUST compute both DHs and MUST reject the result if either
`dh_eph` or `dh_static` evaluates to the 32-byte all-zero string
(small-subgroup attack output). Reject with `EDDBootstrapMITM`
(exit 17) detail `dh-zero`. Combined with §2.5's low-order pubkey
rejection, this closes the contributory-behavior gap on X25519.

The salt is empty; the HKDF `info` string carries both long-term
pubkeys to bind the body key to the identities that negotiated it.
An attacker who knows only `P_A` cannot produce `dh_static`, which
requires `responder_sk` or `initiator_sk`. This is the Noise NK /
X3DH-minus-prekey lineage: the ephemeral component provides freshness
and (local) forward secrecy; the static component provides peer
authentication.

---

## 5. Leg 3 — wire format

Leg 3's body shape differs from plain B because the receiver needs
`eph_pk` **before** it can derive `body_key` to AEAD-open the rest.
`eph_pk` is therefore carried as a cleartext prefix inside the body
field, after the version byte and before the AEAD nonce:

```
body = version(1) ‖ eph_pk(32) ‖ nonce(24) ‖ aead_ct(N) ‖ tag(16)

version  = 0x03   (bootstrap leg-3 body shape; see §5.1)

eph_pk   = 32-byte X25519 pubkey (cleartext; the relay sees it
           but cannot decrypt without either DH private key)

plaintext = pair_id(8) ‖ PSK(32)

N        = 40    (XChaCha20-Poly1305 stream: |plaintext| = 40)

AD       = service_id_bytes(16) ‖ leg3_slot_id(16) ‖ version(1)
           ‖ eph_pk(32) ‖ b"leg3"

nonce    = 24 random bytes per POST

aead_ct, tag = XChaCha20-Poly1305.Seal(
                 key       = body_key,
                 nonce     = nonce,
                 plaintext = pair_id(8) ‖ PSK(32),
                 ad        = AD
               )
```

Total body length: `1 + 32 + 24 + 40 + 16 = 113 bytes`.

Binding `eph_pk` into AD defeats a substitution attack in which an
active attacker swaps `eph_pk` on the wire while keeping the AEAD
ciphertext intact; the receiver's AEAD-open would then run with a
different `eph_pk` value in AD than was used at encryption time,
flipping the tag.

### 5.1 Shipped wire-body versions

| `version` | Meaning                                       | Body shape                                                  | Spec owner                  |
|-----------|-----------------------------------------------|-------------------------------------------------------------|-----------------------------|
| `0x01`    | Plain B — steady-state payload                | `version ‖ nonce ‖ aead_ct ‖ tag`                           | `SPEC_DRAFT_B_capsule.md §3`|
| `0x02`    | Bootstrap legs 1 and 2                        | `version ‖ nonce ‖ aead_ct ‖ tag`                           | `SPEC_BOOTSTRAP.md §2.4`    |
| `0x03`    | Bootstrap leg 3                               | `version ‖ eph_pk ‖ nonce ‖ aead_ct ‖ tag`                  | `SPEC_BOOTSTRAP.md §5`      |
| `0x04…`   | Reserved for future suite changes (F-6 PQC)   | —                                                           | `FUTURE.md` F-6             |

D-23 is preserved: the version byte identifies wire framing and
parser dispatch. Parser dispatch is **by version byte**, full stop
— there is no "dispatch by slot-derivation domain" special rule.
A client that fetches a slot it derived itself still MUST check the
version byte against the body shape it expects for that slot's role
(plain-B for `send` / `recv`, `0x02` for bootstrap legs 1/2, `0x03`
for bootstrap leg 3); a mismatch rejects with `EDDCryptoLocal`
(exit 10).

### 5.2 Receiver parse discipline

Initiator receives leg 3 and MUST:

1. Verify `version == 0x03` first; reject `EDDCryptoLocal` (exit 10)
   on any other value.
2. Read the next 32 bytes as `eph_pk`. Validate it is a valid X25519
   pubkey per §2.5 step 4 (not all-zero, not a low-order point).
   Invalid → `EDDBootstrapMITM` (exit 17) with detail `eph-pk-invalid`.
3. Compute `dh_eph` and `dh_static` per §4.3. If either DH result is
   the 32-byte all-zero string, reject with `EDDBootstrapMITM`
   (exit 17) detail `dh-zero`.
4. Derive `body_key` per §4.3.
5. AEAD-open the remainder with AD per §5 above. AEAD failure →
   `EDDBootstrapMITM` (exit 17) — remediation is "someone swapped a
   pubkey in legs 1/2; re-coordinate and rerun bootstrap from
   scratch with a fresh `P_A`."
6. Enforce `plaintext length == 40`. Any other length → exit 17 with
   detail `leg3-plaintext-length`.
7. Parse `pair_id(8) ‖ PSK(32)` and proceed to §6 → §10 (fingerprint
   compare) → §7 (P_B prompt) → capsule file materialization.

**No partial capsule may be written on leg-3 failure, AND no capsule
is written until the operator confirms the §10 fingerprint voice
compare.** See §7 and §8.

---

## 6. Flow and timing

```
                  Initiator                        Responder
                     │                                  │
                     ├── keygen (identity_sk/pk) ─────┤   (each side
                     │                                  │    generates
                     ◄────── OOB: voice P_A ──────────►│    locally)
                     │                                  │
 t=0s   Leg 1 ──── POST leg-1 slot ───────────►        │
                     │                            (poll 1–2 s)
                     │                          ──── GET leg-1 ◄──
                     │                                  ├── decrypt
                     │                                  │   pin initiator_pk
                     │                                  │   keygen (eph_sk/pk)
                     │                                  │   generate pair_id, PSK
                     │                                  │
                     │                      back-to-back POSTs ▼
                     │             ──── POST leg-2 slot ◄──────┤
                     │             ──── POST leg-3 slot ◄──────┤
                     │                                  │
 (poll 1–2 s) ──── GET leg-2 ────►                      │
       ├── decrypt, pin responder_pk                    │
       │                                                │
       ├── GET leg-3 (address derivable now) ──────►    │
       ├── decrypt (eph_pk → 2DH → body_key)            │
       │                                                │
       ◄───── OOB: fingerprint voice compare ──────────►│
       │    (real MITM defense — see §10 and SECURITY)  │
       │                                                │
       │   prompt P_B locally                           │   prompt P_B locally
       │   (P_B ≠ P_A enforced, §7)                     │   (P_B ≠ P_A enforced)
       │   wrap PSK + pair_id → capsule file            │   wrap PSK + pair_id → capsule
       │                                                │
       ▼   exit 0, zeroize all key material             ▼   exit 0, zeroize
```

### 6.1 Polling cadence and timeouts

- Each side polls for its expected inbound leg every **1–2 seconds**.
  Under normal network conditions bootstrap completes in single-digit
  seconds end-to-end (plus OOB voice-compare wall-clock).
- Bootstrap GET polling (leg-1, leg-2, leg-3) MUST NOT carry the
  `X-DeadDrop-Write` header. Same rule as plain-B `recv` per
  PROTOCOL.md and D-45: write-token is a write-path credential,
  sending it on GET leaks the credential into relay/proxy logs
  for zero authorization benefit.
- Leg 1 and leg 2 ride minute-buckets (§2.3). If the two sides started
  within the same minute, leg 1 lands in the current bucket for both.
- If the initiator does not see leg 2 within the current bucket
  window, it MUST re-POST leg 1 **every ~90 seconds** under the
  currently-active minute bucket for as long as the `--timeout`
  budget allows. This keeps leg 1 addressable on the responder's
  rolling three-bucket probe window even when the two sides started
  more than 3 minutes apart in wall-clock.
- `--timeout` default is **300 seconds** (5 minutes). On timeout,
  both sides exit with `EDDBootstrapTimeout` (exit 19); no capsule is
  written.

### 6.2 Back-to-back leg-2 / leg-3 POST on responder

Once the responder has decrypted leg 1, it holds `initiator_pk` and
has everything it needs to build both leg 2 and leg 3. It MUST post
them **back-to-back** (leg 2 immediately followed by leg 3) without
waiting for a round-trip acknowledgment between them. This pipelines
the responder's replies and shaves one polling cycle off the
initiator's total wait.

### 6.3 Leg-1 collision

If the initiator's POST for leg 1 returns HTTP 409 (slot collision),
exit with `EDDCollision` (exit 12) per D-36 — the bootstrap is not
retried in-process. Operator re-coordinates (fresh `P_A` or wait for
the next minute-bucket boundary) and reruns. Leg-1 collisions are
rare if operators use fresh 6-word Diceware per pair; see §2.3
honest-framing paragraph on the degenerate case of reused
passphrases.

### 6.4 Leg-2 / leg-3 collision

Leg 2's slot is derived under the same `slot_key_A` as leg 1 but with
direction `0x01`, so legs 1 and 2 cannot collide with each other
within a pair. Leg 3's slot is derived from the exchanged pubkeys and
the minute bucket (§4.2), so its 128-bit space is not contention-
prone within a single pair. If any leg-2 or leg-3 POST returns 409
(e.g., clock skew mid-bootstrap or pubkey-space miracle), treat it
as `EDDBootstrapTimeout` (exit 19) — re-coordinate.

---

## 7. P_B ≠ P_A enforcement

After all three legs open cleanly and fingerprints have been
compared OOB (§10), each side prompts locally for the at-rest
passphrase `P_B` used to wrap the capsule file per
`SPEC_DRAFT_B_capsule.md §1`.

Each side holds the Argon2id-derived `passphrase_key` from §2.1 in
mlocked memory for the lifetime of the bootstrap process. On the
P_B prompt, the tool computes:

```
probe_key = Argon2id(
              password   = P_B,
              salt       = bootstrap_salt,   // same salt as §2.1
              m_cost_kib = 1 << 17,
              t_cost     = 3,
              p_cost     = 4,
              output_len = 32
            )
```

and constant-time compares `probe_key` to the retained
`passphrase_key`. If they match, re-prompt with an explanatory
message; reject P_B. The comparison is **local** (each laptop
enforces its own) and does NOT require P_B to match between
laptops — P_B is the per-laptop disk-unlock floor, like a per-laptop
LUKS passphrase.

Rationale: if a user reflexively types the shared `P_A` at both the
P_A prompt (shared OOB) and the P_B prompt (local at-rest), a single
leaked passphrase would unlock both the bootstrap envelopes AND the
on-disk capsule file. The Argon2id-then-CT-compare check prevents the
accidental degenerate case. A plain SHA-256 check was considered and
rejected: `sha256(P_A)` in memory plus a brute-forceable disk capsule
would let an attacker with the memory dump skip the Argon2id step on
the disk capsule entirely. Using `passphrase_key` (the Argon2id
output) as the comparison anchor avoids holding a cheap hash of a
low-entropy secret.

`passphrase_key` (and `probe_key` after comparison) MUST be zeroized
at process exit alongside the other secrets in §8.

---

## 8. `--burn` vs `--keep-keys` semantics

v1 ships `--burn` as the **default and only** mode. The CLI accepts
`--burn` explicitly for forward compatibility, but its behavior is
identical to the default.

### 8.1 `--burn` behavior (v1 normative)

At bootstrap completion (after §10 fingerprint compare and §7 P_B
prompt succeed):

- `capsule file` at `~/.deaddrop/capsule` is materialized per
  `SPEC_DRAFT_B_capsule.md §1` (PSK + pair_id wrapped under `P_B`).
  This is the **sole on-disk artifact** produced by bootstrap, and it
  is written **only after** the §10 fingerprint voice compare
  completes — fingerprint-before-persist is the trust-boundary
  ordering.
- The following material is zeroized in mlocked memory before
  `os.Exit`:
  - `identity_sk` (own side)
  - `identity_pk` (own side — optional but cheap; not secret)
  - the peer's pinned pubkey
  - `eph_sk` (if present — responder side)
  - `eph_pk` (if present)
  - `dh_eph`, `dh_static`, `body_key`, `leg_key`, `slot_key_A`, `leg3_root`
  - `passphrase_key`, `probe_key`, `P_A` bytes, `P_B` bytes

Steady state after exit is indistinguishable from what
`deaddrop keygen` + OOB capsule transfer produces.

### 8.2 `--keep-keys` (parked, not shipped in v1)

`--keep-keys` is **rejected at CLI parse in v1** with exit
`EDDUsage` (exit 2) and detail:

```
--keep-keys is not supported in v1. Gated on agent-style
identity-key protection — see FUTURE.md F-34.
```

Persisting long-term X25519 private keys as plaintext-readable files
is a regression against plain B's symmetric-PQC-safe posture; see
D-42 (WITHDRAWN) for the full argument. `--keep-keys` unlocks only
when F-34 lands.

---

## 9. Exit-code taxonomy

Bootstrap-specific exit codes, added to the D-38 table:

| Exit | Error name           | Trigger                                                                    |
|------|----------------------|----------------------------------------------------------------------------|
|  12  | EDDCollision         | Leg-1 POST 409 (reused from D-36; same semantic as plain-B send collision) |
|  17  | EDDBootstrapMITM     | Leg-3 AEAD open failed; invalid `eph_pk`; `dh_eph` or `dh_static` is zero; leg-3 plaintext length ≠ 40 |
|  18  | EDDBootstrapAuthFail | Leg-1 or leg-2 AEAD open failed (wrong `P_A`) or peer pubkey invalid       |
|  19  | EDDBootstrapTimeout  | `--timeout` fired without completing three legs; leg-2 / leg-3 409 also map here |

Shared with plain-B send/recv where semantics match:

| Exit | Error name           | Bootstrap trigger                                                           |
|------|----------------------|------------------------------------------------------------------------------|
|   2  | EDDUsage             | Bad argv, `--keep-keys` in v1, `--role` missing, argv passphrase, `--passphrase-fd` + stdin |
|  10  | EDDCryptoLocal       | Version byte mismatch (see §2.5 / §5.2), leg-1 / leg-2 plaintext wrong length (≠ 32), RNG / Argon2id / HKDF failure |
|  11  | EDDRelayUnreachable  | Network-layer failures (identical to plain-B send)                          |
|  13  | EDDAuth              | 401 / 403 on any leg (WRITE_TOKEN / mTLS)                                   |
|  14  | EDDSizeCap           | 413 (should never fire — bodies are 73–113 bytes — but covered for parity)   |
|  15  | EDDCapsuleUnwrap     | P_B prompt → capsule wrap/unwrap failure (final step of bootstrap)           |
|  16  | EDDRelayOverloaded   | 503 on any leg                                                              |
|  20  | EDDInternal          | Panic, invariant violation                                                  |

Single-line stderr format `ERROR: <EDDName>: <detail>` is inherited
from D-38 unchanged.

### 9.1 Explicitly NOT mapped

- `EDDBootstrapPassphraseReuse` — rejected in v1 design. P_B == P_A
  is a re-prompt loop, not an exit condition (§7). A user who abandons
  the prompt (Ctrl-C) exits with the shell's signal-synthesized code
  (130 on SIGINT), not a bootstrap-specific code.
- `EDDBootstrapFlagMismatch` — rejected in v1 design. The
  `--generator` flag is parked in F-33; if and when F-33 promotes, a
  matching exit code will be added then, not now.

---

## 10. Fingerprint confirmation print

Before prompting for `P_B`, each side prints the **unified pairing
fingerprint**. This is the real MITM defense for bootstrap (the
leg-3 AEAD-failure / 2DH-construction is a complementary tamper
signal — see `SECURITY.md` bootstrap subsection).

```
bootstrap complete — compare fingerprint OOB before proceeding:

  pairing fingerprint:  <FPR>

both operators: read this to each other now. If the two sides see
different fingerprints, bootstrap was MITM'd — Ctrl-C out and rerun
with a fresh P_A.

press ENTER to continue to local capsule passphrase prompt, or
Ctrl-C to abort (nothing has been written to disk yet).
```

Unified fingerprint binding:

```
FPR = HKDF-SHA256(
        ikm     = PSK(32) ‖ pair_id(8) ‖ initiator_pk(32) ‖ responder_pk(32),
        salt    = b"deaddrop-bootstrap-fpr-v1",
        info    = b"fpr",
        length  = 16
      )
```

Both sides compute the same value because:
- Both sides know the PSK and pair_id after leg 3 decrypts.
- Both sides have pinned both pubkeys from legs 1 and 2.
- Order is fixed: `PSK ‖ pair_id ‖ initiator_pk ‖ responder_pk`,
  regardless of which side is printing.

**Why bind PSK and pair_id into the fingerprint?** An adversary who
learns `P_A` cannot forge leg 3 (requires `initiator_sk` or
`responder_sk` per §4.3), but a defense-in-depth concern motivated
the rebind: if a future implementation bug weakened the 2DH
construction, an attacker who substituted their own PSK in leg 3
would still fail the voice-compare, because a substituted PSK flips
the fingerprint.

Rendered as 32 hex characters in five groups of 6-6-6-6-8 for voice
readability (same cadence as the capsule fingerprint), e.g.:

```
a7c3d2 9f1b4e 6058ff 2c91a0 3e7d88f1
```

If operators read divergent fingerprints, bootstrap was MITM'd
during the handshake window. Ctrl-C out (exit 130) and rerun with a
fresh `P_A`. Under `--burn`, nothing has been persisted yet at this
point — `~/.deaddrop/capsule` is written **after** the fingerprint
comparison + P_B prompt, not before (trust-boundary ordering in
§8.1).

---

## 11. Changes to plain-B steady state

**None.** Once `deaddrop bootstrap` exits 0, the laptop is configured
identically to the pre-bootstrap world's "USB-copied capsule file"
posture. `send`, `recv`, `fingerprint`, `rotate-capsule`, and
`keygen` behave exactly as specified in `SPEC_DRAFT_B_capsule.md` and
D-31. No steady-state branch on "did this capsule come from
bootstrap." The capsule file itself is bit-compatible with a capsule
produced by `keygen` + OOB transfer.

Note: the unified pairing fingerprint (§10) is a **bootstrap-time**
artifact, printed once at handshake completion. It is distinct from
the steady-state capsule fingerprint printed by `deaddrop
fingerprint` (`SPEC_DRAFT_B_capsule.md §1.6`), which binds `PSK ‖
pair_id` only — the steady-state fingerprint cannot include pubkeys
because pubkeys are ephemeral to the bootstrap process under
`--burn` and are not persisted. Operators who want a durable
pubkey-bound record should copy the §10 print out-of-band at
bootstrap time.

---

## 12. Cross-references

- `DECISIONS.md` D-41 — the full rationale for shipping bootstrap as
  a provisioning protocol and the five-point argument against
  violating D-37's threat-model finding on general-purpose variant A.
- `DECISIONS.md` D-37 — the general-purpose A rejection that this
  spec **narrows on scope** but does not reverse. Bootstrap is a
  provisioning protocol, not a revived payload variant.
- `DECISIONS.md` D-42 — (WITHDRAWN) the history of considering B′
  steady-state graduation, and why `--burn` default made that
  unnecessary for v1.
- `DECISIONS.md` D-38 — exit-code taxonomy; §9 above is additive.
- `DECISIONS.md` D-31 — CLI contract (bootstrap subcommand row).
- `DECISIONS.md` D-36 — no-retry-on-409 discipline that §6.3 inherits.
- `DECISIONS.md` D-39 — mlocked-memory posture inherited for
  bootstrap-process secrets.
- `PROTOCOL.md §12` — shipped wire-body-version table (authoritative
  mirror of §5.1 above).
- `SPEC_DRAFT_B_capsule.md` — the capsule file format bootstrap writes
  and the KDF / AEAD suite bootstrap shares.
- `ARCHITECTURAL_PRINCIPLE_GENERIC_PIPELINE.md` — rationale behind
  the version-byte / framing contract.
- `SECURITY.md` bootstrap subsection — what bootstrap protects /
  does not protect; the MITM story in prose.
- `FUTURE.md` F-10 — B′ steady-state (parked).
- `FUTURE.md` F-14 — identity key storage (bypassed by `--burn` for
  v1; re-enters if F-10 graduates).
- `FUTURE.md` F-33 — operator-selectable `--generator` flag (parked).
- `FUTURE.md` F-34 — agent-style identity-key protection (graduation
  gate for `--keep-keys` and F-10).
- `experimental/SPEC_DRAFT_A_passphrase.md` — the rejected general-
  purpose A variant; retained for design history only.
