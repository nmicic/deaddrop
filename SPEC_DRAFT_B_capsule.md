# SPEC DRAFT B — Capsule (Shared PSK) Variant

Variant B is the shipped payload mode (D-22). This document is the
normative crypto and CLI specification for B. It is self-contained —
any URTB reference below is background, not a dependency for
implementation.

A URTB-style pairing capsule replaces the passphrase. Each laptop
holds an identical `~/.deaddrop/capsule` — a 32-byte random PSK
encrypted under a user passphrase using Argon2id +
XChaCha20-Poly1305.

---

## 1. Capsule format

Deaddrop-derived KCAP1 (matches URTB KCAP1 byte layout, bumped magic
to distinguish deaddrop capsules from URTB ones):

```
capsule = magic(4 "DDC1") ‖
          version(1)      ‖
          argon2_salt(16) ‖
          argon2_params(8) ‖
          nonce(24)       ‖
          wrap_ct(40)     ‖
          wrap_tag(16)
```

Where `(wrap_ct, wrap_tag)` is the tuple returned by
`XChaCha20-Poly1305.Seal(key=passphrase_key, nonce=nonce,
plaintext=PSK(32) ‖ pair_id(8), ad=capsule_AD)`. The AEAD output
tuple splits into raw ciphertext (exactly the plaintext length —
XChaCha20 is a stream cipher, so `|wrap_ct| = |PSK ‖ pair_id| = 40`)
and a 16-byte Poly1305 authentication tag. They are serialized
separately, in that order, immediately after `nonce`.

All fields are fixed-width, no length prefixes, no alignment padding.
Total capsule size = 4 + 1 + 16 + 8 + 24 + 40 + 16 = **109 bytes**.
This is the unambiguous byte count — any implementation that writes
125 bytes has mistakenly appended a tag twice (the most common misread
of the old `AEAD_Seal(...) ‖ tag(16)` shorthand).

### 1.0 Outer `version` byte

```
version = 0x01   (this file format; KCAP1 layout under a deaddrop magic)
```

**Normative:** receivers MUST verify `magic == "DDC1"` and
`version == 0x01` as the **first two parse steps**, before
allocating buffers for `argon2_salt`, `argon2_params`, `nonce`,
`wrap_ct`, or `wrap_tag`. Any other value of `version` → reject with
`EDDCapsuleUnwrap` (exit 15) with detail `version-unknown: 0x<hex>`;
no Argon2id derivation is attempted, no AEAD open is attempted, and
no other field is surfaced in the error message (avoid giving an
attacker a file-format oracle). `0x00` and `0xFF` are reserved and
MUST also reject. This mirrors the wire-body version-byte discipline
in §3; the two version bytes are **independent namespaces** (the
capsule file and the wire body are different formats that happen to
share their v1 value) — a future capsule-format bump does not
automatically imply a wire-body bump, nor vice versa.

### 1.1 `argon2_params` byte layout

```
argon2_params (8 bytes) =
  kdf_version (1)   // 0x01 — this capsule layout
  m_cost_log2 (1)   // m = 2^m_cost_log2 KiB; e.g. 17 → 128 MiB
  t_cost      (1)   // Argon2id iterations
  p_cost      (1)   // parallelism lanes
  keylen      (1)   // output length; must be 32 (reserved for growth)
  saltlen     (1)   // must be 16 (matches argon2_salt width above)
  reserved    (2)   // zero bytes, reject if non-zero
```

**Normative default profile** (D-15 cleanup; previously under-
specified):

```
kdf_version = 0x01
m_cost_log2 = 17     →  m = 131072 KiB = 128 MiB
t_cost      = 3
p_cost      = 4
keylen      = 32
saltlen     = 16
reserved    = 0x00 0x00
```

Tuned for ≥1 second per guess on a 2024-era laptop CPU, per URTB D-07.

### 1.2 Policy floor AND ceiling (receiver-side enforcement)

Receivers MUST reject a capsule whose `argon2_params` falls **outside**
this closed range:

```
15 ≤ m_cost_log2 ≤ 22    (32 MiB ≤ m ≤ 4 GiB)
 3 ≤ t_cost      ≤ 10
 1 ≤ p_cost      ≤ 16
     keylen       = 32
     saltlen      = 16
     reserved     = 0x00 0x00
```

- **Floor** defeats a downgrade attack where a hostile encryptor sets
  `m = 1 KiB, t = 1` to make the wrapping passphrase trivially
  brute-forceable if the capsule file is later stolen.
- **Ceiling** defeats an OOM-bomb / CPU-bomb attack where a hostile
  capsule file (e.g. a trojaned capsule sent via an allegedly "safe"
  channel) forces the receiver's process to allocate 64 GiB or spin
  for an hour on parameter-unwrap. At 4 GiB / t=10 / p=16 a well-
  intentioned hardening profile still fits; anything beyond is a
  DoS payload. Ceiling violation → exit 15 `EDDCapsuleUnwrap` with
  detail `param-ceiling-exceeded`.

### 1.3 `passphrase_key` derivation

```
passphrase_key = Argon2id(
    password     = user_passphrase (UTF-8 bytes, NFC-normalized),
    salt         = argon2_salt,
    m_cost_kib   = 1 << m_cost_log2,
    t_cost       = t_cost,
    p_cost       = p_cost,
    output_len   = 32
)
```

### 1.4 Capsule AD (integrity binding)

The capsule's AEAD_Seal MUST bind the non-secret framing so param
tampering flips the AEAD tag:

```
capsule_AD = magic(4) ‖ version(1) ‖ argon2_salt(16) ‖ argon2_params(8)
```

`nonce` does not go into AD (nonces never do in AEAD). `tag` does not
go into AD (it is the AEAD output). Any mutation to the params, salt,
magic, or version → AEAD open fails cleanly.

### 1.5 `pair_id`

8 random bytes generated at `keygen` time. Distinguishes one deaddrop
capsule from another the user may hold (one per friend, one per
project). Feeds into every HKDF `info` string for domain separation,
and into `slot_key` so two capsules that accidentally share a PSK
cannot collide on `slot_id`.

### 1.6 Fingerprint derivation (normative)

The capsule fingerprint is the short OOB-verifiable hash users
read aloud on first pairing. This subsection is the **sole
normative source** of the formula; all other docs (D-31, `SPEC.md`,
`SECURITY.md`, §5 lifecycle examples) reference this block and MUST
NOT re-specify it.

```
fingerprint = HKDF-SHA256(
    secret = PSK(32),
    salt   = "",                                 // empty (HKDF-Extract
                                                 // with zero salt)
    info   = "deaddrop-fingerprint-v2" ‖ pair_id(8),
    length = 16                                  // 128 bits
)
```

Rendered on the wire / stdout as **32 lowercase hex chars**
(`hex.EncodeToString(fingerprint)`).

Named-argument form is normative. The earlier compact form
`HKDF-SHA256(PSK, "deaddrop-fingerprint-v1", "", 8)` was ambiguous
about which positional slot was `salt` vs `info`, and at 64 bits
was below the PGP-style short-fingerprint floor. **The `v1` info
string is retired.** Implementations MUST use `v2` with
`pair_id(8)` folded into `info`; conformance vectors regenerate
under v2.

Why pair_id is in `info`, not `secret`:
- Keeps HKDF-Extract clean (PSK is the sole high-entropy input).
- `info` is RFC 5869's documented domain-separation channel.
- Matches the pattern `aead_key` already uses (§2).

Why 128 bits:
- 64 bits gives 2^32 collision resistance — inside the birthday
  bound for long-lived fingerprints if users accumulate dozens of
  capsules.
- 128 bits matches AES-128 / 16-byte UUID convention and is still
  speakable as 8 groups of 4 hex chars over voice.

Stability: fingerprint is a function of PSK + pair_id only, both
of which are preserved across `rotate-capsule` (which only re-
wraps the passphrase layer). Fingerprint **unchanged** across
`rotate-capsule`. `keygen` produces a fresh (PSK, pair_id) pair
and therefore a fresh fingerprint.

---

## 2. Key derivation

Canonical byte encoding — HMAC/HKDF inputs use ASCII labels + fixed-
width big-endian integers, exactly as specified in `PROTOCOL.md §1`.

```
slot_key = HMAC-SHA256(PSK, "slot-key-v1" ‖ pair_id(8))

slot_id  = HMAC-SHA256(slot_key,
                       "slot" ‖ enc_u64_be(b) ‖ enc_u32_be(attempt))[:16]
              where b = floor(unixtime / 60)

aead_key = HKDF-SHA256(
    secret = PSK,
    salt   = slot_id_bytes(16),
    info   = "deaddrop-v1-B" ‖ pair_id(8) ‖ service_id_bytes(16) ‖ version(1),
    length = 32
)
```

Rationale (D-27):

- `pair_id` in `slot_key` — two capsules that happen to share a PSK
  (botched rotation, cloned file) cannot produce the same `slot_id`.
- `service_id` in HKDF `info` — the body ciphertext under the same PSK
  posted to deployment A cannot open under deployment B's same
  capsule, even within the rolling service window.
- `version` in HKDF `info` — a future v2 key derivation under the same
  PSK/pair_id produces a distinct `aead_key` even if the HKDF info
  strings look similar to a human reader.
- Extra `slot_key` layer (D-17) — the URL `slot_id` is derived from
  `slot_key`, not directly from the PSK, so a side-channel that
  somehow leaked `slot_key` does not directly compute `aead_key`.

---

## 3. Body format (wire version `0x01`)

```
body = version(1) ‖ nonce(24) ‖ aead_ct(N) ‖ tag(16)
```

- `version = 0x01` — first byte of the wire body. Not encrypted;
  bound into AEAD associated data so tampering flips the tag.
  **Normative:** receivers MUST verify `version == 0x01` as the
  very first parse step, before allocating buffers for `nonce`,
  `aead_ct`, or `tag`. Any other value → reject with
  `EDDCryptoLocal` (exit 10); no AEAD open is attempted, no error
  detail beyond `version-unknown: 0x<hex>` is leaked. `0x00` and
  `0xFF` are reserved and MUST also reject.
- `nonce` — 24 random bytes per send (XChaCha20-Poly1305 IETF nonce
  space is large enough that random sampling is safe without a
  counter; D-16).
- `aead_ct` — XChaCha20-Poly1305 raw ciphertext, exactly `N` bytes
  where `N = len(user_plaintext)` (stream cipher: ciphertext length
  equals plaintext length). Does NOT include the tag.
- `tag` — 16-byte Poly1305 authentication tag, serialized
  separately after `aead_ct`. The AEAD primitive returns the tuple
  `(aead_ct, tag) = XChaCha20-Poly1305.Seal(key=aead_key,
  nonce=nonce, plaintext=user_plaintext, ad=AD)`. Implementations
  MUST split the tuple and write the fields in the order above —
  appending a tag twice (a common misread of older shorthand
  notation) produces a 16-byte-over-long body that fails AEAD
  open cleanly but wastes the round trip.

AEAD associated data (D-27):

```
AD = service_id_bytes(16) ‖ slot_id_bytes(16) ‖ version(1)
```

Binding `service_id` prevents cross-deployment replay; binding
`slot_id` prevents cross-slot replay within a deployment; binding
`version` prevents a wire-downgrade attack.

v1 plaintext is **raw user bytes** — no header, no metadata. Metadata
in v2+ is gated on the wire version byte (see §3.1).

### 3.1 Forward compatibility — v2 metadata prelude (design note)

A future v2 plaintext MAY prepend a small metadata prelude before the
user bytes, inside the encrypted envelope:

```
plaintext_v2 = prelude_len(2, BE) ‖ prelude ‖ user_bytes
prelude      = sent_at(8, unix-ms BE) ‖
               filename_len(1) ‖ filename(≤255) ‖
               content_type_len(1) ‖ content_type(≤255) ‖
               reserved(variable, TLV)
```

Not implemented in v1. See `DECISIONS.md` D-23 for the rationale for
shipping the version byte from v1, and D-28 for why content-type does
NOT live in an HTTP header.

### 3.2 Nonce freshness

The sender MUST generate a fresh random nonce on **every POST**,
including network retries. A network timeout on the first POST does
not justify resending `(nonce, aead_ct)` — a fresh nonce is cheap and
sending two different ciphertexts under the same `(aead_key, nonce)`
pair across two different attempt values is catastrophic for
XChaCha20-Poly1305 confidentiality.

Implementation note: derive the nonce from
`getrandom(2)` (Linux), `arc4random_buf` (macOS / BSD), or
`CryptGenRandom` (Windows). The Go reference client uses
`crypto/rand.Read`.

---

## 4. Security properties (variant B)

Symbolic checklist. Gaps are stated as gaps, not glossed over.

```
[X] Confidentiality vs. curious relay      — AEAD over PSK; key never at relay
[X] Integrity vs. relay tampering          — AEAD tag + AD binding
[X] Cross-slot replay blocked              — slot_id in AD
[X] Cross-deployment replay blocked (D-27) — service_id in AD + info
[X] Wire-downgrade blocked                 — version byte in AD + info
[X] Offline passphrase brute-force resistance — Argon2id profile (§1.1)
[X] Downgrade-attack resistance on params  — capsule AD + receiver-side floor (§1.2)
[X] High-entropy session key               — 32 random bytes at keygen

[ ] Forward secrecy                        — NOT provided by B
    A future PSK leak exposes every past message any observer retained.
    For FS, see `experimental/SPEC_DRAFT_Bprime_bootstrap.md`.

[ ] Sender authenticity                    — NOT provided by B
    B is symmetric. Either endpoint can produce any valid message.
    For sender authenticity, see B′.

[ ] Device revocation                      — NOT provided by B
    Any device holding the capsule can decrypt. Revocation = capsule rotation.

[ ] Traffic-analysis resistance            — NOT provided by v1
    Ciphertext size and POST timing leak to any observer (relay, ISP).
    Tracked in `FUTURE.md` F-19.
```

See `SECURITY.md` for the complete threat model.

---

## 5. Capsule lifecycle

The normative CLI contract is D-31 (`SPEC.md` mirrors it). All
commands prompt for the passphrase at a TTY or read it from fd 3;
the passphrase is never on argv and never in an env var by default.

```
# Generate a new capsule (prompts passphrase twice)
deaddrop keygen ./capsule
  → prompts passphrase (and confirm)
  → samples random PSK (32) + pair_id (8)
  → writes passphrase-encrypted capsule file with mode 0600
  → prints capsule fingerprint (§1.6 formula; 32 lowercase hex chars)
    for OOB comparison

# OOB-transfer to peer
# recommended: USB, in-person file copy, URTB session
# acceptable: scp over an existing trusted channel + fingerprint check
scp ./capsule peer-laptop:/home/user/.deaddrop/capsule

# Fingerprint read-aloud check on BOTH sides (required per SECURITY.md)
deaddrop fingerprint
# → resolves capsule via DEADDROP_CAPSULE env or --capsule flag (D-31)
# → prints capsule fingerprint per §1.6 as 32 lowercase hex chars;
#   compare by voice/OOB to peer's output. Stable across rotate-capsule
#   (PSK and pair_id are preserved; only the wrap passphrase changes).

# At runtime (either side)
export DEADDROP_CAPSULE=~/.deaddrop/capsule
deaddrop send ./secrets.tar      # prompts passphrase, encrypts, POSTs
deaddrop recv ./secrets.tar.out  # prompts passphrase, GETs, decrypts

# Re-wrap the same PSK under a new passphrase (fingerprint unchanged;
# peer needs no re-transfer). Use this if a passphrase may be exposed
# but the capsule file has not left a trusted device.
deaddrop rotate-capsule

# Full PSK replacement (fingerprint changes; pair MUST OOB re-transfer):
deaddrop keygen ./capsule.new
```

Flag shapes, passphrase-entry paths, and the "not supported" list are
**specified exactly once** in `DECISIONS.md` D-31. This document uses
the flags by name only; re-specifying them here is where earlier CLI
drift originated.

---

## 6. Memory handling (Go reference client)

Normative for the Go reference client on Linux (the primary client
target — the relay runs Linux per D-39; the client mirrors its
hardening posture for symmetry). macOS / Windows clients use the
closest equivalent primitive and document the gap; the table below
is the Linux floor.

| Protection                  | Primitive                                      | Failure behavior |
|-----------------------------|------------------------------------------------|------------------|
| No page-out to swap         | `mlockall(MCL_CURRENT \| MCL_FUTURE)` at startup (or `mlock` on secret-bearing allocations if `mlockall` would exceed `RLIMIT_MEMLOCK`) | If neither form succeeds: refuse to proceed; exit 20 `EDDInternal` with detail `mlock-failed` |
| No core dump                | `prctl(PR_SET_DUMPABLE, 0)` at startup         | If fails: refuse to proceed; exit 20          |
| No explicit mapping in dump | `madvise(MADV_DONTDUMP)` on secret regions     | Belt-and-suspenders; failure logged, not fatal |
| Clean wipe on SIGTERM/SIGINT/SIGHUP/SIGQUIT | Signal handler zeros PSK, `slot_key`, `passphrase_key`, and `aead_key` regions, then `os.Exit(0)` | Deterministic — all four handlers installed |
| Crash-class signals (SIGSEGV / SIGBUS / SIGKILL / OOM) | **Not wiped.** Crash-time state rests on the no-swap + no-dump + mlock posture: pages exist only in volatile RAM, recovering them requires a physical cold-boot attack on running hardware (not in v1 threat model; matches D-39 relay-side reasoning). | No handler attempted — handler-in-SIGSEGV is itself an attack surface |

Client-side **swap policy** is the operator's responsibility — the
client cannot `swapoff` an unprivileged account's host. Users on
machines with swap enabled MUST either disable swap (laptop with
hibernation off) or accept that the passphrase-unwrap window may
leak `passphrase_key` / PSK to swap. This gap is documented in
`SECURITY.md "Key handling at rest"` and flagged at first run if
the client detects swap-enabled on Linux (`/proc/swaps` non-empty).

Bash diagnostic client (non-normative, `tools/deaddrop.sh`) cannot
mlock and cannot reliably wipe. Its use is restricted to derivation-
vector reproduction and local testing against a local VM instance;
not recommended for real sends.

---

## 7. Pros / Cons

```
+  Strong secret that cannot be brute-forced offline.
+  URTB-lineage capsule — proven byte layout, shared tooling.
+  Capsule on disk is passphrase-protected with a tuned Argon2id profile.
+  Zero PKI. No CSR, no CA, no certificate rotation.
-  One-time out-of-band capsule exchange required.
-  PSK compromise exposes all historical sessions (no PFS).
-  Symmetric — no cryptographic distinction between sender and receiver.
-  No per-device revocation; rotation = regenerate and re-transfer.
```

---

## 8. When B is and isn't the right choice

### Choose B when
- You regularly send to the same peer.
- You can exchange the capsule once (USB, in-person, URTB).
- You want strong offline-brute resistance without PKI complexity.
- Multi-year confidentiality of past sends is NOT a requirement.

### Do not choose B when
- You need forward secrecy. Future `B′` (experimental) provides it;
  until `B′` ships, B is not the right tool for content whose
  confidentiality matters after a plausible device compromise.
- You need sender authenticity (cryptographic distinction between
  sender and receiver). Future `B′` provides it.
- You need per-device revocation without rotating every peer.

---

## 9. References

- `DECISIONS.md` — D-16 (XChaCha20), D-17 (slot_key layer), D-22
  (B + bootstrap scope), D-23 (wire version byte), D-24 (backend profiles),
  D-25 (Go reference client), D-26 (authenticated DELETE), D-27 (AD
  and HKDF domain separation), D-29 (16-byte service_id), D-31 (CLI
  contract).
- URTB `DECISIONS.md` D-05, D-07, D-09 — capsule lineage (background,
  not a dependency).
