# deaddrop — Design Decisions

Numbered, URTB-style. When superseding a prior decision, append a new D-XX
entry marked "Supersedes D-NN" — do not rewrite the original.

---

## D-01  Wire protocol is one, variants are many

Decision: All security variants share `PROTOCOL.md`. The relay does
not know which variant a body belongs to.

Why: Keeps the relay small, swappable, and audit-friendly. Clients own all
cryptographic policy. Future primitives (PQC, new KDFs) touch only the client.

How to apply: When adding a new variant, change only the client's key
derivation and body format. Never add a new relay endpoint.

---

## D-02  Relay stores ciphertext only, never keys

> **Further constrained by D-39.** Not just "no keys" — "no data on
> disk at all." Ciphertext lives in mlocked process memory only; a
> powered-off seizure yields nothing.

Decision: The relay never holds passphrases, PSKs, private keys, or
plaintext. It stores only `(slot_id → ciphertext, ttl, reads_left)` rows.

Why: Subpoena resistance. Compromise resistance. If someone takes the
relay, all they get is delete-on-read opaque bytes.

How to apply: Every PR that touches the relay must answer "did we introduce
a key or decryption path?" If yes, the PR is wrong.

---

## D-03  Rolling service prefix derived from DEPLOY_SECRET

**Superseded in part by D-29 (width widened to 16 bytes) and D-30
(honest framing: "scanner resistance," not "hides the relay from the
internet"). The acceptance window is now "current OR previous hour"
per PROTOCOL.md §2, not "± 1 hour" — the relay never accepts a
future-hour `service_id`.**

Decision: URL paths start with `service_id = HMAC(DEPLOY_SECRET, hour)[:8]`.
Only holders of `DEPLOY_SECRET` can produce a valid path. Relay validates
against the current or previous hour at POST time (write-side tolerance);
GET/DELETE require an exact match against the `service_id` the slot
was stored under at POST (see supersession banner and `PROTOCOL.md §2`).

Why: Hides the relay's existence from scanners. An attacker who knows your
Worker URL cannot even probe without `DEPLOY_SECRET`. Hourly rotation means
logs do not permanently bind a user to a fixed path.

How to apply: All other paths (including `/`) return 404 with empty body.

Rejected: static path prefix (`/api/v1/upload`). Defeats the point —
once leaked, permanent.

Rejected: per-minute service_id rotation. Too much skew friction for a
deployment-level concern. Hour is enough.

---

## D-04  Slot_id derived per minute, not per send, with attempt counter

**Superseded on attempt handling by D-36.** In v1, `attempt` is
fixed at 0; `MAX_SEND_ATTEMPTS = 1`; sender errors out on 409
instead of retrying; receiver probes `attempt = 0` only. The
minute-bucket itself is the hold-timer. The core decision below
(slot_id rotates per minute) is unchanged.

Decision: `slot_id = HMAC(secret, "slot" || floor(ts/60) || attempt)`. Rotates
every minute. `attempt` disambiguates multiple sends within a minute.

Why: Never reuse a URL even when the passphrase is reused. Relay logs
cannot say "this user always posts to slot X." If two sends collide in the
same minute (409), sender retries with `attempt = 1, 2, ...`.

~~How to apply: Sender tries `attempt = 0, 1, 2, ...` until 409 clears.
Receiver probes all attempts within the skew window.~~
Superseded by D-36: sender does not retry on 409, and receiver probes
only `attempt = 0`.

Rejected: random slot_id with a hash-chain claim to the passphrase.
More complex, same security properties.

---

## D-05  Clock skew window: 3 minutes receiver-side, configurable

**Superseded on configurability by PROTOCOL.md §9.** Skew is pinned
at 3 buckets, full stop. Operators cannot widen it via
`DEADDROP_SKEW_BUCKETS` or any other env knob — changing the probe
window is a wire-level behavior and requires a version bump. The
"receiver probes N, N-1, N-2" part of the decision is unchanged.

Decision: Receiver tries buckets `N, N-1, N-2` by default.

Why: Captures common laptop clock drift without making probes cheap for an
attacker running parallel guesses (probing an HMAC domain is still infeasible).

~~How to apply: `DEADDROP_SKEW_BUCKETS=5` extends the window for edge cases
(old laptop, sync disabled).~~
Superseded: no env override; K is pinned at 3.

---

## D-06  Delete on read, not only on TTL

Decision: `reads_left` reaches 0 → relay deletes immediately. TTL is the
outer bound.

Why: Shortens the window where ciphertext exists. If the receiver reads
within 2 seconds, the ciphertext is gone within 2 seconds regardless of TTL.

How to apply: Atomic decrement-and-delete. Cloudflare KV's eventual
consistency may permit a rare double-read race; mitigation via Durable
Objects tracked as `FUTURE.md` F-4.

---

## D-07  Reference client is bash + openssl + curl

**Superseded by D-25.** The normative reference is a Go static binary.
The bash client exists only as a non-normative diagnostic and cannot
run the full variant B flow (`openssl enc` on openssl 3.x does not
expose XChaCha20-Poly1305 as an enc algorithm). Kept below for
historical context.

Decision: The authoritative first implementation is a shell script using
`openssl` and `curl`.

Why: Auditable in an afternoon. Works on every Unix without a runtime.
Matches URTB's "single static binary" ethos in the simplest possible form.
Low setup friction.

How to apply: Bash client is the reference. Go client is an ergonomics and
performance upgrade (see `FUTURE.md` F-3). Python is optional and
discouraged (ships a runtime; pypi is an attack surface).

Rejected: Python as reference. Rejected: a GUI. A CLI is the native shape
for this.

---

## D-08  openssl, not libsodium or Monocypher

**Superseded by D-25 on primitive selection.** The shipped Go client
uses Go stdlib `crypto/` + `golang.org/x/crypto/chacha20poly1305` and
`golang.org/x/crypto/argon2`. The shell-out-to-openssl path below
applies only to the non-normative bash diagnostic. Kept for
historical context.

Decision: Use openssl libcrypto 3.x primitives: HMAC-SHA256, HKDF-SHA256,
XChaCha20-Poly1305 (IETF), X25519.

Why: openssl 3.x is already installed on every macOS, every modern Linux,
every container base image. No vendoring. Unlike URTB's Monocypher decision
(D-02 in URTB), deaddrop is userspace-only — no firmware, dynamic linkers
always available.

How to apply: Bash client shells out to `openssl`. Go client uses
`crypto/` stdlib + `filippo.io/age` primitives where convenient.

Rejected: libsodium (extra install step across distros). Rejected:
Monocypher (bring-your-own crypto is overkill without an embedded target).

---

## D-09  Default max blob 1 MiB

**Superseded by D-24, D-33, and D-74.** The shipped default is
`MAX_BLOB_BYTES = 10485841` (10 MiB plaintext + wire overhead; see
D-74) on the sole VM/Go backend. The
1 MiB figure below was specific to the parked Cloudflare profile and
is no longer in effect. The Cloudflare-KV rationale is moot per D-33.

Decision: `MAX_BLOB_BYTES = 1048576`.

Why: Fits under Cloudflare KV's 25 MiB value limit with 25× margin. Aligns
with the stated use case (small config files, URTB capsules, recovery
phrases, SSH keys). Keeps abuse surface small.

~~How to apply: VM operators MAY raise this. Cloudflare variant SHOULD stay
under 10 MiB to keep Worker CPU and latency predictable.~~
Superseded: the VM/Go default is 10 MiB; Cloudflare is parked.

---

## D-10  Default TTL 10 minutes, max 1 hour

Decision: `MAX_TTL_SECONDS = 3600`, default 600.

Why: Short enough that abandoned slots do not accumulate. Long enough for
slow receivers (laptop on VPN reconnect, receiver not at keyboard).

Rejected: 24h default. Invites accumulation, invites regret when someone
forgets to retrieve.

---

## D-11  Write-token is optional but recommended in production

**Superseded by D-22 (build scope) and the SECURITY.md / PROTOCOL.md §4
rewrite:** `WRITE_TOKEN` is **mandatory** on any internet-facing
deployment. `--local-only` is the explicit opt-out for LAN / Tailscale
deployments. "Optional but recommended" is no longer the policy.

Decision: Relay supports but does not require `X-DeadDrop-Write`. Operator
enables it by setting `WRITE_TOKEN`.

Why: Single-user deployments want it (prevents third-party slot filling).
Test / local deployments want it off (friction).

~~How to apply: Default config sets `WRITE_TOKEN` to empty (disabled). Install
script warns if deploying to production without it.~~
Superseded: default is "required on internet-facing"; install script
refuses to configure an internet-facing deployment without it.

---

## D-12  Docs mirror URTB conventions

Decision: `README`, `SPEC`, `PROTOCOL`, `SECURITY`, `DECISIONS`, `TESTING`,
`FUTURE`, `PRIOR_ART` file set, URTB-style. Numbered decisions with
`Why:` / `How to apply:` blocks.

Why: The author maintains URTB; reusing conventions lowers the cognitive
cost of maintaining both projects. Future contributors encounter a familiar
shape.

---

## D-13  Public repo OK; author runs no shared service

Decision: Source is public (Apache-2.0). The author does NOT run a shared
"deaddrop.io" relay.

Why: Releases the software; does not accept abuse liability. Each user
deploys their own Worker or VM. Comparable to magic-wormhole (self-hosted
rendezvous is the mainstream option) and croc (public relay run by
maintainer, but the software supports self-hosting).

How to apply: README and SPEC state this explicitly. Documentation steers
users toward deploying their own relay. No hosted service, ever.

Rejected: Shared hosted instance. Classic pastebin abuse liability. A
hosted instance defeats the architectural point — the relay would no
longer be single-tenant, and every user would share one `DEPLOY_SECRET`.

---

## D-14  Uniform 404 responses — no oracle

Decision: GET to non-existent slot, expired slot, exhausted slot, and
wrong-prefix path all return a byte-identical 404 with empty body.

Why: Prevents attackers from enumerating which slots ever existed, or
which prefixes are live. Removes any timing / body / header signal.

How to apply: Relay has one 404 helper; all "not allowed" paths route to
it. Tests verify byte-for-byte identical responses.

---

## D-15  Variants are documents, not branches

**SUPERSEDED in part by D-22** (ship scope) **and D-25** (reference client
language). The "variants are documents" principle stands; the specific
reference-implementation and ship-scope sentence below is historical.

Decision: Variants A–F coexist as spec documents. A user picks one by
deploying a relay and a client configured for it. The codebase does not
carry all six simultaneously.

Why: Maintenance cost. Tests would balloon. Users deciding between
variants should read the specs, not feature-flag a binary.

~~How to apply: Reference bash client ships only variant A. B/C
implementations land behind an explicit build flag when written.~~
Superseded: the root build cycle ships variant B plus the `deaddrop
bootstrap` provisioning protocol (D-22 + D-41), and the reference
client is a Go static binary (D-25). Parked variants live in
`experimental/`.

---

## D-16  Body AEAD is XChaCha20-Poly1305 (IETF)

Decision: XChaCha20-Poly1305 with 24-byte random nonce per send.

Why: Large nonce space → random nonces safe without a counter. Available in
openssl 3.x, Go stdlib (`chacha20poly1305`), and URTB already uses it.

Rejected: AES-GCM. 96-bit nonce is too narrow for per-send randomness without
a counter; a counter would require client state.

---

## D-17  Slot derivation key for variants B/C via `slot_key = HMAC(PSK, "slot-key-v1")`

> **OBSOLETE — do not implement literally.** Superseded by D-27 / D-29 and
> SPEC_DRAFT_B §3. Current derivation is
> `slot_key = HMAC(PSK, "slot-key-v1" || pair_id)`; the `pair_id` binding
> is load-bearing for cross-capsule isolation. The principle stated below
> (separate key for URL vs. AEAD body) remains valid.

Decision: The URL `slot` is derived from `slot_key`, not directly from the
PSK. The AEAD key for the body is derived from `PSK` (or from DH output).

Why: If an adversary somehow learns `slot_key` (e.g. via a side channel in
the URL path), they cannot directly compute the AEAD key. Minor defense
in depth at zero cost.

---

## D-18  HKDF salt = slot_bytes; info = "deaddrop-v1-<variant>" (+ context)

Decision: HKDF for the AEAD key uses the binary slot_id as salt and an
info string embedding the protocol version and variant letter.

Why: Salt is public and random per send (slot varies with time + attempt).
Info enforces domain separation across variants — a key derived for A is
cryptographically distinct from a key derived for B, even with the same
secret input.

---

## D-19  No variant mixing in a single deployment

Decision: A given relay serves exactly one variant. Clients on that relay
all use the same variant.

Why: Simplifies the trust story. Mixing (say, some clients use A, some use
C, on the same relay) makes the security guarantee the weakest of the set.

How to apply: Client config is explicit about `DEADDROP_VARIANT=A|B|B′|C|...`.
Relay is unaware (D-01), but operator documentation pins the variant in use.

---

## D-20  B is default; security upgrades are client-side

Decision: Variant B (shared PSK capsule) is the recommended default. Any
stronger property (forward secrecy, sender authenticity, hardware-backed
keys, fleet PKI) is added as a client-side layer built on top of B. The
relay and the wire protocol do not change.

Why: Mirrors URTB `DECISIONS.md` D-03 — "firmware is a blind modem."
Keeping the relay dumb is the architectural point of deaddrop (see
`ARCHITECTURAL_PRINCIPLE_GENERIC_PIPELINE.md`). A stable floor lets
clients evolve independently: B → B′ → CSR/CA → keyring/hardware key
storage, all without touching the Worker or VM. The user also gets a
graceful path to re-key or harden without re-deploying infrastructure.

How to apply: New security features default to client-side implementations
on top of B. Any proposal that requires relay-side awareness of crypto
state is rejected by default and must justify why it cannot live in the
client.

Rejected: Building variant C as a first-class peer of B. C requires the
capsule to ship private keys between devices, which couples key management
to capsule distribution and blocks hardware-backed storage.

---

## D-21  B′ supersedes C for 2-party use

Decision: For new 2-party deployments that want forward secrecy and sender
authenticity, use B′ (B + bootstrap pubkey pinning), not C. C remains
documented as a reference.

Why: B′ provides the same cryptographic properties as C (Noise_IK-shaped
body, ephemeral DH, static-key sender authentication) with three
operational wins:

1. Private key never leaves the device that generated it — SSH model.
   C requires shipping `my_identity_priv` inside the capsule, which
   undermines "capsule theft = attacker needs only the wrap passphrase."
2. Identity re-key does not require re-shipping a capsule. Regenerate
   `identity.key`, re-run `bootstrap`. Under C, identity rotation means
   regenerating and securely re-transferring the capsule pair.
3. Clean migration path to hardware-backed keys (K2–K4 in B′) and to
   fleet-scale CSR/CA enrollment (F-13) without protocol change.

The cost is a one-time `bootstrap` step per peer pair with an OOB
fingerprint check. That is acceptable for the target use case (a pair of
laptops that send regularly).

How to apply: README, SPEC, and variant selection text recommend B′ over
C. Existing C content stays as "reference / historical" with a banner
pointing to B′. No code drops C; it simply stops being the suggested path.

Rejected: Removing C from the repo. It is useful context for why B′ is
shaped the way it is (Noise_IK lineage), and for users who want a capsule
that contains everything needed to decrypt without a bootstrap round trip
(niche use case — e.g. one-shot deploy of a pre-provisioned pair).

---

## D-22  Build cycle scoped to variant B + bootstrap

Decision: The first build cycle ships variant B (steady-state
payload) and the `deaddrop bootstrap` provisioning protocol
(D-41). Specs for variants A, B′, C, D, E, F, and the G
messaging-bus sketch are moved to `experimental/`. They are not
on the roadmap.

**Note on Variant A:** D-37 supersedes the "parked for scope"
framing for A specifically. A is rejected on threat model, not
merely parked awaiting scope. `deaddrop bootstrap` (D-41) is a
provisioning protocol, not a revival of generic variant A.
B′, C, D, E, G remain parked for scope as described below.

Why: The biggest risk the project faced at the end of the design phase
was architecture-astronaut drift: ~2000 lines of spec across ~15 files,
zero lines of code. Scoping hard to B forces a working artifact that
will teach more than any further variant can. B′ and friends can be
promoted back only on evidence of real need.

How to apply: New features, specs, and design decisions in the root
repo apply to variant B. Proposals to add variant-specific behavior are
deferred to `experimental/` and revisited only once B is running in
anger. `experimental/README.md` tracks the index of parked specs and
what would trigger their promotion.

Supersedes D-15 on the "which variant ships" question. D-15's core
principle — variants are documents, not branches — still holds for the
parked specs, and is in fact reinforced: the parked directory is the
mechanism.

Rejected: Keeping B′ in root as a "recommended upgrade." Reason: every
additional spec in root invites design work that should be deferred until
B exists. B′ is a clean additive upgrade to B, so it loses nothing by
waiting in `experimental/` until B is built and the upgrade is earned.

---

## D-23  Wire body carries a version byte from v1

> **AD FORMULA BELOW IS OBSOLETE — do not implement literally.**
> Superseded by D-27 / D-29. Current AD is
> `AD = service_id ‖ slot_id ‖ version` (16 + 16 + 1 bytes), binding
> both the rolling `service_id` and the full 16-byte `slot_id`. The
> version-byte-from-v1 principle below remains normative; only the
> AD concatenation has widened.

Decision: The encrypted wire body leads with a 1-byte `version` field
(`0x01` for the shipped format). The version byte is bound into AEAD
associated data (`AD = slot_id_bytes ‖ version`) so tampering flips
the tag. v1 plaintext is raw user bytes; no metadata prelude. See
`PROTOCOL.md` §7 and `SPEC_DRAFT_B_capsule.md` "Body format."

Why: Direct lesson from URTB. The KCAP1 capsule format shipped with a
version byte from day one (`magic(4) ‖ version(1) ‖ …`), and when the
author later considered adding ESP-channel and rate fields the version
byte was what made the extension path clean — new fields land under a
new version number, old parsers reject unknown versions, no ambiguous
flag day. Wire formats that omit a version byte on day one pay a
disproportionate tax the moment they need to grow (TLS 1.0 vs 1.3,
Signal protocol's double-ratchet evolution, Noise framework's pattern
byte). One byte now buys an open-ended evolution path later.

The cost is 1 byte per send (trivially insignificant against a 24-byte
nonce + 16-byte AEAD tag + user bytes). The benefit is that any v2
concern — encrypted metadata prelude (`sent_at`, `filename`,
`content_type`), a new AEAD primitive, a framing change — can ship as
`version = 0x02` alongside v1 receivers for a transition period,
rather than forcing a synchronized client+relay upgrade.

How to apply: Every client that produces or consumes a deaddrop wire
body MUST read the version byte first and dispatch on it. Unknown
version → reject. New wire-format work gets a new version number and a
transition plan, never a silent format change.

Rejected: Omit the version byte; rely on the HKDF `info` string to
provide domain separation. Reason: the HKDF info string distinguishes
*keys* across variants but does not help a receiver parse an unknown
*body layout*. If v2 changes nonce length, adds a prelude, or swaps
AEAD primitives, a v1-only receiver would mis-parse silently — exactly
the flag-day risk a version byte avoids.

Rejected: Put the version inside the plaintext (first byte after
decrypt). Reason: receiver must commit to a nonce layout and an AEAD
primitive *before* decrypting, so the parsing dispatch has to happen
before the AEAD tag is checked. The version byte must therefore live
outside the ciphertext; AD-binding defends it against tampering.

Reference: URTB `references/capsule_format.md` (KCAP1 layout),
URTB `DECISIONS.md` D-05 (capsule parameter integrity via AEAD AD).

---

## D-24  Two backend profiles: `worker-kv` and `vm-tx`

**Superseded by D-33.** Cloudflare is parked; VM/Go is the only
supported deployment target for v1. The profile split below is kept as
the historical record of why the split was considered and what its
collapse simplified.

Decision: The same wire protocol has two supported backend profiles with
different operational guarantees. The client does not change between
them.

- `worker-kv` — Cloudflare Worker + KV. Low-ops, global edge, best-effort
  delete-on-read (KV eventual consistency can permit a rare concurrent
  double-read), default `MAX_BLOB_BYTES = 1 MiB`, `WRITE_TOKEN` required.
- `vm-tx` — self-hosted VM with a transactional store (sqlite / bbolt),
  caddy/nginx in front, optional mTLS. Strict single-read (atomic
  decrement-and-delete inside one transaction), default
  `MAX_BLOB_BYTES = 10 MiB`, `WRITE_TOKEN` required for internet-exposed
  deployments.
  *(D-39 replaces the bbolt store with an in-memory map; the "atomic
  decrement-and-delete" guarantee is preserved but now backed by a Go
  `sync.Mutex` rather than a bbolt transaction.)*

Why: The Cloudflare-KV design can oversell one-shot semantics. Rather
than downgrade the whole project to
"best-effort," split the guarantee by backend. Operators who need strict
one-shot deploy `vm-tx`; operators who want zero-ops convenience deploy
`worker-kv` and accept the race window. Durable Objects as a third
profile (strict one-shot on Cloudflare) is tracked in `FUTURE.md` F-4.

How to apply: `experimental/BACKEND_CLOUDFLARE_parked.md` and `BACKEND_VM.md` document the
profile-specific operator contract. `PROTOCOL.md` retains common wire
semantics; per-profile deviations are collected in one section. `SECURITY.md`
carries a backend matrix. `TESTING.md` splits tests into common-B /
`worker-kv` / `vm-tx` / optional-mTLS.

Rejected: Require Durable Objects as the only Cloudflare path. Reason:
DO has higher cost and complexity; the user wants a "personal free-tier
relay" option, and best-effort delete-on-read with a documented caveat
is acceptable for that use case when paired with short TTL.

Rejected: Hold Cloudflare release until DO is implemented. Reason: the
project has two real deployment targets today; documenting the honest
guarantee of each ships value immediately.

Supersedes D-09's "Cloudflare variant SHOULD stay under 10 MiB" framing
on max blob size — `worker-kv` stays at 1 MiB, `vm-tx` at 10 MiB, and the
guidance is now profile-explicit.

---

## D-25  Reference client is a Go static binary, not bash

**Supersedes D-07 and D-08.**

Decision: The authoritative reference client is a single static Go
binary using `crypto/` stdlib + `golang.org/x/crypto/chacha20poly1305`
+ `golang.org/x/crypto/argon2`. Bash + openssl is retained only as a
non-normative diagnostic harness for derivation-vector reproduction.

Why: The bash + openssl choice was empirically unsound for the shipped
crypto.
1. openssl 3.x does not expose XChaCha20-Poly1305 as an `enc` algorithm
   (`enc: AEAD ciphers not supported` on openssl 3.6.1; independently
   verified). The Go path has it in
   `golang.org/x/crypto/chacha20poly1305.NewX`.
2. Bash cannot `mlock` memory, set `MADV_DONTDUMP`, or reliably
   zero-out secrets across signal handlers. The security checklist
   listed these as client properties; bash cannot provide them.
3. Passphrase entry from bash leaks to argv (`/proc/<pid>/cmdline`),
   environment inspection, `/tmp` intermediate files, and shell
   history. Go can read the passphrase from fd/stdin directly and keep
   it in a single short-lived allocation.
4. Canonical derivation-vector interop is much easier to enforce across
   clients when there is one authoritative implementation in a language
   with byte-level control.

How to apply: `SPEC.md`, `SPEC_DRAFT_B_capsule.md`, `SECURITY.md`, and
`TESTING.md` describe the Go client as normative. Bash may ship as
`tools/deaddrop.sh` for diagnostics; any security claim it cannot meet
is called out in that file, not in root specs.

Cost accepted: one static-binary distribution step. Mitigation: Go
cross-compiles to every target the project cares about; a 4–8 MB
binary is copyable over the same channel as the capsule.

Rejected: Keep bash as reference, switch AEAD to IETF ChaCha20-Poly1305
(12-byte nonce, counter). Reason: nonce management becomes client
state; the v1 design's "random 24-byte nonce, no counter" simplicity is
the whole reason XChaCha was picked in the first place (D-16).

Rejected: `age` as the crypto core. See D-32.

Rejected: Rust. Would also be defensible; Go was picked because the
broader project set the operator maintains is already Go,
and cross-language consistency reduces cognitive cost.

---

## D-26  Authenticated DELETE ships in v1

Decision: `DELETE /{service_id}/{slot_id}` is authenticated by a
per-slot delete token. The sender chooses a random 32-byte
`delete_token` at POST time, attaches
`X-DeadDrop-Delete-Hash: hex(SHA-256(delete_token))` to the POST, and
the relay stores the hash alongside the slot row. A later DELETE must
carry `X-DeadDrop-Delete-Token: hex(delete_token)`; the relay compares
SHA-256 of the provided token against the stored hash in constant time.

- Match → delete the slot, respond 204.
- Mismatch or absent token within a valid `service_id` → respond 404
  (byte-identical to the GET "not found" response per D-14).
- Invalid `service_id` → respond 404 (same uniform-404 class).

Why: Unauthenticated DELETE was an oracle (anyone who learned a slot
URL could pre-expire it, and a "204 always" response combined with the
legit receiver's subsequent 404 was a correlation signal). An
authenticated DELETE costs the relay one 32-byte hash column and one
constant-time compare, and does not re-introduce a key or decryption
path at the relay (D-02 still holds). 32 bytes per POST is a trivial
wire cost to avoid a future protocol bump.

Delete-token lifecycle (superseded by D-35): the sender holds the
token **in mlocked process memory only** for the lifetime of the
sending process. Never persisted, printed, or exported. The only use
case is in-process transactional batches — see D-35 for the full
policy and escape clause. Delete token is not derived from PSK — it
is fresh entropy per send — so compromising the capsule does not let
an attacker pre-expire in-flight slots.

How to apply: `PROTOCOL.md §3` defines the DELETE endpoint with the
hash/token headers and the match/mismatch/wrong-service behavior.
`TESTING.md` covers AC-DEL-01..03. `FUTURE.md` F-9 (previously "add
authenticated DELETE later") is removed.

Rejected: Drop DELETE from v1 entirely. Reason: cheap to ship
correctly, useful in "sender realizes mistake" and "receiver confirmed
out-of-band, drain the slot now" cases.

Rejected: Use the capsule PSK to authenticate DELETE. Reason: tying
DELETE auth to PSK means a relay seeing many DELETEs from the same
pair could correlate activity; fresh per-send tokens avoid that.

Rejected: `DELETE` always returns 204. Reason: correlation oracle with
the legit receiver's 404.

---

## D-27  AEAD AD and HKDF info bind deployment and wire version

**Amended by D-29:** `service_id` is 16 bytes, not 8. The AD and
HKDF info strings below use the current 16-byte width; the original
text with 8-byte `service_id` is obsolete. The structure (what is
bound, in what order) is unchanged; only the width changes.

Decision: The AEAD associated data for variant B body encryption is:

```
AD = service_id_bytes(16) ‖ slot_id_bytes(16) ‖ version(1)
```

The HKDF `info` string for `aead_key` is:

```
info = "deaddrop-v1-B" ‖ pair_id(8) ‖ service_id_bytes(16) ‖ version(1)
```

And the URL `slot_key` is derived with `pair_id` folded in:

```
slot_key = HMAC-SHA256(PSK, "slot-key-v1" ‖ pair_id)
```

Why: Three separate hardening gaps with the same shape (missing domain
separation) are bundled into one decision.
1. Cross-deployment replay: a body posted to deployment A (with
   `DEPLOY_SECRET_A`) using capsule X could be replayed at deployment B
   (with `DEPLOY_SECRET_B`) using the same capsule X within the
   service-window of B. Binding `service_id` into AD closes this.
2. Cross-capsule `slot_id` collision: two capsules that share a PSK
   (botched rotation, cloned capsule) produce the same `slot_id`.
   Binding `pair_id` into `slot_key` gives full URL-layer separation.
3. Wire-version evolution: v2 key-derivation rules differing from v1
   under the same HKDF info string would silently produce the same
   `aead_key`. Binding the version byte into HKDF info removes the
   collision.

How to apply: `SPEC_DRAFT_B_capsule.md` "Key derivation" and "Body
format" sections encode this exactly. Derivation test vectors
(`testdata/derive/*.json`, tracked in `TESTING.md` AC-DER-FIXTURES)
carry `(PSK, pair_id, service_id, bucket, attempt, slot_id, aead_key,
info_bytes, ad_bytes)` tuples so any two independent implementations
produce byte-identical keys.

Cost: zero. `service_id` and `version` are already computed client-side
per send.

Rejected: Fold `service_id` into the PSK itself at capsule-bind time.
Reason: capsules would then be deployment-specific, which defeats the
"one capsule, one or more relays" operator model (and URTB capsules are
not deployment-scoped either).

---

## D-28  Remove `HEAD /` and `X-DeadDrop-Content-Type`

Decision: Two relay surfaces are removed from v1.

1. `HEAD /` — removed. Previously documented as a liveness probe that
   "leaks nothing." In fact it leaks that a deaddrop relay exists at the
   hostname, which directly contradicts the rolling-service-prefix
   design intent (D-03) and D-14's uniform-404 posture. Cloudflare has
   platform health checks; VM operators can use an operator-private
   `/.well-known/deaddrop-health` gated behind mTLS or a loopback bind
   without spec-level support.
2. `X-DeadDrop-Content-Type` — removed. Plaintext metadata at the relay
   contradicts "relay stores only ciphertext + TTL + read-count" (D-02).
   When content-type hinting is actually needed, it lives inside the
   encrypted envelope under the v2 metadata prelude (D-23).

Why: Both items were "free" features that each leaked something the
design otherwise worked hard to hide. Removing them is cost-free and
tightens the invariants.

How to apply: `PROTOCOL.md §3` drops `HEAD /`; §6 drops the header;
§7/§11 stop referencing either. The uniform-404 class in D-14 covers
every non-listed path/method.

Rejected: Keep `HEAD /` with a random-delayed 404 response. Reason:
timing delays add test flakiness and still leave behavioral signals.

Rejected: Keep `X-DeadDrop-Content-Type` as "stored but never served."
Reason: dead weight; a relay that stores a field it never serves is
exactly the kind of silent metadata accumulation D-02 forbids.

---

## D-29  `service_id` widened to 16 bytes (32 hex chars)

Decision: `service_id = HMAC-SHA256(DEPLOY_SECRET, "svc" ‖ h)[:16]`
(16 raw bytes, encoded as 32 lowercase hex characters in the URL).
`slot_id` remains at 16 raw bytes / 32 hex chars.

Why: The original 8-byte width was cryptographically fine against
random scanners but comfortably weak as a deployment-access gate: an
attacker who saw one live URL in any log had a valid `service_id` for
roughly 2 hours without needing `DEPLOY_SECRET`. At 16 bytes the
guessing cost becomes astronomical. The URL grows by 16 hex characters
per path — immaterial against the 32 already used by `slot_id`.

How to apply: `PROTOCOL.md §1` states truncation to 16 raw bytes and
explicit hex encoding of 32 characters. `SPEC.md` URL example updated.
Derivation test vectors in `testdata/derive/*.json` carry
16-byte `service_id`.

Rejected: Keep 8 bytes, require `WRITE_TOKEN` as the real access gate.
Reason: `WRITE_TOKEN` is now mandatory on internet-facing deployments
(D-24 / SECURITY.md rewrite), but widening `service_id` is
near-free and closes the "GET enumeration with a single leaked URL"
path against unauthenticated GETs.

---

## D-30  Honest framing of the rolling service prefix

Decision: The rolling `service_id` is documented as "scanner
resistance + log-binding friction," **not** as "hides the relay from
the internet" or "access control." The per-deployment anti-scanner
benefit is real; the "hidden from the internet" framing is oversold
against Certificate Transparency and platform-specific enumeration
(e.g. `*.workers.dev`-style wildcard sweeps on parked backends, or
hostname discovery via CT logs on the VM deployment).

Why: Any relay hostname is discoverable via CT logs regardless of
what path it accepts. The prefix rejects scanner probes at the HTTP
layer; it does not hide the existence of the hostname. Access
control is provided by `WRITE_TOKEN` (PROTOCOL.md §4 / SECURITY.md)
and optionally by operator-provisioned mTLS
(`experimental/SPEC_DRAFT_D_private_CA.md`, referenced by
`BACKEND_VM.md §5`). Truth-in-advertising: the prefix is a useful
layered defense,
not a cloaking device.

How to apply: `PROTOCOL.md §2`, `SPEC.md`, and `SECURITY.md` state the
property as "scanner-resistance + log-binding friction." `README.md`
Scope drops "hides the relay from random scanners" phrasing.

Rejected: Drop the rolling prefix entirely, rely on `WRITE_TOKEN`.
Reason: the prefix costs nothing operationally once `DEPLOY_SECRET` is
shipped, and it does reduce the volume of unauthenticated probe
traffic hitting the Worker CPU budget. Layered defense earns its keep.

---

## D-31  CLI contract: single-process `send` / `recv`

**This section is the sole normative source of CLI syntax.** Other
docs (README.md, SPEC.md, SPEC_DRAFT_B_capsule.md, SECURITY.md)
reference commands by name and describe their role in the flow, but
MUST NOT restate flag shape or argument positions — re-specification
is where earlier CLI drift originated. If you find a flag shape
in any other file that contradicts the block below, the other file
is wrong.

Decision: The normative CLI is a single-process tool with two primary
subcommands, plus capsule management:

```
deaddrop send <file>         # read plaintext from <file>, encrypt, POST
deaddrop recv [output]       # GET, decrypt, write to <output> or stdout
deaddrop keygen <out-path>   # generate a new capsule (prompt passphrase)
deaddrop fingerprint         # print capsule fingerprint (SPEC_DRAFT_B_capsule.md §1.6) for OOB verification
deaddrop rotate-capsule      # re-wrap SAME PSK under a new passphrase
                             # (fingerprint unchanged; no OOB re-transfer).
                             # Full PSK replacement = `keygen` + OOB re-transfer.
deaddrop bootstrap --role={initiator|responder}
                             # interactive three-leg provisioning protocol
                             # (D-41). Delivers PSK + pair_id to both
                             # laptops via a shared Diceware passphrase.
                             # Primary pairing path; offline capsule-file
                             # transfer remains as backup (`keygen` + OOB
                             # copy). `--burn` is the default and only v1
                             # mode (identity X25519 keypairs are
                             # ephemeral to the process). See
                             # `SPEC_BOOTSTRAP.md`.
                             # Bootstrap-specific flags (normative):
                             #   --role={initiator|responder}  (required)
                             #   --burn                        (default; accepted for forward-compat)
                             #   --keep-keys                   (rejected in v1 — FUTURE.md F-34)
                             #   --passphrase-fd <n>           (scripted P_A entry)
                             #   --passphrase-env VAR          (scripted P_A entry, with warning)
                             #   --deploy-secret-fd <n>        (D-43: read DEPLOY_SECRET from fd; preferred over --deploy-secret argv)
                             #   --timeout <seconds>           (default 300)
```

Capsule path comes from `DEADDROP_CAPSULE` env or `--capsule <path>`;
default `~/.deaddrop/capsule`. Passphrase is read from a TTY prompt
(`read -s`-equivalent) or from fd 3 / stdin when invoked
non-interactively (`--passphrase-fd 3`). `--passphrase-env VAR` exists
but prints a security warning when used.

The passphrase MUST NOT be passed as an argv argument. No
`DEADDROP_PASSPHRASE` default environment variable. No long-lived
unlock agent in v1.

The same argv prohibition extends to **`DEPLOY_SECRET`** (D-43,
v0.1.1): argv exposure leaks the value to process list, shell
history, and process snapshots — exactly the same threat model
that motivates the no-argv-passphrase rule. `DEPLOY_SECRET` MUST
be delivered via `--deploy-secret-fd <n>` or
`$DEADDROP_DEPLOY_SECRET` from v0.2 onward; the v0.1.x argv path
remains functional with a stderr deprecation WARN. The rule
applies symmetrically to the relay's `WRITE_TOKEN`. See D-43 for
the deprecation timeline and per-binary mechanics.

Why: The three-way CLI contradiction across SPEC/README/B-draft was
the largest source of ambiguity in the docs. Pinning the contract in
one place removes that ambiguity and aligns with the "prompt/fd/stdin
only" secret-entry guidance from SECURITY.md.

How to apply: `SPEC.md`, `README.md`, `SPEC_DRAFT_B_capsule.md` all use
the contract above. `SECURITY.md` "Key handling at rest" cross-
references D-31. Any other invocation form (`-s <secret>`,
`DEADDROP_PASSPHRASE=...`, `./deaddrop unlock` separate process) is
deleted from normative docs.

Rejected: Long-lived `deaddrop-agent` (ssh-agent shape). Reason:
additional attack surface, IPC design work, daemon supervision.
Justifiable as `FUTURE.md` F-15 (keyring integration) once the CLI
is stable.

Rejected: Keep `DEADDROP_PASSPHRASE` as a "test-only" knob. Reason: it
has a way of sneaking into production scripts. One entry path in v1.

### Rotate-capsule semantics (normative)

`rotate-capsule` re-wraps the **same** PSK under a **new** passphrase:

- The PSK (the 32-byte key shared between sender and receiver) is
  unchanged.
- The new capsule file is the old PSK wrapped under a freshly-prompted
  passphrase using fresh Argon2id salt and a fresh AEAD nonce.
- The capsule fingerprint is UNCHANGED (fingerprint is a PSK-derived
  HKDF output per D-19; it does not depend on wrap parameters).
- No out-of-band re-transfer is required — the peer's capsule file
  still decrypts to the same PSK under the peer's own passphrase.

Use case: a sender worries a passphrase may have been shoulder-surfed
or typed on a compromised machine, but the capsule file itself has not
left a trusted device. Rotating the wrap invalidates the old
passphrase without disturbing the pair.

**Full PSK replacement is a different operation.** It is
`deaddrop keygen` (new PSK + new capsule) followed by out-of-band
re-transfer of the new capsule to the peer. The fingerprint changes.
This is the correct response to: suspected PSK compromise, lost/stolen
device holding the capsule file, or any event where the PSK itself may
be known to an adversary.

How to apply: `SPEC.md`, `SECURITY.md` rotation runbook,
`SPEC_DRAFT_B_capsule.md` fingerprint-stability claim, and any new
docs all use this split. "Generate new capsule, retire old" wording is
deleted from `rotate-capsule` everywhere — that phrasing describes
`keygen`, not `rotate-capsule`.

---

## D-32  Do not adopt `age` as the crypto core

Decision: v1 keeps the hand-rolled construction (XChaCha20-Poly1305
with explicit AD binding of `service_id ‖ slot_id ‖ version`, Argon2id
for capsule wrap, HKDF-SHA256 for per-send key derivation). `age` is
not adopted as the v1 crypto layer.

Why: `age` is mature and would remove roughly a third of the
cryptographic spec surface. The reasons to not adopt it at v1:
1. `age` has its own framing (`age-encryption.org/v1` header) and does
   not expose per-message AD binding. deaddrop's `service_id`,
   `slot_id`, and wire-version byte are bound into AEAD AD precisely to
   defeat cross-deployment replay (D-27). Adopting `age` would require
   an age-outside-age wrapper that re-adds AD binding, which is the
   opposite of simplification.
2. `age`'s passphrase mode uses scrypt with a fixed profile. The
   deaddrop capsule uses Argon2id with a tuned profile (URTB KCAP1
   lineage). Rebinding the capsule on scrypt drops a load-bearing
   parameter set that is already shared with URTB.
3. The URL scheme (rolling `service_id`, per-minute `slot_id`) is the
   real value deaddrop adds; the payload framing is commodity.
   Replacing the commodity piece removes no friction from the part of
   the project that required design work.

Noted for the design record: if the AD binding + Argon2id profile
requirements were relaxed, `age` would be a strict simplification win.
That is the scenario under which D-32 would be revisited.

How to apply: `D-08` is now superseded on primitive selection (see
D-25: Go stdlib `crypto/` + `golang.org/x/crypto/chacha20poly1305`);
`age` stays an option for the body layer only if a future decision
explicitly supersedes D-32. `PRIOR_ART.md` already documents the
comparison with `age` at the tool level.

Rejected: Adopt `age` and drop AD binding. Reason: cross-deployment
replay is a real attack in the operator model (same capsule, multiple
relays).

Rejected: Adopt `age` and wrap it with AD binding externally. Reason:
the wrapper introduces its own spec surface (what bytes are bound,
how they're bound, how the wrapped ciphertext is framed), which is
what the hand-rolled construction already specifies.

---

## D-33  Park Cloudflare. VM/Go is the sole deployment target.

**Supersedes D-24.**

Decision: Cloudflare (`worker-kv`) is parked. The shipped deployment is
variant B on a self-hosted VM with the Go reference binary and an
in-memory transactional store (D-39 replaces the earlier bbolt choice;
the "atomic decrement-and-delete" semantics are preserved). There is
no longer a "profile" choice at the backend layer — the backend is the
project's backend. Variant F ceases to be called a "variant" and
becomes the backend reality of deaddrop.

Why:
1. Cloudflare adds a trust-path participant and operational
   dependencies that are not needed for the supported deployment:
   Cloudflare-as-adversary in the threat model, paid-tier
   lock-in for mTLS, eventually-consistent KV that forces "best-effort"
   caveats through the entire security surface.
2. Maintaining both profiles imported contradictions:
   strict-vs-best-effort one-shot, 1 MiB vs 10 MiB caps,
   mandatory-vs-optional WRITE_TOKEN. Collapsing to one backend lets
   every property be stated plainly.
3. The supported deployment is a single VM with a Go binary, caddy,
   systemd, and nftables. Standing up a second story (Worker + KV +
   wrangler + Worker Secrets + CF dashboard) for an unsupported backend
   is architectural noise.
4. Strict one-shot is the protocol guarantee, not a profile-dependent
   attribute. This simplifies security reasoning: the spec can say
   "deaddrop provides strict single-read" without qualifying which
   backend the reader has in mind.

How to apply:
- `BACKEND_CLOUDFLARE.md` is moved to `experimental/BACKEND_CLOUDFLARE_parked.md`
  as a frozen snapshot. Root docs do not reference Cloudflare except to note it is
  parked.
- `BACKEND_VM.md` stays at the root as the deployment document; the
  "profile" framing is dropped.
- `SPEC.md`, `PROTOCOL.md`, `SECURITY.md`, `README.md`, `TESTING.md`
  remove per-profile splits. Strict one-shot is the protocol
  guarantee; WRITE_TOKEN is required on internet-facing deployments;
  `--local-only` exists for LAN/Tailscale.
- `FUTURE.md` items that exist only to rescue Cloudflare (F-4 Durable
  Objects, F-7 CF Access mTLS alt, F-17 DEPLOY-WORKER, F-24 KV quota,
  F-26 DO graduation checklist) are collapsed into a single "Parked
  with Cloudflare" stub that points at `experimental/` for anyone who
  wants to reopen the question.
- `TESTING.md` removes `AC-RACE-KV`, `AC-QUOTA-KV`, `check-worker`,
  `deployed-worker-smoke`. `AC-RACE-VM` becomes the canonical one-shot
  race test, not a profile-specific variant.

Rejected: Keep both profiles with worker-kv marked "best-effort."
Reason: the noise-to-value ratio on the shipped spec is the problem
being fixed. Documenting a backend we will not use still taxes every
section with conditional language.

Rejected: Delete the Cloudflare Worker design entirely. Reason: the
design work is non-trivial. Preserve it under `experimental/` as
history, same policy as the other parked variants
(`experimental/README.md`).

Downstream: `TESTING.md` S-04's split into `AC-RACE-KV` / `AC-RACE-VM`
collapses back to `AC-RACE-VM` only. Capsule derivations are unchanged.
No wire-protocol change is required — the client already targets a
single `RELAY_BASE_URL` and is protocol-identical across backends.

---

## D-34  Caddy edge filtering via static `CADDY_PREFIX` + shape regex

Decision: The caddy reverse proxy in front of the Go relay accepts
traffic ONLY under a deployment-configured `CADDY_PREFIX` AND only if
the remaining path matches the rolling-URL shape
`^/<service_id_hex>/<slot_id_hex>$` (32 hex chars each, 16 bytes
raw). Everything else — `/`, `/admin`, `/wp-login.php`, random
scanner fuzz, wrong-prefix-but-right-shape — is terminated at caddy
with 404 and never reaches the Go binary or the unix socket.

Two independent edge secrets:

- `DEPLOY_SECRET` — protocol-layer, drives `service_id` (hour-rolling,
  HMAC-based, already specified in D-03 / D-22).
- `CADDY_PREFIX` — operator-layer, a static opaque path component
  chosen at deploy time (`/<random>`, ≥16 bytes of entropy base32url-
  encoded). Compromise of `CADDY_PREFIX` does NOT compromise
  ciphertext; compromise of `DEPLOY_SECRET` does not leak
  `CADDY_PREFIX` (or vice versa). A caller needs both to produce a
  request that the Go binary will see.

Clients are configured with
`RELAY_BASE_URL = https://host/<CADDY_PREFIX>`. The client does not
need to know the prefix is filtered at caddy — it just posts to the
URL it was given. `PROTOCOL.md` is unchanged; the prefix sits to the
left of `service_id` from the protocol's point of view.

Caddyfile sketch (Option D hybrid):

```
@api {
    path_regexp ^/<CADDY_PREFIX>/[0-9a-f]{32}/[0-9a-f]{32}$
}
handle @api {
    uri strip_prefix /<CADDY_PREFIX>
    reverse_proxy unix//run/deaddrop/app.sock
}
handle {
    respond 404
}
```

`uri strip_prefix` is load-bearing: the Go binary's router is written
against the wire-level path `/{service_id_hex}/{slot_id_hex}` only
(per `PROTOCOL.md`). Caddy rewrites the request before
`reverse_proxy`, so the Go binary never observes `CADDY_PREFIX` —
which keeps the operator-layer secret from leaking into structured
logs, stack traces, or error responses emitted by the app.

Why:
1. **DDoS / scanner absorption.** A standard VM IP attracts a
   constant background of scanner fuzz (`/wp-admin`, `/.env`,
   `/.git/config`, SSRF probes, automated exploit kits). Terminating
   this at caddy with a regex match keeps the Go binary and the unix
   socket untouched. Only requests with the right shape AND the right
   prefix AND a valid rolling `service_id` reach the relay.
2. **Two-key blast-radius reduction.** `DEPLOY_SECRET` compromise is
   already bad (attacker can produce valid rolling paths) but the
   attacker still needs `CADDY_PREFIX` to be routed past caddy. This
   is defense-in-depth, not a new primary security boundary — the
   relay's uniform 404 is still the authoritative protocol-layer
   answer.
3. **Lineage note (not inheritance).** A sibling Go service
   ships a path-whitelist + `remote_ip` allowlist at
   caddy, not the shape-match-regex + static-prefix pattern used
   here. D-34 is deaddrop-specific; the pattern was chosen
   independently because deaddrop's wire-level paths are
   high-entropy and uniformly shaped, which lets caddy regex-filter
   scanner traffic at the edge without enumerating legitimate
   endpoints. If that service later adopts a similar pattern, the
   stories converge — but the decision was not made to match an
   existing external posture.

Rejected: **Dynamic / time-rotating `CADDY_PREFIX`.** Adds a caddy
reload coupled to a timer; introduces a failure mode where a failed
reload produces a total outage even though the Go binary is healthy.
The protocol's `service_id` already rotates hourly (D-03), which is
where time-based rotation belongs. Rotating the static prefix too
would duplicate a property the protocol already provides while adding
an operational hazard. If `CADDY_PREFIX` ever leaks, rotate it
manually via the runbook — same cadence as `DEPLOY_SECRET`.

Rejected: **No caddy filter — let the Go binary see everything.**
Wastes Go-binary CPU on scanner traffic, pollutes structured logs
with unauthenticated fuzz, enlarges the auditable surface on the
critical path. A regex match in caddy is cheaper and happens before
the unix socket.

Rejected: **Shape-match only, no static prefix.** The rolling-URL
shape alone is a 32-hex/32-hex pattern; a scanner that learned the
shape from a leaked client could still hit the unix socket for every
guess. A static per-deployment prefix forces the scanner to guess a
second secret, independent of the protocol layer.

How to apply:
- `BACKEND_VM.md §5` references this pattern; the eventual
  `deploy/vm/caddy.conf` template ships with the regex preconfigured
  and `CADDY_PREFIX` read from `/etc/deaddrop/caddy_prefix`.
- `SECURITY.md` notes the caddy layer absorbs scanner/DDoS traffic
  before the Go binary; the uniform-404 relay property is unchanged.
- The rotation runbook treats `CADDY_PREFIX` as a third rotation
  knob alongside `DEPLOY_SECRET` and `WRITE_TOKEN`. Rotation
  requires a caddy reload, not a Go-binary restart, so capsule
  bootstrap is unaffected.
- Client-side: `RELAY_BASE_URL` now typically includes the prefix.
  The client treats it as opaque; no behavioral change.

Downstream: No protocol change. No wire-format change. No capsule
derivation change. Strict one-shot and uniform 404 remain at the
protocol layer; caddy filtering is a deployment defense that sits
above.

---

## D-35  `delete_token` lives in-process only, never persisted

**Supersedes D-26's sender-side lifecycle clause.** Relay-side
primitive (stores `SHA-256(delete_token)`; constant-time compare)
is unchanged.

Decision: The sender holds every `delete_token` it generates in an
mlocked, `MADV_DONTDUMP` + `MADV_WIPEONFORK` buffer — the same
playbook as the capsule PSK and URTB's OTP. `delete_token` is
NEVER persisted to disk, written to an environment variable,
emitted on stdout/stderr/logs, passed on argv, exposed over IPC,
or handed to a keyring. When the client process exits (normal,
panic, or signal), the buffer is zeroized and released. When the
process dies, the recall capability dies with it; the slot then
drains via TTL or strict one-shot.

The only use case is **in-process transactional batches** —
operations that POST N slots and, on failure of the Nth, need to
roll back the first N-1 before exiting. Example flows:
- Chunked-file send (F-1): `deaddrop send --chunked` posts N
  chunks; if chunk 3 fails, DELETEs chunks 1 and 2 before exit.
- Multi-recipient fanout (F-2): posts N per-recipient slots;
  partial failure triggers DELETE of the already-successful ones.
- Future transactional compositions that emit >1 slot per
  user-visible operation.

Non-use cases (explicitly):
- "Recall an hour later from a fresh shell" — gone. TTL or
  `rotate-capsule` only.
- Cross-device recall — gone.
- Any CLI surface that makes the token visible to the user —
  `--show-token`, `--save-recall-token`, `deaddrop recall <URL>
  --token <hex>` — not shipped. The token has no UX.

Batch rollback is **best-effort**: if the network fails between
the failing POST and the rollback DELETEs, some slots survive
until TTL. The sender logs "N of M rollback DELETEs succeeded"
and exits; partial rollback is not a correctness failure. The
receiver's strict-one-shot + TTL guarantees still bound slot
lifetime.

Escape clause (explicit): D-35 is a **tentative keep**. If the
Go implementation reveals that the mlocked-buffer bookkeeping,
the batch-rollback control flow, or any other part of the
in-process-only policy introduces complexity out of proportion
to the capability, the DELETE endpoint and the
`X-DeadDrop-Delete-Hash` / `X-DeadDrop-Delete-Token` headers are
removed entirely. TTL + strict one-shot then become the sole
expiry mechanism, and a new D-XX records the removal.

Why:
1. Persistent storage of `delete_token` (file, keyring,
   daemon) turns a per-send secret into a long-lived one.
   Sender-laptop compromise at rest then includes "attacker
   can pre-expire every in-flight slot," which is a DoS vector
   the protocol did not previously expose.
2. The legitimate use case is transactional; single-process
   memory covers it without a UX surface.
3. Single-process-only also matches D-31's prohibition on
   long-lived unlock agents — same principle (no
   out-of-process secret lifetime), same answer.

How to apply:
- Go client: `internal/secretbuf` provides the mlocked buffer
  type; `internal/client.SendSession` holds the
  `[(slot_id, delete_token)]` list during a batch and wipes on
  `Close()`.
- `PROTOCOL.md §3` DELETE endpoint and §6 header table are
  unchanged.
- `SECURITY.md §Key handling at rest` documents the
  in-process-only policy.
- `TESTING.md AC-DEL-01..03` tests in-session batch rollback;
  there is no "save token, restart process, recall" case.

Rejected: Persist `delete_token` at `~/.deaddrop/deletes/`.
Reason: adds an on-disk secret with no ergonomic rotation or
cleanup story; expands the sender-compromise blast radius.

Rejected: Print `delete_token` to stderr on POST and require
the user to save it. Reason: creates a UX surface that invites
users to paste tokens into chat logs, issue trackers,
screenshots. If the protocol has a recall primitive, it should
not leak through the CLI.

Rejected: Drop DELETE from the protocol outright now.
Reason: the batch-rollback capability is a real future need
(F-1 / F-2), and the relay-side cost (32 bytes + one compare)
is already paid in D-26. Keep the primitive; constrain the
client's handling. If implementation proves the constraint
unworkable, the escape clause above removes it.

---

## D-36  `MAX_SEND_ATTEMPTS = 1`; minute-bucket is the hold-timer

Decision: `MAX_SEND_ATTEMPTS` is pinned at 1. Sender posts once at
`attempt = 0`. 409 (slot already exists in this minute) is an
error and NOT retried. Receiver continues to probe `attempt = 0`
only. The `attempt` field stays in the `slot_id` derivation
formula as a reserved value, fixed at 0 in v1; a future wire
bump may reintroduce nonzero attempts.

Why: The minute-bucket in the `slot_id` derivation acts as a
hold-timer on the slot address — the same pattern mobility
networks use with idle timeout + IP hold-timer to prevent same-IP
reuse within a window. Within one minute, the derived `slot_id`
is an occupied address; two legitimate same-capsule same-pair
sends in the same minute collide deterministically. After the
minute rolls, `slot_id` changes and the "IP" is free again.
128-bit slot_id collision across capsules is vanishingly rare
(~2^64 same-minute sends before a birthday collision), so 409 in
practice means "same capsule posted twice in one minute."

Multi-slot operations that legitimately need to post N slots in
rapid succession do NOT use `attempt` to disambiguate — they use
**domain-separated `slot_id` derivations** layered on top of the
base formula:

- Chunked send (`FUTURE.md F-1`): `slot_id = HMAC(slot_key,
  "chunk" ‖ bucket ‖ idx)` — one per chunk index.
- Multi-recipient fanout (`FUTURE.md F-2`): per-recipient
  `slot_key` (different capsule per recipient) → different
  `slot_id` baseline.

Both sidestep `attempt` entirely. `attempt` was never the right
tool for legitimate multi-send; it existed to catch cryptographic
collisions which at 128 bits do not happen.

Previous state (now replaced): `MAX_SEND_ATTEMPTS = 8`, receiver
probes `attempt = 0` only. This combination was incoherent —
any send landing on `attempt ≥ 1` was invisible to the receiver.
This contradicted receiver behavior and is replaced here.

How to apply:
- `PROTOCOL.md §9` replaces the `MAX_SEND_ATTEMPTS = 8` text
  with `MAX_SEND_ATTEMPTS = 1`; adds the hold-timer rationale.
- `DECISIONS.md D-04` receives a supersession banner on the
  "sender tries `attempt = 0, 1, 2, ...` until 409 clears" and
  "Receiver probes all attempts within the skew window" lines.
- `TESTING.md` `AC-RT-01` covers the single-attempt 201 path;
  a new `AC-COLL-01` covers the 409 → error path (no retry).
- Go client: on 409 at `attempt = 0`, return an error with the
  stable code `EDDCollision`; user retries next minute
  manually or uses a domain-separated derivation for
  multi-slot operations.

Rejected: Restore bounded receiver probing (`attempt ∈ {0..K-1}`).
Reason: K× more GETs on every recv; ambiguity when receiver
finds valid ciphertexts at two attempts (which is "the" message);
handles a case (128-bit collision) that does not occur in
practice; the multi-send cases it was meant to help already use
domain-separated derivations, not `attempt`.

Rejected: Remove `attempt` from the `slot_id` formula entirely.
Reason: keeping the formula stable across v1 and v2 is cheap
(the field stays fixed at 0 on the wire); reintroducing it in
v2 without a formula change is then a pure receiver-side
behavior change.

Downstream: Supersedes D-04's sender/receiver attempt-handling
clauses. The core decision — "slot_id rotates every minute,
not per send" — is unchanged.

---

## D-37  Variant A rejected on threat model (not on scope)

**Supersedes the "parked for scope" framing of Variant A in
D-22.** The other parked variants (B′, C, D, E, G) remain parked
for scope; A is different.

**Narrowed on scope by D-41 (2026-04).** D-41 ships `deaddrop
bootstrap` as a **provisioning protocol** — a three-leg handshake
in which the PSK never travels under passphrase-derived keying
(legs 1–2 carry only pubkeys; leg 3 uses a two-DH body key
requiring an identity private key, not `P_A`). Bootstrap is not a
revival of general-purpose variant A as a payload mode. The
threat-model finding in this decision is unchanged for every
surface other than `deaddrop bootstrap`: `send --mode=A` remains
rejected. See D-41 for the provisioning protocol and its argument
against violating the finding below.

Decision: Variant A (passphrase-only, zero-setup: PSK derived
directly from a user-chosen passphrase via Argon2id, no capsule
file) is **rejected as a shipped primary variant** of deaddrop.
Not "parked for scope and revisitable." The `experimental/
SPEC_DRAFT_A_passphrase.md` file is preserved as design history
with a rejection banner; `FUTURE.md` and `experimental/README.md`
are updated to say "rejected (D-37)."

Why: A's ciphertext-confidentiality budget equals the user's
passphrase entropy passed through Argon2id. At the normative
m=128MiB / t=3 / p=4 profile:
- 6-word Diceware (≈77 bits): infeasible (~230M core-years).
- 4-word Diceware (≈52 bits): ~7M core-years; safe in practice
  but margin-thin.
- Typical user-chosen 8–10 character password (≈30–40 bits):
  **feasible** for a determined offline attacker who captured
  the ciphertext.

deaddrop's threat model assumes captured-ciphertext attacks
(network observer; rootkited relay that retained bytes before
delete). The offline brute of a captured body MUST be infeasible
regardless of user behavior. Variant B achieves this by using a
32-byte random PSK inside an Argon2id-wrapped capsule — even
with a weak wrap passphrase, the ciphertext itself is safe
because the PSK is 256 bits. Variant A has no such layer; it
binds ciphertext security directly to user passphrase hygiene.
That is not a floor deaddrop is willing to stand on.

"Parked for scope" (D-22 framing) invites future reopening on
scope grounds — "we have time now, let's ship A as a
zero-setup mode." D-37 closes that door: A would still be
weak under the same threat model no matter how much scope
opens up.

What remains open: a **different** zero-setup variant with a
**forced strong-passphrase floor** (e.g., require 6-word Diceware
generated by the tool, reject user-chosen passphrases below a
measured entropy threshold). That is a new variant design, not a
revival of A. It would need its own D-XX and spec.

How to apply:
- `experimental/SPEC_DRAFT_A_passphrase.md` — add a rejection
  banner at the top citing D-37.
- `experimental/README.md` — A row reads
  `rejected on threat model (D-37)`.
- `FUTURE.md` — the line "Variant A was rejected on threat
  model in D-22" is corrected to cite D-37.
- `DECISIONS.md D-22` — retains its scope framing for B′, C,
  D, E, G; D-22's "A was moved to experimental for scope
  reasons" clause receives a pointer to D-37 for A.

Rejected (in the sense: why not just leave A parked):
Consistency with other parked variants (C, E, G) superficially
argues for uniform "parked for scope." But A is categorically
different — those variants parked on implementation complexity,
not on a threat-model gap. Using identical language conflates two
different decisions.

Rejected (in the sense: why not design the strong-passphrase
variant now): It would land as a new D-XX after B is running.
Adding it to the roadmap pre-implementation risks exactly the
architecture-astronaut drift D-22 was written to prevent.

---

## D-38  Sender exit-code taxonomy + stable error names

Decision: `deaddrop send` (and `recv`, `keygen`, `rotate-capsule`,
`fingerprint`) return distinct, stable POSIX exit codes per failure
class so wrapper scripts can branch on `$?` without parsing stderr.
Every non-zero exit also emits a single-line
`ERROR: <EDDName>: <detail>` to stderr. Stdout on failure is empty
(no partial URL, no partial capsule info).

Send-side taxonomy (normative for v1):

| Exit | Error name           | Triggers                                       |
|------|----------------------|------------------------------------------------|
|   0  | —                    | success (no URL printed — blind-probe handoff, see `PROTOCOL.md §9`) |
|   2  | EDDUsage             | flag parsing, bad argv, missing file           |
|  10  | EDDCryptoLocal       | AEAD seal/open, HKDF, RNG (does NOT include Argon2id capsule unwrap — see exit 15) |
|  11  | EDDRelayUnreachable  | DNS, connect, TLS handshake, non-503 5xx, other network-layer failure |
|  12  | EDDCollision         | 409 on POST (see D-36 — no retry, one attempt) |
|  13  | EDDAuth              | 401 / 403 (WRITE_TOKEN, mTLS)                  |
|  14  | EDDSizeCap           | 413 (payload over MAX_BLOB_BYTES)              |
|  15  | EDDCapsuleUnwrap     | wrong wrap passphrase, corrupt capsule file, Argon2id unwrap failure |
|  16  | EDDRelayOverloaded   | 503 from relay back-pressure (semaphore gate full OR `MAX_STORE_BYTES` cap — see `BACKEND_VM.md §3.2` and D-39). Distinct from 11 so wrappers can treat it as transient-retry-later rather than permanent-unreachable. |
|  17  | EDDBootstrapMITM     | `deaddrop bootstrap` leg-3 AEAD open failed; invalid `eph_pk` or peer pubkey (RFC 7748 §5 low-order rejection); `dh_eph` or `dh_static` evaluated to zero; or leg-3 plaintext length ≠ 40. Indicates pubkey/DH tampering during the handshake window (D-41). No partial capsule is written; operator re-coordinates and reruns bootstrap. |
|  18  | EDDBootstrapAuthFail | `deaddrop bootstrap` leg-1 or leg-2 AEAD open failed — wrong `P_A` typed on the receiving side, or passphrase mismatch. Distinct from 17 because remediation is "retype the passphrase" rather than "investigate an active attacker." |
|  19  | EDDBootstrapTimeout  | `deaddrop bootstrap --timeout` (default 300 s) fired without completing the three-leg exchange. Leg-2 / leg-3 409 also map here. Operator re-coordinates and reruns. |
|  20  | EDDInternal          | panic-class bug, invariant violation           |

Why:
1. **Scripting.** The intended use is scripted: CI pipelines that post
   a build artifact and fail the job on non-zero, watchdogs that retry
   only transient classes (11 transient-network; 16 transient-overload,
   retry with backoff; 12 retriable-with-new-minute per D-36; 13 / 14 /
   15 NOT retriable), paired-laptop sync scripts that need to
   distinguish "relay down" from "relay overloaded" from "capsule bad"
   without parsing English.
2. **Stability.** The names (`EDDCollision`, etc.) are part of the
   conformance surface — renaming them is a wire-adjacent break and
   requires a D-XX.
3. **No ambiguity with standard shell semantics.** Codes 1, 126, 127,
   128+, 130, 137 are reserved by shell / signal convention. Codes
   ≤9 are reserved for future primary classes. The numeric gaps
   17–19 (originally reserved for intra-class expansion) were
   consumed by D-41's `EDDBootstrap*` class; next primary class
   extension should land at 21+ (leaving 20 `EDDInternal` as the
   "panic boundary" marker).

Note: `EDDCollision` (exit 12) is reused for `deaddrop bootstrap`
leg-1 409 — a slot collision at the passphrase-derived leg-1 slot
is still "409 on POST, no retry, re-coordinate" in semantic terms,
and wrapper scripts treating 12 as retriable-with-new-minute
continue to work. The bootstrap-specific codes 17 (`EDDBootstrapMITM`)
and 18 (`EDDBootstrapAuthFail`) cover failures with no plain-B
analogue. Exit 19 (`EDDBootstrapTimeout`) covers timeout AND
leg-2 / leg-3 409 (a 409 past leg 1 means the bootstrap window
couldn't complete within the minute bucket; treating it as timeout
matches operator remediation — "re-coordinate and rerun" — and
avoids proliferating a fourth bootstrap exit code for a rare edge).

Receiver side: same scheme with additional probe-exhaustion and
AEAD-open codes. Not part of this decision's v1 send-side scope;
captured as a follow-up when `recv` ergonomics land.

How to apply:
- Go client: centralize the taxonomy in `internal/cli/exit.go` so all
  command handlers funnel into a single `ExitWith(EDDName, detail)`
  helper. Never call `os.Exit` from outside that helper.
- `TESTING.md AC-EXIT-01` exercises every row by injecting the
  corresponding error path.
- `PROTOCOL.md §9` points to this table when describing the 409 /
  413 / 401 surface from the CLI's perspective.
- Release notes on any exit-code change MUST flag the break
  explicitly; downstream scripts will break silently otherwise.

Rejected: **Single non-zero (`exit 1`) for everything.** Trivial
shell-grep is not enough: a CI wrapper that retries on network errors
would retry on bad-capsule errors too, locking out the user after a
typo. Discrimination is the whole point.

Rejected: **Encode the class in stderr only.** Forces every wrapper
to parse strings; breaks on locale / translation; stderr is routinely
truncated or redirected separately. `$?` is the POSIX interface.

Rejected: **Reuse HTTP status codes (`exit 409`).** Exit codes wider
than 8 bits are not portable; most shells truncate modulo 256. And
HTTP-layer concepts ("413") leak into scripts that should not know
about HTTP.

---

## D-39  In-memory-only storage; zero persistence; no data on disk

Decision: The relay stores ciphertext **exclusively in process
memory**. There is no bbolt file, no sqlite, no tmpfs overlay, no
snapshot, no WAL, no LUKS volume, no `/var/lib/deaddrop` data
directory. Process crash or restart is total state loss — by design.

Memory hardening is mandatory, not optional:

- `mlockall(MCL_CURRENT | MCL_FUTURE)` at startup. The systemd unit
  sets `LimitMEMLOCK=infinity` so the binary can lock its entire
  address space (ciphertext, heap, stack, code). If `mlockall`
  fails at startup, the relay **refuses to accept traffic** — this
  is a hard error, not a warning.
- The VM host MUST boot with **swap disabled** (`swapoff -a` at
  install time; no swap partition in the disk layout). Without this,
  mlock's guarantee weakens and kernel pages may spill to disk.
- Core dumps disabled: `prctl(PR_SET_DUMPABLE, 0)` at startup;
  `LimitCORE=0` in the systemd unit.
- `madvise(MADV_DONTDUMP)` on any explicitly-mapped regions
  (belt-and-suspenders against residual dumps).
- Clean-shutdown signals (SIGTERM, SIGINT, SIGHUP) run a handler
  that iterates the slot map and zeroes every ciphertext byte
  before `os.Exit`. The zeroize loop holds the store-level mutex
  so no concurrent read can race it.
- Crash-class signals (SIGKILL, SIGSEGV, SIGBUS, OOM-kill) cannot
  run a handler. The defensive posture is: mlock + no-swap +
  no-core-dump means the pages exist only in volatile RAM at the
  moment of crash, and recovering them requires a physical cold-boot
  attack on running hardware. That is not in the v1 threat model.

Strict one-shot is preserved, with a simpler primitive:

```go
// storeKey binds service_id_at_post with slot_id so GET/DELETE must
// present the exact service_id the slot was stored under. Write-side
// hour tolerance (current OR previous hour — PROTOCOL.md §2) is
// handled by the POST path accepting either service_id and storing
// under whichever the client presented; read-side lookup is then
// always exact-match.
type storeKey struct {
    svc  [16]byte   // service_id_at_post
    slot [16]byte
}

type store struct {
    mu    sync.Mutex
    bytes int64            // total ciphertext bytes resident
    m     map[storeKey]*slot
}

// Take atomically reads, decrements, and deletes (if reads_left==0).
// Returns a fresh copy of the ciphertext bytes so the caller can
// stream outside the lock. Zeroes the original storage on delete.
// k carries BOTH service_id_at_post and slot_id — a request under a
// different service_id cannot resolve the slot even if slot_id matches.
func (s *store) Take(k storeKey) ([]byte, bool) {
    s.mu.Lock()
    defer s.mu.Unlock()
    sl, ok := s.m[k]
    if !ok || time.Now().After(sl.expires) { return nil, false }
    out := append([]byte(nil), sl.ct...)
    sl.readsLeft--
    if sl.readsLeft == 0 {
        for i := range sl.ct { sl.ct[i] = 0 }
        s.bytes -= int64(len(sl.ct))
        delete(s.m, k)
    }
    return out, true
}
```

A single mutex around `map[storeKey]*slot` yields the exact atomic
read-decrement-delete semantics bbolt's write transaction provided,
in fewer moving parts and without ever touching a page cache. Keying
by `(service_id_at_post, slot_id)` — not `slot_id` alone — closes a
destructive wrong-hour read: a GET under the "wrong" `service_id` at
the hour-boundary seam simply misses the map and returns uniform 404
without decrementing `reads_left` (per-bucket-hour client derivation
in `PROTOCOL.md §9` means this is a defensive bound, not a normal
path). The per-request ciphertext copy is necessary because the
store lock must be released before `io.Copy` streams the response —
identical reasoning to `BACKEND_VM.md §3.2` under the old bbolt
design.

`MAX_STORE_BYTES` is a new normative operational knob:

- POST that would push `bytes > MAX_STORE_BYTES` is rejected with
  **503** → client exit code 16 `EDDRelayOverloaded` (D-38). This
  reuses the semaphore-gate back-pressure path added for GET; the
  wrapper-script signal is the same (transient, retry later).
- Default: `MAX_STORE_BYTES = 512 * MAX_BLOB_BYTES` (≈ 5 GiB at
  defaults) — operator-tunable to the VM's `MemoryMax=` budget.

Why:

1. **Cold-storage attack surface collapses to zero.** A seized or
   powered-off VM yields no ciphertext, no slot metadata, no TTL
   hints, no traffic pattern — there is literally nothing on the
   block device. The entire "can the operator yield historic
   ciphertext to a subpoena" conversation disappears for any
   cold-state seizure. Compare against bbolt + LUKS: LUKS only
   helps if the VM is powered off AND the passphrase is not in
   RAM / TPM — which for an unattended relay means a TPM-sealed
   keyfile, which reintroduces a cold-attack path via TPM
   extraction. No-disk skips this entire class.
2. **DMZ-risk-reduction parallels F-31's logic.** The same
   argument that said "a scoped admin token is narrower blast
   radius than SSH-to-root" now says "no disk is narrower blast
   radius than encrypted disk + boot-time unlock." The best
   guarantee is the one that has no key to lose.
3. **Durability was never a protocol property.** Slots are
   ephemeral by spec: TTL ≤ 1 hour, default `reads = 1`.
   `BACKEND_VM.md §3.2` already accepts that a TLS drop during
   download loses the message. A process crash losing in-flight
   slots is the same class of event, not a new failure mode. A
   sender that needs delivery confirmation MUST obtain it
   out-of-band — the relay is not the durability layer.
4. **bbolt's value was strict one-shot; that's cheaper in Go.** A
   `sync.Mutex` around a `map[[16]byte]*slot` is fewer primitives
   than a bbolt write transaction and gives identical atomicity.
   The bbolt mmap region was also the reason §3.2 had to explain
   copy-out-of-mmap semantics; with an in-memory store the ct
   lives in Go-managed memory directly.

How to apply:

- `BACKEND_VM.md §3` replaces the bbolt/LUKS stack diagram with an
  in-memory store diagram. §3.1 replaces the bbolt schema with the
  Go struct above. §3.2 replaces "single bbolt write transaction"
  wording with the mutex critical-section wording; the copy-out
  + stream-outside-lock pattern is unchanged in intent, only the
  locking primitive changes.
- `BACKEND_VM.md §5` gets new mandatory hardening: swap off,
  `LimitMEMLOCK=infinity`, `LimitCORE=0`, `PrivateTmp` + the
  existing `ProtectSystem=strict` are sufficient FS protections
  (there is nothing sensitive on disk to protect).
- `BACKEND_VM.md §7` drops `/var/lib/deaddrop` from the install
  steps. `/run/deaddrop/app.sock` (unix socket for caddy) is the
  only runtime-state path.
- D-02 ("relay stores ciphertext only, never keys") is refined by
  D-39: the ciphertext is stored in memory only, never on disk.
- D-24 / D-25 / D-33 bbolt references get a "superseded by D-39"
  note — bbolt is no longer the reference store.
- `SECURITY.md` subpoena / compromise section splits into
  "running relay" (whatever is in mlocked RAM at seizure time,
  TTL-bounded) and "stopped relay" (nothing at all).
- `TESTING.md` adds `AC-CRASH-01`: SIGKILL the process, restart,
  confirm no slots survive. `AC-RACE-VM` semantics are unchanged
  (the atomicity primitive changes, not the expected behavior).
- `FUTURE.md F-32` captures hot-standby replication as the right
  place for any durability-adjacent work — explicitly a live
  stream to a peer relay's mlocked memory, NOT a disk mirror.

Rejected: **bbolt + LUKS.** Previous choice. Reasons against,
revisited: (a) LUKS-at-rest only helps a powered-off seizure and
requires a boot-time key source that reopens a cold-attack path;
(b) bbolt's strict-one-shot guarantee is cheaper in Go memory;
(c) durability was never required.

Rejected: **Ephemeral tmpfs mount.** tmpfs content spills to swap
by default. Disabling swap globally to contain that is equivalent to
the mlockall posture above, but without the page-level guarantees
and without the `RLIMIT_MEMLOCK` accounting the kernel gives you
for free under `mlockall`. tmpfs rediscovers this decision with
extra steps.

Rejected: **Periodic snapshot to disk for "durability".** See
point 3 above: durability is not a protocol property, and the
moment the relay holds plaintext-adjacent state outside RAM the
entire collapse-of-cold-storage argument goes away.

Rejected: **WAL-only, no full persistence.** Same failure mode —
a WAL on disk is a disk. If a compromise requires durable state
the answer is hot-standby replication (F-32), not disk.

Non-goals:

- Replication, hot standby, failover. Deferred to F-32 and
  explicitly kept to live-memory-to-live-memory streaming; a
  future peer relay's storage is also in-memory.
- Backup / restore tooling. Not coherent with the design; any
  proposal that introduces one must first reopen D-39.

---

## D-40  Read-only filesystem; no application-level disk logging; debug is build-tagged out of release

Decision: D-39 eliminates ciphertext on disk. D-40 extends the
same posture to *everything the deaddrop Go binary writes*, and to
the filesystem sandbox the binary runs under.

Rules:

- **Filesystem sandbox.** The deaddrop systemd unit runs with
  `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
  and no `ReadWritePaths=` entries for a data directory. The only
  writable path visible to the process is `/run/deaddrop`
  (tmpfs), which holds the unix socket for caddy — no ciphertext,
  no log file, no lock file, no pid file lives there.
- **Application logs.** The binary writes to stderr only. stderr
  is captured by the systemd journal configured with
  `Storage=none` (RAM-only ring buffer) for the deaddrop unit, or
  redirected to `/dev/null` on hosts without journald. There is
  no log-file codepath in the binary. There is no logrotate
  integration. There is no `--log-file=` flag.
- **Double-step to disk (intentional double-think).** Directing
  *any* deaddrop-adjacent log stream to a file on disk MUST
  require at least two distinct operator actions — e.g., edit
  the systemd unit AND `systemctl daemon-reload + restart`;
  or edit the caddy access-log block AND `systemctl reload
  caddy`. A single environment variable, a single CLI flag, a
  single admin-endpoint call, or a single env-file edit MUST
  NOT be sufficient to turn a no-disk deployment into a disk-
  logging deployment. The purpose is defensive: "enable disk
  logging" must look like a deliberate, auditable configuration
  change — never like a one-line runtime toggle that can be
  flipped under pressure and forgotten. This is the operator-
  layer expression of the same discipline that moves debug
  output to compile-time on the binary.
- **Build matrix: testing image vs. production image.** Verbose
  / diagnostic logging lives behind a Go build tag (`-tags
  debug`).
  - **Testing image** (`-tags debug`): full verbose output,
    per-request traces, slot-lifecycle logs, all
    development-useful instrumentation. Runs ONLY on the
    disposable KVM harness (`FUTURE.md F-27`) and on local
    developer boxes. Never deployed to a VPS.
  - **Production image** (no debug tag): debug codepaths are
    absent from the compiled binary — linker strips them.
    Production retains a bounded, pre-determined debug
    surface: fatal-error reasons on stderr (why did the
    binary refuse to start, why did `mlockall` fail, why did
    the listener-bind fail), coarse aggregate counters
    (live-slot count, resident bytes, hit/miss/404
    aggregates — no per-slot, no per-IP), and the optional
    health endpoint (`FUTURE.md F-23`). This is "limited
    debug," not "zero debug": enough to diagnose why the
    process won't start or serve, nothing granular enough to
    reconstruct traffic.
  There is deliberately no runtime flag (`--debug`, `-v`,
  `LOG_LEVEL=debug`) that promotes a production binary into
  verbose mode. The only way to get verbose output on a VPS is
  to rebuild from source with `-tags debug` and redeploy —
  which by construction defeats the "release image" label and
  is an explicit operator choice, not an in-place toggle.
- **What the binary MAY still write.** Nothing persistent. The
  process may `write(2)` to the AF_UNIX socket in
  `/run/deaddrop/app.sock`, to stderr (journald), and to
  response bodies on the listening socket. It MUST NOT `open(2)`
  any path under `/var/`, `/tmp/`, `/home/`, `/root/`, or any
  writable directory for `O_CREAT`, `O_WRONLY`, or `O_RDWR`.
  CI checks this under strace against a production build.
- **Operator-layer observability is out-of-scope and marked as
  a local downgrade.** Caddy access logs, `tcpdump`,
  `nftables log`, and host-side `strace` / `gdb` all ride on
  capabilities outside the deaddrop binary. If the operator
  enables any of them — especially caddy's file-based access
  log or a persistent pcap — they are explicitly downgrading the
  D-39 / D-40 posture on that deployment. D-40 does NOT forbid
  this: operators may decide the debug value outweighs the
  snapshot-exfil cost for a specific engagement. But the binary's
  no-disk guarantee ends at the binary's boundary; anything the
  operator wires up around it is their own risk.

Why:

1. **Cloud-VPS snapshot threat.** The deployment target is a
   cloud VPS. Cloud-provider disk snapshots are a routine
   administrative primitive: they may be taken by the
   hypervisor for backup, by a support engineer for diagnosis,
   or compelled via legal process. A disk snapshot captures
   everything on the block device and is trivially forensic-
   indexable offline. A memory snapshot is also possible on most
   cloud providers, but is materially harder to extract and
   analyze: snapshot tooling is less standardized, Go-managed
   heap layout is harder to parse than a bbolt file, and the
   snapshot window is narrow. Reducing the *disk*-write surface
   to zero makes the disk snapshot useless against deaddrop;
   the memory snapshot remains a residual risk bounded by the
   TTL of whatever slots are live at that instant.
2. **Reload = compromise.** A VPS that reboots on an unattended
   schedule may have been mutated — new binary, new config,
   tampered journal. D-39 removes the "was my data tampered on
   disk" question by having no disk data. D-40 extends that:
   there is no log file for an attacker to have rewritten, no
   audit trail to have falsified, no persistent state that
   survives the compromised reboot other than the binary and
   `/etc/deaddrop/*` which are operator-managed and signed.
3. **Privacy and security align inside deaddrop's scope.** This
   alignment is not universal — in systems with authenticated
   users or admin actions, security often wants *more* audit
   logging than privacy wants. For deaddrop the story is
   narrower: the binary never sees plaintext, never holds keys,
   never handles user identity, and the only legitimate log
   content would be coarse traffic counters (which journald-in-
   RAM handles). Under that scope, "log nothing to disk" is
   simultaneously the pro-privacy and pro-security choice. When
   F-31 (admin control-plane) eventually promotes, the
   authenticated-admin-action branch will reopen this tension;
   that D-XX will have to resolve it explicitly rather than
   inheriting D-40 by default.
4. **Runtime debug flags are the leak mechanism.** The usual
   failure mode for a "log nothing" discipline is an operator
   flipping `--debug` for "just one hour" during an incident
   and forgetting to turn it off, or the flag being quietly
   left on in a config-management template. Making verbose
   output a build-time property removes that failure mode
   structurally: there is no knob to leave on.

How to apply:

- `BACKEND_VM.md §5` systemd unit: add `ProtectHome=true`,
  `PrivateTmp=true`, empty `ReadWritePaths=`, and explicitly no
  `StateDirectory=` / `LogsDirectory=` directives. Add a comment
  pointing at D-40.
- `BACKEND_VM.md §5` journald guidance: document the
  `Storage=none` override for the deaddrop unit so its stderr
  ring-buffers in RAM and never touches `/var/log/journal`.
- `BACKEND_VM.md §7` install script: MUST NOT create
  `/var/log/deaddrop` or any log file path. Verify that the
  rendered unit has no `ReadWritePaths=` pointing outside
  `/run/deaddrop`.
- `TESTING.md` adds `AC-NODISK-01` (new row): run the release
  binary under `strace -e trace=openat,open` while exercising
  AC-RACE-VM. Assert zero successful `open*()` calls with
  `O_CREAT | O_WRONLY | O_RDWR` against any path other than
  `/run/deaddrop/app.sock`. Assert no files exist under `/var/`,
  `/tmp/`, `/home/` that were created by the deaddrop UID.
- `TESTING.md` adds a CI guard in `go-build`: release build
  must be `go build -trimpath -ldflags='-s -w'` with no
  `-tags debug`. A nm / `go tool objdump` check asserts that
  no symbol named `debugPrint*` / `traceLog*` (reserved
  prefixes) is present.
- `SECURITY.md §Operational hardening`: add a bullet noting
  that enabling caddy file-based access logs, persistent
  tcpdump, or host-side journald disk storage is a **local
  posture downgrade** from D-39 / D-40. Operator's call;
  binary's guarantee ends at the binary.
- `FUTURE.md F-32` (hot-standby replication): replication
  channel MUST be end-to-end encrypted AND MUST NOT spill to
  disk on either endpoint. Both endpoints inherit D-39 + D-40.
  (Strengthens the existing F-32 wording.)

Rejected alternatives:

- **Runtime `--debug` / `LOG_LEVEL=debug` flag.** The flag is
  the leak mechanism — see Why #4. Rejected structurally.
- **Log to `/var/log/deaddrop.log` with logrotate.** Even with
  size-capped rotation, this is the exact snapshot-exfil
  surface D-39 was written to eliminate. A log entry that says
  "POST bucket=X resp=201" leaks traffic-pattern metadata that
  the wire protocol already works hard to avoid exposing.
- **Persistent audit log of authenticated admin actions.** Not
  decided here. When F-31 promotes, its D-XX has to choose
  explicitly: stay on journald-RAM (accept audit-loss on
  reboot) or write a dedicated audit log (accept posture
  downgrade). D-40 does not prejudge that choice; it only
  asserts the default.

Non-goals:

- Operator's caddy configuration and host-side observability
  tooling are out of scope. D-40 constrains the deaddrop Go
  binary, not the operator's broader ops environment.
- Preventing operator with root on the host from running
  `strace`, `gdb`, or `cat /proc/<pid>/mem` on the running
  relay. On-host root is outside the threat model (see
  `SECURITY.md §Worked example — rootkited relay`).

---

## D-41  Ship `deaddrop bootstrap` as a provisioning protocol

**Narrows D-37 on scope; does not reverse its threat-model
finding.** D-37's rejection of generic variant A as a send/recv
mode stands — A's passphrase-only ciphertext-confidentiality budget
is still unacceptable for bulk traffic. D-41 does not revive A as
a payload variant; it ships a **separate provisioning protocol**
whose sole output is a plain-B capsule materialized on both peers
after an interactive three-leg handshake. Once bootstrap exits 0,
the system is indistinguishable from `keygen` + offline capsule
transfer. Bootstrap is the **primary pairing path**; offline
capsule-file transfer remains as a **backup** for paranoid-mode
operators or when a pre-existing side channel is already present.

Decision: introduce `deaddrop bootstrap` as a dedicated client
subcommand. `deaddrop send --mode=A` remains rejected per D-37;
general-purpose variant A is not reachable as a send primitive.
The bootstrap protocol reuses A-style Argon2id-keyed AEAD for legs
1–2 (pubkey exchange only) and a two-DH construction for leg 3
(PSK delivery); these are implementation building blocks, not a
payload-variant revival.

The flow (normative at the architectural level; full KDF /
wire detail lives in `SPEC_BOOTSTRAP.md`):

1. Both laptops run `deaddrop bootstrap --role={initiator|responder}`.
   Both processes stay alive until the round-trip pubkey exchange
   completes or the timeout (`--timeout`, default 300s) fires.
2. Bootstrap passphrase `P_A`: by default the initiator generates a
   6-word Diceware string (≈77 bits entropy — D-37's documented
   infeasible-brute floor) and prints it. Operator reads it OOB
   (voice / Signal) to the responder, who types it. Scripted entry
   uses `--passphrase-fd <n>` or `--passphrase-env VAR` per D-31's
   universal rule — **argv passphrase is forbidden**; the tool
   rejects `--passphrase "$P"` with `EDDUsage` (exit 2).
   Each side holds the Argon2id-derived `passphrase_key` in mlocked
   RAM for the lifetime of the bootstrap process (used in step 8 to
   enforce P_B ≠ P_A via a constant-time Argon2id-result compare).
   Zeroized at process exit; never written to disk.
3. **Leg 1 (pubkey exchange init→resp, wire version `0x02`).**
   Initiator POSTs a bootstrap-leg-1/2 envelope carrying
   `{ initiator_pubkey(32) }` encrypted under a key derived from
   `Argon2id(P_A, fixed_bootstrap_salt)`.
   **Nothing else travels in the envelope — no PSK, no pair_id.**
4. **Leg 2 (pubkey exchange resp→init, wire version `0x02`).**
   Responder polls, decrypts, validates `initiator_pubkey` per
   RFC 7748 §5 (rejects all-zero and low-order points), pins it,
   generates its own keypair, and POSTs a reply envelope carrying
   `{ responder_pubkey(32) }` under the same passphrase but a
   different **direction bit** folded into the slot derivation
   (`direction = 0x00` for init→resp, `0x01` for resp→init) so the
   two legs land at distinct addresses from one passphrase.
5. Initiator polls, decrypts, validates and pins `responder_pubkey`.
   Both sides now hold each other's pubkey pins.
6. **Leg 3 (PSK delivery, wire version `0x03`).** Responder —
   having just decrypted leg 1 and now holding `initiator_pubkey`
   — generates `{ pair_id(8), PSK(32) }` and a one-shot ephemeral
   X25519 sender key. The leg-3 body key is derived from **two
   Diffie-Hellman shared secrets**:
   ```
   dh_eph    = X25519(eph_sk,       initiator_pk)
   dh_static = X25519(responder_sk, initiator_pk)
   body_key  = HKDF(dh_eph ‖ dh_static,
                    info = "deaddrop-bootstrap-leg3-body"
                          ‖ initiator_pk ‖ responder_pk)
   ```
   Both sides reject the result if either DH evaluates to the
   all-zero string. The static component is what prevents an
   attacker who learns `P_A` from forging leg 3 — forgery now
   requires either `initiator_sk` or `responder_sk`, not just the
   passphrase. XChaCha20-Poly1305 AEAD with `version(0x03)`,
   `service_id`, `leg3_slot_id`, and `eph_pk` bound in AD.
   **Responder POSTs legs 2 and 3 back-to-back** without waiting
   for a confirmation between them — responder already has
   everything it needs after leg 1, so there is no idle gap. This
   pipelines the responder's two replies and shaves one polling
   cycle off the initiator's side.
   Leg-3 slot address is derived from the exchanged pubkeys (not
   from `P_A`): `leg3_slot_id = HMAC(HKDF(init_pk ‖ resp_pk,
   "bootstrap-leg3"), "slot" ‖ enc_u64_be(bucket)
   ‖ enc_u32_be(0))[:16]`. Both sides can compute this
   deterministically after legs 1–2 complete (full KDF in
   `SPEC_BOOTSTRAP.md §4`). Initiator polls for leg 2 first, pins
   `responder_pubkey`, then polls for leg 3 and decrypts via the
   two-DH body key, obtaining `pair_id` and `PSK`. If leg 3 fails
   AEAD open (e.g. pubkey swap by an MITM in legs 1/2), both sides
   abort with `EDDBootstrapMITM`; no partial capsule is written.
7. **Print the unified pairing fingerprint and wait for OOB voice
   compare.** Both sides compute and print:
   ```
   FPR = HKDF(PSK ‖ pair_id ‖ init_pk ‖ resp_pk,
              salt = "deaddrop-bootstrap-fpr-v1",
              info = "fpr", length = 16)
   ```
   rendered as 32 hex in 6-6-6-6-8 groups. Operators read it OOB
   (voice). **Binding `PSK ‖ pair_id` into the fingerprint (not
   just pubkeys) is defense-in-depth against the "substituted PSK
   in leg 3" class of attacks** — a substituted PSK flips the
   fingerprint structurally. The OOB voice compare is the real
   MITM defense for bootstrap; leg-3 AEAD failure is a
   complementary tamper signal, not the whole story (see
   `SECURITY.md` bootstrap subsection).
8. **Only after the operator confirms fingerprint match (ENTER)**
   does each side prompt for its **local** at-rest passphrase
   `P_B`. The prompt REJECTS (re-prompts) if `Argon2id(P_B,
   bootstrap_salt)` constant-time-equals the retained
   `passphrase_key` from step 2 — the tool enforces P_B ≠ P_A
   locally during bootstrap. `P_B` does NOT need to match between
   laptops; it is the per-laptop disk-unlock floor for the capsule
   file, like a per-laptop LUKS passphrase.
9. Both sides persist `~/.deaddrop/capsule` (PSK + pair_id wrapped
   under `P_B` per `SPEC_DRAFT_B_capsule.md §1`). **Under the default
   `--burn` mode no pubkey pin is written** — the identity X25519
   keypairs generated in steps 3–4 are ephemeral to the bootstrap
   process only. The capsule file is the sole on-disk artifact.
   **Trust-boundary ordering: fingerprint-before-persist** — no
   capsule is written to disk before step 7's OOB compare
   completes. The steady-state deployment is plain B (identical to
   the current `SPEC_DRAFT_B_capsule.md`).
10. Both exit 0. `P_A`, `passphrase_key`, `probe_key`, identity
    X25519 private keys (both sides), `dh_eph`, `dh_static`, and
    ephemeral DH scalars are all zeroized before exit. Reuse of
    `P_A` across bootstraps is operator discipline; the tool does
    not enforce it (see Rejected).

Why this carve-out does not violate D-37:

1. **The PSK never travels in an A envelope.** Offline brute of
   the A envelope recovers pubkeys only, which are non-secret by
   construction. A-brute therefore yields **zero payload
   information** about the capsule or any subsequent traffic. This
   is a stronger floor than the earlier (two-leg) draft of this
   decision, which carried `{pair_id, PSK, init_pk}` inside the
   first A envelope and would have been broken by passphrase
   compromise. The three-leg split is load-bearing.
2. Leg 3 inherits B′'s forward-secrecy properties, and `--burn`
   default strengthens them. Under `--burn`, **both** sides' identity
   X25519 keypairs are ephemeral to the bootstrap process — not just
   the leg-3 ephemeral sender scalar. All four scalars (initiator
   identity sk, responder identity sk, leg-3 ephemeral sender sk, and
   the implicit DH shared secret) are zeroized at process exit. There
   is no long-term identity-key artifact to compromise later; captured
   leg-3 ciphertext cannot be decrypted by any future disclosure
   because no decryption-capable material survives bootstrap.
3. Strong-passphrase floor is still honored by default (Diceware
   on `P_A`). D-37's own escape clause ("a different zero-setup
   variant with a forced strong-passphrase floor ... would need
   its own D-XX") is what D-41 is — and the three-leg split makes
   the floor even less load-bearing (passphrase entropy now only
   protects integrity of the pubkey handshake, not payload
   secrecy).
4. Burn-after-use. `P_A` is single-use by construction: the
   bootstrap only runs once per pair, the passphrase is not stored
   beyond the Argon2id-derived `passphrase_key` held in mlocked
   RAM for the P_B ≠ P_A check (zeroized at process exit), and
   all subsequent traffic is keyed from the exchanged pubkeys
   (B′) or the delivered PSK (B) — not from `P_A`.
5. **P_B ≠ P_A enforcement.** Even if a user reflexively types
   the same passphrase at both the `P_A` prompt (shared OOB) and
   the `P_B` prompt (local at-rest), the tool detects the equality
   by running Argon2id on the entered `P_B` with the same
   `bootstrap_salt` and constant-time comparing to the retained
   `passphrase_key`; on match it re-prompts. Prevents the
   accidental degenerate case where a single leaked passphrase
   unlocks both the bootstrap envelopes AND the on-disk capsule.
   (A plain `sha256(P_A)` check was considered and rejected: holding
   a cheap hash of a low-entropy secret in memory alongside a
   brute-forceable disk capsule is a harvest-now amplifier — see
   `SPEC_BOOTSTRAP.md §7`.)

Why un-park A for this surface now:

- The v1 README's "Quickstart" requires USB / Signal / existing-SSH
  to ferry the capsule file to the peer. For a freshly provisioned
  VM, that forces cloud-init-level pre-seeding — defeats the
  "self-hosted, just run it" UX. Bootstrap replaces OOB file
  transfer with OOB passphrase transfer (a few seconds of voice
  that auditably happens in the moment and leaves no artifact).
- Scripted absorber: `deaddrop bootstrap --role=responder
  --passphrase-fd 3 3<<<"$P"` is headless. Cloud-init, CI
  provisioning, and paired sysadmin scripts can do unattended
  bootstrap without breaking the interactive UX for humans.
  (Argv passphrase is forbidden per D-31; `--passphrase-fd` /
  `--passphrase-env` are the only scripted surfaces.)
- Under `--burn` default, capsule rotation ("rekey") = another
  `deaddrop bootstrap` run. That is still a net win over v1's USB /
  Signal / SCP file transfer: a ~15-second voice call + `bootstrap
  --role=…` on each side, rather than producing and moving a binary
  file. In-band rekey over a persistent forward-secret channel is
  the future direction (F-10, gated on F-34) but is **not** what v1
  ships — under `--burn` no such channel exists post-bootstrap.

Interaction with existing decisions:

- **D-37** is not reversed. A-as-general-purpose remains rejected.
  D-37 receives a pointer: "see D-41 for the bootstrap-only
  carve-out; the threat-model finding is unchanged for any surface
  other than `deaddrop bootstrap`."
- **D-31** (single-process `send` / `recv` CLI contract) extends:
  `bootstrap` joins `send`, `recv`, `keygen`, `fingerprint`,
  `rotate-capsule` as a top-level subcommand. Same exit-code
  discipline (D-38) — a new `EDDBootstrap*` class is added.
- **D-22** (build cycle scope) is updated: was "B only" → now
  "B + bootstrap". C, D, E, G remain parked. B′ stays future (F-10) with
  a new gate (F-34, agent-style identity-key protection); D-42 was
  drafted to promote B′ to normative end-state but was **withdrawn
  before commit** — see D-42's withdrawal banner.
- **Relay is untouched.** All three bootstrap legs ride the same
  `POST /{service_id}/{slot_id}` wire as B; the server remains
  variant-agnostic (D-02, D-20, D-34). The client-side framing
  uses three distinct wire-body versions (per-parser dispatch is by
  version byte, preserving D-23 — there is no "dispatch by slot-
  derivation domain" special rule):
    - `0x01` — plain B steady-state body
    - `0x02` — bootstrap leg 1 / leg 2 body (same shape as B body:
      `version ‖ nonce ‖ aead_ct ‖ tag`, but KDF-keyed from
      `Argon2id(P_A)` with direction-bit separation)
    - `0x03` — bootstrap leg 3 body (`version ‖ eph_pk ‖ nonce ‖
      aead_ct ‖ tag`; the eph_pk cleartext prefix is required
      because the receiver needs it before it can derive the 2DH
      `body_key`; leg 3's body shape is genuinely different from
      plain B, so it gets its own version)
    - `0x04…` — reserved for future suite changes (F-6 PQC hybrid)
  Shipped-wire-body table is mirrored in `PROTOCOL.md §12` and
  `SPEC_BOOTSTRAP.md §5.1`. This is a client-only D-XX in the D-20
  sense; the relay still sees opaque bodies and does not parse any
  internal structure.
- **Three legs, not two.** Earlier draft of this decision used two
  legs (PSK carried in leg 1 under `Argon2id(P_A)`). Revised to
  three legs to keep the PSK out of any passphrase-derived
  envelope. Net timing cost vs the two-leg draft is ~1s of
  polling because the responder pipelines legs 2 and 3 back-to-
  back (see flow step 6). Bootstrap still completes in single-
  digit seconds end-to-end.
- **Responder generates the PSK by default.** Saves one polling
  cycle (the responder POSTs legs 2 and 3 back-to-back; the
  initiator can fetch both with consecutive polls rather than
  waiting for a leg-3 round-trip). An operator-selectable "who
  generates" flag is parked in `FUTURE.md` F-33 for cases where
  the operator wants the more-trusted side (console access,
  better entropy source) to be the generator regardless of who
  is initiator vs responder. v1 ships with responder-generates
  fixed.

Key lifetime (`--burn` default):

- `deaddrop bootstrap` runs with `--burn` by default. Identity
  X25519 keypairs generated for legs 1–3 live only in RAM for the
  duration of the bootstrap process; they are zeroized on exit. The
  **only** on-disk artifact is `~/.deaddrop/capsule` — which is the
  same file `deaddrop keygen` produces today. Steady-state deployment
  after bootstrap is therefore indistinguishable from plain B per
  the current `SPEC_DRAFT_B_capsule.md`: identical send/recv
  semantics, identical symmetric-PQC-safe property, identical
  capsule-rotation flow. Bootstrap replaces the OOB capsule-file
  transfer — it does not change the steady state.
- `--keep-keys` is an opt-in flag parked for future B′ steady-state
  graduation. When enabled, identity keypairs persist to
  `~/.deaddrop/id_{ed25519,x25519}` (wrapped under `P_B`) and the
  peer's pubkey pin lands in `~/.deaddrop/peers.d/<fingerprint>.pub`.
  v1 does **not** expose this flag: persisting long-term X25519
  private keys as plaintext-readable files on each laptop is a
  regression against plain B's "one file, passphrase-wrapped, no
  agent needed" posture. Gated on `FUTURE.md` F-34 (agent-style
  identity-key protection, ssh-agent analogue) landing before
  `--keep-keys` ships. Until then, the only supported mode is
  `--burn`.

How to apply:

- `experimental/SPEC_DRAFT_A_passphrase.md` — retain the D-37
  rejection banner for the original A (general-purpose); add a
  second banner making clear that `deaddrop bootstrap` is a
  **provisioning protocol**, not a revival of this payload
  variant. See `SPEC_BOOTSTRAP.md`.
- `SPEC_BOOTSTRAP.md` (renamed from the earlier
  `SPEC_DRAFT_A_bootstrap.md` working-tree file — "DRAFT A"
  framing is dead) is the normative peer to
  `SPEC_DRAFT_B_capsule.md`.
- `D-37` banner: append "Narrowed on scope by D-41."
- `D-31`, `D-38` tables: add `bootstrap` subcommand and its exit
  codes.
- `README.md` Quickstart rewrite: lead with `deaddrop bootstrap`;
  demote USB / Signal file transfer to "alternate offline bootstrap."
  Keep the post-bootstrap steady-state sections unchanged (plain B).
- `FUTURE.md` — add F-33 (operator-selectable `--generator` flag)
  and F-34 (agent-style identity-key protection, graduation gate
  for `--keep-keys` / B′ steady-state). F-10 remains future, with
  a new cross-reference to F-34 as its implementation dependency.

Rejected: auto-generating a strong `P_A` and displaying as QR.
Adds camera / image-render dependency and UX for a ~3-min
artifact. Voice-reading 6 Diceware words is faster and needs no
extra hardware. (QR could be added later for users with reliable
cameras on both sides; not a v1 concern.)

Rejected: re-allowing argv `--passphrase "$P"` for scripted entry.
Would violate D-31's universal no-argv-passphrase rule (argv is
visible in `ps` and shell history). Scripted callers use
`--passphrase-fd <n>` or `--passphrase-env VAR` (with warning);
tool-side entropy estimators are not imposed — Diceware-by-default
already satisfies D-37's "forced strong-passphrase floor" for
interactive use, and the operator owns the floor for scripted use.

Rejected: persisting a used-passphrase blacklist on each laptop to
prevent `P_A` reuse. Feature creep; reuse is an operator concern,
and the blacklist itself is a new artifact on an otherwise
stateless machine (counter to D-40's read-only filesystem posture).

Rejected: collapsing legs 1–3 into a single envelope (the earlier
two-leg draft). Would shave one polling cycle (~1–2s) at the cost
of putting the PSK under `Argon2id(P_A)` — an offline brute of the
passphrase then recovers the capsule outright. The three-leg split
makes A-brute yield only pubkeys (non-secret). The timing cost is
invisible against the bootstrap window's human-scale UX.

Rejected: deriving the PSK from the exchanged pubkeys instead of
generating it fresh (`PSK = HKDF(DH(init_sk, resp_pk), "psk")`).
Tempting — no leg 3 needed — but then the PSK is a deterministic
function of the long-term identity keys. Loses the ability to
`rotate-capsule` (fresh PSK) without a new bootstrap, and any
later compromise of either identity key recovers the PSK
retroactively. Keeping PSK as fresh random delivered over leg 3
preserves B's "long-term PSK, rotatable independent of identities"
property.

Rejected: persisting identity X25519 keys by default in v1 (i.e.
shipping with `--keep-keys` on). The appeal is real — persisted
pubkey pins enable B′ steady-state (per-send forward secrecy) and
in-band rekey without a second voice call. But without ssh-agent-
style identity-key protection (F-34), the persisted private key
would sit on disk as a file whose only protection is filesystem
permissions plus `P_B` (when wrapped) or nothing (when not). That
is a **regression** against plain B's posture:
- Plain B's capsule file is symmetric-PQC-safe: an attacker with
  the wrapped capsule recovers nothing unless they also break
  `P_B`, and even a future quantum adversary cannot shortcut
  XChaCha20-Poly1305 / Argon2id.
- A persisted X25519 private key is classic-crypto-only: a future
  quantum adversary who has captured both the key file and any
  B′-era ciphertext recovers all plaintext. Plain B does not have
  this exposure.
Also: the on-disk key file is new attack surface (theft, backup
leak, accidental sync) that plain B avoids entirely. `--burn`
default keeps v1's steady state strictly ≥ plain B on every axis.
B′ graduation is parked in F-10 with F-34 as its gate.

Rejected: exposing a `--generator={initiator|responder}` flag in
v1. The trust-surface rationale is real (see `FUTURE.md` F-33) —
if the current machine was reached via a jump host, the operator
may rationally prefer the peer machine to generate the PSK so the
fresh-random moment happens on the more-trusted side. But the flag
adds a CLI surface and a spec surface (asymmetric flow diagrams)
to a v1 that already carries a lot. Ship with responder-generates
fixed; revisit via F-33 once the rest of the stack is stable.

---

## D-42  (WITHDRAWN before commit) Promote B′ to normative end-state

**WITHDRAWN 2026-04-21, never committed.** This slot is retained
as a stub so the D-XX numbering stays monotonic and so future
readers can trace the reasoning path that led to D-41's `--burn`
default. Do **not** reuse D-42 for a new decision; allocate D-43
instead.

Originally drafted to promote `experimental/SPEC_DRAFT_Bprime_bootstrap.md`
to a normative `SPEC_DRAFT_Bprime.md` and make B′ (per-send
ephemeral DH over pinned pubkeys) the default post-bootstrap mode.
Withdrawn because D-41 evolved to `--burn` default:

- Under D-41 `--burn`, identity X25519 keypairs are ephemeral to
  the bootstrap process — nothing on disk to enable B′ steady-state.
  Post-bootstrap = plain B, unchanged from current
  `SPEC_DRAFT_B_capsule.md`.
- Shipping B′ steady-state *without* `--burn` would require
  persisting long-term X25519 private keys on each laptop. Without
  ssh-agent-style identity-key protection, those keys would sit as
  files whose only guard is filesystem permissions plus (optionally)
  a wrap under `P_B`. That is a **regression** against plain B's
  symmetric-PQC-safe posture: a persisted X25519 private key is
  classic-crypto-only, so a future quantum adversary who captured
  key file + any B′-era ciphertext recovers plaintext — an exposure
  plain B does not have. Plus the persisted key file is new attack
  surface (theft, backup leak, accidental sync) that plain B avoids
  entirely.
- The A-brute-exposure argument that motivated promoting B′ ("A-brute
  recovers the PSK from a captured bootstrap envelope") was itself
  obsolete by the time D-42 was drafted: D-41's three-leg split
  keeps the PSK out of any passphrase-derived envelope, so A-brute
  yields pubkeys only (non-secret). Leg 3's ephemeral-DH FS is
  sufficient for the bootstrap-transit window; no steady-state B′
  is required to repair A's security story.

B′ therefore remains future work under `FUTURE.md` F-10, with a new
gate added: `FUTURE.md` F-34 (agent-style identity-key protection,
ssh-agent analogue) must land before `--keep-keys` / B′ steady-state
can ship without the regression above. D-21 ("B′ supersedes C for
2-party use") still stands as the long-term direction; it is
conditional on F-34, not on D-42.

See D-41 for the v1 bootstrap design (plain-B steady state,
`--burn` default) that replaced this decision.

---

## D-43  DEPLOY_SECRET argv deprecation

Following D-31's argv-passphrase prohibition, `DEPLOY_SECRET`
follows the same rule: argv exposure leaks the value to
process list, shell history, and process snapshots. The relay
is the worst footgun because it is long-lived — the secret
sits in `ps` for the entire process lifetime, not just a
brief one-shot.

Per-binary mechanics:

- All four binaries (`deaddrop send`, `deaddrop recv`,
  `deaddrop bootstrap`, `deaddrop-relay`) accept
  `--deploy-secret-fd <n>` reading from an open file
  descriptor. The fd is read until first LF or EOF (≤1024
  bytes); one trailing LF (and one preceding CR) are stripped.
  The resulting string flows through
  `internal/secretparse.Parse` unchanged, so the `hex:`/`b64:`
  prefix discipline (PROTOCOL.md §8) applies uniformly.
- All four accept `$DEADDROP_DEPLOY_SECRET`. The relay binary
  also accepts the legacy unprefixed `$DEPLOY_SECRET` for
  backward compatibility with the existing
  `/etc/deaddrop/relay.env` shape, with a stderr deprecation
  WARN at startup. Symmetric for the relay's
  `$DEADDROP_WRITE_TOKEN` / legacy `$WRITE_TOKEN`.
- `--deploy-secret <value>` on argv emits a stderr deprecation
  WARN, detected via `flag.FlagSet.Visit` (the "argv equals
  env-default" case still triggers the warning).

Precedence (highest first):
`-fd` > `$DEADDROP_DEPLOY_SECRET` > legacy `$DEPLOY_SECRET`
(relay only) > `--deploy-secret` argv. When more than one
source is set, a stderr WARN names the precedence winner.

v0.1.x: the argv path remains functional. v0.2: the argv path
is removed; `--deploy-secret` without `-fd` becomes a usage
error.

The relay's systemd unit
(`deploy/systemd/deaddrop-relay.service`) drops the
`--deploy-secret ${DEPLOY_SECRET}` / `--write-token ${WRITE_TOKEN}`
ExecStart expansion in v0.1.1; secrets reach the daemon via
`EnvironmentFile=/etc/deaddrop/relay.env` only. Operators
upgrading from v0.1.0 must `systemctl daemon-reload &&
systemctl restart deaddrop-relay`.

Phased deprecation gives existing scripts a release cycle to
migrate while closing the security drift in the long run.
Symmetry with D-31's argv-passphrase rule is the load-bearing
motivation.

---

## D-44  Zeroization & constant-time compare — chosen approach

Compares of symmetric keys, MAC/AEAD tags, signatures,
passphrases, derived keys, fingerprints, delete-tokens (D-35),
and intermediate HMAC outputs MUST use
`crypto/subtle.ConstantTimeCompare` (or the project-internal
wrapper `internal/crypto.ConstantTimeEqual`, which calls it).
Test code may use `bytes.Equal`. Production code that compares
non-secret material (size checks, version-byte equality,
magic-byte sentinels) may also use `bytes.Equal` and the
secret-vs-non-secret call must be obvious from context — when
in doubt, use the constant-time path.

Pre-release validation found that all
remote-attacker-reachable secret / MAC / AEAD / derived-key
compares already use `subtle.ConstantTimeCompare` — the
sites are `internal/relay/handler.go` (write-token,
service_id), `internal/relay/store.go` (delete-token hash),
`internal/bootstrap/state.go` (low-order-point check), and
`internal/bootstrap/pb_check.go` (P_B ≠ P_A). The lone
production `bytes.Equal` site is `internal/capsule/wrap.go:92`,
a non-secret magic-byte check, which correctly stays. No code
change is required by D-44; the entry codifies the discipline
so future contributors do not introduce a non-constant-time
compare on secret material.

`internal/passphrase/passphrase.go` is intentionally exempt:
its `bytesEqual` (lines 146-160) is a length-first byte-by-byte
helper used to compare two passphrase reads in
`ReadPassphraseConfirm`. Both buffers are local-process state
held in memory for the duration of one interactive prompt;
neither side of the compare is reachable to a remote attacker
who could time the comparison. The function comment names this
as a UX check, not a credential check, and both buffers are
zeroized on return regardless of outcome. Future contributors
should not "fix" `bytesEqual` to constant-time on cargo-cult
grounds.

Wipe (zeroization) of secret material in memory uses a simple
zero-loop helper. Rationale: stdlib-only (C-4); the threat
model excludes memory forensics and page-swap attacks (out of
scope, see SECURITY.md §«Memory forensics / page swap»).
`crypto/subtle` exposes constant-time compare primitives but
no wipe / zeroize helper; the zero-loop is the correct
stdlib-only approach.

External libraries like `memguard` (or comparable
mlock-and-finalize helpers) are explicitly NOT adopted: they
violate stdlib-only and add an attack surface larger than the
threat they mitigate for our deployment shape.

---

## D-45  GET requests MUST NOT carry the write-token

The `X-DeadDrop-Write` header is a write-path credential. The
relay only checks it on POST (`internal/relay/handler.go`
`handlePost`). Sending it on GET leaks the credential into
relay access logs, proxy logs, and traffic-capture tooling
with zero authorization benefit.

Removed in v0.1.1 from:
- `internal/client/recv.go` GET path (and the `WriteToken`
  field on `RecvConfig` is dropped — recv is read-only).
- `cmd/deaddrop/recv.go` `--write-token` flag (full removal;
  recv had no use for it).
- `cmd/deaddrop/bootstrap.go` GET sites — `pollLeg`'s GET
  loop, plus the two inline GETs at the leg-2 / leg-3 polling
  sites in `initiatorBootstrap` / `responderBootstrap`.
- `cmd/deaddrop/main.go` `printUsageBanner` — recv line no
  longer advertises `[--write-token TOKEN]`.

The bootstrap subcommand's `--write-token` flag is **retained**
because bootstrap POST sites (leg-1 from the initiator,
leg-2 / leg-3 from the responder) still need it. Send keeps
its `--write-token` flag for the same reason.

PROTOCOL.md §«GET /{service_id}/{slot_id}» and
SPEC_BOOTSTRAP.md §6.1 carry the normative MUST NOT.
Relays MUST NOT inspect `X-DeadDrop-Write` on GET.

---

## D-46  Client-side maxBlobBytes hardcoded at 10 MiB

Set `maxBlobBytes = 10 * 1024 * 1024` (10 MiB) in
`cmd/deaddrop/send.go` as a build-time constant, not a flag.

Rationale: keeps the client-side knob count low; matches the
relay-side default of 10 MiB (D-24, D-33); prevents operator
mis-config that would let a sender exceed the relay's per-blob
limit. Operators who need a different cap recompile.

Supersedes the misattributed `(D-25 default)` comment in
`cmd/deaddrop/send.go:27`. D-25 is "Reference client
is a Go static binary, not bash" and does not cover the blob
size cap. The 10 MiB value's actual lineage is D-09 (superseded),
D-24, D-33; D-46 consolidates and pins the client-side cap.

---

## D-47  CLI flag-naming convention: kebab-case

CLI flags use kebab-case (`--deploy-secret`, `--write-token`,
`--max-concurrent-gets`, `--passphrase-fd`, etc.). This is the
Go standard-library `flag` package's idiomatic convention and
matches the rest of the Go ecosystem.

Rationale: documentation of current convention so future flags
follow the same shape; no surprise additions in `snake_case` or
`camelCase`.

---

## D-48  Env-var naming: `DEADDROP_*` SCREAMING_SNAKE_CASE

Client env-vars use the `DEADDROP_*` prefix in
SCREAMING_SNAKE_CASE: `DEADDROP_RELAY`, `DEADDROP_WRITE_TOKEN`,
`DEADDROP_DEPLOY_SECRET`, `DEADDROP_CAPSULE`,
`DEADDROP_PASSPHRASE` (D-31). The relay daemon's canonical
env-vars follow the same shape (`DEADDROP_DEPLOY_SECRET`,
`DEADDROP_WRITE_TOKEN`); the legacy unprefixed names
`DEPLOY_SECRET` and `WRITE_TOKEN` are accepted with a
deprecation WARN per D-43 for backward compatibility with
pre-v0.1.1 deployment files (`/etc/deaddrop/relay.env`).

Rationale: a single namespace prefix lets operators sweep all
deaddrop env-vars with `env | grep DEADDROP_`; SCREAMING_SNAKE
matches POSIX environment-variable convention.

---

## D-49  Client HTTP timeout: 30 seconds

Both `deaddrop send` and `deaddrop recv` set
`http.Client.Timeout = 30 * time.Second`
(`cmd/deaddrop/send.go:sendHTTPTimeout`,
`cmd/deaddrop/recv.go:recvHTTPTimeout`). Bootstrap subcommand
uses its own per-leg timeouts driven by the bootstrap state
machine.

Rationale: 30 s is generous for a 10 MiB upload over a typical
home/office link and tight enough to surface a wedged relay
quickly. Operators with degraded links recompile (no flag).

---

## D-50  Client recv body cap: 11 MiB

`internal/client/recv.go:maxRecvBody` caps a 200 GET response
body at 11 MiB — one MiB over the relay's 10 MiB
`maxBlobBytes` (D-46) cap. The slack handles the AEAD
overhead (version + 24-byte nonce + 16-byte tag = 41 bytes)
plus future small additions without immediately tripping the
client.

Rationale: a hard client-side cap prevents a malicious or
broken relay from streaming an unbounded body and exhausting
client memory. The 1 MiB slack is comfortable headroom for
the wire-overhead delta without re-tuning when the wire
format adds tens of bytes.

---

## D-51  User-Agent header: Go stdlib default (`Go-http-client/1.1`)

The reference client does not set a `User-Agent` header on
outbound HTTP requests; Go's `net/http` therefore sends its
default `Go-http-client/1.1`. Earlier wording that described the
header as intentionally omitted was imprecise.

Rationale: the relay does not depend on UA for any decision,
PROTOCOL.md §«Relay-side ignores most headers» states UA is
ignored / not logged by default, and the value adds no
operator-diagnostic signal worth a custom string. A branded
`deaddrop/<version>` UA is a FUTURE.md candidate (operator
ergonomics + version-skew diagnosis); it is not in v0.1.x
because there is no problem to solve.

---

## D-52  Relay 404 Content-Type: `text/plain; charset=utf-8`

Uniform-404 responses (`internal/relay/handler.go:uniform404`)
set `Content-Type: text/plain; charset=utf-8` and an empty
body, per D-14's uniform-404 discipline.

Rationale: text/plain is the conservative choice — JSON or
HTML would imply structured content the relay does not
provide; an absent Content-Type would surprise some HTTP
intermediaries. The 404 body itself is empty; the
Content-Type only describes a hypothetical body.

---

## D-53  Empty POST body → 413 (Payload Too Large)

A POST with an empty body (`Content-Length: 0` or no body)
is rejected with HTTP 413, the same status code used for
oversized bodies. The relay is body-opaque (PROTOCOL.md §7)
but an empty wrapped body is structurally invalid (the
minimum valid wrapped body is version(1) + nonce(24) +
tag(16) = 41 bytes per `cmd/deaddrop/send.go:25`).

Rationale: 413 unifies "size violation in either direction"
under one error class. 400 Bad Request was rejected because
the relay does not parse the body and therefore has no
structural complaint to make beyond size. The collision with
the over-size 413 is acceptable because the client-side
guarantee (`maxBlobBytes` lower-bounded by AEAD overhead)
prevents the client from ever sending an empty body in the
first place — only adversarial / malformed senders hit this
path.

---

## D-54  Relay `--max-concurrent-gets` default: 100

`cmd/deaddrop-relay/main.go:defaultMaxConcurrentGets = 100`.
Setting `0` disables the semaphore (test convenience, not
recommended for production). The semaphore enforces an upper
bound on concurrent in-flight GETs so a slow-loris client
swarm cannot pin all relay goroutines.

Rationale: 100 concurrent GETs comfortably exceeds the
expected steady-state request rate for the single-tenant
deployment shape (D-39) while keeping memory bounded. The
flag is operator-tunable for high-volume deployments.

---

## D-55  Relay `--max-store-bytes` default: 512 × `MaxBlobBytes`

`cmd/deaddrop-relay/main.go:defaultMaxStoreBytes =
int64(512) * int64(relay.DefaultMaxBlobBytes)` — at the
v0.1.x `DefaultMaxBlobBytes = 10 MiB`, this is 5120 MiB
(5 GiB) of in-memory store. New POSTs that would push the
store past the cap are rejected with 503.

Rationale: 5 GiB is comfortable headroom for the expected
single-tenant workload (a few hundred concurrent capsules at
≤10 MiB each), well within typical relay-host RAM, and far
below memory-pressure thresholds that would push the kernel
into swap (which would defeat the mlockall discipline of
D-40). Operators with constrained RAM tune downward.

---

## D-56  Relay GC sweep interval: 60 seconds

`cmd/deaddrop-relay/main.go:defaultGCInterval = 60 *
time.Second`. The GC ticker scans the store once per minute
and removes entries whose TTL has elapsed; not exposed as a
flag.

Rationale: 60 s is tight enough that an expired slot is gone
within one TTL-tick of its `expires_at`, loose enough that
the GC goroutine is not a measurable load on the relay even
at high steady-state slot counts. TTL granularity is
minutes (D-10 default 10 min, max 1 hour); a sub-second GC
period would not improve user-visible behavior.

---

## D-57  Hour-boundary `service_id` check: both compares always run

The relay's `service_id` validation runs both the current-
hour and previous-hour HMAC compares unconditionally, then
combines via bitwise OR (`internal/relay/handler.go:170`:
`if matchCur|matchPrev != 1`). It does not short-circuit on
the current-hour match.

Rationale: short-circuiting would leak a one-hmac-vs-two-hmac
timing distinction that correlates with whether the request
arrived in the leading or trailing edge of an hour boundary.
Constant-time discipline (per PROTOCOL.md §«Comparisons are
constant-time on the relay») requires both compares to run
for every request regardless of which (if any) matches.

---

## D-58  Relay default listen address: `:8080`

`cmd/deaddrop-relay/main.go:defaultListenAddr = ":8080"`.
Operators override via `--listen` (host:port, :port, or
`unix:/path/to.sock`).

Rationale: `:8080` is the conventional non-privileged HTTP
testing port; the relay sits behind Caddy on `:443` for
TLS termination (D-34) and does not need the privileged
`:80` itself. Listening on a non-privileged port also lets
the relay run as a non-root user without `CAP_NET_BIND_SERVICE`.

---

## D-59  POST `?reads=N` cap: 10

`internal/relay/store.go:DefaultMaxReads = 10` is the upper
bound on the `?reads=N` query parameter accepted by **POST**
`/{service_id}/{slot_id}`; values larger than 10 are clamped,
not rejected (`internal/relay/handler.go:parseClampedReads`,
inside `handlePost`). Default when the query parameter is
absent: 1 read. The clamp is a POST-time decision: the sender
declares the read budget at upload, and subsequent GETs
decrement it server-side until the slot is drained.

Rationale: 10 is high enough for legitimate fan-out (one
sender publishes a capsule, a small team of receivers each
GETs once); 100+ would be operationally suspicious for a
single-tenant relay and risks a sender unintentionally
publishing a long-lived capsule. Documented at PROTOCOL.md:121
under the POST endpoint's query-parameter table:
`?reads=<N> default 1, max 10 (clamped)`.

---

## D-69  Linux identity keyring: UID-scoped persistent, session fallback on ENOSYS/EPERM

`internal/identitystore/keyutils_linux.go:New()` calls
`KEYCTL_GET_PERSISTENT(uid=-1, dest=session)` to link the
calling UID's persistent keyring into the session keyring and
returns its serial. On `ENOSYS` (kernel built without
`CONFIG_PERSISTENT_KEYRINGS`) or `EPERM` (lockdown / namespace
restriction), it falls back to the session keyring with a
stderr WARN that names `KEYCTL_GET_PERSISTENT` and the errno.
Any other error is fatal: `New()` returns `ErrUnsupported`.

Rationale: the predecessor design (referenced in earlier code
comments as "D-63 keyring choice") used the session keyring
unconditionally. That made `bootstrap` write an entry that did
not survive logout, forcing operators to re-bootstrap on every
new login. Moving to the UID-scoped persistent keyring matches
operator expectations (`send` / `recv` work after relog) while
keeping the entry kernel-RAM-resident and never touching disk.

The persistent keyring is UID-scoped, kernel-RAM-resident, and
survives logout. The upstream default expiry is 3 days (read
from `/proc/sys/kernel/keys/persistent_keyring_expiry`); the
value is system-tunable, and any access via
`KEYCTL_GET_PERSISTENT` refreshes the timer. Reboot wipes the
keyring (RAM-only by design).

The fallback path keeps deaddrop usable on kernels without
`CONFIG_PERSISTENT_KEYRINGS` (e.g. minimal or namespace-restricted
configurations) at the cost of a per-session entry plus the
visible WARN. The matrix in `tests/scripts/run_kernel_matrix.sh`
declares an expected mode per kernel and fails when a kernel
configured for persistent keyrings silently drops to fallback —
preventing false-green regressions. The matrix probe at
`cmd/keyring-matrix-probe/main.go` validates cross-session
visibility by joining a fresh session keyring in the child via
`KEYCTL_JOIN_SESSION_KEYRING` before reading; this prevents an
inherited session keyring from masking a broken persistent path.

Supersedes the prior session-keyring-by-default direction (the
"D-63 keyring choice" referenced by older comments and SPEC
text). Code/spec wording that says "Linux identity persists for
this login session only" is no longer accurate and is being
swept out alongside this decision.

---

## D-70  `recv --watch` — client-side polling loop (closes O-1)

Decision: `deaddrop recv --watch` adds a client-side polling loop
that repeatedly calls `RecvCtx` until a message is found, a deadline
expires, or a signal (SIGINT/SIGTERM) is received. The loop does NOT
retry non-miss errors (429/503/auth/crypto are terminal). HTTP
requests accept `context.Context` so Ctrl-C aborts in-flight GETs
within ~1 s.

Flags:
- `--watch` (bool, default false): enables the polling loop.
- `--duration` (duration, default 1h, max 24h, 0=unbounded): wall-clock
  deadline for the polling loop.
- `--watch-interval` (duration, default 60s, min 30s): sleep between
  probes. The minimum floor prevents relay abuse and is enforced in
  both production and tests.

Exit codes:
- 0: message found and written.
- 1 (NotFound): deadline reached without finding a message.
- 130 (Interrupted): SIGINT or SIGTERM received during the loop.
- Other D-38 codes: terminal error from a probe (auth, overloaded, etc.).

Testability: `watchClock` seam struct allows tests to inject fake
time, fake sleep, and fake probe functions. The 30s interval floor
is enforced at the flag-validation layer, not bypassed in tests —
tests use the seam to make sleeps instant while keeping flag
validation strict.

Why not retry 429/503: the relay's overload signal is meaningful.
Hammering a relay that just said "back off" is antisocial, and the
operator can re-run `recv --watch` after the relay recovers. The
simple rule (only IsMiss retries) keeps the loop predictable and the
test matrix small.

Why 30s floor: at 60s default interval and 3-bucket probe, each
poll touches 3 relay endpoints. 30s minimum keeps the worst-case
probe rate at 6 GETs/minute, well within single-tenant relay
capacity. Lower values risk log noise and unnecessary relay load
for zero latency benefit (the relay's bucket window is 60s).

Closes O-1.

---

## D-71  `--require-e2e` defaults to true at v0.2.0 on `send`, `recv`, `bootstrap`; `--no-require-e2e` is the documented opt-out

Decision: `--require-e2e` defaults to `true` on `send`, `recv`, and
`bootstrap` starting at v0.2.0. A new `--no-require-e2e` flag opts
back into legacy 0x01 mode with a deprecation WARN. `fingerprint
--identity` is explicitly out of scope: it has no legacy mode to gate
and is already strict.

Flag-handling rules:
- `--require-e2e=false` is rejected at the pre-`fs.Parse` argv scan
  with a usage error pointing at `--no-require-e2e`.
- `--require-e2e` and `--no-require-e2e` together is rejected with
  `exitcode.Usage` naming both flags as conflicting.
- `--no-require-e2e` emits a deprecation WARN once per invocation to
  stderr.

Rationale:
- D-69 closed the only platform-side blocker (Linux logout-survival
  via persistent keyring).
- Identity entries are now persistent on both macOS (Keychain) and
  Linux (persistent keyring). Default-on is the correct posture for a
  tool whose threat model assumes the relay is hostile.
- The escape hatch (`--no-require-e2e`) carries a deprecation WARN so a
  future major release can remove legacy 0x01 entirely after a stated
  deprecation period.

D-71 default-on E2E makes the Linux identity-keyring path part of the
normal happy path. Future interaction work must wait until the kernel
matrix is green.

---

## D-72  `--deploy-secret` argv flag removed at v0.2.0 from every binary

Decision: The `--deploy-secret` argv flag is removed from every binary
that accepted it: `send`, `recv`, `bootstrap`, AND `deaddrop-relay`.
`--deploy-secret-fd` and `$DEADDROP_DEPLOY_SECRET` remain as the two
supported input paths.

The removal is detected before `fs.Parse` in both `cmd/deaddrop/main.go`
(client dispatcher) and `cmd/deaddrop-relay/main.go` (relay binary).
Operators passing the removed flag get exit 2 with a migration message
naming the replacement paths.

`resolveDeploySecret` precedence is now: `--deploy-secret-fd` >
`$DEADDROP_DEPLOY_SECRET`. The argv branch and the
`emitDeploySecretArgvWarning` helper are removed.

Rationale:
- The deprecation WARN has been active since v0.1.1 (D-43); v0.2.0 is
  the promised removal point.
- argv exposes the secret in `ps`, shell history, and process
  snapshots. `--deploy-secret-fd` and `$DEADDROP_DEPLOY_SECRET` cover
  every use case without that exposure.
- The relay is the longest-lived process in any deployment; excluding
  it would let the v0.2.0 claim "DEPLOY_SECRET is never on argv" be
  false in the most important place.
- Detection-then-error path keeps migration cost to a one-line edit on
  the operator's side.

---

## D-73  Relay HTTP server has explicit direct-exposure timeouts

Decision: `deaddrop-relay` sets non-zero `http.Server` timeouts:

- `ReadHeaderTimeout = 5s`
- `ReadTimeout = 30s`
- `WriteTimeout = 30s`
- `IdleTimeout = 60s`

Rationale: the recommended production path puts the relay behind Caddy,
but the binary can also listen on a TCP socket directly. The direct path
must not rely on Go's zero-value no-timeout behavior. `ReadHeaderTimeout`
closes the classic slow-header resource pin; the full read/write
timeouts align with the reference client's 30s send/recv timeout (D-49)
for the 10 MiB default file cap; `IdleTimeout` bounds keep-alive
connection retention.

No flags are added. Operators needing unusual slow-link behavior can put
Caddy or another reverse proxy in front, or rebuild with different
constants.

---

## D-74  Relay default body cap includes current max wire overhead

Decision: the user-facing client plaintext cap remains 10 MiB, but the
relay default `MaxBlobBytes` is now:

```
DefaultMaxPlaintextBytes + wire.PlainBodyE2EOverhead
= 10,485,760 + 81
= 10,485,841 bytes
```

`wire.PlainBodyE2EOverhead` is the largest currently-shipped plain-body
wire expansion:

- outer body envelope: version(1) + nonce(24) + AEAD tag(16) = 41 bytes
- optional E2E content envelope: nonce(24) + AEAD tag(16) = 40 bytes

Rationale: D-46 intended a 10 MiB file to be accepted by the default
client and the default relay. With E2E default-on (D-71), a 10 MiB
plaintext file produces a body larger than 10 MiB by up to 81 bytes.
Keeping the relay cap at exactly 10 MiB makes the client-side size check
look successful while the relay rejects the POST with 413.

This corrects D-46 / D-50 / D-55 wording where those decisions treated
"10 MiB client plaintext" and "10 MiB relay body" as interchangeable.
They are no longer interchangeable in code or docs: the public file cap
is 10 MiB plaintext; the default relay opaque-body cap includes current
wire overhead.
