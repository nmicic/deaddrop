# deaddrop — Security Specification

---

## Threat model

Assume:
- The relay is untrusted but HTTPS-authenticated. The operator owns
  the VM; treat it as compromised for design purposes anyway — a
  stolen box or a subpoena is the interesting case.
- The network path is observed (TLS hides body, not endpoints or URL
  paths — the rolling prefix is anti-enumeration, not privacy against
  wire observers; see `README.md §Deployment privacy: rolling
  service prefix` and `PROTOCOL.md §2`).
- An adversary may subpoena the relay operator. From an *honest*
  conforming relay that operator can yield only: (a) whatever
  ciphertext happens to be currently unread and unexpired (TTL-bound,
  ≤ 1 hour by default), and (b) IP/timestamp metadata from logs. A
  *hostile* or compromised relay can have already retained ciphertext
  before the transactional delete and yield that too — see §Worked
  example — rootkited relay.
- Laptops holding capsules or passphrases may be stolen or
  disk-imaged.
- An adversary may run parallel probes against guessed `slot_id`s.
- An adversary may scan known VM IPs and enumerate Certificate
  Transparency logs for the relay hostname.
- An adversary may NOT compromise the client binary itself (tampered
  binary is out of scope — distribute via signed releases).

Do NOT assume:
- The relay is honest. Treat it as a log-hungry host that reads every
  byte it touches. The design must make that safe.
- The user's passphrase is strong unless the tool generated it.
- Clocks are synchronized. Expect skew; receiver probes current and
  two prior slot buckets (skew = 3, fixed).
- **Forward secrecy exists.** It does not in variant B. A capsule
  compromise plus captured on-wire ciphertext = plaintext recovery.
  If this matters, plan capsule rotation on a cadence that matches
  your ciphertext-capture threat model, or wait for B′
  (`FUTURE.md` F-10).

---

## Security properties (variant B on VM/Go)

Properties are split three ways. A **cryptographic** property is
enforced by the wire protocol and key derivation — it holds against
any conforming relay, including a malicious one. An **implementation**
property is one the **normative Go reference relay** (D-25; not yet
implemented in this repo) is required to provide, and is only as
strong as that binary on its host once it lands. A **non-property**
is something a naïve reader might expect but the design does NOT
provide; listed so operators size their threat model correctly.

> **Repo status (2026-04):** deaddrop is spec-only in this repo. The
> Go relay and client described below are a *normative target* (D-25,
> F-3, F-9) that any conforming implementation must meet — they are
> not yet built here. Claims of the form "the Go relay enforces X"
> should be read as conformance requirements on the planned reference
> implementation, not as statements about running code.

### Cryptographic properties (hold regardless of relay behavior)

```
[X] Confidentiality            — XChaCha20-Poly1305 body AEAD under a
                                  key derived from the capsule PSK,
                                  HKDF-bound to slot_id and service_id.
[X] Integrity                  — AEAD tag; associated-data binds
                                  (service_id || slot_id || version).
                                  No cross-slot or cross-deployment
                                  ciphertext reuse (D-27).
[X] Offline-brute resistance   — 32-byte PSK derived from an
                                  Argon2id-wrapped capsule; no
                                  guessable passphrase travels
                                  in-band.
```

### Implementation properties (normative requirements on the Go reference relay — not yet built)

```
[X] Strict one-shot read       — single in-memory critical section
                                  under one mutex: decrement + delete +
                                  stage body. Concurrent GETs
                                  serialize; exactly one wins. See
                                  `BACKEND_VM.md §3.2` and D-39. This
                                  is a protocol guarantee, not a
                                  deployment-conditional property.
[X] Zero persistence           — ciphertext lives only in mlocked
                                  process memory (D-39). Process exit
                                  or crash = total data loss, by
                                  design. No bbolt / no tmpfs / no
                                  swap / no core dumps. A seized VM
                                  with the relay stopped yields no
                                  ciphertext at all.
[X] Scanner-resistance         — rolling `service_id` rejects
                                  probes from callers without
                                  `DEPLOY_SECRET`. NOT "hides the
                                  relay from the internet" (D-30);
                                  hostnames are discoverable via CT.
[X] Fit for untrusted WAN      — relay never holds plaintext or keys.
[X] Authenticated early DELETE — sender holds a `delete_token` in
                                  mlocked process memory only, never
                                  persisted (D-26 + D-35). Relay
                                  stores only `SHA-256(delete_token)`.
                                  Use case is in-process transactional
                                  batch rollback (F-1, F-2); not a
                                  cross-process recall feature.
```

### Non-properties (do NOT hold; listed to prevent mis-sizing)

```
[ ] Forward secrecy            — NOT provided. A capsule compromise
                                  plus captured on-wire ciphertext
                                  yields plaintext. Rotate capsules;
                                  see F-10 (B′ bootstrap).
[ ] Sender authenticity        — NOT provided. Anyone holding the
                                  capsule can forge a valid slot. See
                                  F-10 for B′.
[ ] Relay access control       — NOT provided by the wire protocol.
                                  Available as an optional layer:
                                  operator-provisioned mTLS
                                  (`experimental/SPEC_DRAFT_D_private_CA.md`).
[ ] Device revocation          — NOT provided. Capsule rotation only
                                  (`deaddrop rotate-capsule`).
[ ] Protection against a       — NOT provided. A compromised relay
    malicious relay holding        can retain ciphertext, delay
    ciphertext                     delete-on-read, and log every
                                   (service_id, slot_id) pair. AEAD
                                   still prevents it from reading or
                                   forging plaintext; see worked
                                   example below.
```

---

## Per-layer properties

### Relay (VM/Go, in-memory)

```
[X] Never holds plaintext, passphrase, or PSK.
[X] Never holds a decryption key.
[X] Stores ciphertext only in mlocked process memory — no disk, no
    tmpfs, no swap, no core dumps (D-39).
[X] Deletes ciphertext transactionally when reads_left reaches 0,
    zeroizing the backing slice under the store mutex.
[X] Zeroizes all live ciphertext on SIGTERM/SIGINT/SIGHUP before
    exit. SIGKILL / SIGSEGV / OOM-kill cannot zeroize; mitigation is
    mlockall + swap-disabled + no-core-dump (D-39).
[X] Enforces MAX_TTL (1 hour).
[X] Enforces MAX_BLOB_BYTES (10 MiB plaintext plus wire overhead by
    default, operator-tunable).
[X] Enforces MAX_STORE_BYTES (5 GiB default); POST exceeding the cap
    returns 503, surfaced to clients as EDDRelayOverloaded (D-38).
[X] Returns 404 with empty body for non-existent / expired /
    exhausted / wrong-service_id — no oracle.
[X] Rejects paths outside the rolling service_id window.
[X] Enforces HTTPS (caddy terminates TLS; systemd + nftables
    hardening per `BACKEND_VM.md §5`).
[X] Caddy edge filter (D-34): requests that do not match
    `/<CADDY_PREFIX>/<32hex>/<32hex>$` are 404ed at caddy and
    never reach the Go binary. `CADDY_PREFIX` is an operator-
    layer secret independent of `DEPLOY_SECRET`; compromise of
    one does not compromise the other. Absorbs scanner / DDoS
    fuzz before the unix socket.
[X] Uses constant-time comparison for WRITE_TOKEN.
[X] WRITE_TOKEN is mandatory unless operator sets `--local-only`
    (LAN / Tailscale deployments).
[X] Authenticated DELETE: accepts delete_token iff SHA-256 matches
    stored delete_hash; constant-time compare.
```

### Client — Go reference binary (D-25, normative)

```
[X] mlocks derived key material (PSK, slot_key, AEAD key).
[X] Wipes derived keys at process exit and on panic
    (runtime.SetFinalizer + explicit zeroize on defer paths).
[X] Uses crypto/subtle constant-time comparisons.
[X] Generates passphrases on user request with ≥77 bits of entropy.
[X] Refuses to upload plaintext if encryption fails for any reason.
[X] Never logs the passphrase, PSK, capsule bytes, or derived keys.
[X] AEAD associated data = service_id || slot_id || version — rules
    out cross-slot reuse AND cross-deployment replay (D-27).
[X] Prints capsule fingerprint on keygen and on every send / recv so
    the pair can verify out-of-band they share the same capsule.
[X] Generates delete_token fresh per send and mlocks it in memory;
    never writes it to disk; never prints it; sends SHA-256(token) as
    delete_hash at POST. Used only as a sender-side, in-process
    batch-rollback primitive (D-35): if a multi-slot batch fails
    partway, the sender can DELETE the slots it already posted.
    The receive path does NOT hold or present delete_token;
    authenticated DELETE is a sender-only capability.
```

### Client — bash diagnostic (NON-normative)

```
[-] Cannot mlock; keys live in shell variables and argv fragments.
[-] Cannot run the full variant B flow: `openssl enc` on openssl 3.x
    does not expose XChaCha20-Poly1305 as an enc algorithm.
[X] Useful only for: HMAC path derivation demos, skew probes,
    testing error-code surface. Do NOT carry real secrets through it.
```

See `DECISIONS.md` D-25. Conformance is tracked against the Go binary
only; the bash script exists for interop debugging.

---

## Worked example — rootkited relay

Scenario: the VM is rootkited. The attacker owns the Go binary, the
caddy layer, and the journal, and can read the running process's
memory via `/proc/<pid>/mem` or a ptrace. There is no on-disk
ciphertext store to seize (D-39) — but a live process with live
slots is still exposed to an attacker with root on the same box.
Sender posts slot `S`; receiver retrieves it; transfer looks normal
on both ends.

What the attacker CAN do:

- Retain a copy of the ciphertext after the "transactional delete" —
  the delete is only transactional inside the honest binary. A
  modified binary can fork a write to a shadow store (disk, network,
  or another in-memory buffer) before returning, despite D-39.
- Log every `(service_id, slot_id, client_ip, timestamp)` tuple.
- Correlate POST and GET by timing and IP regardless of TTL.
- Silently drop DELETEs from senders trying to roll back (D-35).
- Delay the GET long enough for the sender to close and leave town,
  then retain the ciphertext indefinitely.
- Mount a DoS: return 404 to the real receiver, serve the ciphertext
  to an attacker-controlled GET later.

What the attacker CANNOT do without the capsule:

- Decrypt the ciphertext. The body is XChaCha20-Poly1305 under a key
  the relay never sees.
- Substitute a different plaintext for the receiver. Any re-encrypted
  body fails AEAD because AD binds
  `service_id || slot_id || version` (D-27) and the attacker does
  not hold the aead_key.
- Forge a sender. Same argument — no capsule, no valid AEAD tag.
- Learn anything about past ciphertexts they did not capture on the
  wire (the relay only ever held current-window ciphertext).

Design consequence: variant B's value against a hostile relay is
**confidentiality + integrity of the message body**, not
availability, not metadata privacy, not forward secrecy. If the
threat model includes a hostile VM host, the mitigations are:

- Rotate capsules aggressively — a retained ciphertext is only
  useful while the capsule that decrypts it still exists (D-35
  delete_token helps for in-flight rollback but NOT against a relay
  that ignores DELETE).
- Route through Tor / VPN so the attacker does not get a usable
  `(sender_ip, receiver_ip)` edge.
- Promote to B′ (`FUTURE.md` F-10) for forward secrecy so a future
  capsule seizure does not retroactively decrypt the retained
  ciphertext.
- Run the VM yourself on hardware you control. "Self-hosted" is
  load-bearing.

---

## Known non-properties

- **Forward secrecy.** Listed above, repeated here because it bites:
  capsule compromise is catastrophic against any ciphertext an
  adversary managed to capture. Rotate capsules. Budget for the fact
  that B is not a substitute for a Double-Ratchet protocol.

- **Anonymity.** The relay sees client IPs and timestamps. Use Tor or
  a shared-egress VPN if that matters. Tor / VPN usage is orthogonal
  — nothing in deaddrop assumes or prevents them.

- **Traffic analysis resistance.** Blob sizes leak the plaintext size
  class. POST → GET timing correlation can link a sender to a
  receiver if both endpoints are on observed networks. Mitigations
  (padding, delay) are out of scope for v1; tracked as `FUTURE.md`.

- **URL-path confidentiality.** `service_id` and `slot_id` are
  visible above TLS termination. caddy's access log format is under
  operator control; by default it logs the path — disable path
  logging or rotate through a salted hash if the trust boundary
  includes "the VM host itself is hostile."

- **Post-quantum.** XChaCha20 is symmetric PQC-safe; X25519 (parked
  in `experimental/` variants C / E) is not. `FUTURE.md` F-6 tracks
  the hybrid upgrade.

- **Firmware / bootloader / evil-maid threats.** Out of scope.

- **Shoulder surfing / keyloggers / screen capture.** Out of scope.

- **Memory forensics / page swap.** deaddrop's threat model does
  not defend against attackers with memory-read access on the
  endpoint (memory dumps, swap-file inspection, debugger
  attach). Secret zeroization in this codebase is best-effort:
  secrets are wiped via a simple zero loop after use, but Go's
  runtime, OS swap, and CPU caches may retain copies. Operators
  who need stronger guarantees should run sender / receiver in
  isolated VMs whose disk images are wiped after use, or use
  hardware-backed key storage (out of scope for v0.1.x).

- **Correct time on receiver.** The probe window is past-only and
  fixed at 3 minute-buckets. The hard rule: **the receiver's clock
  MUST NOT lead the sender's clock by more than ~3 minutes**. If it
  does, the sender's minute-bucket has already rolled out of the
  probe window by the time the receiver runs `recv`, and the
  response is uniform 404 with no recourse. Sender-ahead is
  absorbed by waiting (the receiver just needs to delay `recv`
  until the sender's bucket enters its probe window); receiver-ahead
  is not recoverable.

---

## Capsule fingerprint

Both laptops must be certain they hold the same capsule. The CLI prints
a short fingerprint at keygen and on every send / recv:

Fingerprint formula, length, and encoding are defined exactly once
in `SPEC_DRAFT_B_capsule.md §1.6` (normative): rendered as a
32-hex-char string (16-byte HKDF-SHA256 output), `pair_id`-bound,
named-arg HKDF. This document does not restate the formula.

Out-of-band verification: compare fingerprints over a trusted channel
(voice call, Signal) before first use. If they disagree, the capsule
transfer failed or was tampered with — regenerate, do not work around.

---

## Bootstrap (`deaddrop bootstrap`) — what it protects and what it doesn't

`deaddrop bootstrap` (D-41, `SPEC_BOOTSTRAP.md`) is the **primary**
pairing path. It replaces offline capsule-file transfer for the common
case. The offline path remains as a backup for paranoid-mode operators
or when a pre-existing side channel (e.g., URTB between two laptops)
is already present.

### What bootstrap protects

- **Confidentiality of the shipped PSK against passive observers.**
  The PSK is delivered only inside the leg-3 body, encrypted under a
  body key derived from **two DHs** — one ephemeral (X25519 with a
  fresh per-run sender scalar), one static (X25519 against the
  responder's bootstrap-session identity key). Neither DH input is
  observable on the wire; an attacker who captures the full
  three-leg exchange and later learns `P_A` still cannot compute
  either shared secret without one of the X25519 private keys.
- **Freshness of per-run key material.** The leg-3 ephemeral scalar
  is fresh per bootstrap run and zeroized immediately after leg 3 is
  sealed. Under `--burn` (v1 default and only mode), the identity
  X25519 scalars on both sides are ephemeral to the bootstrap process
  — no long-term private key lands on disk.
- **Detection of active pubkey tampering.** If an active MITM swaps
  a pubkey in legs 1 or 2, leg 3 will fail to decrypt on the
  initiator (the 2DH construction binds both pinned pubkeys into
  `body_key`), AND the printed pairing fingerprint will differ
  between the two operators.

### What bootstrap does NOT protect — the real MITM story

**The OOB fingerprint voice-compare is the real MITM defense.**
Leg-3 AEAD failure is a complementary tamper signal — not the whole
story. The unified pairing fingerprint
`FPR = HKDF(PSK ‖ pair_id ‖ init_pk ‖ resp_pk, …)` binds every piece
of state that was negotiated over the wire. If two operators read
matching fingerprints, no MITM succeeded; if they read different
fingerprints, bootstrap was tampered with and MUST be aborted
(Ctrl-C, no capsule written under the fingerprint-before-persist
trust-boundary ordering in `SPEC_BOOTSTRAP.md §8.1`).

What bootstrap cannot defend against:

- **Voice-channel impersonation.** If the OOB channel itself is
  compromised (an attacker is on both operators' voice call faking
  fingerprint digits), bootstrap fails silently. Use a voice channel
  both operators recognize the other's voice on.
- **Rubber-hose / endpoint compromise.** Bootstrap assumes both
  laptops are not already compromised before they run. A rootkit
  on either side can log `P_A`, `P_B`, and the capsule plaintext
  regardless of any protocol property.
- **Offline brute of `P_A`** — mitigated but not zero. Legs 1/2 are
  `Argon2id(P_A)`-keyed XChaCha20-Poly1305 over a 32-byte pubkey.
  A wire-capture attacker can run offline Argon2id against the
  captured envelopes. Success recovers only the pubkeys (non-secret
  by construction) — it does NOT let them decrypt leg 3, which is
  DH-keyed. The 6-word Diceware default (≈77 bits) keeps Argon2id
  cost-to-success at the D-37 "infeasible" floor; operators who
  substitute weaker passphrases lower that floor.

### Why `--burn` exists

`--burn` is the v1 default and only mode (see D-41 /
`SPEC_BOOTSTRAP.md §8`). It zeroizes all identity-key scalars at
process exit, so bootstrap produces exactly one on-disk artifact:
the plain-B capsule file, Argon2id-wrapped under `P_B`. This keeps
v1's steady-state security posture strictly ≥ plain B (no
harvestable long-term X25519 private key on disk — see D-42
WITHDRAWN for the PQC-harvest-now argument against persistent
identity keys).

`--keep-keys` is parked pending `FUTURE.md` F-34 (agent-style
identity-key protection). v1 rejects it at CLI parse.

### Passphrase-entry discipline (bootstrap)

Bootstrap inherits D-31's universal no-argv-passphrase rule. `P_A`
is entered via TTY prompt (default), `--passphrase-fd <n>`, or
`--passphrase-env VAR` (emits warning). `--passphrase "$P"` on argv
is rejected with `EDDUsage` (exit 2). `P_B` follows the same rule
(enters through the local TTY prompt at the end of bootstrap, after
fingerprint voice-compare).

---

## Key handling at rest

```
Capsule (variant B)           : Argon2id-wrapped file, mode 0600.
                                Unlocked into mlock'd memory at
                                runtime; wiped on exit. Holds PSK(32)
                                ‖ pair_id(8). Passphrase is entered
                                interactively; no env var for it
                                (removed: prior DEADDROP_PASSPHRASE
                                was footgun-shaped).
DEPLOY_SECRET, WRITE_TOKEN    : `~/.deaddrop/config`, mode 0600.
                                Set once at install; rotated on
                                suspicion. 32-byte hex, `hex:`
                                prefixed.
delete_token                  : in-memory only; mlocked; never
                                persisted by the client; never
                                printed. Generated fresh per send
                                (32 bytes from a CSPRNG; not derived
                                from the capsule). Sender-side only;
                                receiver has no delete capability.
```

Go client mlocks; bash client cannot. Use bash client only on a host
with full-disk encryption, and only for diagnostic traffic.

---

## Subpoena / compromise response

If the relay is served a subpoena or seized by an attacker:

- **Stopped relay (cold seizure):** nothing. Under D-39 the conforming
  Go binary holds ciphertext only in mlocked process memory with no
  disk backing, no tmpfs, no swap, and no core dumps. If the process
  is not running at seizure time, there is no ciphertext on the box to
  produce, regardless of subpoena scope.
- **Live relay, honest (warm seizure):** bounded — the conforming Go
  binary's in-memory map holds only posted-and-unread-and-unexpired
  slots, with TTL ≤ 1 hour by default. Worst case: a message posted
  within the last hour that was never retrieved. If the process is
  signalled cleanly (SIGTERM) before imaging, every live slot is
  zeroized under the store mutex and nothing remains.
- **Live relay, compromised (warm seizure of a rootkited host):**
  unbounded in principle. A rootkited relay may have been forking a
  copy of every POST body to a shadow store (disk, network, another
  in-memory buffer) before the transactional delete committed. D-39
  eliminates the *honest-relay* disk footprint; it does not constrain
  a modified binary. The protocol's strict-one-shot guarantee holds
  for the visible receiver (exactly one 200), but a silent duplicate
  outside the in-memory store is a host-level property, not a
  protocol property. This is the threat that forward secrecy
  (B′ bootstrap, F-10) and aggressive capsule rotation exist to
  bound. See §Worked example — rootkited relay.
- **"Who sent to whom":** the relay has client IPs and timestamps. It
  does NOT have passphrases, capsule material, or identity. Linking a
  sender's POST to a receiver's GET requires correlating timing
  across both IPs — defeated by routing either end through Tor or a
  shared egress.
- **`DEPLOY_SECRET` or `WRITE_TOKEN` disclosed:** attacker can fill
  slots to DoS the deployment; CANNOT decrypt any past or future
  ciphertext. Rotate per the runbook below; all in-flight slots
  become unreachable and clients must repost.
- **Capsule file seized:** Argon2id-encrypted. Attacker must
  brute-force the wrapping passphrase. Use a strong wrapping
  passphrase (≥77 bits, or a long human-memorable phrase). B does
  NOT provide forward secrecy: any on-wire ciphertext captured
  before the seizure is now decryptable.

---

## Rotation runbook

```
Passphrase-only rotation (wrapping passphrase exposed; PSK intact):
  On EACH host independently:
       deaddrop rotate-capsule
     Prompts for current passphrase, then a new one. Re-wraps the
     SAME PSK in place at the capsule path resolved per D-31
     (`DEADDROP_CAPSULE` env or `--capsule <path>`; default
     `~/.deaddrop/capsule`). Fingerprint is UNCHANGED — no OOB
     re-transfer; the peer does NOT need to rotate in lockstep.
     Use this if only the wrapping passphrase may be compromised.

Full PSK rotation (capsule file exposure, device loss, on-wire risk):
  1. On laptop A:
       deaddrop keygen ./capsule.new
     Prompts for a new passphrase; emits a fresh PSK. Fingerprint
     CHANGES.
  2. OOB-transfer ./capsule.new to laptop B (air-gapped / USB /
     authenticated channel — NOT over the relay).
  3. Verify by voice that `deaddrop fingerprint` prints the same
     32-hex-char value on both hosts.
  4. Atomically replace the old capsule on both hosts and wipe the
     old file (shred / secure delete).

DEPLOY_SECRET rotation:
  Write new hex to /etc/deaddrop/deploy_secret (mode 0600), then:
      systemctl reload deaddrop
  Then update both laptops' ~/.deaddrop/config with the new value.
  All in-flight slots become unreachable; clients must repost.

WRITE_TOKEN rotation:
  Same mechanics as DEPLOY_SECRET. Senders need the new token; recv
  does not require it.

CADDY_PREFIX rotation (D-34):
  Write new base32url string to /etc/deaddrop/caddy_prefix (mode 0640,
  owned by caddy), then:
      systemctl reload caddy
  Then update both laptops' RELAY_BASE_URL to include the new prefix.
  Does NOT restart the Go binary; in-flight slots are not disturbed
  at the protocol layer but existing client URLs become unroutable
  at caddy until clients reconfigure. Rotate on any suspicion that
  the prefix has leaked in logs, backups, or chat history.
```

Distribution: capsule and `DEPLOY_SECRET` must move out of band. USB,
Signal, or an existing authenticated SSH channel are all fine. Do NOT
email the capsule; do NOT commit `~/.deaddrop/config`.

---

## Operational hardening

- `WRITE_TOKEN` is mandatory on any internet-reachable deployment.
  `--local-only` is available for LAN / Tailscale.
- **DEPLOY_SECRET delivery (D-72):** the `--deploy-secret` argv flag
  is removed from both clients and relay at v0.2.0. DEPLOY_SECRET
  reaches the binary via `--deploy-secret-fd` (file descriptor) or
  `$DEADDROP_DEPLOY_SECRET` (environment variable) only — never on
  argv, where `ps` and `/proc/*/cmdline` expose it for the process
  lifetime. For systemd units, use `EnvironmentFile=`.
- Rotate `DEPLOY_SECRET` on any compromise suspicion.
- Rotate capsules when a device is retired (D-26 makes early DELETE
  authenticated, but that only closes the in-flight slot).
- Monitor relay logs for abnormal slot fill rate (abuse signal).
- Set `MAX_BLOB_BYTES` as low as use case allows.
- Enable nftables + fail2ban per `BACKEND_VM.md §5`.
- Caddy edge filter (D-34) absorbs internet scanner and
  opportunistic-fuzz traffic before the Go binary. Keep
  `CADDY_PREFIX` treated as a secret — do not post it in issue
  trackers, screenshots, or chat logs.
- Runtime-policy overlay (seccomp + AppArmor, `FUTURE.md` F-29) is
  mandatory once the deployment faces the public internet; deferred
  until after all code + e2e tests pass.
- **Linux identity entries (D-69)** are stored in the UID-scoped
  persistent keyring (kernel RAM only). Any process running as the same
  UID can read them — same threat boundary as the macOS Keychain
  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Entries survive
  logout but NOT reboot. The upstream kernel default idle expiry is
  3 days; the value is system-tunable via
  `/proc/sys/kernel/keys/persistent_keyring_expiry` and an operator may
  raise or lower it. Each `KEYCTL_GET_PERSISTENT` access refreshes the
  timer, so day-to-day `send` / `recv` activity prevents expiry. On
  kernels without `CONFIG_PERSISTENT_KEYRINGS`, entries fall back to the
  session keyring (wiped at logout) and the binary prints a WARN that
  names `KEYCTL_GET_PERSISTENT` and the errno.

---

## Security tests

See `TESTING.md §Security matrix`. Covers (naming aligned with
D-26/D-27):

- S-01 Argon2id-wrap brute-force lower bound (77-bit wrapping
  passphrase infeasible; 32-bit recoverable — sanity check on the
  parameter choice).
- S-02 slot_id un-guessability without capsule material (HMAC-SHA256
  strength; `pair_id` prevents cross-capsule collision).
- S-03 uniform 404 oracle (byte-identical responses across
  not-found, expired, exhausted, wrong-service_id).
- S-04 one-shot under concurrent GETs: `AC-RACE-VM` — exactly one
  200, all others 404.
- S-05 rolling-prefix enforcement across hour boundaries.
- S-06 WRITE_TOKEN timing-attack resistance.
- S-09 authenticated DELETE: reject wrong token with uniform 404.
- S-10 AEAD AD binding prevents cross-deployment replay (a capsule
  reused against a different `DEPLOY_SECRET` MUST fail AEAD).
- S-11 capsule fingerprint: two keygens produce distinct
  fingerprints with overwhelming probability; `rotate-capsule`
  preserves it.

---

## Reporting a vulnerability

Private disclosure: open a draft security advisory on the GitHub
repo, or email the listed maintainer. 90-day coordinated disclosure
policy.
