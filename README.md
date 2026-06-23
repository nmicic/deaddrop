<!-- Copyright (c) 2026 Nenad Mićić -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# deaddrop — one-shot encrypted file relay

Two laptops, one capsule, one ephemeral URL.
Sender posts; receiver gets once; relay forgets.
Relay is a small self-hosted HTTP server — never sees plaintext.

Development note: this project was AI-assisted — though in 2026, what
project isn't? Design, code, and release decisions remain maintainer-owned.

Shares DNA with:
- `URTB`    — capsule and PSK concepts, Argon2id passphrase-wrap
- a sibling Go service — architectural principles (generic pipeline,
              security posture), self-hosted VM deployment shape

---

## Quickstart (variant B — shared capsule)

### 1. One-time pairing (preferred: `deaddrop bootstrap`)

Run the interactive handshake on both laptops — no capsule file
transfer needed. Requires a shared `DEPLOY_SECRET` already present
on both sides (set at install time, separate from the per-pair
capsule).

```
# laptop A (generates the bootstrap passphrase and reads it OOB)
deaddrop bootstrap --role=initiator
# prints a 6-word Diceware passphrase; read it to the peer via voice

# laptop B (types the passphrase the peer just read out)
deaddrop bootstrap --role=responder
# types the 6 words; both processes stay alive until the three-leg
# exchange completes, fingerprints are printed, each side prompts
# locally for its at-rest capsule passphrase P_B, and both exit 0.
```

Under the default `--burn` mode, the only on-disk artifact either
side produces is `~/.deaddrop/capsule` — identical in format to a
capsule from `deaddrop keygen`. As of v0.1.5, the bootstrap X25519
keypair is *also* persisted, but to the OS keyring (Keychain on
macOS, keyutils session keyring on Linux) rather than to disk —
see "End-to-end identity layer" below. On platforms with no keyring
backend, the bootstrap keys remain process-ephemeral. See
`SPEC_BOOTSTRAP.md` for the full protocol (KDFs, three-leg flow,
timing, exit codes) and `DECISIONS.md` D-41 for the design rationale.

### 2. Alternate offline bootstrap (no shared relay yet, or air-gap)

```
# one-time: generate and OOB-transfer a capsule (URTB-style)
deaddrop keygen ~/.deaddrop/capsule
export DEADDROP_CAPSULE=~/.deaddrop/capsule
deaddrop fingerprint                           # compare OOB on both laptops
# copy the capsule to the other laptop via USB / Signal / existing SSH
```

Functionally equivalent to `bootstrap`; use this when the two laptops
cannot reach the relay at the same time, when one side is being
provisioned from a cold image, or when you just prefer the
file-transfer shape.

### 3. Send / receive (after either pairing method)

```
export DEADDROP_CAPSULE=~/.deaddrop/capsule

# blind-probe handoff: no URL exchanged — both sides derive the slot
# address independently from capsule + clock + DEPLOY_SECRET; see
# PROTOCOL.md §9.
deaddrop send ./secrets.tar                    # encrypt + POST, exit 0 on success
deaddrop recv ./secrets.tar.out                # probe last ~3 min; GET + decrypt (strict one-shot: GET drains)
```

These bare commands assume a **bootstrap** pair (method 1), where E2E
is automatic. If you paired via the **offline `keygen`** route (method 2),
the capsule has no identity entry, so add `--no-require-e2e` to every
`send`/`recv` — otherwise they exit 22 (`IdentityMiss`). See the E2E
section just below.

#### End-to-end identity layer (v0.1.5+; strict by default since v0.2.0)

If `deaddrop bootstrap` ran on a host with an OS-level identity store
(macOS Keychain or Linux UID-scoped persistent keyutils), each pair gets
a long-term X25519 keypair persisted alongside the capsule. From that point on,
`send` / `recv` automatically wrap the file payload with a
content-AEAD layer derived from the X25519 shared secret — the relay
operator can tamper with the wire body all they want, the inner layer
stays sealed by a key the relay never sees.

The wire byte at offset 0 changes from `0x01` (legacy) to `0x04` (E2E)
when the inner layer is in play; the body shape is otherwise byte-
identical and the v0.1.4 relay binary serves v0.1.5 clients without
modification.

Strict mode is the **default since v0.2.0** (D-71): `send`, `recv` and
`bootstrap` behave as if `--require-e2e` were always passed. A capsule
with no identity entry — which includes every `deaddrop keygen` capsule
(§2) and any pre-v0.1.5 capsule — is refused with exit 22
(`IdentityMiss`). The escape hatch is `--no-require-e2e`, which selects
the legacy 0x01 path and prints a deprecation warning.

```
deaddrop send ./secrets.tar                      # E2E by default (0x04); exit 22 if no identity entry
deaddrop send --no-require-e2e ./secrets.tar     # legacy 0x01 fallback (keygen / pre-v0.1.5 capsules)
deaddrop recv --no-require-e2e ./secrets.tar.out # accept legacy 0x01 bodies
deaddrop fingerprint --identity                  # OOB-comparable pairing fingerprint
```

On Linux, the identity entry lives in the UID-scoped persistent keyring
and survives logout. Reboot wipes (RAM-only); running idle for ≥3 days
will re-prompt (kernel default, configurable). On older kernels without
`CONFIG_PERSISTENT_KEYRINGS`, falls back to session keyring with a WARN.
macOS uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so the entry
persists across reboots without iCloud sync.

Both laptops must have the same `DEPLOY_SECRET` (set at install time) to
speak to the same relay. That is separate from the per-pair capsule,
and is prerequisite to both pairing methods above — `deaddrop
bootstrap` rides the same relay wire as `send` / `recv`.

**Effective reach is ~3 minutes** per single-shot `recv`, not the
relay's 10-minute TTL. The receiver blind-probes the last three
minute-buckets from its own clock. For one-shot recv, the receiver
MUST run `recv` within ~3 min of the sender's `send`. TTL is a
relay-side retention safety-net, not a user-visible delivery window;
the two numbers are separate by design. See `SPEC.md` timing table.

#### `recv --watch` — polling mode (D-70)

For "send now, recv when I get to my other laptop later", use
`--watch` to poll continuously:

```
deaddrop recv --watch ./secrets.tar.out                  # poll for up to 1h (default)
deaddrop recv --watch --duration 30m ./secrets.tar.out   # poll for 30 minutes
deaddrop recv --watch --duration 0 ./secrets.tar.out     # poll indefinitely until Ctrl-C
deaddrop recv --watch --watch-interval 45s               # poll every 45s (min 30s)
```

The first probe runs immediately (no pre-wait). On miss: sleep
`min(interval, remaining)` then re-probe. On success: write plaintext
and exit 0. Non-miss errors (auth, overloaded, crypto) are terminal
and not retried. Ctrl-C (SIGINT/SIGTERM) exits cleanly with code 130.
Deadline reached exits with code 1 (NotFound).

### 4. Local QA test (no deploy needed)

```sh
# run the full QA suite — builds, starts relay, tests 4 sizes + one-shot semantics
sh test/smoke/qa-roundtrip.sh
```

Or step by step (copy-paste each line):

```sh
# build
go build -trimpath -o /tmp/dd-test/deaddrop       ./cmd/deaddrop
go build -trimpath -o /tmp/dd-test/deaddrop-relay  ./cmd/deaddrop-relay

# start relay (local-only mode, no mlockall). Recommended: pass the
# secret via $DEADDROP_DEPLOY_SECRET so the value never lands on
# argv (D-43). The "hex:" prefix is mandatory per PROTOCOL.md §8.
SECRET=0101010101010101010101010101010101010101010101010101010101010101
DEADDROP_DEPLOY_SECRET="hex:$SECRET" \
  /tmp/dd-test/deaddrop-relay --listen :19876 --local-only &

# keygen
printf 'mypass\nmypass\n' | /tmp/dd-test/deaddrop keygen --passphrase-fd 0 /tmp/dd-test/capsule

# create random file
dd if=/dev/urandom of=/tmp/dd-test/original.bin bs=1M count=1 2>/dev/null

# send — env-path is the recommended ad-hoc shape. The "hex:" prefix
# on the env value is mandatory per PROTOCOL.md §8. (The same prefix
# rule applies to the relay's --write-token at server startup. The
# client's --write-token, when used, is forwarded verbatim as a
# bearer token in the X-DeadDrop-Write header — not parsed — so it
# does NOT take the prefix.)
# This is a keygen capsule (no bootstrap pairing), so it has no E2E
# identity entry. --require-e2e is default-on (D-71), so add
# --no-require-e2e or send/recv exit 22 (IdentityMiss).
DEADDROP_PASSPHRASE=mypass DEADDROP_DEPLOY_SECRET="hex:$SECRET" \
  /tmp/dd-test/deaddrop send \
  --capsule /tmp/dd-test/capsule --passphrase-env DEADDROP_PASSPHRASE \
  --no-require-e2e \
  --relay http://127.0.0.1:19876 /tmp/dd-test/original.bin

# recv
DEADDROP_PASSPHRASE=mypass DEADDROP_DEPLOY_SECRET="hex:$SECRET" \
  /tmp/dd-test/deaddrop recv \
  --capsule /tmp/dd-test/capsule --passphrase-env DEADDROP_PASSPHRASE \
  --no-require-e2e \
  --relay http://127.0.0.1:19876 /tmp/dd-test/received.bin

# verify
md5sum /tmp/dd-test/original.bin /tmp/dd-test/received.bin   # must match

# cleanup
kill %1; rm -rf /tmp/dd-test
```

### `DEPLOY_SECRET` delivery options (D-43)

All four binaries (`deaddrop send`, `deaddrop recv`,
`deaddrop bootstrap`, `deaddrop-relay`) accept the secret via:

```sh
# Env path — recommended for ad-hoc / dev use. The "hex:" prefix is
# mandatory.
DEADDROP_DEPLOY_SECRET="hex:$SECRET" deaddrop send ...

# Fd path — recommended for scripts. Requires bash 4+ for the
# here-string syntax; the flag value is the integer FD number (3),
# not a path. Process substitution `<(...)` returns a path and does
# NOT work with --deploy-secret-fd. Do NOT use fd 0 (stdin)
# alongside --passphrase-fd 0 — the two consumers will deadlock
# or cross-read; pick fd 3+.
deaddrop send ... --deploy-secret-fd 3 3<<<"hex:$SECRET"

# Argv path — REMOVED in v0.2.0 (D-72). Passing --deploy-secret on
# argv now exits 2 with a migration message.
# deaddrop send ... --deploy-secret "hex:$SECRET"  # ← no longer works
```

The relay binary additionally accepts the legacy unprefixed
`$DEPLOY_SECRET` (and `$WRITE_TOKEN`) for backward compatibility
with the existing `/etc/deaddrop/relay.env` shape, with a
deprecation WARN; rename to `$DEADDROP_DEPLOY_SECRET` /
`$DEADDROP_WRITE_TOKEN`.

---

## Supported scope

deaddrop's normative steady-state payload is variant **B** (shared
PSK capsule, URTB-style). The shipped surface also includes
`deaddrop bootstrap` (D-41 / `SPEC_BOOTSTRAP.md`), a one-time
provisioning protocol whose sole output is a plain-B capsule on
both peers. Both target a self-hosted VM with a Go reference binary
and an in-memory transactional store (D-39) — see `BACKEND_VM.md`.
Strict one-shot is a protocol guarantee, not a deployment option.

Cloudflare was considered as a parallel backend and parked — see
`DECISIONS.md` D-33. The parked design lives under
`experimental/BACKEND_CLOUDFLARE_parked.md` for anyone who wants to
reopen the question; they are not part of the normative story.

Parked variant sketches live in `experimental/`; see `DECISIONS.md`
D-22 and D-32.

---

## Deployment privacy: rolling service prefix

The URL has a second rolling path segment derived from a per-deployment
`DEPLOY_SECRET`. The intent is **anti-enumeration**: unauthenticated
callers cannot brute-force valid paths, so undirected internet scanners
produce a uniform 404 class from caddy and never reach the Go binary
(D-14, D-34). It is NOT relay invisibility — the hostname is
discoverable from Certificate Transparency logs, and any observer who
already sees your TLS traffic sees the destination IP / SNI / exact
URL path (TLS hides body, not endpoints). See `PROTOCOL.md §2` and
`SECURITY.md`.

---

## Scope

- NOT forward-secret. If a capsule is compromised AND an adversary
  captured on-wire ciphertext, the plaintext is recoverable. Plan
  capsule rotation accordingly. See `SECURITY.md` and `FUTURE.md` F-10.
- NOT a hosted service. Each user runs their own VM.
- NOT a chunked file transfer (10 MiB cap by default; see `FUTURE.md` F-1).
- NOT anonymous. Relay sees client IPs. Use Tor / VPN if that matters.
- NOT a replacement for Signal or magic-wormhole. See `PRIOR_ART.md`.

---

## Doc map

| File                                             | What                                            |
|--------------------------------------------------|-------------------------------------------------|
| `SPEC.md`                                        | System specification (what deaddrop is, is NOT) |
| `PROTOCOL.md`                                    | Wire protocol                                   |
| `SPEC_DRAFT_B_capsule.md`                        | Variant B — shared PSK capsule (this build)     |
| `SPEC_BOOTSTRAP.md`                              | `deaddrop bootstrap` — three-leg pairing handshake (D-41) |
| `BACKEND_VM.md`                                  | VM/Go deployment (strict one-shot, in-memory)   |
| `ARCHITECTURAL_PRINCIPLE_GENERIC_PIPELINE.md`    | Why the relay stays dumb                        |
| `DECISIONS.md`                                   | Numbered design decisions + rationale           |
| `SECURITY.md`                                    | Threat model, properties provided / not         |
| `TESTING.md`                                     | Tiered test plan                                |
| `FUTURE.md`                                      | Deferred items                                  |
| `PRIOR_ART.md`                                   | magic-wormhole, croc, age, PrivateBin — diffs   |
| `experimental/`                                  | Parked variant specs + Cloudflare design (D-33) |
| `extra/mcp/`                                     | Optional MCP wrapper over deaddrop send/recv |

---

## License

Apache-2.0.
