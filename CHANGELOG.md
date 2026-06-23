<!-- Copyright (c) 2026 Nenad Micic -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## v1.0.3 (2026-06-24)

CI / build-tag fix. No protocol, wire, or runtime-behavior changes;
v1.0.x binaries and capsules are unaffected.

### Fixed

- macOS build under `CGO_ENABLED=0` no longer fails with
  `undefined: identitystore.New` (and the same for `passcache`). The
  Keychain backends call `Security.framework` via cgo and are dropped
  when cgo is disabled, leaving no `New()`. Added `darwin && !cgo`
  stubs that return `ErrUnsupported` — mirroring the existing
  unsupported-platform stubs — so `go vet` / `make lint` / `make build`
  pass on the macOS CI lane. A functional macOS Keychain backend still
  requires `CGO_ENABLED=1` (HOWTO.md §1).
- `identitystore`: moved the package-private `zeroize` helper into a
  `linux || (darwin && cgo)` build-tagged file. It is only called by
  the keyutils and Keychain backends, so once the `darwin && !cgo`
  stub build started compiling it tripped the `unused` linter on the
  macOS CI lane.

---

## v1.0.2 (2026-06-24)

CI / tooling fix. No protocol, wire, or runtime-behavior changes.

### Fixed

- CI: `make lint-install` now runs before `make doctor`, which had
  failed on missing `golangci-lint` / `staticcheck`.
- CI: `setup-go` pinned to `1.25.x` to match `go.mod` (`go 1.25.0`);
  `1.22.x` cannot build the module.
- CI: pinned `actions/checkout@v5.0.0` and `actions/setup-go@v6.4.0`
  (Node 24) to clear the Node 20 runner deprecation.
- Fixed pre-existing lint findings (`errcheck` on `fmt.Sscanf` /
  `rand.Read` / `os.Chmod`, an unused alias, and an `SA1019` on an
  intentional `curve25519.ScalarMult` low-order-point test).

---

## v1.0.1 (2026-06-24)

### Fixed

- Relay HTTP server now sets read-header, read, write, and idle timeouts
  for direct internet-facing deployments.
- Default relay body cap now admits the documented 10 MiB plaintext file
  limit plus the currently-shipped max wire overhead.

---

## v1.0.0 (2026-06-24)

- Initial public release.

---

## v0.2.1 (2026-04-27)

Docs-only patch release. No code, protocol, or behavior changes;
v0.2.0 binaries and capsules are unaffected.

### Docs

- `HOWTO.md` — promoted to a standalone operator guide (install,
  env vars, capsule creation, send/recv, `--watch`, fingerprint,
  passcache, kernel keyring deep-dive, proxy, self-signed TLS,
  deploy, tests, exit codes, gotchas, quick reference).
- `HOWTO.md` — macOS specifics added across the guide:
  - Section 1: `CGO_ENABLED=1` requirement on macOS (the Makefile
    default of `0` fails the build because identitystore /
    passcache call `Security.framework` via cgo); Xcode CLT
    prerequisite; Apple Silicon vs Intel arch; Gatekeeper / xattr
    notes for downloaded binaries.
  - Section 9b (new): macOS Keychain deep-dive parallel to the
    Linux kernel-keyring section — login keychain, two services
    (`deaddrop` for passcache, `deaddrop-identity` for pair
    identity) and account formats, persistence model (survives
    reboot, unlike Linux RAM-only), `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
    semantics (no iCloud sync, no migrate-to-new-Mac), the
    "Always Allow" vs "Allow" ACL distinction, locked-keychain
    → `IdentityMiss` (D-62), Touch ID, troubleshooting.
  - Section 10: macOS system proxy is not auto-read by Go; export
    `HTTPS_PROXY` even when `scutil --proxy` reports a system
    proxy. PAC files are not supported.
  - Section 11: `SSL_CERT_FILE` works on macOS unchanged;
    optional System keychain trust path documented with caveats.
  - Section 15: Gatekeeper / quarantine workaround, ACL re-prompt
    fix when "Allow" was picked instead of "Always Allow",
    `PlatformUnsupported` (exit 24) cannot occur on macOS
    (Keychain is always present).

---

## v0.2.0 (2026-04-27)

Three things land together as v0.2.0:

1. **Linux identity entries persist across logout** (D-69). UID-scoped
   persistent keyring on kernels with `CONFIG_PERSISTENT_KEYRINGS`
   (mainline ≥ v5.4); session-keyring fallback with stderr WARN on
   older kernels. Reboot still wipes (RAM-only, by design).
2. **Protocol gates flipped** (D-70, D-71, D-72). `recv --watch`
   polling loop, `--require-e2e` default-on, `--deploy-secret` argv
   removed from every binary including the relay. Both CLI flips have
   been WARNing since v0.1.x.
3. **Operational hardening.** Proxy end-to-end test suite, unified
   deploy script (VM + VPS), and a perf-roundtrip harness.

### BREAKING — migration required

Two CLI flips. Both have been WARNing since v0.1.x.

1. `--require-e2e` is now the default on send / recv / bootstrap.
   If your capsule has no per-pair identity entry,
   you have two options:
   - **Recommended:** rebootstrap (`deaddrop bootstrap --role=…`) to
     create the identity entry on both sides.
   - **Stopgap:** add `--no-require-e2e` to your existing
     send/recv invocations. This carries its own deprecation WARN
     and will be removed in v0.3.0.

2. `--deploy-secret <hex:…>` on argv is removed. Pick one:
   - `export DEADDROP_DEPLOY_SECRET=hex:…` (env var, not on argv).
   - `--deploy-secret-fd 3 3<<<"hex:…"` (file descriptor).
   - For systemd / cron, prefer the env var via `EnvironmentFile=`.

If you run `deaddrop` on an old shell wrapper, run `deaddrop send
<file>` once and read the migration message — it names the exact
replacement flag.

### Code

- **`internal/identitystore/keyutils_linux.go`** — `New()` now uses
  `KEYCTL_GET_PERSISTENT(uid=-1, dest=@s)` to anchor identity entries
  in the UID-scoped persistent keyring. `ENOSYS` / `EPERM` fallback
  to session keyring with a one-line stderr WARN (D-69).
- No change to `internal/passcache/` — session keyring with TTL is
  correct for the short-lived passphrase cache.
- No change to `cmd/deaddrop/identity.go` or `identity_test.go` — the
  `newIdentityStore` seam abstracts the keyring choice.
- **`internal/client/recv.go`** — `RecvCtx(ctx, cfg)` added: context-aware
  variant of `Recv` using `http.NewRequestWithContext`. Existing `Recv` is
  now a thin wrapper calling `RecvCtx(context.Background(), cfg)`.
  `IsMiss(err)` helper for watch-loop miss detection.
- **`internal/exitcode/exitcode.go`** — `Interrupted = 130`
  (EDDInterrupted) added for signal exit convention.
- **`cmd/deaddrop/recv.go`** — three new flags: `--watch` (bool),
  `--duration` (default 1h, max 24h, 0=unbounded), `--watch-interval`
  (default 60s, min 30s). `watchClock` seam struct for testability.
  `runRecvWatch` polling loop: immediate first probe, IsMiss→sleep→retry,
  non-miss errors terminal (429/503 NOT retried), SIGINT/SIGTERM→130,
  deadline→1. Single-shot path unchanged.
- **`cmd/deaddrop/main.go`** — recv usage line updated with
  `[--watch] [--duration 1h] [--watch-interval 60s]`. Pre-dispatch argv
  scans added for `--deploy-secret` (D-72) and `--require-e2e=false`
  (D-71). `resolveDeploySecret` simplified: argv branch removed,
  precedence is now `--deploy-secret-fd > $DEADDROP_DEPLOY_SECRET`.
  Usage banner updated: `--deploy-secret` replaced with
  `--deploy-secret-fd N`, `--require-e2e` replaced with
  `--no-require-e2e`.
- **`cmd/deaddrop/send.go`** — `--require-e2e` default flipped to
  `true`. New `--no-require-e2e` flag with deprecation WARN.
  `--deploy-secret` flag removed from FlagSet. D-71 flag conflict
  detection (`--require-e2e` + `--no-require-e2e` → exit 2).
- **`cmd/deaddrop/recv.go`** — same D-71/D-72 changes as send.go.
- **`cmd/deaddrop/bootstrap.go`** — same D-71/D-72 changes as send.go.
- **`cmd/deaddrop-relay/main.go`** — `--deploy-secret` flag removed
  from FlagSet. Pre-parse argv scan rejects removed flag with
  migration message.

### Decisions

- **D-69** (new): Linux persistent keyring with session-keyring
  fallback. UID-scoped, RAM-only, idle expiry ≥3 days (kernel
  default). Same threat boundary as macOS Keychain.
- **D-63** superseded: session-keyring-only paragraph marked with
  cross-link to D-69.
- **D-70** (new): `recv --watch` client-side polling loop. 30s interval
  floor, 24h duration ceiling, watchClock seam, terminal non-miss errors.
- **D-71** (new): `--require-e2e` defaults to true at v0.2.0 on `send`,
  `recv`, `bootstrap`. `--no-require-e2e` is the documented opt-out.
  `fingerprint` is explicitly excluded.
- **D-72** (new): `--deploy-secret` argv flag removed from every binary
  (`send`, `recv`, `bootstrap`, AND `deaddrop-relay`). Precedence:
  `--deploy-secret-fd > $DEADDROP_DEPLOY_SECRET`.

### Docs

- `SECURITY.md` — operational-hardening section now names the
  same-UID + RAM-only + idle-expiry properties of the persistent
  keyring; DEPLOY_SECRET via `-fd` or env-only; argv path removed
  from clients AND relay.
- Open-items tracker — O-1 marked CLOSED with D-70 cross-link; O-6 marked
  CLOSED with D-69 cross-link.
- `README.md` — Linux identity section updated (survives logout,
  reboot wipes, idle expiry note); `recv --watch` subsection added.
- Live-test HOWTO — `recv --watch` example added; post-bootstrap
  inspection now shows `keyctl show @us` alongside `keyctl list @s`.
- `DECISIONS.md` — D-69, D-71, D-72 added.

### Tests

- `internal/client/recv_ismiss_test.go` — IsMiss true/false coverage.
- `cmd/deaddrop/recv_watch_test.go` — 8 tests via injected watchClock:
  happy path, deadline, non-miss terminal, no-overshoot, SIGINT, unbounded,
  interval floor, future-interaction placeholder.
- `cmd/deaddrop/main_test.go` — 6 new rejection tests: argv rejection
  for send/recv/bootstrap, equals-form rejection, `--require-e2e=false`
  rejection, flag conflict rejection. All existing tests migrated from
  `--deploy-secret` argv to `$DEADDROP_DEPLOY_SECRET` env var.
- `cmd/deaddrop/bootstrap_test.go` — all tests migrated from
  `--deploy-secret` argv to env var + `--no-require-e2e`.
- `cmd/deaddrop/passcache_test.go` — all tests migrated.
- `cmd/deaddrop/identity_test.go` — non-strict tests gain
  `--no-require-e2e`; strict tests unchanged (default is now strict).
- `cmd/deaddrop-relay/main_test.go` — argv WARN tests converted to
  rejection tests.

### Validation

- `tests/scripts/run_kernel_matrix.sh` — kernel-matrix harness
  (virtme-ng) covering v4.19 (ENOSYS fallback), v5.4, v5.15, v6.1,
  v6.8 (persistent keyring). Local-only for v0.2.0; CI integration
  deferred.
- `test/proxy/proxy-e2e.sh` — proxy end-to-end suite (7 cases) through
  a local Squid to the live VPS relay: round-trip,
  `HTTPS_PROXY` / `http_proxy` / `NO_PROXY` env handling, invalid
  proxy clean error, `recv --watch` polling through proxy, 5 MiB
  payload, bad relay URL. All verified against live Squid logs.
- `test/perf/perf-roundtrip.sh` — perf-roundtrip harness validated
  across 1K–100K payloads against both VM and VPS targets.
- `scripts/deploy.sh` + `deployment.yaml.example` — single-command
  deploy to VM (self-signed TLS) and VPS (Let's Encrypt ACME). Reads
  `deployment.yaml` for target config, syncs via `git archive`,
  patches Caddyfile for self-signed when needed, handles Docker setup
  and legacy systemd migration. VM smoke test PASS, VPS smoke
  test PASS.

## v0.1.6 (2026-04-27)

Hardening patch for v0.1.5. No protocol changes; v0.1.5 capsules and
identity entries continue to work unchanged.

### Code

- **`send` / `recv`** now emit a stderr `WARN` when the identity
  entry is missing (or the platform store is unavailable) and
  `--require-e2e` is unset, instead of silently falling back to
  legacy 0x01 mode. After Linux session-keyring loss on logout the
  operator now sees an explicit "rerun bootstrap to enable E2E"
  hint rather than a silent E2E downgrade.
- **`bootstrap`** now emits a stderr `WARN` before substituting
  `identitystore.Noop()` on platforms without a Keychain / keyutils
  backend. Same signal: persistent E2E is off; the bootstrap will
  still produce a working capsule.
- **D-65 zeroize gap closed.** Idempotent
  `defer s.ZeroizeIdentity()` added after bootstrap `State`
  construction. Previously, errors between `State` construction and
  `FinishBootstrap`'s own zeroize defer left `IdentitySK`,
  `IdentityPK`, and `PeerPK` uncleared.

### Docs

- **README.md §4** rewritten so the bootstrap-keys-are-ephemeral
  claim no longer contradicts the §72 description of v0.1.5
  OS-keyring persistence. The ephemeral fallback is correctly
  scoped to platforms without a keyring backend.
- **Top-level `deaddrop --help`** banner now lists `--require-e2e`
  for `send` / `recv` / `bootstrap` and `--identity` for
  `fingerprint`.

---

## v0.1.5 (2026-04-27)

Long-term per-pair E2E identity (X25519 keypairs persisted in
the OS keyring) plus a content-AEAD layer above the existing capsule.
Threat-model upgrade: offline disk-theft now requires capsule + P_B +
identity SK (3 pieces, was 2). Live-session attacker model unchanged.

Wire body shape unchanged; the wire-version byte space gains
`VersionPlainBE2E = 0x04` (D-68) for clients to dispatch on. Mixed-mode
is allowed by default — only `--require-e2e` makes 0x04 mandatory.

### Code

- **`internal/identitystore/`** (new) — pluggable per-pair identity
  store with two real backends (macOS Keychain Services + Linux
  keyutils session keyring) and a noop fallback for unsupported
  platforms. Common file owns the `Store` interface, `Entry` struct
  (97 bytes: Role || OwnSK(32) || OwnPK(32) || PeerPK(32)), and
  shared errors; `New()` lives only in tagged backends (D-61).
- **macOS Keychain backend** (`keychain_darwin.go`, cgo +
  Security.framework) — service `deaddrop-identity`,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no iCloud sync
  (D-62).
- **Linux keyutils backend** (`keyutils_linux.go`) — session keyring
  (`@s`), description prefix `deaddrop-id-`, no per-key timeout
  (D-63). Persistent keyring upgrade deferred to v0.2 (O-6 in
  the open-items tracker); v0.1.5 fallback to legacy 0x01 mode keeps pairs
  functional after logout.
- **`internal/client.ContentLayer`** (new) — content-AEAD layer
  keyed by `HKDF-SHA256(X25519(OwnSK, PeerPK), nil,
  "deaddrop-e2e-content-v1" || PairID, 32)` (D-66). Per-pair stable;
  24-byte random nonce per send. AD = `info_label || PairID ||
  ContentLayerVersion`.
- **`bootstrap`, `send`, `recv`, `fingerprint`** — all four
  subcommands gain `--require-e2e`. New exit codes: `EDDE2EUnwrap=21`,
  `EDDIdentityMiss=22`, `EDDIdentityStore=23`,
  `EDDPlatformUnsupported=24`. `fingerprint --identity` prints the
  D-67 role-ordered fingerprint (PSK || PairID || initPK || respPK)
  using the local identity entry.
- **`internal/wire`** — `VersionPlainBE2E = 0x04` constant + helper
  `IsPlainBody`. Wire-version dispatch happens before crypto.Open so
  recv refuses 0x04+nil-ContentLayer (`EDDIdentityMiss`) and
  0x01+ContentLayer+`--require-e2e` (`EDDE2EUnwrap`).

### Spec / docs

- **D-60 through D-68** — static-static ECDH (D-60),
  `internal/identitystore/` package shape (D-61), Keychain item
  attributes (D-62), keyutils description / no-TTL (D-63), Entry
  layout (D-64), wire-version dispatch matrix (D-65), content-AEAD
  HKDF info derivation (D-66), role-ordered fingerprint (D-67), new
  wire-version byte (D-68).
- **`README.md`, live-test HOWTO** — new "E2E identity layer"
  section covering the threat-model delta, `--require-e2e` flag,
  rebootstrap-to-recover error class, and the keychain / keyring
  artifacts.
- **Open-items tracker** — O-3 closed (Keychain shipped at v0.1.4); O-6 added
  (Linux session-vs-persistent keyring deferral).

### Validation

- macOS smoke: keychain integration tests (env-gated), scripted
  bootstrap, plain + `--require-e2e` round-trips, negative
  `EDDIdentityMiss`, and `fingerprint --identity` (D-67) all green.
- Linux validation: clean pass on the validation run (no fixes required).

### Quality

- Independent build/test/vet verification of each change.
- ~2230 LOC across 28 files; 17 packages green incl. new
  `internal/identitystore` and `internal/crypto.IsAllZero`
  (hoisted from `internal/bootstrap/leg3.go`).

---

## v0.1.4 (2026-04-26)

Rollup of three usability slices plus deployment + correctness fixes
between v0.1.1 and v0.1.4.

### Code

- **`tools/test-derive/`** — single-phrase deterministic
  secret derivation. One passphrase derives `RELAY`, `DEPLOY_SECRET`,
  `WRITE_TOKEN`, `BOOTSTRAP_PA`, `CAPSULE_PASSPHRASE`, and
  `CADDY_PREFIX` so a fresh deploy + first round-trip needs exactly
  one secret to remember. `--site-addr` also derives `CADDY_PREFIX`.
- **`internal/passcache/keyutils_linux.go`** — Linux
  keyutils session-keyring backend for the at-rest capsule
  passphrase. `--passcache=auto` picks keyutils on Linux;
  `--passcache=keyutils` is the strict-mode equivalent. TTL
  honoured via `KEYCTL_SET_TIMEOUT`.
- **`internal/passcache/keychain_darwin.go`** — macOS
  Keychain Services backend (cgo + Security.framework,
  `kSecClassGenericPassword`,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no iCloud sync).
  TTL is documented as unsupported on macOS — keychain has no
  per-item expiry; lifetime is keychain-lock-bounded. An explicit
  `--passcache-ttl` on darwin emits a one-line asymmetry warning.
- **Write-token wire format fix** — client and relay now agree on
  hex encoding of `X-DeadDrop-Write` (regression caught by
  cross-capsule round-trip test).
- **Bootstrap pairing + cross-capsule round-trip tests** added to
  `scripts/`.

### Deployment

- **Docker Compose** for relay + Caddy (`caddy:alpine`) with
  systemd-equivalent security hardening (`no-new-privileges`,
  read-only fs, dropped caps).

### Spec / docs

- **Live-test HOWTO** — derive-workflow examples (§§11–12)
  showing the one-phrase passphrase flow end-to-end; auto-resolve
  for the `deaddrop` binary; passcache sections for keyutils and
  Keychain.
- **Open-items tracker** — O-3 (Keychain) closed at v0.1.4. O-4 (gpg-agent)
  recorded as deferred.

---

## v0.1.1 (2026-04-25)

Eight deliverables closing correctness and documentation gaps surfaced
during the v0.1.0 run.

### Code

- **`--deploy-secret-fd N` and env-canonical delivery** (DEL-1, D-43) —
  all four binaries (`deaddrop send`, `deaddrop recv`,
  `deaddrop bootstrap`, `deaddrop-relay`) now accept the secret
  via fd or `DEADDROP_DEPLOY_SECRET` env. argv path remains for
  v0.1.x with a deprecation `WARN` at startup; argv removal is
  scheduled for v0.2. Precedence: `fd > canonical env > legacy
  env > argv`. Relay accepts legacy `DEPLOY_SECRET` env for
  backward compat (with WARN; removed in v0.2). systemd unit and
  `deploy/vm/*` updated to use the env path; `--deploy-secret`
  removed from `ExecStart`.
- **GET requests no longer carry `X-DeadDrop-Write`** (DEL-3, D-45) —
  the header is now strictly write-path. `deaddrop recv`'s
  `--write-token` flag is fully removed (recv is read-only; the
  header had no auth effect on GETs anyway). Bootstrap GET
  callsites (pollLeg, leg-2 inline, leg-3 inline) all stripped.
  `PROTOCOL.md` and `SPEC_BOOTSTRAP.md` updated with the
  GET-MUST-NOT-carry rule.
- **Constant-time-compare discipline documented** (DEL-2, D-44) —
  validation confirmed the codebase already uses
  `subtle.ConstantTimeCompare` everywhere it matters; D-44 makes
  the rule explicit and adds a `SECURITY.md` carve-out for
  memory-forensics threats (out of scope; operators wanting
  stronger guarantees use VM-isolated send/recv).
- **`internal/fdread` package** (new, used by DEL-1) — bounded
  fd-read helper with hard 1 KiB cap (`io.LimitReader`-based
  overflow check), LF and optional preceding CR strip, and
  proper `defer Close`. Source-agnostic so future fd / env / argv
  paths share one validator with `internal/secretparse.Parse`.
- **`maxBlobBytes` correctly attributed** (DEL-4, D-46) — the
  pre-existing `(D-25 default)` comment in
  `cmd/deaddrop/send.go:27` was misattributed (D-25 is the
  static-binary decision); D-46 now pins the 10 MiB
  client-side cap and the comment points at it.

### Spec / docs

- **13 retroactive D-XX entries** (DEL-8, D-47..D-59) formalizing
  values that shipped in v0.1.0 without explicit decision-log
  backing: flag-naming convention (D-47), env-var naming
  (D-48), HTTP timeout (D-49), client recv body cap (D-50),
  User-Agent (D-51), 404 Content-Type (D-52), empty-POST → 413
  (D-53), `--max-concurrent-gets` default (D-54),
  `--max-store-bytes` default (D-55), GC sweep interval
  (D-56), constant-time hour-boundary check (D-57), default
  listen address (D-58), POST `?reads=N` cap (D-59).
- **PROTOCOL.md §8.1** — documents the v0.2 hard-removal of
  `--deploy-secret` argv and the relay's legacy env-var
  acceptance window.
- **DECISIONS.md D-31** — bootstrap-flag table extended with
  `--deploy-secret-fd`; the no-argv-passphrase rule is now
  explicitly extended to cover `DEPLOY_SECRET`.

### Operator migration notes

- Relay systemd unit (`deploy/systemd/deaddrop-relay.service`)
  drops `--deploy-secret ${DEPLOY_SECRET}` from `ExecStart`.
  After upgrade: `systemctl daemon-reload && systemctl restart
  deaddrop-relay`.
- Relay `/etc/deaddrop/relay.env`: `DEPLOY_SECRET` continues
  to work (deprecation WARN at startup), but operators are
  encouraged to rename to `DEADDROP_DEPLOY_SECRET` for v0.2
  compatibility. Same applies to `WRITE_TOKEN` →
  `DEADDROP_WRITE_TOKEN`.
- `deaddrop recv --write-token` is **removed**. Scripts that
  still pass `--write-token` to recv will fail with `EDDUsage`.
  Drop the flag from recv invocations only; send / bootstrap
  usage is unchanged.

### Quality

- Pre-merge validation found two issues (fdread cap not enforced;
  D-59 mis-labeled as GET), both patched before merge.
- 8 new tests added across `internal/fdread`, `internal/client`,
  `cmd/deaddrop`, `cmd/deaddrop-relay`. Two scripted smoke
  tests (`scripts/v0.1.1-deploy-secret-{fd,argv-warn}-smoke.sh`)
  exercise the new fd path and deprecation warning across all
  four binaries.

---

## v0.1.0 (2026-04-23)

Initial release. One-shot encrypted file relay with body-opaque design:
the relay stores and serves ciphertext without ever seeing plaintext or keys.

### Crypto layer (Phases 1.1-1.3)
- AEAD encryption (XChaCha20-Poly1305) with HKDF-SHA256 key derivation
- Capsule format: 109-byte file wrapping PSK + pair_id with Argon2id passphrase protection
- Slot/service derivation: deterministic slot IDs and service keys from PSK + epoch
- Wire version byte for future-proofing

### Relay server
- In-memory ephemeral slot store with configurable size limits
- One-shot semantics: POST stores, GET retrieves and deletes, HEAD probes, DELETE wipes
- Uniform 404 for all non-matching paths (no information leakage)
- Background GC for expired slots
- SIGTERM graceful shutdown with store zeroization

### Client CLI
- `deaddrop keygen` — generate capsule with passphrase protection
- `deaddrop send <file>` — encrypt and POST to relay
- `deaddrop recv [output]` — GET from relay, decrypt, write to file or stdout
- 3-bucket past-only epoch probing for clock-skew tolerance
- Structured exit codes for scripting

### Bootstrap pairing
- `deaddrop bootstrap --role=initiator|responder` — interactive 3-leg handshake
- 2-DH body key derivation (X25519) for forward secrecy
- Hex pairing fingerprint for visual confirmation of shared secret

### Deployment hardening (Phases 5.1-5.3)
- Caddyfile with D-34 CADDY_PREFIX edge filtering and IP header sanitization
- systemd unit with mlockall, no swap, no core dumps, read-only filesystem (D-39, D-40)
- journald volatile storage (no logs persist to disk)
- Docker Compose for Caddy (caddy:alpine) with security hardening
- Idempotent VM bootstrap script for Ubuntu 22.04/24.04

### Testing
- Golden test vectors for all crypto primitives
- Unit tests across all packages (race-detector enabled)
- E2E round-trip harness (send/recv with checksum verification)
- Caddy prefix-strip integration test (9 test cases)
- 10x 10 MiB smoke test with RSS stability and SIGTERM verification
