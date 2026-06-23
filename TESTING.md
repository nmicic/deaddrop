# deaddrop — Testing

> **Status:** this file describes the **planned** test structure. None
> of the `tools/`, `testdata/`, `internal/`, `cmd/` paths listed below
> exist yet — they are specified here as the acceptance contract the
> shipped code must meet. When the Go binary lands (F-3 / D-25), this
> banner comes off and each row in the inventory gets a PASS/FAIL
> evidence line.

URTB-style tiered testing. Two hardware-free tiers, one deployed tier,
one manual tier. Conformance is tracked against variant B on the VM/Go
deployment (D-33) with the Go reference client (D-25). The bash
diagnostic client is not part of the conformance set.

---

## Overview — four test tiers

1. **No-network tier.** Pure-local: Go crypto unit tests, fixture
   vectors for HMAC / HKDF / AEAD derivations, capsule pack/unpack
   round-trip, skew-bucket probing logic, constant-time compare
   sanity, size-cap boundary. Mocked relay (in-process HTTP). ~10 s
   wall.

2. **Local-relay tier.** `./deaddrop-server --self-signed` — full Go
   client round trip, strict one-shot race test, firewall-audit dry
   run. Deterministic; always runs in CI.

3. **Deployed-relay tier.** Against a real running VM with real DNS
   and real certs. ~60 s wall.

4. **Interactive tier** (manual). Two physical laptops; confirm
   nothing identifiable leaks in relay logs. No automation.

---

## Quick start

```
make doctor              # check go toolchain, curl, openssl
make check               # tier 1 (no-network, ~10 s)
make check-vm            # tier 1 + tier 2 against local ./deaddrop-server
make deployed-vm         # tier 3 against a deployed VM
make smoke               # tier 1 tight inner loop, ~2 s
```

`deployed-vm` requires a `.env` file with `RELAY_BASE_URL`,
`DEPLOY_SECRET`, and `WRITE_TOKEN` — never commit it.

Expected `make check` line: one `PASS` per test function (Go `-v`
output), one `[ok]` per acceptance-criterion covered; count reported
on the last line as `<N> PASS / 0 SKIP / 0 FAIL`. Exact `N` is
asserted by the CI check against the inventory below —
`tools/count_acs.sh` counts unique `AC-*` IDs and fails if the
`N` printed does not match. Do not hard-code a number here; the
inventory is the single source of truth.

---

## Test inventory — variant B

| Test ID              | Tier     | Command                               | Covers (AC IDs)                                     | Runtime |
|----------------------|----------|---------------------------------------|-----------------------------------------------------|---------|
| go-build             | no-net   | `go build ./cmd/deaddrop`             | build hygiene                                       | <2 s    |
| go-vet-test          | no-net   | `go test ./...`                       | AC-UNIT-01 (Go unit + fixture tests)                | ~5 s    |
| cli-surface          | no-net   | `deaddrop --help`                     | AC-CLI-01 (send/recv/keygen/fingerprint/rotate/bootstrap) | <1 s    |
| derive-fixtures      | no-net   | `go test ./internal/derive -run Fix`  | AC-DER-FIXTURES (slot_key / slot_id / aead_key)     | <1 s    |
| version-dispatch     | no-net   | `go test ./internal/wire -run Ver`    | AC-VER-01 (unknown version byte → clean error)      | <1 s    |
| capsule-pack         | no-net   | `go test ./internal/capsule`          | AC-CAP-01 (DDC1 pack/unpack), AC-CAP-02 (fingerprint stable across rotate) | <1 s |
| skew-probe           | no-net   | `go test ./internal/client -run Skew` | AC-SKEW-01 (receiver probes current, −1, −2 only)   | <1 s    |
| rolling-prefix       | no-net   | `go test ./internal/derive -run Roll` | AC-ROLL-02 (hour boundary), AC-ROLL-03 (prev hour accepted during current) | <1 s |
| gen-phrase           | no-net   | `go test ./internal/entropy`          | AC-ENT-01 (≥77 bits passphrase entropy)             | <1 s    |
| roundtrip-mock       | no-net   | `go test ./internal/e2e -run Mock`    | AC-RT-01 (variant B send+recv, in-proc relay)       | ~1 s    |
| size-cap             | no-net   | `go test ./internal/e2e -run Size`    | AC-SZ-01 (cap → 413, cap+1 refused)                 | <1 s    |
| delete-auth          | no-net   | `go test ./internal/e2e -run Del`     | AC-DEL-01..03 (authenticated DELETE)                | ~1 s    |
| collision-noretry    | no-net   | `go test ./internal/e2e -run Coll`    | AC-COLL-01 (409 → EDDCollision, no retry; D-36)     | <1 s    |
| exit-codes           | no-net   | `go test ./internal/cli -run Exit`    | AC-EXIT-01 (distinct `$?` per failure class; D-38, incl. 16 `EDDRelayOverloaded`) | <1 s    |
| overload-503         | no-net   | `go test ./internal/server -run Overload` | AC-OVERLOAD-01 (exhaust semaphore → 503 to next GET; legitimate receivers get transient-retry signal, NOT a 404 that would corrupt strict one-shot; `BACKEND_VM.md §3.2`) | <1 s    |
| uniform-404          | no-net   | `go test ./internal/server -run Uniform404` | AC-404-WRONGSVC, AC-404-NOSLOT, AC-404-EXPIRED, AC-404-EXHAUSTED, AC-404-WRONGTOKEN (all five 404 classes byte-identical; oracle-free; `PROTOCOL.md §5`, S-03) | <1 s    |
| hour-seam-read       | no-net   | `go test ./internal/server -run HourSeam` | AC-HOUR-01 (per-bucket-hour client derivation, write-vs-read asymmetry: POST accepted under current-or-prev-hour, GET exact-match only; `PROTOCOL.md §2 / §9`) | <1 s    |
| fingerprint-v2       | no-net   | `go test ./internal/capsule -run FpV2` | AC-FP-V2 (fingerprint = HKDF-SHA256(PSK, "", "deaddrop-fingerprint-v2"‖pair_id, 16); named-arg form; 32 hex chars; pair_id-bound; `SPEC_DRAFT_B_capsule.md §1.6`) | <1 s    |
| arg2-ceiling         | no-net   | `go test ./internal/capsule -run Ceiling` | AC-ARG2-CEIL (reject m_cost_log2>22, t_cost>10, p_cost>16 → exit 15 `param-ceiling-exceeded`; `SPEC_DRAFT_B_capsule.md §1.2`) | <1 s    |
| crash-noslot         | local-linux | `tools/test_crash.sh`              | AC-CRASH-01 (D-39: SIGKILL → restart → no slots survive; no on-disk store). **Linux-only** — uses `/proc/<pid>/status` and `/proc/swaps`; skipped on macos-14 runner with a recorded SKIP, not a FAIL. | ~5 s    |
| nodisk-strace        | local-linux | `tools/test_nodisk.sh`             | AC-NODISK-01 (D-40: release binary under strace performs no persistent disk writes). **Linux-only** — uses `strace`; skipped on macos-14 with recorded SKIP. | ~10 s   |
| check-vm             | local    | `tools/check_vm.sh`                   | self-signed cert, local server, round trip         | ~15 s   |
| AC-RACE-VM           | local    | `tools/test_race.sh`                  | strict one-shot: exactly one 200, rest 404          | ~5 s    |
| deployed-vm          | deployed | `tools/test_deployed_vm.sh`           | AC-E2E-VM (real VM, real certs, full round trip)    | ~30 s   |
| firewall-audit       | deployed | `./scripts/vm-firewall-check.sh`      | expected nftables rules present                     | ~5 s    |

### Bootstrap conformance rows (D-41 / `SPEC_BOOTSTRAP.md`)

| Test ID                        | Tier     | Command                                      | Covers (AC IDs)                                                                                 | Runtime |
|--------------------------------|----------|----------------------------------------------|-------------------------------------------------------------------------------------------------|---------|
| bootstrap-happy                | no-net   | `go test ./internal/bootstrap -run Happy`    | AC-BOOT-HAPPY (two in-proc clients complete 3-leg handshake, matching FPR, both persist capsule) | ~2 s    |
| bootstrap-wrong-pa             | no-net   | `go test ./internal/bootstrap -run WrongPA`  | AC-BOOT-WRONGPA (responder typed different P_A → leg-1 AEAD fails → exit 18 `EDDBootstrapAuthFail`) | <1 s    |
| bootstrap-fingerprint-abort    | no-net   | `go test ./internal/bootstrap -run FprAbort` | AC-BOOT-FPR-ABORT (Ctrl-C at §10 fingerprint prompt → exit 130, capsule file NOT written — fingerprint-before-persist) | <1 s    |
| bootstrap-timeout              | no-net   | `go test ./internal/bootstrap -run Timeout`  | AC-BOOT-TIMEOUT (`--timeout 2s` with no peer → exit 19 `EDDBootstrapTimeout`)                   | ~3 s    |
| bootstrap-leg1-collision       | no-net   | `go test ./internal/bootstrap -run Collide`  | AC-BOOT-COLL (two pairs share reused P_A in same minute → leg-1 POST 409 → exit 12 `EDDCollision`) | <1 s    |
| bootstrap-pb-reuse-reprompt    | no-net   | `go test ./internal/bootstrap -run PBReuse`  | AC-BOOT-PB-REUSE (P_B equals P_A via Argon2id CT compare → re-prompt, capsule not written until distinct) | <1 s    |
| bootstrap-exit-codes           | no-net   | `go test ./internal/bootstrap -run Exit`     | AC-EXIT-01 rows 12 / 17 / 18 / 19 (bootstrap-specific codes)                                    | <1 s    |

### AC-DER-FIXTURES (golden vectors)

`testdata/derive/*.json` contains fixed `(DEPLOY_SECRET, PSK, pair_id,
ts, attempt)` tuples and the expected `service_id`, `slot_key`,
`slot_id`, `aead_key`, and `AD`. Any implementation change that alters
these vectors is a wire-break and MUST come with a version-byte bump.

### AC-VER-01

The relay is version-opaque (D-23): it stores the whole body as bytes
and does not parse the leading version byte. Dispatch happens on the
**receiver**. Test: receiver is fed a response whose body starts with
`0x02`; the Go client rejects with a stable error code before any
AEAD key derivation and before any Argon2id unwrap. Covers `PROTOCOL.md §7`
and D-23 (relay opacity + receiver-side version dispatch).

### AC-CAP-01 / AC-CAP-02

- 01: `deaddrop keygen` → `deaddrop rotate-capsule` (new passphrase) →
  pack + unpack round-trip reproduces the same `PSK` and `pair_id`.
- 02: `deaddrop fingerprint` output is byte-identical before and after
  `rotate-capsule`; distinct across independent `keygen` invocations
  with overwhelming probability (birthday bound 2^64 on the 128-bit
  v2 fingerprint per `SPEC_DRAFT_B_capsule.md §1.6` — comfortably
  beyond any practical user's capsule population).

### AC-DEL-01 / -02 / -03 (sender-side, in-process batch rollback — D-35)

DELETE is exercised inside a single sender process performing a
multi-slot batch (simulating the F-1 chunked / F-2 fanout flows).
The token never crosses a process boundary, is never written to
disk, and is never printed. Tests drive this by posting N slots,
then invoking the in-process rollback path, then asserting slot
state on the relay.

- 01: Sender posts N slots each with `delete_hash = SHA-256(token_i)`,
  then issues DELETE with the matching raw `token_i` from the same
  process's mlocked buffer. Each slot transitions to 404.
- 02: A DELETE issued with a wrong token returns uniform 404; the
  targeted slot remains retrievable by its intended GET. AUTH failure
  MUST NOT be distinguishable from non-existence.
- 03: DELETE against a slot already drained by a strict-one-shot GET
  (`reads_left = 0`) is a no-op 404. No oracle about whether the
  slot ever existed.

AC-DEL MUST NOT include any scenario that persists, prints, exports,
or re-loads a `delete_token` across processes. Such scenarios
contradict D-35 and are out of scope.

### AC-COLL-01 (minute-bucket collision — D-36)

Sender A and sender B post in the same minute bucket with the same
capsule. Second POST returns 409. `MAX_SEND_ATTEMPTS = 1`: the
client does NOT retry with `attempt = 1`. Exit path is the
`EDDCollision` error (`PROTOCOL.md §9`); retry is a policy decision
above the CLI. Receiver-side probing still enumerates
`attempt = 0` only across skew buckets.

### AC-EXIT-01 (sender exit-code taxonomy — D-38)

`deaddrop send` must return distinct shell exit codes so wrapping
scripts can branch on `$?` without parsing stderr. Test simulates
each failure class by injecting the corresponding error inside the
client and asserts `$?`:

| Condition                                           | Exit | Error name           |
|-----------------------------------------------------|------|----------------------|
| success                                             |   0  | —                    |
| usage / flag parsing / bad argv                     |   2  | EDDUsage             |
| local-crypto fault (AEAD seal, HKDF, RNG)           |  10  | EDDCryptoLocal       |
| relay unreachable (DNS, connect, TLS, non-503 5xx)  |  11  | EDDRelayUnreachable  |
| slot collision (409 on POST)                        |  12  | EDDCollision         |
| auth rejected (WRITE_TOKEN, mTLS) — 401 / 403       |  13  | EDDAuth              |
| payload over cap (413)                              |  14  | EDDSizeCap           |
| capsule unwrap failed (wrong passphrase, corrupt)   |  15  | EDDCapsuleUnwrap     |
| relay back-pressure (503; semaphore gate full)      |  16  | EDDRelayOverloaded   |
| bootstrap leg-3 AEAD / DH failure (D-41)            |  17  | EDDBootstrapMITM     |
| bootstrap leg-1/-2 AEAD failure (wrong P_A)         |  18  | EDDBootstrapAuthFail |
| bootstrap `--timeout` fired (incl. leg-2/-3 409)    |  19  | EDDBootstrapTimeout  |
| internal invariant violation (panic-class bug)      |  20  | EDDInternal          |

Non-zero exits MUST also emit a single-line `ERROR: <EDDName>: <detail>`
to stderr — stable machine-grepable prefix. Stdout on failure is empty
(no partial URL, no partial capsule info). Receiver side uses the same
scheme with additional codes for probe exhaustion (not part of v1
send-side scope).

### AC-ROLL-02 / AC-ROLL-03

- 02: Slot posted at second 3599 under `service_id(h)` remains
  retrievable from the receiver at second 3601 by probing under that
  **same** `service_id(h)` — the receiver tracks which hour the slot
  was stored under and uses exact-match GET (hour boundary doesn't
  strand the message).
- 03: POST is accepted under `service_id(current_hour)` OR
  `service_id(current_hour - 1)` (write-vs-read asymmetry,
  `PROTOCOL.md §2 / §9`). GET / DELETE require **exact match** on
  the `service_id` the slot was stored under — the in-memory store
  is keyed by `(service_id_at_post, slot_id)` per D-39. A GET with
  any other hour's `service_id` returns 404. Hence the test: POST
  at second 3599 lands under `h = prev_hour`; at second 3601 a GET
  under `h = prev_hour` returns 200 while a GET under `h = curr_hour`
  returns 404.

### AC-RACE-VM

100 concurrent GETs against a `reads=1` slot. Expected: exactly one
`200` with body, 99 uniform `404`s. This is the canonical one-shot
race test.

### AC-CRASH-01 (D-39: zero persistence on crash or restart)

The relay MUST hold ciphertext only in mlocked process memory. Any
restart — clean or crash — loses every live slot. Test:

1. Start the relay on a known port; POST 5 slots with distinct
   bodies. Verify GET on one of them returns 200 with the expected
   body (health check).
2. `kill -KILL $(pidof deaddrop-server)` — a SIGKILL the process
   cannot handle, so no zeroize runs.
3. Restart the relay. Assert no on-disk state persisted across the
   restart: `test ! -e /var/lib/deaddrop` AND `test ! -e /run/deaddrop/*.db`
   (no bbolt, no snapshot, no WAL anywhere — D-39 invariant).
4. GET each of the 5 previously-posted slot paths. Every response
   MUST be 404 with an empty body.
5. Repeat with SIGTERM instead of SIGKILL (clean shutdown exercises
   the zeroize-on-signal path). Same outcome: every slot 404 after
   restart.

Also asserts that the process's `/proc/<pid>/status` reports
`VmLck` ≥ `VmRSS` under load (mlockall is actually engaged) and
that `cat /proc/swaps` on the test host is empty.

**Runner coverage:** this row is Linux-only. On the macos-14 CI
runner the test is SKIPPED with evidence `platform != linux`, not
FAILED — the underlying property (no-disk-persistence) is a D-39
invariant about the Linux deployment target, not a portable
guarantee. A Linux runner failure is a D-39 breach and blocks
release; a macOS skip is expected.

## Security matrix

| ID    | Scenario                                                          | Expected                                                             |
|-------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| S-01  | Argon2id-wrap brute-force (variant B capsule)                     | 77-bit passphrase: infeasible. 32-bit: recoverable < 1 s locally.   |
| S-02  | Guess `slot_id` without capsule material                          | No faster than 2^128 — HMAC-SHA256, 16-byte truncation.              |
| S-03  | GET for non-existent / expired / wrong-prefix / wrong-token       | Byte-identical 404 responses (diff returns 0 bytes).                 |
| S-04  | Concurrent double-GET contention                                  | Exactly one 200, rest 404. Covered by AC-RACE-VM.                    |
| S-05  | Fast-forward past hour boundary with stale `service_id`           | Returns 404. Covered by AC-ROLL-02/-03.                              |
| S-06  | Timing distinguisher on `WRITE_TOKEN`                             | σ < 1 ms across 10k probes (constant-time compare).                  |
| S-07  | Argon2id profile floor (wrap unlock cost)                         | Client refuses to unwrap a capsule whose embedded params are below the policy floor per `SPEC_DRAFT_B_capsule.md §1.2` (`m < 32 MiB`, `t < 3`, `p < 1`). Lower params → rejected with a distinct error; the capsule is NOT silently accepted. Note: defaults emitted by `keygen` are stronger (`m = 128 MiB, t = 3, p = 4`, §1.1); the test asserts the accept/reject boundary at the floor, not the default. |
| S-08  | Replay of previously-deleted ciphertext                           | 404. AEAD AD binds `(service_id, slot_id, version)` so even a replay into a different deployment fails AEAD. |
| S-09  | Authenticated DELETE: wrong token                                 | Uniform 404; slot remains retrievable. Covered by AC-DEL-02.         |
| S-10  | Cross-deployment capsule replay                                   | Capsule reused against a different `DEPLOY_SECRET` → AEAD fail. D-27.|
| S-11  | Capsule fingerprint collision / rotate stability                  | Two `keygen` outputs have distinct fingerprints with overwhelming probability (birthday 2^64 on 128-bit v2 fp); `rotate-capsule` preserves fingerprint. Covered by AC-CAP-02 + AC-FP-V2. |
| S-17  | Wire-version downgrade                                            | Unknown version byte rejected before AEAD attempt; no oracle about key state. Covered by AC-VER-01. |

---

## Interactive tier — I-01 manual leak check

Goal: verify relay logs contain no plaintext, no derived key, no
capsule bytes — only opaque slot hashes and timing.

Procedure:

1. On the VM, run `journalctl -fu deaddrop` (and `tail -f` the caddy
   access log if enabled).
2. On laptop A: `deaddrop send --no-require-e2e ./test.bin` (capsule
   pre-shared via `keygen` — no identity entry, so the default-on
   `--require-e2e` must be opted out; D-71).
3. On laptop B: `deaddrop recv --no-require-e2e ./out.bin`.
4. Diff `./test.bin` and `./out.bin` — must be identical.
5. Grep tail output for:
   - the wrapping passphrase                  → must NOT appear
   - the content bytes                        → must NOT appear
   - capsule bytes (magic "DDC1", PSK region) → must NOT appear
   - the full `slot_id` / `service_id`        → acceptable only in the
     POST, GET, and DELETE path logs; MUST NOT appear in error messages
     or metrics beyond a rolling hash prefix.
6. Record PASS/FAIL with a log snippet in
   `test-evidence/I-01-<date>.txt`.

---

## Continuous integration

GitHub Actions:

```
.github/workflows/test.yml
  - matrix.os: [macos-14, ubuntu-22.04]
  - steps:
      - make doctor
      - make check           # tier 1 (all rows tier = "no-net" — portable)
      - make check-vm        # tier 2
          # - "local" rows run on both OSes.
          # - "local-linux" rows (crash-noslot, nodisk-strace) SKIP
          #   on macos-14 with recorded reason; FAIL on ubuntu-22.04
          #   is release-blocking.
```

Tier 3 (`deployed-vm`) runs on a manual workflow gated behind
protected secrets.

---

## Test evidence convention

Each PR that moves a PASS → FAIL or adds a new AC must include a line
in this inventory and an evidence snippet under `test-evidence/`.
Matches URTB's convention.
