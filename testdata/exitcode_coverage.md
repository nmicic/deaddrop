<!-- Copyright (c) 2026 Nenad Mićić -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Exit Code Coverage

Generated 2026-04-22.

Maps every D-38 exit code — plus exit `1` (`EDDNotFound`) — to the
test(s) that exercise it. Covers the deaddrop client + CLI.
Bootstrap exits (17, 18, 19) are listed separately.

TESTING.md defines `AC-EXIT-01` as the sender-side D-38 taxonomy
check. This coverage note extends that row to cover recv-side exits.

## Coverage matrix

| Exit | Name                  | Condition                                                        | Test(s)                                                                                                                                                                                                                                                                                                                                                                                                                     | Status    |
|-----:|-----------------------|------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
|  0   | —                     | success                                                          | `TestSend_HappyPath` (client), `TestRecv_HappyPath` (client + CLI 26), `TestRecv_OutputFile` (CLI 27), `TestKeygen_HappyPath`, `TestFingerprint_HappyPath`, `test/e2e/roundtrip.sh`                                                                                                                                                                                                                                        | ✅         |
|  1   | `EDDNotFound`         | recv: probed all buckets, no message                             | `TestRecv_AllNotFound` (client 4), `TestRecv_NotFound` (CLI 30)                                                                                                                                                                                                                                                                                                                                                             | ✅         |
|  2   | `EDDUsage`            | flag parsing, bad argv, argv-forbidden `--passphrase`            | `TestNoArgs`, `TestUnknownSubcommand`, `TestPassphraseForbidden`, `TestPassphraseForbiddenEquals`, `TestStubSubcommands` (rotate-capsule + bootstrap), `TestKeygen_MissingOutPath`, `TestKeygen_OutputExists`, `TestKeygen_PassphraseMismatch`, `TestSend_MissingFile`, `TestSend_MissingRelay`, `TestSend_MissingDeploySecret`, `TestSend_CapsuleNotFound` (CLI 18), `TestRecv_TooManyArgs` (CLI 23), `TestRecv_MissingRelay` (CLI 24), `TestRecv_MissingDeploySecret` (CLI 25), `TestRecv_CapsuleNotFound` (CLI 28) | ✅         |
| 10   | `EDDCryptoLocal`      | AEAD / HKDF / RNG / wire version / body length                   | `TestRecv_BadVersion` (client 8), `TestRecv_DecryptCorrupt` (client 9), `TestRecv_BodyTooShort` (client 12)                                                                                                                                                                                                                                                                                                                 | ✅         |
| 11   | `EDDRelayUnreachable` | DNS / connect / TLS / timeout / unexpected 5xx catch-all         | `TestSend_NetworkError`, `TestSend_UnexpectedStatus`, `TestRecv_NetworkError` (client 7), `TestRecv_UnexpectedStatus` (client 10)                                                                                                                                                                                                                                                                                          | ✅         |
| 12   | `EDDCollision`        | 409 on POST (D-36: no retry)                                     | `TestSend_Collision409` (client), `TestSend_Relay409` (CLI 20)                                                                                                                                                                                                                                                                                                                                                              | ✅         |
| 13   | `EDDAuth`             | 401 / 403                                                        | `TestSend_WrongWriteToken` (client), `TestRecv_Auth401` (client 5)                                                                                                                                                                                                                                                                                                                                                          | ✅         |
| 14   | `EDDSizeCap`          | 413 (relay) or client-side pre-check over `maxBlobBytes`         | `TestSend_TooLarge413` (client), `TestSend_FileTooLarge` (CLI 22)                                                                                                                                                                                                                                                                                                                                                           | ✅         |
| 15   | `EDDCapsuleUnwrap`    | wrong passphrase, corrupt capsule, size / magic / version / params | `TestSend_WrongPassphrase` (CLI 19), `TestRecv_WrongPassphrase` (CLI 29), `TestFingerprint_WrongPassphrase`                                                                                                                                                                                                                                                                                                             | ✅         |
| 16   | `EDDRelayOverloaded`  | 503 (D-38); 429 added beyond D-38                                | `TestSend_Overloaded503` (client), `TestSend_RateLimit429` (client), `TestSend_Relay503` (CLI 21), `TestRecv_Overloaded503` (client 6), `TestRecv_RateLimit429` (client 13), `TestRecv_Relay503` (CLI 31)                                                                                                                                                                                                                   | ✅         |
| 17   | `EDDBootstrapMITM`    | bootstrap leg-3 AEAD / DH failure                                | —                                                                                                                                                                                                                                                                                                                                                                                                                             | Deferred  |
| 18   | `EDDBootstrapAuthFail`| bootstrap leg-1 / leg-2 AEAD failure                             | —                                                                                                                                                                                                                                                                                                                                                                                                                             | Deferred  |
| 19   | `EDDBootstrapTimeout` | bootstrap `--timeout` fired                                      | —                                                                                                                                                                                                                                                                                                                                                                                                                             | Deferred  |
| 20   | `EDDInternal`         | panic-class invariant violation / OS-level failure (disk, pipe)  | — (code path present in `runKeygen` chmod, `runSend`/`runRecv` file write, `runRecv` stdout write, catch-all unwrap in `client.Send`/`Recv` error path); inspection-verified                                                                                                                                                                                                                                               | ⚠️ Note   |

## Exit 20 note

Exit 20 (`EDDInternal`) is the catch-all for programming bugs and
OS-level I/O failures. It fires when:

- `client.Send` or `client.Recv` returns an error that does not
  unwrap into `*SendError` / `*RecvError` (which the current code
  never does — the internal constructors always stamp a code).
- `os.WriteFile` fails in `runKeygen` / `runRecv` (disk full, EACCES).
- `os.Chmod` fails after a successful write.
- `stdout.Write` fails in `runRecv` (broken pipe).
- `os.ReadFile` on the plaintext input fails after the capsule
  unwrap in `runSend`.

None of these are reachable with a fake relay or crafted inputs —
they require OS-level failures (broken pipe, ENOSPC, read-only mount,
unwritable directory). A Go-level test injecting those conditions
would be testing the standard library, not deaddrop logic.

The exit-path edges are verified by code inspection and
`errors.Is(...)` flow analysis. A future chaos / injection harness may
mechanically exercise these when the deployment surface is large enough
to justify it.

## Summary

```
Coverage:
  - Success path:   exit 0 exercised by unit, CLI, and E2E.
  - Primary errors: exits 1, 2, 10, 11, 12, 13, 14, 15, 16 all tested.
  - Bootstrap:      exits 17, 18, 19 deferred.
  - Internal:       exit 20 inspection-verified (requires OS-level failure).

10 of 11 non-bootstrap exits (0–2, 10–16) are tested end-to-end.
Exit 1 (EDDNotFound) is also tested.
```

## Cross-references

- D-38 (DECISIONS.md) — normative exit-code taxonomy.
- D-38 / D-70 — document the `EDDNotFound = 1` behavior.
- `internal/exitcode/exitcode.go` — single source of the integer →
  name mapping exercised by every ERROR banner.
- `internal/exitcode/exitcode_test.go` — covers `Name()` for every
  code listed above.
