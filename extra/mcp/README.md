# deaddrop/extra/mcp/

An **MCP wrapper** that turns deaddrop's one-shot file relay into a
client-to-client message channel — two CLI processes on different
machines passing messages through a relay that can't read them.

**Status: minimal wrapper.** Not part of the normative build
(variant B). It shells out to the existing `deaddrop send` / `recv`
binary and makes **zero protocol changes**.

## Why two capsules

deaddrop's slot address derives purely from `(capsule, minute-bucket)`,
so both machines holding one capsule compute the *same* slot. A single
capsule is therefore a direction-agnostic, half-duplex mailbox: the
sender can read its own message back, and two sends in the same minute
collide (409). To get a clean A↔B channel, use **two capsules = two
one-way channels**:

```
Machine A:  OUTBOUND = a2b   INBOUND = b2a
Machine B:  OUTBOUND = b2a   INBOUND = a2b
```

## Setup

1. Build the binary and put it on `PATH` (`go build -o deaddrop ./cmd/deaddrop`).
2. Generate the two capsules and copy **both** to **both** machines:
   ```sh
   sh keygen-channels.sh            # writes ~/.deaddrop/a2b and ~/.deaddrop/b2a
   ```
3. `pip install "mcp[cli]"`.
4. Register the server with your agent (paths/secrets via env, never tool args):
   ```json
   {
     "mcpServers": {
       "deaddrop": {
         "command": "python3",
         "args": ["/path/to/extra/mcp/deaddrop_mcp.py"],
         "env": {
           "DEADDROP_BIN": "/path/to/deaddrop",
           "DEADDROP_RELAY": "https://relay.example/PREFIX",
           "DEADDROP_DEPLOY_SECRET": "hex:....",
           "DEADDROP_WRITE_TOKEN": "hex:....",
           "DEADDROP_PASSPHRASE": "....",
           "DD_OUTBOUND_CAPSULE": "/home/me/.deaddrop/a2b",
           "DD_INBOUND_CAPSULE":  "/home/me/.deaddrop/b2a"
         }
       }
     }
   }
   ```
   On machine B, swap `DD_OUTBOUND_CAPSULE` / `DD_INBOUND_CAPSULE`.

## Tools

| Tool | Behaviour |
|------|-----------|
| `send_to_peer(message)` | Drops one message on the outbound channel. Returns `sent`, or a "channel busy" notice on a same-minute collision. |
| `receive_from_peer(timeout_s=120)` | Blocks (polling) on the inbound channel until a message arrives or the window expires; consumes it. |
| `pair(role, capsule, timeout_s=180)` | Runs one leg of an E2E pairing (`bootstrap`) to upgrade a capsule from a plain PSK to a mutually authenticated X25519 identity. Returns a **fingerprint** for the human to compare. |

## Pairing (E2E) — `keygen` vs `bootstrap`

The quick path above uses `keygen` capsules: a pre-shared key, no peer
identity. The relay still can't read the body, but it (or anyone who
grabs a capsule file) could *impersonate* the other side. To close that,
`bootstrap` the channel instead — a 3-leg PAKE that mints a per-machine
X25519 identity bound to the peer, with **no file copying between
machines** (each side writes its own paired capsule).

The `pair` tool drives the mechanics; **two trust gates stay with the
human and must never be delegated to the caller**:

1. **P_A** — the shared bootstrap passphrase (the trust root). The human
   picks it and shares it out-of-band (Signal, in person — *never* through
   the relay), and sets `$DD_BOOTSTRAP_PA` to the **same value on both
   machines**. It is never a tool argument.
2. **The fingerprint** — after pairing, `pair` returns a fingerprint. The
   human confirms it is **identical on both machines** before trusting the
   channel. That comparison is the MITM check.

A successful pair triggers an OS-keyring write — **a Keychain prompt on
macOS that the human approves.**

### Pairing one channel (a2b), cross-machine

The two machines take opposite roles; one pairs its `outbound`, the other
its `inbound`. Start the responder first (it waits), then the initiator:

```
# machine B (responder)          # machine A (initiator)
pair("responder", "inbound")     pair("initiator", "outbound")
```

Then the human compares the two fingerprints. Repeat with the roles/capsules
flipped for the reverse channel (b2a) to make both directions E2E. Once both
capsules are paired you can drop `--no-require-e2e` from `COMMON` and the
content layer is enforced.

> Same-machine note: never run both roles for one channel on a single
> machine — both writes key the identity entry by the shared `pair_id` and
> the second silently overwrites the first. Pairing is inherently
> cross-machine.

## Smoke test against a live relay

```
# machine A
send_to_peer("ping")
# machine B
receive_from_peer()        # -> "ping"
```

## Known constraints (one-shot model showing through)

- **Same-minute, same-direction sends collide.** Surfaced as "channel
  busy." Keep exchanges turn-based, or add a retry-next-bucket loop.
  Do **not** grow this into a durable queue — that belongs in a separate
  mailbox mode (see `../../experimental/SPEC_DRAFT_G_messaging_bus.md`), not here.
- **No non-destructive peek.** `recv` consumes; there is no "is there a
  message?" probe without eating it.
- **10 MiB message cap.** Fine for reports / JSON; keep large artifacts
  in git.
- **`--require-e2e` is default-on** in the binary; the wrapper passes
  `--no-require-e2e` because `keygen` capsules have no OS-keyring
  identity. `bootstrap` both machines and drop that flag to get the
  X25519 content layer + peer-identity binding.
