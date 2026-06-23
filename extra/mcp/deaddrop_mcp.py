#!/usr/bin/env python3
# Copyright (c) 2026 Nenad Mićić
# SPDX-License-Identifier: Apache-2.0
"""deaddrop MCP wrapper — exposes the one-shot file relay as a
client-to-client message channel for two CLI processes running on
different machines.

Design: deaddrop's slot address derives purely from (capsule,
minute-bucket), so a single capsule is a direction-agnostic, half-duplex
mailbox — the sender can read its own message back, and two sends in the
same minute collide. To get a clean A<->B channel we use TWO capsules =
two one-way channels (see keygen-channels.sh). No protocol change.

  Machine A: OUTBOUND = a2b   INBOUND = b2a
  Machine B: OUTBOUND = b2a   INBOUND = a2b

The caller only ever sees `message` strings. ALL key material stays in
this process's environment and is never a tool argument.

Env (set by the operator, never by the caller):
  DEADDROP_BIN            path to the deaddrop binary (default: deaddrop)
  DEADDROP_RELAY          e.g. https://relay.example
  DEADDROP_DEPLOY_SECRET  "hex:..." (the relay's per-deployment secret)
  DEADDROP_WRITE_TOKEN    "hex:..." (relay write token; read by the binary
                          from env — required for an internet-facing relay)
  DEADDROP_PASSPHRASE     capsule passphrase (P_B; read via --passphrase-env)
  DD_OUTBOUND_CAPSULE     path to this-machine -> peer capsule
  DD_INBOUND_CAPSULE      path to peer -> this-machine capsule
  DD_BOOTSTRAP_PA         shared bootstrap passphrase (P_A) for the `pair`
                          tool. MUST be identical on both machines and
                          shared out-of-band by the human — it is the
                          trust root. Never route it through the relay.

Run: python3 deaddrop_mcp.py   (stdio transport)
Requires: pip install "mcp[cli]"  and a built `deaddrop` binary on PATH.

STATUS: minimal wrapper. Not part of the normative build (variant B).
"""
import os
import pathlib
import subprocess
import tempfile

from mcp.server.fastmcp import FastMCP

BIN = os.environ.get("DEADDROP_BIN", "deaddrop")
RELAY = os.environ["DEADDROP_RELAY"]
OUT_CAP = os.environ["DD_OUTBOUND_CAPSULE"]
IN_CAP = os.environ["DD_INBOUND_CAPSULE"]

# The child process inherits this env, so the deploy-secret and
# passphrase travel via env (never argv, never a tool argument).
CHILD_ENV = {
    **os.environ,
    "DEADDROP_DEPLOY_SECRET": os.environ["DEADDROP_DEPLOY_SECRET"],
    "DEADDROP_PASSPHRASE": os.environ["DEADDROP_PASSPHRASE"],
}

# --no-require-e2e: this wrapper assumes you paired with `keygen` (no
# OS-keyring identity entry). If you `bootstrap` both machines instead,
# drop this flag to get the X25519 content-AEAD layer + peer-identity
# binding for free. The relay can't read the body either way.
COMMON = [
    "--relay", RELAY,
    "--passphrase-env", "DEADDROP_PASSPHRASE",
    "--no-require-e2e",
]

mcp = FastMCP("deaddrop")


def _run(args, timeout):
    return subprocess.run(
        [BIN, *args],
        env=CHILD_ENV,
        timeout=timeout,
        capture_output=True,
        text=True,
    )


@mcp.tool()
def send_to_peer(message: str) -> str:
    """Drop one message on the outbound channel to the peer machine.

    One-shot: the message sits in the relay until the peer fetches it
    (or its TTL expires). Returns "sent" on success.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".msg", delete=False) as f:
        f.write(message)
        path = f.name
    try:
        # Go's flag package stops at the first positional arg, so the
        # file path MUST come after all flags.
        r = _run(["send", "--capsule", OUT_CAP, *COMMON, path], timeout=60)
    finally:
        pathlib.Path(path).unlink(missing_ok=True)

    if r.returncode == 0:
        return "sent"
    if r.returncode == 12:  # EDDCollision — slot busy this minute
        return ("ERROR: channel busy (an unread message occupies this "
                "minute's slot); the peer hasn't fetched yet, retry shortly")
    return f"ERROR: send failed ({r.returncode}): {r.stderr.strip()}"


@mcp.tool()
def receive_from_peer(timeout_s: int = 120) -> str:
    """Block until a message arrives on the inbound channel, or time out.

    Consumes the message (one-shot read). Returns the message text, or a
    "(no message — timed out)" sentinel if nothing arrived in time.
    """
    out = tempfile.mktemp(suffix=".msg")
    try:
        r = _run(
            # Flags before the positional [output] path (Go flag parsing).
            ["recv", "--capsule", IN_CAP,
             "--watch", "--duration", f"{timeout_s}s",
             "--watch-interval", "30s", *COMMON, out],
            timeout=timeout_s + 15,
        )
        if r.returncode == 0:
            return pathlib.Path(out).read_text()
        if r.returncode == 1:  # EDDNotFound — watch window expired
            return "(no message — timed out)"
        return f"ERROR: recv failed ({r.returncode}): {r.stderr.strip()}"
    finally:
        pathlib.Path(out).unlink(missing_ok=True)


@mcp.tool()
def pair(role: str, capsule: str = "outbound", timeout_s: int = 180) -> str:
    """Run ONE leg of a deaddrop E2E pairing (`bootstrap`) for one channel.

    This upgrades a capsule from a plain pre-shared key to a mutually
    authenticated X25519 identity (the relay still can't read the body,
    and now a relay/MITM can't impersonate the peer either).

    role: 'initiator' or 'responder'. The two machines MUST take opposite
          roles for the same channel.
    capsule: 'outbound' or 'inbound' — which local capsule file to (re)pair.
             For a given channel one machine pairs its 'outbound', the
             other pairs its 'inbound'.

    P_A (the shared bootstrap passphrase / trust root) is read from
    $DD_BOOTSTRAP_PA and P_B (the capsule's at-rest passphrase) from
    $DEADDROP_PASSPHRASE — NEITHER is ever a tool argument.

    Both sides must call within the timeout window (start the responder
    first, then the initiator). On success this triggers an OS-keyring
    write (a Keychain prompt on macOS — a HUMAN must approve it).

    RETURNS the pairing **fingerprint**. A HUMAN must confirm it is
    identical on both machines before trusting the channel — that
    comparison is the man-in-the-middle check and cannot be delegated to
    the caller.
    """
    if role not in ("initiator", "responder"):
        return "ERROR: role must be 'initiator' or 'responder'"
    cap = {"outbound": OUT_CAP, "inbound": IN_CAP}.get(capsule)
    if cap is None:
        return "ERROR: capsule must be 'outbound' or 'inbound'"
    pa = os.environ.get("DD_BOOTSTRAP_PA")
    if not pa:
        return ("ERROR: $DD_BOOTSTRAP_PA is not set — the human operator "
                "must provide the shared bootstrap passphrase out-of-band")
    pb = os.environ["DEADDROP_PASSPHRASE"]

    # Feed P_A then P_B over a dedicated fd (never argv); ENTER on stdin
    # auto-advances past the fingerprint prompt — we return the fingerprint
    # for the human to compare rather than confirming automatically.
    r_fd, w_fd = os.pipe()
    os.set_inheritable(r_fd, True)
    os.write(w_fd, f"{pa}\n{pb}\n".encode())
    os.close(w_fd)
    try:
        proc = subprocess.run(
            [BIN, "bootstrap", "--role", role, "--capsule", cap,
             "--relay", RELAY, "--passphrase-fd", str(r_fd),
             "--timeout", str(timeout_s)],
            env=CHILD_ENV,
            pass_fds=(r_fd,),
            input="\n",
            capture_output=True,
            text=True,
            timeout=timeout_s + 30,
        )
    finally:
        os.close(r_fd)

    blob = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        return f"ERROR: bootstrap failed ({proc.returncode}):\n{blob}"
    return ("PAIRED. Have the human verify this matches the peer's output "
            "before trusting the channel:\n" + blob)


if __name__ == "__main__":
    mcp.run()
