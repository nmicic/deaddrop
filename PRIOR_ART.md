# deaddrop — Prior Art

Things that look like deaddrop, how deaddrop differs, and why deaddrop
exists despite them.

---

## magic-wormhole

- Code: https://github.com/magic-wormhole/magic-wormhole
- Docs: https://magic-wormhole.readthedocs.io/

What it is: Python tool, similar shape to deaddrop. Sender gets a short
human-readable code ("7-guitarist-revenge"); receiver types it. SPAKE2
PAKE over a rendezvous server. Relay never sees plaintext.

Differences from deaddrop:
- Uses a shared rendezvous server (`mailbox.mw.leastauthority.com`).
  deaddrop uses your own VM; no shared service (D-13).
- Codes are short (~20 bits) — safe because PAKE prevents offline brute
  force. deaddrop's variant B uses a 32-byte PSK from an Argon2id-wrapped
  capsule, sidestepping the guessable-secret problem rather than relying
  on a PAKE. Variant A (passphrase-only) was rejected on exactly this
  axis — see D-37.
- Python + pypi install. deaddrop is a single Go static binary (D-25)
  with a non-normative bash diagnostic for interop debugging.
- Optional direct P2P via hole-punch; relay fallback only. deaddrop
  always goes through the relay (by design — store-and-forward).

If you want "works today with a shared service, Python stack," use
magic-wormhole. If you want "I run my own relay, one Go binary, strict
one-shot, delete-on-read," use deaddrop.

---

## croc

- Code: https://github.com/schollz/croc

What it is: Go tool, similar to magic-wormhole in spirit. Share a code,
transfer a file through a relay (the author runs a public one, or you
host your own).

Differences:
- croc's public relay is a persistent service run by the maintainer.
  deaddrop's author explicitly does NOT run a shared relay (D-13).
- croc is a full file-transfer tool with resume and progress. deaddrop
  is a capped blob drop (10 MiB default; chunking is `FUTURE.md` F-1).
- Both reference clients are Go static binaries; deaddrop's is the
  only conformant client (D-25), and the wire protocol is intentionally
  narrower — one POST, one GET, one optional DELETE.
- deaddrop guarantees strict one-shot at the protocol layer via a
  single in-memory mutex-guarded critical section (`BACKEND_VM.md
  §3.2`, D-39). croc does not expose that as a protocol guarantee.

---

## age

- Code: https://github.com/FiloSottile/age

What it is: File encryption, not file transfer. Recipients specified by
public key or passphrase. Output is a file; you move it however you like.

Differences:
- age provides encryption-at-rest primitives. deaddrop provides an
  ephemeral transport. They are complementary — you could use age to
  encrypt and deaddrop to transport.
- age has no notion of a relay, TTL, or one-shot read.
- age's `-r <public-key>` recipient mode is conceptually similar to
  deaddrop's parked variant C (see `experimental/`), but without a
  session key / DH exchange (age uses per-file ephemeral keys).
- age was considered as the crypto core for deaddrop and rejected in
  D-32 (`DECISIONS.md`). Rationale lives there; short version: age
  optimises for at-rest-encryption ergonomics, not a bounded
  strict-one-shot wire protocol with AD binding to `(service_id,
  slot_id, version)`.

---

## PrivateBin

- Site: https://privatebin.info/

What it is: Zero-knowledge pastebin. Encrypt in the browser, POST
ciphertext, URL fragment holds the key. Server never sees plaintext.

Differences:
- Web-first, UI-oriented. deaddrop is CLI-first (web client is
  `FUTURE.md` F-8).
- PrivateBin server holds pastes until TTL. deaddrop defaults to
  delete-on-read; exhausted slots are purged transactionally.
- URL contains the key after a `#` (URL fragment, not sent to server).
  deaddrop keeps the key entirely off the wire — the key is derived
  client-side from the capsule PSK and never transmitted.
- Shared-hosting model is the norm. deaddrop is single-tenant per
  deployment (D-13).

---

## OnionShare

- Site: https://onionshare.org/

What it is: Run a Tor hidden service on your laptop, share a .onion URL.

Differences:
- Both laptops must be online simultaneously. deaddrop is
  store-and-forward.
- Requires Tor. deaddrop uses normal HTTPS.
- Anonymous (Tor). deaddrop is explicitly not anonymous — the relay
  sees client IPs (Tor / VPN is an orthogonal mitigation users can
  layer on).
- Peer-to-peer. deaddrop has a relay.

If you want anonymity AND simultaneity, use OnionShare. If you want
asynchronous and simple, use deaddrop.

---

## Firefox Send (retired) / Send-v3 forks

- Original: https://github.com/mozilla/send (archived)
- Fork:     https://github.com/timvisee/send

What it was: Mozilla's one-shot encrypted file sharer. Ciphertext at rest,
key in URL fragment. Mozilla shut down the hosted service due to abuse.

Differences:
- Self-hostable forks (send-v3) are the closest tool in spirit to
  deaddrop's VM deployment (`BACKEND_VM.md`, D-33).
- Firefox Send was a shared Mozilla service; that model failed at
  scale due to abuse. deaddrop avoids that by being single-tenant per
  user (D-13).
- Send uses a web UI; deaddrop is CLI. A web client is
  `FUTURE.md` F-8 but would be served from the same single-tenant VM.

The Send postmortem is one of the reasons deaddrop explicitly will not
run a shared hosted service.

---

## Signal (attachments)

What it is: E2EE messaging. Attachments go through Signal's relay,
encrypted.

Differences:
- Signal requires accounts (phone / username). deaddrop has no identity —
  anyone with the capsule can read (pair-level shared secret, by design).
- Signal is a production messaging platform with forward secrecy. deaddrop
  is a small single-purpose tool and variant B does NOT provide forward
  secrecy — `FUTURE.md` F-10 tracks B′.
- Signal is a recommended choice for person-to-person secure comms.
  deaddrop does not compete with it; it is for the "share a config file
  between my two laptops" use case.

---

## scp / rsync / SSH-based transfer

What it is: The incumbent solution.

Differences:
- scp/rsync require an SSH endpoint both ends can reach — often via an
  intermediate server. This is the author's original motivating problem:
  sharing a URTB pairing capsule between two laptops required SSH to an
  intermediate VPS.
- SSH gives transport encryption but no one-shot semantics.
- scp needs the sender and receiver to be online simultaneously (or the
  sender needs to reach a long-lived receiver).
- deaddrop is "drop and forget" — sender can close their laptop and
  receiver picks up later (within TTL).

---

## nullcontext / dpaste / similar pastebins

Standard pastebins without E2E encryption. Server sees plaintext. Out of
scope for comparison — deaddrop explicitly does not trust the server.

---

## Why deaddrop exists given all of the above

The immediate use case was: the author needed to move a URTB pairing
capsule between two laptops and ended up SSHing through an intermediate
VPS. None of the above tools were ideal for:

- single-user, self-hosted, no account, no Python install,
- one-shot delete-on-read as a protocol guarantee (not a server
  convention),
- a single Go static binary as the normative client (D-25),
- XChaCha20-Poly1305 body AEAD with AD binding
  `(service_id, slot_id, version)` so ciphertext cannot be replayed
  across deployments (D-27),
- CLI-first, with a narrow wire protocol — one POST, one GET, one
  optional sender-side DELETE,
- same doc conventions as URTB (for cognitive reuse).

deaddrop is the intersection of those requirements. None of the above
tools are the intersection — they each solve a larger or different
problem.

If one of them works for your use case, use it. This project exists for
the specific case where none of them do.
