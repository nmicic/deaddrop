# SPEC DRAFT G — Private Messaging Bus (multi-peer, multi-role)

> **Status: exploratory sketch.** Generalizes B / B′ from a 2-party file
> drop into a multi-peer messaging bus. NOT a committed variant. Captured
> here so the B-family architecture does not accidentally foreclose this
> direction, and so the design can be revisited cold.

---

## Relationship to B / B′ / F

- Reuses the B / B′ capsule as a **group** PSK instead of a pair PSK.
- Reuses the B′ bootstrap so each peer's identity private key stays local.
- Adds one derivation mechanism on top: GID + SID + counter + role suffix.
- The relay is unchanged (D-20). No new endpoints, no new headers, no
  awareness of groups.
- Transport layer (D, F) is orthogonal.

If B′ is "SSH between two laptops," G is "a small IRC-shaped bus where
the broker cannot see topics, membership, or message timing correlations."

---

## Motivation

Two-laptop file drop is v1. Once it exists, the same substrate happens to
fit several problems without changing the relay:

- **Private multi-host orchestration.** Several trusted clients across
  one or more hosts exchanging tasks, status, and results without a
  readable broker. Polling-based coordination becomes event-driven if a
  notification slot exists.
- **Multi-host build / test fan-out.** macOS builds here, Linux tests
  there; CPU server versus GPU server. Currently synced via GitHub.
- **Disposable VMs.** Short-lived VMs that reboot frequently — no
  persistent identity at any broker is appropriate.
- **`authorized_keys` and similar infrequent exchanges** between hosts.

A shared git repo, an IRC server, a real message broker all work — each
adds a service with its own identity, logs, and access story. If one
extra derivation layer turns the already-deployed zero-knowledge relay
into a private bus, that is strictly cheaper than standing up another
service.

---

## Concepts

- **GID — group identifier.** Names a logical group of peers. Derived from
  a group key (the B / B′ capsule's PSK). Used for group-wide slots.
- **SID — session identifier.** Names a session within a group (often a
  peer-pair sub-channel, or a topic). Rotates on a schedule or on demand.
- **Counter (n).** Advances per message within a (GID, SID). Both sides
  pre-compute the window `[n, n+K]` of expected slots. HOTP model.
- **Role suffix.** Domain-separator in the HKDF info string. Distinguishes
  content / notify / resync / broadcast / webhook / dummy slots at the
  URL layer.

One derivation rule:

```
slot_id = HMAC-SHA256(group_key,
                      "bus-v1" || role || GID || SID || counter)[:16]
```

The relay sees an opaque HMAC URL. It does not learn GID, SID, counter,
role, or membership. Same architectural contract as B / B′.

---

## Slot roles

| Role      | Suffix  | Purpose                                                    | Lifetime     |
|-----------|---------|------------------------------------------------------------|--------------|
| content   | `"c"`   | Message body (AEAD-encrypted under a DH-derived key)       | one-shot     |
| notify    | `"n"`   | Presence flag for a specific (SID, counter)                | one-shot     |
| broadcast | `"b"`   | Group-wide notification (GID + epoch, no SID)              | one-shot     |
| resync    | `"r"`   | Well-known recovery slot — "I'm lost at counter N"         | short-lived  |
| rekey     | `"k"`   | DH rekey exchange (post-compromise recovery; see §Rekey)   | per epoch    |
| webhook   | `"w"`   | Callback URL registration for push delivery                | per session  |
| dummy     | `"d"`   | Traffic padding; AEAD-encrypted sentinel                   | one-shot     |

Each role is just a different info-string suffix in the HMAC. No new relay
code. No new wire protocol.

---

## Send pattern (notify-mode, 2-peer within a group)

```
Sender:
  1. content_slot = slot(group_key, role=c, GID, SID, n)
  2. POST ciphertext to content_slot
  3. notify_slot  = slot(group_key, role=n, GID, SID, n)
  4. POST tiny marker to notify_slot

Receiver:
  Poll ONLY notify_slot. On 200 → fetch content_slot (single attempt).
```

Observer watching the relay sees polls against a URL that is not the
content URL. Without the group key plus (SID, counter) state, the
content URL is unpredictable. The poll activity does not narrow what or
when the content will be fetched.

---

## Broadcast pattern (group of N peers)

```
Sender (any group member):
  1. Content to slot(group_key, role=c, GID, SID=self_or_topic, n).
  2. Broadcast marker to slot(group_key, role=b, GID, epoch).

All members poll the broadcast slot. On 200 they enumerate known active
SIDs within the group until one has fresh content.
```

GID-level broadcast is a "new mail for someone in the group" bell. Content
remains per-SID so only the intended recipients decrypt. Group members see
metadata (how many broadcasts today); non-members see nothing.

---

## Resync (HOTP-style)

Both sides maintain the expected counter N. Loss recovery:

```
If no content at any slot in window [N, N+K] within timeout:
  Post to slot(group_key, role=r, GID, SID, epoch):
    { "last_good_n": M, "reseed_at": HKDF(root, nonce) }

Sender reads its resync slot at the start of each send as a preflight.
On resync request: acknowledge, both sides reset counter to reseed_at.
```

Resync slot is derived without the current SID state, so a lost peer can
find it from group key alone. A PSK holder can read resync traffic — fine,
PSK holders can read everything in this threat model anyway.

Inherits HOTP's resync semantics (RFC 4226 §7.4): walk forward K slots,
then fall through to the resync channel.

---

## Dummy traffic (optional, per-deployment)

Each active peer posts one encrypted dummy per interval (e.g. one per
minute) regardless of real traffic. Dummies:

- Indistinguishable from real content at the relay (same size class,
  same AEAD shape).
- Decrypt to a known sentinel on the receiver; discarded silently.
- Break the "POST to group X happened → a real message happened" signal.

Trade: one POST per peer per interval. Cheap for small groups, wasteful
for large ones. Configurable.

---

## Rekey policy — closing the post-compromise recovery gap

The counter ratchet alone gives forward secrecy but NOT post-compromise
recovery: a stolen ratchet state follows the session forever. To close
this gap, G adds a periodic **DH rekey** using one more slot role.

Three cadences, pick per deployment:

| Mode            | Trigger                          | Crypto per rekey           | PCR window                  | Client       |
|-----------------|----------------------------------|----------------------------|-----------------------------|--------------|
| `rekey=off`     | never (chain only)               | HKDF step                  | none                        | bash         |
| `rekey=window`  | every T minutes OR N messages    | fresh X25519 pair + mix    | bounded by T / N            | bash OK      |
| `rekey=per-msg` | every message                    | fresh X25519 pair + mix    | next message                | Go / C only  |

`rekey=window` is the default for a bash client. `T = 60 min, N = 100
messages` (whichever first) is a reasonable starting point; mirrors
WireGuard's "2 min or 120 GB" philosophy scaled to low-volume use.

`rekey=per-msg` is the Signal Double Ratchet. Two X25519 ops per send
(~microseconds in Go stdlib `crypto/ecdh`). Bash client cannot keep up
with fork-exec of openssl at message rate; forces F-3 (Go client).

### Mechanism (all modes)

Rekey rides on a dedicated slot role:

```
rekey_slot = slot(group_key, role="k", GID, SID, rekey_epoch)

Contents: eph_pub_A (32) + AEAD_Seal(current_root, "rekey" || eph_pub_A)

Both sides mix:
  new_root = HKDF(current_root,
                  salt = X25519(eph_priv, peer_pub) || X25519(eph_priv_old, peer_pub_old),
                  info = "bus-v1-rekey")
```

The double-mix (current ephemeral × peer static, plus prior ephemeral ×
peer prior static) is the Double Ratchet shape — each rekey requires an
attacker to have stolen BOTH the previous and the current ephemeral
private keys to follow. One missed rekey capture = attacker locked out.

### Prior art

- **Noise Protocol `rekey()`** — HKDF-next without new DH. Gives FS only.
  Equivalent to `rekey=off` / chain-step.
- **WireGuard** — fresh handshake every 2 min / 120 GB. Template for
  `rekey=window`.
- **Signal Double Ratchet** — fresh DH every message. Template for
  `rekey=per-msg`.
- **TLS 1.3 KeyUpdate** — HKDF-next only; no new DH per KeyUpdate. FS but
  no PCR. Illustrates that "rekey" without new DH input is a weaker
  operation than many assume.

---

## Window pre-computation

Both sides compute `[slot_n, slot_{n+1}, …, slot_{n+K}]` in advance.
`K = 32` handles low-volume multi-agent traffic with room for drops and
out-of-order. This is the same look-ahead window HOTP uses for OTP
resync and BIP-32 uses for address scanning.

When `K` is exceeded without progress, fall through to the resync role.

---

## Security properties (added beyond B / B′)

```
[X] URL-layer forward secrecy: past slot_ids become unpredictable even to
    a holder of the group key, without the SID + counter state.
[X] Broker unlinkability across roles: polling, content, notify, resync,
    and dummy slots are independent HMAC outputs at the relay.
[X] Per-session isolation: compromising one SID reveals only that
    session's slot stream, not group history or other topics.
[X] Traffic padding (opt-in): dummy role hides event timing.
[X] Post-compromise recovery (opt-in): `rekey=window` gives bounded
    window PCR; `rekey=per-msg` gives Signal-grade PCR per message.
    `rekey=off` (default for single-shot file drops) gives FS but no PCR.
[ ] Not post-quantum on the DH parts (unchanged from B′). HMAC-SHA256 is
    symmetric PQC-safe.
[ ] Not anonymous: relay still sees peer IPs.
```

---

## Use cases

- **Multi-client orchestration on one host.** Co-located trusted clients
  POST tasks and results. Coordinators subscribe to notify slots instead
  of running scheduled polls.
- **Multi-client across hosts.** Same as above but across a private
  laptop + a cloud VM + a GPU server. Group key in every peer's capsule.
- **Mac-codes / Linux-tests split.** Mac POSTs new commit bundle to a
  content slot; Linux picks up via notify, runs tests, posts result.
  Replaces the github-as-sync-bus pattern for this specific workflow.
- **Disposable VMs.** VM joins group at boot, POSTs status per stage,
  reboots. No persistent identity at the broker.
- **`authorized_keys` rotation.** Host A POSTs its new pubkey; host B's
  notify flag flips; B fetches. No persistent poll footprint.

---

## Expansion path — private settings sync

G shares architectural DNA with private settings-sync systems:

- Both use HMAC tokens that a server can count / group but not decrypt.
- Both use HKDF domain separation from a master seed to derive
  purpose-specific keys.
- Both keep the master secret on the device.

Two natural fits if G is ever promoted out of `experimental/`:

1. **Multi-device client settings sync.** Block-list edits, per-domain
   overrides, and tagged domains can sync through a zero-knowledge
   deaddrop deployment; each device derives slot_ids from the shared
   master.

2. **Private threat-intel bus between independent operators.** Share
   "I blocked X" / "seen N times" / "confidence 0.9"
   IOC records across peer operators without any central authority
   learning group membership. Existing threat-intel sharing (MISP,
   commercial feeds) is identity-forward; a zero-knowledge pub/sub for
   IOCs is a strong fit for G.

Both fits reuse existing crypto primitives — no new crypto, just the G
bus overlay. If G earns its way out of `experimental/`, these are the
two targets to prototype first.

---

## Open questions (must resolve before promoting out of exploratory)

1. **Membership mutation.** How does a peer join or leave an existing
   group without re-seeding the whole chain? Sender-keys (Signal group
   messaging) is one answer; MLS is another. Either is more protocol
   surface than B′ currently has.
2. **SID allocation policy.** One SID per peer-pair? Per topic?
   Per originating peer? Needs a convention before multi-peer use.
3. **Broadcast slot collision** under concurrent senders — probably
   handled by the existing `attempt` counter.
4. **Dummy calibration.** Rate that hides events without burning
   bandwidth on quiet groups. Likely deployment-specific.
5. **Scope ceiling.** At what feature count does this stop being
   "deaddrop with a derivation library" and start being "a small Signal
   group chat"? A deliberate stop line is required — otherwise the
   project scope drifts.
6. **Relay size budget.** Dummies and broadcast epochs multiply slot
   pressure. 1 MiB × N peers × dummy interval is non-trivial on a free
   Cloudflare tier.

---

## How this composes with other variants

- **Group key source.** A B / B′ capsule shared across group members
  instead of a pair. For B′, each member keeps its own local
  `identity.key`; the capsule carries peer pubkeys (or an in-group CA
  root if F-13 is taken).
- **Transport.** Any of D (private CA) / F (self-hosted VM) / Cloudflare.
  Orthogonal to the bus layer.
- **Relay.** Unchanged. Every slot is still an opaque HMAC URL with a
  TTL and a reads_left counter. D-20 holds.

---

## References

- HOTP (RFC 4226) — counter-based OTP, look-ahead resync window.
  Direct model for the window / resync mechanism.
- S/KEY (RFC 1760) — precomputed hash chain of one-time tokens.
  Earliest deployed form of this pattern.
- BIP-32 HD wallets — deterministic child-key derivation from master seed
  + chain code. Reference implementation in the author's `~/bi22.py`.
- Signal Double Ratchet — skip-key window for out-of-order tolerance;
  sender-keys for group variants.
- QUIC connection ID rotation — rotating public identifier for
  unlinkability against on-path observers.
- Tor v3 onion services — time-period-blinded descriptor keys, same
  "rotating identifier from secret state" flavor.
- URTB — HOTP / OTP-family derivation is already in use.
- Deaddrop `DECISIONS.md` D-20, D-21 — B default; client-side upgrades;
  B′ supersedes C. This sketch applies those principles.
