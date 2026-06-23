# G — Client-side subset planning notes

Catalog of which G features could fold into the B client as pure
client-side upgrades without touching the broker, the wire protocol, or
the 2-party model.

Not a roadmap. Planning artifact for B-next work once B is shipped.

---

## Promotion rule

A G feature is a candidate for promotion into B if and only if:

1. **Broker stays dumb.** No new endpoints, no new relay awareness, no
   crypto state at the relay. (D-20.)
2. **2-party model holds.** Features that require a group concept are
   scope expansion, not a B upgrade.
3. **Works behind NAT / proxy.** B is for laptops — many of them live
   behind corporate proxies, home NATs, or CGNAT. Anything that requires
   inbound connectivity to the client is disqualified for the bash
   reference client; might be acceptable for a Go/daemon variant later.
4. **Bash-implementable at the required rate.** Per-message DH ratcheting
   exceeds what shell-out-to-openssl can sustain; window-mode rekey is
   fine.

---

## Bucket 1 — Safe 2-party client-side upgrades

Zero broker change. Zero new client-side infrastructure. No mode change
from "CLI tool." Promote in roughly the order listed.

| G feature                             | What it adds                                                               | Bash cost                              |
|---------------------------------------|----------------------------------------------------------------------------|----------------------------------------|
| Role-suffixed slots (`"c"`, `"n"`, `"r"`) | Multiple independent HMAC-derived URLs per session via HKDF info string  | trivial — one HKDF call                |
| **Notify slot** (poll → fetch asymmetry) | Receiver polls a URL distinct from content URL; observer of poll traffic can't predict where content lands | ~10 lines               |
| **Resync slot**                       | HOTP-style well-known recovery channel for lost counter state              | small — extends notify mechanism       |
| **session_id + counter ratchet**      | URL-layer forward secrecy: past / future slot_ids unpredictable even to a PSK holder | small — one HKDF chain step per send |
| **Pre-computed counter window**       | Receiver tolerates out-of-order / skipped messages (K look-ahead, HOTP model) | extends existing clock-skew probe    |
| **DH rekey — window mode** (every T min / N msgs) | Post-compromise recovery on a bounded window (WireGuard pattern) | ~40ms per rekey in bash, fine at low rate |
| **B′-style pubkey bootstrap**         | Private key stays local on each device; Noise_IK body; sender authenticity | moderate — promotes the full B′ spec |

These are the natural B-next candidates. Each is independent; promotion
is additive.

---

## Bucket 2 — Multi-party client-side (scope expansion of the 2-party model)

Zero broker change, still D-20 compliant, but they change what B *is*:

- **GID (group identifier) + broadcast role** — needs a group membership
  concept in the client.
- **Sender-keys-style group fanout** — Signal's design; non-trivial
  client state.
- **Multi-party rekey / membership churn** — adds join / leave protocol.

These are scope expansion, not a B upgrade. A deliberate decision is
required before promoting any of them. Do not drift in.

---

## Bucket 3 — Client-side but requires new infrastructure

Features that technically don't touch the broker but grow the client's
surface area significantly. Most are disqualified by rule 3 (works
behind NAT / proxy).

### Webhook role — **disqualified for bash reference**

Problems (ranked by severity):

1. **Requires inbound connectivity.** The receiver must listen on a
   reachable HTTP endpoint. Laptops behind NAT / corporate proxy /
   CGNAT cannot accept inbound connections — the dominant case for
   deaddrop's target use.
2. **Needs an HTTP server in the client.** Shifts the client from a
   "CLI tool" to "CLI + daemon." Non-trivial jump in size, footprint,
   dependencies, and attack surface.
3. **TLS termination and cert story.** Without TLS the callback is
   cleartext and authenticates nothing. With TLS the receiver needs
   certs, rotation, a listener, and a port — likely a full
   Docker / reverse-proxy setup.
4. **Authentication of the callback.** Must cryptographically bind the
   incoming callback to a specific session so an attacker cannot
   replay / forge. Adds another key derivation.
5. **Firewall / operational posture.** Opening an inbound port on a
   personal laptop is a meaningful security decision that most users
   should not be pushed into.

Polling is strictly simpler and works everywhere a web browser works.
The notify-slot pattern in Bucket 1 delivers most of the webhook value
(low-latency "new message" signal) without any of the above.

If webhook is ever revisited, it belongs on the Go client side with an
explicit deployment guide and is probably only appropriate for
long-lived servers (not laptops).

### Dummy traffic — **low value for B use case**

Useful against traffic analysis, but:

- Adds scheduling / timing discipline to the client.
- Wastes bandwidth on quiet days.
- Low marginal value for file-drop use case (the attacker already knows
  a file was dropped when ciphertext size and POST timing are observed
  — dummies only help if they run continuously for long periods).

Opt-in configuration knob, not a default. Revisit only if there is
evidence of a real traffic-analysis threat against a specific deployment.

---

## Bucket 4 — Requires a different language

- **DH rekey — per-message mode** (Signal Double Ratchet cadence). Bash
  fork / exec of openssl per message cannot sustain message-rate DH.
  Gated on F-3 (Go client). Until then, window-mode rekey (Bucket 1)
  is the closest bash-compatible substitute.

---

## Suggested promotion order (after B ships)

Rough order of return-on-complexity for B-next:

1. Role-suffixed slots (primitive; everything else depends on it).
2. Notify slot (biggest user-visible win — poll / fetch asymmetry).
3. session_id + counter ratchet (closes the PSK-holder slot-enumeration gap).
4. Pre-computed counter window (resync's prerequisite).
5. Resync slot (needed once ratchet can desync).
6. B′ bootstrap (promotes private-key-stays-local + sender authenticity).
7. DH rekey — window mode (post-compromise recovery).

Each step is independently useful. Stop at any point and the result is
still a coherent B client.

Multi-party (Bucket 2), webhook (Bucket 3), and per-message DH
(Bucket 4) are **not** on this order — they require separate deliberate
decisions.

---

## References

- `../DECISIONS.md` D-20 — relay stays dumb; security upgrades are
  client-side. The rule that makes this planning possible.
- `../DECISIONS.md` D-22 — B-only build cycle. Adopting any Bucket 1
  feature *now* undoes this; they wait until B is running.
- `SPEC_DRAFT_G_messaging_bus.md` — the full G sketch these buckets
  reference.
- `SPEC_DRAFT_Bprime_bootstrap.md` — B′ spec; the "pubkey bootstrap"
  line in Bucket 1 promotes this wholesale.
