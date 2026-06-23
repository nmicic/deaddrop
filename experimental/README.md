# deaddrop/experimental/

Parked variant specs and exploratory sketches. **None of this is in the
current build cycle.** The root of the repo tracks variant **B** only —
see `../SPEC_DRAFT_B_capsule.md` — deployed on a self-hosted VM with
the Go reference binary (`../BACKEND_VM.md`, D-33).

These documents are kept because:
- They capture design reasoning and prior-art links that are cheap to
  preserve and expensive to reconstruct.
- If one becomes relevant again, it can be evaluated cold without
  rebuilding the context from scratch.

**Do not** treat these as a roadmap. Promotion out of `experimental/`
requires evidence of real need (a problem B cannot solve) and a
deliberate decision recorded in `../DECISIONS.md`.

See `../DECISIONS.md` D-22 for the scoping decision that put these
here, D-24 → D-33 for the backend choice (parallel Cloudflare profile
considered then parked), and D-32 for age being rejected as the crypto
core.

---

## Index

| File                                     | Status                                     | What                                                                               |
|------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------------|
| `SPEC_DRAFT_A_passphrase.md`             | **rejected on threat model (D-37)**        | Variant A — passphrase only. Rejected because user-chosen passphrase entropy does not reliably meet the offline-brute floor B gets from a 32-byte PSK. Not "parked for scope." |
| `SPEC_DRAFT_Bprime_bootstrap.md`         | **designated post-B upgrade**              | Variant B′ — B + one-time pubkey pinning; forward secrecy, identity key local. Gated on Go client (D-25) + wire-version bump. See `../FUTURE.md` F-10. |
| `SPEC_DRAFT_C_capsule_PKI.md`            | superseded by B′ (D-21)                    | Variant C — capsule with X25519 pairs. Kept for Noise_IK lineage notes.            |
| `SPEC_DRAFT_D_private_CA.md`             | optional mTLS layer on the VM deployment   | Operator-provisioned private CA for transport-level access control. Referenced by `../BACKEND_VM.md §5`. |
| `SPEC_DRAFT_E_hybrid_capsule_plus_CA.md` | superseded by B′ + D (D-21)                | Variant E — C + D.                                                                 |
| `SPEC_DRAFT_F_self_hosted_vm.md`         | **graduated** → `../BACKEND_VM.md` (D-24)  | Kept for historical reference only. Do not edit — edits belong in `../BACKEND_VM.md`. |
| `SPEC_DRAFT_G_messaging_bus.md`          | parked (scope expansion)                   | Private messaging bus sketch.                                                     |
| `G_CLIENT_SIDE_SUBSET.md`                | parked (planning)                          | Which G features could land in B as client-only upgrades.                          |
| `BACKEND_CLOUDFLARE_parked.md`           | **parked (D-33)** — Cloudflare Worker + KV | Frozen snapshot of the Cloudflare backend design that was considered alongside the VM backend in D-24 and parked in D-33; not part of the shipped story. |

---

## Relationships worth preserving

- **B → B′** is additive. B′ adds a `bootstrap` command and per-send
  ephemeral DH. Same capsule, same relay, same wire protocol shape
  (with a version-byte bump for the AEAD AD / KDF change). This is the
  designated graduation path if the non-forward-secret property of B
  proves to matter in practice (`../SECURITY.md`, `../FUTURE.md` F-10).
- **C / E** are superseded by B′ (and B′ + D) per D-21. Kept for the
  Noise_IK lineage notes and the "capsule carries everything" niche.
- **D** is orthogonal to the B / B′ axis — a transport-layer add-on
  (mTLS). Already referenced as an optional layer in
  `../BACKEND_VM.md §5`.
- **F has graduated**. The VM-specific operational story lives in
  `../BACKEND_VM.md`. The file in this directory is a frozen snapshot.
- **BACKEND_CLOUDFLARE** is parked (D-33). The parallel Cloudflare
  backend was considered but brought its own threat-model surface
  (Cloudflare as trust-path participant), eventually-consistent
  delete-on-read, and paid-tier lock-in for mTLS — none of which the
  shipped VM deployment needs. Reopening the decision means a new D-XX
  that supersedes D-33.
- **G** is the largest scope expansion — multi-peer private messaging
  bus with ratchets, rekey policies, and role-suffixed slots.
