# SPEC DRAFT E — Hybrid (C + D): Capsule PKI + Private CA

> **Status: SUPERSEDED by B′ + D** (see `../DECISIONS.md` D-21). Not on
> any current roadmap. Prefer the modern composition
> (`SPEC_DRAFT_Bprime_bootstrap.md` + `SPEC_DRAFT_D_private_CA.md`).
> It provides the same layered security with private keys that never leave
> the device, and a clean path to fleet-scale CSR/CA (FUTURE.md F-13) and
> hardware-backed key storage (FUTURE.md F-14). See `DECISIONS.md` D-21.

Combines variant C (payload forward secrecy + mutual authenticity via X25519
identity keys in the capsule) with variant D (mTLS at the relay).

---

## Security stack

```
Layer 3 — CA / mTLS          : only enrolled devices reach the relay (D)
Layer 2 — DEPLOY_SECRET path : relay existence hidden from scanners    (PROTOCOL.md §2)
Layer 1 — Variant C PKI      : forward-secret, mutually authenticated body (C)
Layer 0 — Variant C capsule  : Argon2id-encrypted file at rest          (C)
```

An attacker must compromise all four layers to decrypt historical messages.

```
Scanner on the internet          → TLS handshake fails (no valid cert)
Attacker with stolen cert        → gets 404 (wrong service_id without DEPLOY_SECRET)
Attacker with cert + DEPLOY_SEC  → can fill slots, cannot decrypt anything
Attacker with cert + DEPLOY_SEC + capsule → decrypts FUTURE messages only
                                                  (past messages protected by ephemeral DH)
```

---

## When to choose E

- You use deaddrop for credentials, keys, recovery phrases, incident artifacts.
- You have >2 devices or a small team.
- You are willing to manage a private CA.
- Long-term confidentiality of past messages matters even if a device is
  later compromised.

## When NOT to choose E

- It's just two personal laptops — variant B or C is sufficient.
- You cannot commit to CA maintenance — pick C alone.
- You do not need revocation — pick C alone.

---

## Operational notes

- Rotate device certs annually (short-lived intermediate CA is ideal).
- Keep CA root offline. Intermediate CA signs device certs.
- Capsule rotation is cheaper than CA rotation; rotate capsules whenever
  a device is decommissioned, even if its cert is revoked.
- Rotate `DEPLOY_SECRET` and `WRITE_TOKEN` quarterly.
- Rotate the X25519 identity keys in the capsule annually (regenerate pair).

---

## No new wire protocol

E reuses C's body format and D's TLS. No new endpoints. No new headers.
Anything E-aware is client-side configuration of both layers.

---

## Configuration snippet

`~/.deaddrop/config`:

```
RELAY_BASE_URL=https://relay.example.com
DEPLOY_SECRET=<hex>
WRITE_TOKEN=<hex>
CAPSULE_PATH=~/.deaddrop/capsule
CLIENT_CERT=~/.deaddrop/client.pem
CLIENT_KEY=~/.deaddrop/client.key
CA_BUNDLE=~/.deaddrop/ca.pem
```

Capsule passphrase is prompted at runtime; never stored in config.
