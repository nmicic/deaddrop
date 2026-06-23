# SPEC DRAFT D — Private CA + mTLS (Transport Auth Layer)

> **STATUS: FROZEN / PRE-LOCK. NOT CURRENT GUIDANCE.**
>
> This draft predates D-33 (VM/Go as sole deployment target), D-37
> (variant A rejected), and the A/B/C/E framing is obsolete. The
> paragraphs below that reference **Cloudflare Access mTLS**,
> **variant C**, or **"variant F + D"** describe a parallel-backend
> world that was parked.
>
> **Current guidance for optional mTLS on the normative VM
> deployment** lives in `BACKEND_VM.md §5` (the "Optional mTLS"
> bullet) and is referenced from `SPEC.md §6`. Treat this file as a
> historical record of the enrollment flow and CA-choice discussion —
> do NOT use it as current deployment instructions.
>
> The VM-relevant subset of this draft is:
>   • operator-run private CA (step-ca / smallstep / cfssl /
>     openssl); CA root offline, intermediate signs device certs
>   • caddy `client_auth { trusted_ca_cert_file ... }` on the relay host
>   • `~/.deaddrop/client.pem` + `client.key` on each laptop (mode 0600)
>   • annual rotation of device certs; capsule rotation still handles
>     the shared-secret layer independently
>
> Cloudflare Access, variant C, and variant-F/D composition should be
> ignored until/unless D-33 is reopened.

Orthogonal to A/B/C: adds TLS client-certificate authentication so only
enrolled devices can speak to the relay at all. Payload secrecy is still
provided by one of A/B/C (in practice, usually C — then this becomes E).

---

## What's added

1. A private Certificate Authority the user runs locally (`cfssl`, `step-ca`,
   `smallstep`, or even a 20-line openssl recipe). The CA signs one device
   certificate per laptop.
2. **Cloudflare Access with mTLS** enforced on the Worker route, OR a
   TLS-terminating reverse proxy (caddy/nginx) with `client_auth` on the VM
   variant.
3. The client sends its client certificate on every TCP connection.

Reference: https://developers.cloudflare.com/cloudflare-one/identity/devices/access-integrations/mutual-tls-authentication/

---

## Enrollment (one-time, per device)

```
./deaddrop enroll --ca-url https://ca.my.domain
  # prints CSR
  # user approves on CA (manual, or automated with step-ca ACME)
  # client receives signed cert
  # stored in ~/.deaddrop/client.pem + client.key (mode 0600)
```

On the relay:

- **Cloudflare Worker**: upload CA root cert to Cloudflare Access, enforce
  mTLS on the Worker route (Zero Trust → Access → Service Auth → mTLS).
- **VM** (variant F + D): caddy `client_auth { trusted_ca_cert_file /etc/deaddrop/ca.pem }`
  or nginx `ssl_verify_client on; ssl_client_certificate /etc/deaddrop/ca.pem;`

---

## Runtime

Client adds client cert to every request:

```
curl --cert ~/.deaddrop/client.pem --key ~/.deaddrop/client.key \
     -H "X-DeadDrop-Write: $WRITE_TOKEN" \
     --data-binary @- \
     "https://relay/{service}/{slot}"
```

Worker Access policy rejects any request whose client cert is not signed by
the configured CA. Rejection happens BEFORE the Worker script runs — zero
compute cost for bad clients.

---

## Security

Adds on top of the underlying A/B/C variant:

```
[X] Unauthenticated entities cannot interact with the relay at all — not
    even probe for 404s. They see a TLS handshake failure (certificate_unknown).
[X] Revocation: if a laptop is lost, revoke that device's cert at the CA.
    No need to rotate DEPLOY_SECRET or the capsule.
[X] Audit trail: Cloudflare Access logs which cert made which request.
    Useful in small teams for non-repudiation.
[ ] Does NOT protect payload. If payload encryption is broken, mTLS cannot help.
[ ] Introduces a CA that must be protected — CA compromise lets an attacker
    sign new device certs and reach the relay.
```

---

## CA key handling

The CA root key is the highest-value secret in this variant.

Recommendations:

- Keep CA root offline (airgapped laptop, YubiKey with PIV slot, HSM).
- Use an intermediate CA for day-to-day signing; root only signs the
  intermediate.
- Rotate intermediate annually; rotate root only on compromise.
- If a device is lost: revoke device cert (CRL or OCSP), not the CA.

---

## Pros / Cons

```
+  Defense-in-depth: passphrase leak alone is insufficient to reach relay.
+  Revocation without payload-secret rotation.
+  Per-device log correlation.
+  Cloudflare Access enforces at edge (zero Worker CPU on rejected requests).
-  Setup overhead: CA, enrollment workflow, cert rotation.
-  CA key must be stored securely — adds a high-value target.
-  Cloudflare Access mTLS is a paid feature (Teams plan).
   The VM variant with caddy/nginx is free.
```

---

## When to choose D

- You have >2 devices or a small team.
- You want revocation without rotating per-send secrets.
- You are already running (or willing to run) a private CA.

## When NOT to choose D

- It's just two laptops — rolling service prefix + `WRITE_TOKEN` from
  `PROTOCOL.md §4` gives comparable protection with far less setup.
- You are not willing to maintain a CA long-term.
- You need payload forward secrecy — D alone doesn't give it; combine with
  C (that combination is variant E).

---

## Fallback when Cloudflare Access mTLS is unavailable

If you do not have Cloudflare Teams (paid plan), deploy as variant F (VM)
and terminate mTLS on caddy/nginx. Same client-side code; different relay.
Tracked as `FUTURE.md` F-7.
