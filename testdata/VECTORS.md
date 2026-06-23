# Computation log — golden vectors

## 1. Computation environment

- Python 3.12.3
- `cryptography` 41.0.7 (pinned; `pip show cryptography`)
- `hashlib` (stdlib) — SHA-256
- `hmac` (stdlib) — HMAC-SHA256
- `struct` (stdlib) — big-endian integer encoding
- XChaCha20-Poly1305: implemented as HChaCha20 (hand-rolled quarter-round)
  + `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` for the
  IETF ChaCha20-Poly1305 step. `cryptography` 41.0.7 does not expose a
  native XChaCha20-Poly1305 API; the standard HChaCha20 subkey + IETF
  nonce construction is used per RFC 8439 §2.3 + draft-irtf-cfrg-xchacha-03 §2.

### pip list excerpt

```
cryptography    41.0.7
```

## 2. Declared test inputs

All fixtures use these deterministic values:

```
DEPLOY_SECRET = 0x01 repeated 32 times
PSK           = 0x02 repeated 32 times
pair_id       = 0x03 repeated 8 times
ts            = 1800000000
h             = floor(1800000000 / 3600)  = 500000
b             = floor(1800000000 / 60)    = 30000000
attempt       = 0
version       = 0x01
```

## 3. Per-fixture computation transcript

### DEL-3: slot_key (`testdata/derive/slot_key.json`)

Formula: `slot_key = HMAC-SHA256(PSK, "slot-key-v1" || pair_id(8))`
Source: `SPEC_DRAFT_B_capsule.md §2` line 206.

```python
import hmac, hashlib
PSK = bytes([0x02] * 32)
PAIR_ID = bytes([0x03] * 8)
slot_key_input = b"slot-key-v1" + PAIR_ID
# = 736c6f742d6b65792d76310303030303030303 (19 bytes)
slot_key = hmac.new(PSK, slot_key_input, hashlib.sha256).digest()
# = a3e97ca4d4b813bab5be9b57ca4b9d3c5990cf3a4848a11fcd36f296a59ab762
```

Output: `a3e97ca4d4b813bab5be9b57ca4b9d3c5990cf3a4848a11fcd36f296a59ab762` (64 hex = 32 bytes, full HMAC, NOT truncated).

### DEL-1: service_id (`testdata/derive/service_id.json`)

Formula: `service_id = HMAC-SHA256(DEPLOY_SECRET, "svc" || enc_u64_be(h))[:16]`
Source: `PROTOCOL.md §1` line 39.

```python
import struct
DEPLOY_SECRET = bytes([0x01] * 32)

# Case 1: h=500000
hmac_input = b"svc" + struct.pack(">Q", 500000)
# = 737663 000000000007a120 (11 bytes: 3 + 8)
full = hmac.new(DEPLOY_SECRET, hmac_input, hashlib.sha256).digest()
service_id = full[:16]
# = 7a78ba5bef18bfd32e35198ed3dc30b6

# Case 2: h=499999
# hmac_input = 737663 000000000007a11f
# service_id = 497b7191d93f845b72102a0d8b09ecb4

# Case 3: h=500001
# hmac_input = 737663 000000000007a121
# service_id = e86ca2a995183d85c653d43fe19b2c02
```

### DEL-2: slot_id (`testdata/derive/slot.json`)

Formula: `slot_id = HMAC-SHA256(slot_key, "slot" || enc_u64_be(b) || enc_u32_be(attempt))[:16]`
Source: `PROTOCOL.md §1` line 41.

```python
slot_key = bytes.fromhex("a3e97ca4d4b813bab5be9b57ca4b9d3c5990cf3a4848a11fcd36f296a59ab762")

# Case 1: b=30000000, attempt=0
hmac_input = b"slot" + struct.pack(">Q", 30000000) + struct.pack(">I", 0)
# = 736c6f74 0000000001c9c380 00000000 (16 bytes: 4+8+4)
slot_id = hmac.new(slot_key, hmac_input, hashlib.sha256).digest()[:16]
# = 7f010cca7be46267194e1dac4a0f0297

# Case 2: b=29999999, attempt=0
# hmac_input = 736c6f74 0000000001c9c37f 00000000
# slot_id = f1e30123071537123209e7c50ee9c36d

# Case 3: b=30000001, attempt=0
# hmac_input = 736c6f74 0000000001c9c381 00000000
# slot_id = 3d94d7139147ee403aadfdb732bc11a4

# Case 4: b=30000000, attempt=1
# hmac_input = 736c6f74 0000000001c9c380 00000001
# slot_id = 8da6f12e878bb1270548abe7dfe2f580
```

### DEL-4: capsule_fpr (`testdata/derive/capsule_fpr.json`)

Formula: `fingerprint = HKDF-SHA256(secret=PSK, salt="", info="deaddrop-fingerprint-v2" || pair_id(8), length=16)`
Source: `SPEC_DRAFT_B_capsule.md §1.6` lines 160-166 (sole normative source).

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

PSK = bytes([0x02] * 32)
PAIR_ID = bytes([0x03] * 8)

# Case 1: canonical
info = b"deaddrop-fingerprint-v2" + PAIR_ID
# = 6465616464726f702d66696e6765727072696e742d7632 0303030303030303 (31 bytes: 23+8)
hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=b"", info=info)
fpr = hkdf.derive(PSK)
# = 9270616b0e781796d63600536027c541

# Case 2: pair_id last byte mutated (0x03 -> 0xFF)
pair_id_mut = bytes([0x03]*7) + bytes([0xFF])
info2 = b"deaddrop-fingerprint-v2" + pair_id_mut
hkdf2 = HKDF(algorithm=hashes.SHA256(), length=16, salt=b"", info=info2)
fpr2 = hkdf2.derive(PSK)
# = 972d88a0db1aa95e5312beece166238d
# Fingerprints differ: True (proves pair_id sensitivity)
```

### DEL-5: rfc_vectors (`testdata/aead/rfc_vectors.json`)

Source: `draft-irtf-cfrg-xchacha-03 §A.3.1` (IETF published draft).

The draft vectors are authoritative. Python output matches byte-for-byte:

```python
# Inputs from draft §A.3.1
key   = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
aad   = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
pt    = b"Ladies and Gentlemen of the class of '99: " \
        b"If I could offer you only one tip for the future, sunscreen would be it."

# XChaCha20-Poly1305 = HChaCha20(key, nonce[:16]) then
#   ChaCha20-Poly1305(subkey, 0x00000000 || nonce[16:24], pt, aad)
ct, tag = encrypt(key, nonce, pt, aad)

# Expected from draft:
# ct  = bd6d179d...c68b13b52e (114 bytes)
# tag = c0875924c1c7987947deafd8780acf49
# Match: True (both ct and tag)
```

Flip-bit case: AAD byte 0 flipped (0x50 -> 0x51), same ct+tag, decrypt fails as expected.

### DEL-6: ad_binding (`testdata/aead/ad_binding.json`)

Key derivation: `aead_key = HKDF-SHA256(secret=PSK, salt=slot_id_bytes(16), info="deaddrop-v1-B" || pair_id(8) || service_id_bytes(16) || version(1), length=32)`
Source: `SPEC_DRAFT_B_capsule.md §2` line 212.

AD: `service_id_bytes(16) || slot_id_bytes(16) || version(1)` = 33 bytes.
Source: `PROTOCOL.md §7` line 267.

```python
# Using canonical service_id from DEL-1 and slot_id from DEL-2
service_id = bytes.fromhex("7a78ba5bef18bfd32e35198ed3dc30b6")  # 16 bytes
slot_id    = bytes.fromhex("7f010cca7be46267194e1dac4a0f0297")  # 16 bytes

aead_info = b"deaddrop-v1-B" + PAIR_ID + service_id + bytes([0x01])
# = 6465616464726f702d76312d42 0303030303030303 7a78ba5bef18bfd32e35198ed3dc30b6 01
# (38 bytes: 13 + 8 + 16 + 1)

hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=slot_id, info=aead_info)
aead_key = hkdf.derive(PSK)
# = 9d64cde9176f319b9bd1e2aabde028bdb1410a5e91c3a07dd8bf7c249864e9f3

ad = service_id + slot_id + bytes([0x01])
# = 7a78ba5bef18bfd32e35198ed3dc30b6 7f010cca7be46267194e1dac4a0f0297 01
# (33 bytes)

nonce = bytes([0x05] * 24)
plaintext = bytes.fromhex("6465616464726f7020706861736520302e322041442062696e64696e67207465737420766563746f720a")  # 42 bytes

ct, tag = xchacha20poly1305_encrypt(aead_key, nonce, plaintext, ad)
# ct  = f61257249f12591d6885bdf6ea6eca44b1566d14b61461e83eb9c664c6cb73a0b5f91743c361c104389f
# tag = 1b842d076dd81c9aaecc3d3e8674e2f7

# Flip-bit cases (all use same ct+tag from canonical, mutated AD):
# service_id-bit0-flipped (AD[0] ^= 0x01): decrypt REJECTED
# slot_id-bit0-flipped    (AD[16] ^= 0x01): decrypt REJECTED
# version-flipped          (AD[32] ^= 0x01): decrypt REJECTED
# trailing-byte-appended   (AD + 0x00, 34 bytes): decrypt REJECTED
```

Nonce reuse warning: the 0x05-repeated nonce is a deterministic fixture value.
Real encryptions MUST use `crypto/rand.Read` (Go) or `os.urandom` (Python) for
the 24-byte nonce. Nonce reuse under XChaCha20-Poly1305 is catastrophic for
confidentiality.

## 4. Cross-checks

All mandatory independent cross-checks per DEL-0.

### Second oracle: hand-rolled RFC 2104 HMAC-SHA256

A ~10-line RFC 2104 §2 implementation using only `hashlib.sha256`:

```python
def hmac_sha256_rfc2104(key, message):
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key + b'\x00' * (block_size - len(key))
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5c for k in key)
    inner = hashlib.sha256(ipad + message).digest()
    return hashlib.sha256(opad + inner).digest()
```

### Second oracle: hand-rolled RFC 5869 HKDF-SHA256

A ~12-line RFC 5869 §2 implementation using the hand-rolled HMAC above:

```python
def hkdf_sha256_handrolled(ikm, salt, info, length):
    if salt == b"":
        salt = b'\x00' * 32
    prk = hmac_sha256_rfc2104(salt, ikm)
    n = (length + 31) // 32
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = hmac_sha256_rfc2104(prk, t_prev + info + bytes([i]))
        okm += t_prev
    return okm[:length]
```

### DEL-1 cross-check (service_id)

```
stdlib hmac:    7a78ba5bef18bfd32e35198ed3dc30b6
hand-rolled:    7a78ba5bef18bfd32e35198ed3dc30b6
Match: True
```

### DEL-2 cross-check (slot_id)

```
stdlib hmac:    7f010cca7be46267194e1dac4a0f0297
hand-rolled:    7f010cca7be46267194e1dac4a0f0297
Match: True
```

### DEL-3 cross-check (slot_key)

```
stdlib hmac:    a3e97ca4d4b813bab5be9b57ca4b9d3c5990cf3a4848a11fcd36f296a59ab762
hand-rolled:    a3e97ca4d4b813bab5be9b57ca4b9d3c5990cf3a4848a11fcd36f296a59ab762
Match: True
```

### DEL-4 cross-check (capsule_fpr)

```
cryptography:   9270616b0e781796d63600536027c541
hand-rolled:    9270616b0e781796d63600536027c541
Match: True

Case 2 (mutated pair_id):
cryptography:   972d88a0db1aa95e5312beece166238d
hand-rolled:    972d88a0db1aa95e5312beece166238d
Match: True
```

### DEL-6 cross-check (aead_key + re-encrypt)

```
aead_key (cryptography HKDF): 9d64cde9176f319b9bd1e2aabde028bdb1410a5e91c3a07dd8bf7c249864e9f3
aead_key (hand-rolled HKDF):  9d64cde9176f319b9bd1e2aabde028bdb1410a5e91c3a07dd8bf7c249864e9f3
Match: True

Re-encrypt with hand-rolled-derived aead_key:
  ciphertext match: True
  tag match: True
```

## 5. Known-unknowns

None. All formulas were unambiguous; no pending-decision entries surfaced.

The `v1` → `v2` fingerprint migration (`SPEC_DRAFT_B_capsule.md §1.6` line 176)
was noted but is not a trap for this phase: `v1` is retired, all fixtures use
`v2` exclusively. No fixture references `deaddrop-fingerprint-v1` anywhere.
