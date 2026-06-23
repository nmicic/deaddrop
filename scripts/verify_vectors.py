#!/usr/bin/env python3
"""Principal re-derivation script for golden vectors.

Independently verifies service_id, slot_key, and capsule_fpr against
the committed testdata/derive/*.json fixtures. Run with:

    python3 scripts/verify_vectors.py

Exits 0 if all vectors match; exits 1 on any mismatch.
"""

import hmac
import hashlib
import struct
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def verify_service_id():
    """Verify service_id derivation vectors."""
    with open("testdata/derive/service_id.json") as f:
        data = json.load(f)

    for case in data["cases"]:
        deploy_secret = bytes.fromhex(case["inputs"]["DEPLOY_SECRET"])
        h = case["inputs"]["h"]
        msg = b"svc" + struct.pack(">Q", h)
        result = hmac.new(deploy_secret, msg, hashlib.sha256).digest()[:16]
        expected = case["expected_hex"]
        assert result.hex() == expected, (
            f"service_id {case['name']}: got {result.hex()}, want {expected}"
        )
        print(f"  service_id {case['name']}: {result.hex()} OK")


def verify_slot_key():
    """Verify slot_key derivation vector."""
    with open("testdata/derive/slot_key.json") as f:
        data = json.load(f)

    case = data["cases"][0]
    psk = bytes.fromhex(case["inputs"]["PSK"])
    pair_id = bytes.fromhex(case["inputs"]["pair_id"])
    msg = b"slot-key-v1" + pair_id
    result = hmac.new(psk, msg, hashlib.sha256).digest()
    expected = case["expected_hex"]
    assert result.hex() == expected, (
        f"slot_key: got {result.hex()}, want {expected}"
    )
    print(f"  slot_key: {result.hex()} OK")
    return result.hex()


def verify_slot_id(slot_key_hex):
    """Verify slot_id derivation vectors."""
    with open("testdata/derive/slot.json") as f:
        data = json.load(f)

    for case in data["cases"]:
        sk = bytes.fromhex(case["inputs"]["slot_key"])
        b = case["inputs"]["b"]
        attempt = case["inputs"]["attempt"]
        msg = b"slot" + struct.pack(">Q", b) + struct.pack(">I", attempt)
        result = hmac.new(sk, msg, hashlib.sha256).digest()[:16]
        expected = case["expected_hex"]
        assert result.hex() == expected, (
            f"slot_id {case['name']}: got {result.hex()}, want {expected}"
        )
        print(f"  slot_id {case['name']}: {result.hex()} OK")


def verify_capsule_fpr():
    """Verify capsule fingerprint derivation vectors."""
    with open("testdata/derive/capsule_fpr.json") as f:
        data = json.load(f)

    for case in data["cases"]:
        psk = bytes.fromhex(case["inputs"]["PSK"])
        pair_id = bytes.fromhex(case["inputs"]["pair_id"])
        info = b"deaddrop-fingerprint-v2" + pair_id
        hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=b"", info=info)
        result = hkdf.derive(psk)
        expected = case["expected_hex"]
        assert result.hex() == expected, (
            f"capsule_fpr {case['name']}: got {result.hex()}, want {expected}"
        )
        print(f"  capsule_fpr {case['name']}: {result.hex()} OK")


def main():
    print("Principal re-derivation of golden vectors")
    print("=" * 50)

    try:
        print("\nservice_id vectors:")
        verify_service_id()

        print("\nslot_key vector:")
        slot_key_hex = verify_slot_key()

        print("\nslot_id vectors:")
        verify_slot_id(slot_key_hex)

        print("\ncapsule_fpr vectors:")
        verify_capsule_fpr()

        print("\n" + "=" * 50)
        print("ALL VECTORS MATCH")
        return 0
    except AssertionError as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
