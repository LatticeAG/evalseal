"""Ed25519 signing and verification for evalseal-signed/1 envelopes (spec §3.4).

Signature message: UTF8("evalseal/1/signature\n" + kind + "\n" + key_id + "\n" + body_hash).
body_hash = D(kind, body). References to a signed artifact use H(envelope).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .canon import canonical_hash, domain_hash, signature_message
from .schema import KINDS, SIGNED_BODY_VALIDATORS, SchemaError, check_signed


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_envelope(kind: str, key_id: str, body, sk: Ed25519PrivateKey) -> dict:
    """Produce a complete evalseal-signed/1 envelope."""
    if kind not in KINDS:
        raise SchemaError("sign.kind")
    SIGNED_BODY_VALIDATORS[kind](body)
    body_hash = domain_hash(kind, body)
    sig = sk.sign(signature_message(kind, key_id, body_hash))
    return {
        "schema": "evalseal-signed/1",
        "kind": kind,
        "key_id": key_id,
        "body_hash": body_hash,
        "body": body,
        "signature": b64u(sig),
    }


def verify_envelope(envelope, kind: str, key: dict) -> str:
    """Verify a Signed envelope against a Key object.

    Returns "VALID" or the first integrity code: BAD_SCHEMA / HASH_MISMATCH /
    KEY_UNKNOWN / KEY_REVOKED / SIGNATURE_INVALID.
    """
    try:
        check_signed(envelope, SIGNED_BODY_VALIDATORS.get(kind), kind)
    except SchemaError:
        return "BAD_SCHEMA"
    if envelope["key_id"] != key["key_id"]:
        return "KEY_UNKNOWN"
    if domain_hash(kind, envelope["body"]) != envelope["body_hash"]:
        return "HASH_MISMATCH"
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_decode(key["public_key"]))
        sig = b64u_decode(envelope["signature"])
        if len(sig) != 64:
            return "SIGNATURE_INVALID"
        pk.verify(sig, signature_message(kind, key["key_id"], envelope["body_hash"]))
    except (InvalidSignature, ValueError):
        return "SIGNATURE_INVALID"
    return "VALID"


def find_key(keys: list, key_id: str):
    for k in keys:
        if k["key_id"] == key_id:
            return k
    return None


def verify_with_keyring(envelope, kind: str, keyring_body: dict, now: int | None = None) -> str:
    """Verify an envelope using a keyring body: role, revocation, and validity."""
    key = find_key(keyring_body["keys"], envelope.get("key_id", ""))
    if key is None:
        return "KEY_UNKNOWN"
    if key["revoked"]:
        return "KEY_REVOKED"
    if kind not in key["roles"]:
        return "KEY_ROLE"
    if now is not None and not (key["not_before"] <= now <= key["not_after"]):
        return "KEY_INACTIVE"
    return verify_envelope(envelope, kind, key)


# RFC 8032 test seed used by the spec fixture. Production trust-root loading
# must reject it (spec §7.2).
RFC8032_TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_TEST_PUBLIC_B64 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def key_id_for_public_key(public_key_b64: str) -> str:
    """Stable operator key id: es_key_ + first 21 base64url chars of SHA-256(pk)."""
    from .canon import sha256_hex
    import hashlib

    digest = hashlib.sha256(b64u_decode(public_key_b64)).digest()
    return "es_key_" + b64u(digest)[:21]


def is_test_key(public_key_b64: str) -> bool:
    return public_key_b64 == RFC8032_TEST_PUBLIC_B64
