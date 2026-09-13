"""Emit an evalseal-devservice/1 provisioning document for the reference server.

Usage: python3 provision.py > provision.json
Uses the in-repo Python package (tests/conformance sys.path convention).
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

import time  # noqa: E402

from evalseal import fixture as fx  # noqa: E402
from evalseal.mock import RECORDER_HASH  # noqa: E402

TENANT_B = fx.idof("tnt", "B")

NOW = int(time.time())
KEYRING = fx.signed("keyring", {
    "schema": "evalseal-keyring/1", "epoch": 1, "issued_at": NOW - 10,
    "valid_until": NOW - 10 + 86400,
    "keys": fx.KEYRING["body"]["keys"],
    "previous_hash": None,
})

PROV = {
    "schema": "evalseal-devservice/1",
    "issuer_seed_hex": fx.SK.private_bytes_raw().hex()
        if hasattr(fx.SK, "private_bytes_raw")
        else fx.SK.private_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.Raw,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PrivateFormat.Raw,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).NoEncryption(),
        ).hex(),
    "issuer_key_id": fx.K,
    "keyring": KEYRING,
    "principals": [
        {"token": "tok-owner", "principal_id": "owner-1", "tenant_id": fx.T, "role": "owner"},
        {"token": "tok-submitter", "principal_id": "sub-1", "tenant_id": fx.T, "role": "submitter"},
        {"token": "tok-reader", "principal_id": "reader-1", "tenant_id": fx.T, "role": "reader"},
        {"token": "tok-tenant-b-reader", "principal_id": "reader-b", "tenant_id": TENANT_B, "role": "reader"},
        {"token": "tok-operator", "principal_id": "op-1", "tenant_id": None, "role": "issuer-operator"},
    ],
    "workers": [{
        "token": "tok-worker",
        "entry": {"worker_id": fx.W, "tenant_id": fx.T, "recorder_hash": RECORDER_HASH,
                  "identity_env": "EVALSEAL_WORKER_TOKEN", "capacity": 1},
    }],
    "targets": [
        {"tenant_id": fx.T, "target_ref": "target-fixture", "target": fx.TARGET},
        {"tenant_id": TENANT_B, "target_ref": "target-fixture", "target": fx.TARGET},
    ],
    "releases": [{
        "signed": fx.RELEASE,
        "cases": fx.CASES,
        "sources": {"fixture.json": base64.b64encode(fx.SOURCE).decode()},
    }],
}

json.dump(PROV, sys.stdout)
