"""TV-E--01..09: canonicalization, parsing, signatures (spec §14.1)."""

import copy

import pytest

from evalseal import fixture as fx
from evalseal.canon import JsonError, canonical_hash, canonicalize, parse
from evalseal.schema import SchemaError
from evalseal.sign import find_key, verify_envelope

KEY = fx.KEYRING["body"]["keys"][0]


def test_tv_e_01_canonical_object_hash():
    assert canonical_hash({}) == \
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_tv_e_02_key_order_is_not_identity():
    assert canonical_hash({"b": 2, "a": 1}) == canonical_hash({"a": 1, "b": 2})
    assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_tv_e_03_duplicate_json_member():
    with pytest.raises(JsonError) as e:
        parse(b'{"track":"private","track":"public"}')
    assert e.value.code == "BAD_JSON"


def test_tv_e_04_unsafe_numeric_domain():
    with pytest.raises(JsonError) as e:
        parse(b'{"revision":9007199254740992}')
    assert e.value.code == "BAD_SCHEMA"


def test_tv_e_05_negative_zero_rejected():
    with pytest.raises(JsonError) as e:
        parse(b'{"revision":-0}')
    assert e.value.code == "BAD_SCHEMA"


def test_tv_e_06_id_prefix_confusion(svc):
    st, r = call_cancel(svc, fx.P)   # es_prd_* where a run ID is required
    assert st == 400
    assert r["error"]["code"] == "BAD_SCHEMA"


def call_cancel(svc, run_id):
    from conftest import call, TOK_OWNER
    return call(svc, TOK_OWNER, "run.cancel",
                {"run_id": run_id, "expected_revision": 1, "reason": "OWNER_CANCELLED"},
                "k-tv06")


def test_tv_e_07_valid_domain_bound_certificate_signature():
    assert verify_envelope(fx.CERT, "certificate", KEY) == "VALID"


def test_tv_e_08_signed_body_mutation():
    env = copy.deepcopy(fx.CERT)
    env["body"]["band"] = "B"
    assert verify_envelope(env, "certificate", KEY) == "HASH_MISMATCH"


def test_tv_e_09_cross_role_signature_substitution():
    env = copy.deepcopy(fx.CERT)
    env["kind"] = "release"
    assert verify_envelope(env, "release", KEY) == "BAD_SCHEMA"
