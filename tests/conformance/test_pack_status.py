"""TV-E--39..49, 58, 61: status semantics, packs, audit, zip bounds."""

import copy
import struct
import zlib

from evalseal import fixture as fx
from evalseal.audit import (checkpoints_equivocate, verify_against_checkpoint,
                            verify_chain, verify_checkpoint_set)
from evalseal.canon import canonical_hash, domain_hash
from evalseal.pack import current, verify_pack, zip_check
from evalseal.render import badge_lines, render_badge_unknown, render_page
from evalseal.sign import sign_envelope

ROOTS = fx.KEYRING["body"]["keys"]
KEY = ROOTS[0]


def pack_opts(**kw):
    o = {"root_keys": ROOTS, "now": fx.T0 + 70, "status": None,
         "keyring": None, "min_keyring_epoch": 1, "keyring_observed_at": fx.T0 + 65}
    o.update(kw)
    return o


def test_tv_e_39_expiry_exact_boundary():
    # validly signed status as_of=EXP+59 cannot extend validity to now=EXP+60
    status = fx.signed("status", dict(fx.STATUS["body"], as_of=fx.EXP + 59,
                                    valid_until=fx.EXP + 119))
    cur, reasons = current(fx.CERT, status, fx.KEYRING, fx.EXP + 60, 1)
    assert cur == "NOT_QUALIFIED"
    assert reasons == ["CERT_EXPIRED"]


def test_tv_e_40_offline_signature_is_not_current_certification(tmp_path):
    pack = fx.pack_bytes()
    v = verify_pack(pack, pack_opts(status=None, keyring_observed_at=None))
    assert v == {"integrity": "VALID", "band": "A", "coverage": "summary-only",
                 "current": "UNKNOWN", "reasons": ["STATUS_MISSING"]}


def test_tv_e_41_public_redaction_limits_replay_claims():
    pack = fx.pack_bytes()  # public pack: no evidence.json/transcript.bin
    status = fx.final_status()
    status = fx.signed("status", dict(status["body"], as_of=fx.T0 + 70,
                                      valid_until=fx.T0 + 130))
    v = verify_pack(pack, pack_opts(status=status))
    assert v["integrity"] == "VALID"
    assert v["coverage"] == "summary-only"
    assert v["current"] == "QUALIFIES"


def test_tv_e_42_expired_status_cannot_remain_green():
    status = fx.signed("status", dict(fx.STATUS["body"], as_of=fx.T0 + 60,
                                    valid_until=fx.T0 + 120))
    cur, reasons = current(fx.CERT, status, fx.KEYRING, fx.T0 + 120, 1)
    assert cur == "UNKNOWN"
    assert reasons == ["STATUS_STALE"]
    assert b"STATUS UNKNOWN" in render_badge_unknown(fx.CERT, fx.T0 + 120)


def test_tv_e_43_compromised_signing_key():
    # root-authorized keyring epoch 2 marks K revoked
    key2 = dict(KEY, revoked=True)
    kr2 = fx.signed("keyring", {
        "schema": "evalseal-keyring/1", "epoch": 2, "issued_at": fx.T0 + 65,
        "valid_until": fx.T0 + 86400, "keys": [key2],
        "previous_hash": canonical_hash(fx.KEYRING)})
    status = fx.signed("status", dict(fx.final_status()["body"], as_of=fx.T0 + 70,
                                    valid_until=fx.T0 + 130))
    cur, reasons = current(fx.CERT, status, kr2, fx.T0 + 70, 1)
    assert cur == "NOT_QUALIFIED"
    assert reasons == ["KEY_REVOKED"]
    # an earlier issued_at cannot rescue a revoked key
    cur2, _ = current(fx.CERT, status, kr2, fx.T0 + 70, 1)
    assert cur2 == "NOT_QUALIFIED"


def test_tv_e_44_missing_audit_predecessor():
    assert verify_against_checkpoint([fx.AUDIT[0], fx.AUDIT[2]], fx.CHECKPOINT) == "SEQ_GAP"


def test_tv_e_45_observed_signed_fork():
    alt_head = domain_hash("audit", dict(fx.AUDIT[2]["body"], at=fx.T0 + 61))
    cp2 = fx.signed("checkpoint", dict(fx.CHECKPOINT["body"], head=alt_head))
    assert checkpoints_equivocate(fx.CHECKPOINT, cp2)
    assert verify_checkpoint_set([fx.CHECKPOINT, cp2]) == "LOG_EQUIVOCATION"


def test_tv_e_46_renderer_treats_markup_as_text():
    cert = fx.signed("certificate", dict(fx.CERT_BODY,
                                         product_label="<script>alert(1)</script>"))
    page = render_page(cert, fx.RESULT, fx.STATUS, fx.RELEASE)
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert b"<script>" not in page


def test_tv_e_47_client_cannot_choose_ssrf_origin(svc):
    from conftest import TOK_OWNER, call
    st, r = call(svc, TOK_OWNER, "product.create",
                 {"label": "Agent", "target_ref": "http://169.254.169.254"}, "k47")
    assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"


def _hand_zip(name: bytes, declared_size: int, payload: bytes) -> bytes:
    """Minimal STORE archive whose central directory lies about sizes."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0,
                        crc, declared_size, declared_size, len(name), 0) + name + payload
    cdir = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0,
                       crc, declared_size, declared_size, len(name), 0, 0, 0, 0,
                       0, 0)
    cdir += name
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cdir), len(local), 0)
    return local + cdir + eocd


def test_tv_e_48_pack_traversal():
    data = _hand_zip(b"../certificate.json", 1, b"x")
    assert zip_check(data) == "PACK_PATH_INVALID"


def test_tv_e_49_archive_bomb_bound():
    data = _hand_zip(b"report.pdf", 33554433, b"x")
    assert zip_check(data) == "PACK_SIZE_LIMIT"


def test_tv_e_58_full_badge_scope_cannot_be_shortened(svc):
    from conftest import get
    st, r = get(svc, "/badges/" + fx.C + ".svg?style=compact")
    assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"
    lines = badge_lines(fx.CERT, fx.STATUS)
    for s in fx.SCOPE:
        assert s in lines
    joined = "\n".join(lines)
    assert fx.HT in joined
    assert "Expiry:" in joined
    assert "/certificates/" + fx.C in joined


def test_tv_e_61_fresh_forged_status_cannot_refresh_old_keyring():
    status = fx.signed("status", dict(fx.STATUS["body"], as_of=fx.T0 + 3600,
                                    valid_until=fx.T0 + 3660))
    cur, reasons = current(fx.CERT, status, fx.KEYRING, fx.T0 + 3600, 1,
                           keyring_observed_at=None)
    assert cur == "UNKNOWN"
    assert reasons == ["KEYRING_STALE"]
