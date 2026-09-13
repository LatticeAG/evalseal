"""Attestation pack build + offline verification (spec §9.2, §9.4, §7.5).

verify_pack(bytes, options) -> Verification. Integrity first, then explicit
revocation/expiry/nonqualifying band, then missing/stale status, then keyring
freshness. Offline integrity and current qualification are separate outputs.
"""

from __future__ import annotations

from .audit import verify_against_checkpoint, verify_chain
from .canon import JsonError, canonical_hash, domain_hash, is_hash, parse
from .evidence import family_results, reproducibility_hash
from .grade import grade, qualifies
from .oracle import evaluate_oracle
from .schema import (
    FAMILIES, SchemaError, check_audit_entry, check_case, check_checkpoint_body,
    check_certificate_body, check_keyring_body, check_pack_body, check_release,
    check_result, check_status_body, check_target,
)
from .sign import b64u_decode, find_key, verify_envelope
from .zipio import PRIVATE_EXTRA, PUBLIC_ENTRIES, ZipError, read_directory, extract

# The built-in closed-oracle evaluator identity. A release pins oracle_hash;
# full-replay coverage requires the pinned oracle to be one this verifier
# implements (spec §9.2 "unsupported oracle code yields INVALID").
ORACLE_IMPL = {"schema": "evalseal-oracle-impl/1", "name": "evalseal-closed-oracle", "version": "1.0.0"}
SUPPORTED_ORACLE_HASHES = {canonical_hash(ORACLE_IMPL)}

SIGNING_KIND_ROLES = {
    "certificate": "certificate", "pack": "pack", "checkpoint": "checkpoint",
    "status": "status", "keyring": "keyring", "release": "release",
    "release-index": "release-index",
}
ROOT_KINDS = ("release", "release-index", "keyring")


def _parse_json(data: bytes):
    return parse(data)


def _sig_verify(envelope, kind: str, keys) -> str:
    """Mathematical signature check: schema, body_hash, key presence, signature."""
    if not isinstance(envelope, dict) or envelope.get("kind") != kind:
        return "MANIFEST_INVALID" if kind == "pack" else "BAD_SCHEMA"
    from .schema import SIGNED_BODY_VALIDATORS, check_signed
    try:
        check_signed(envelope, SIGNED_BODY_VALIDATORS[kind], kind)
    except SchemaError:
        return "MANIFEST_INVALID" if kind == "pack" else "BAD_SCHEMA"
    if domain_hash(kind, envelope["body"]) != envelope["body_hash"]:
        return "HASH_MISMATCH"
    key = find_key(keys, envelope["key_id"])
    if key is None:
        return "KEY_UNKNOWN"
    if kind not in key["roles"]:
        return "KEY_UNKNOWN"
    return verify_envelope(envelope, kind, key)


def zip_check(data: bytes) -> str:
    """Validate declared names/sizes before extraction; return code or 'VALID'."""
    try:
        read_directory(data)
        return "VALID"
    except ZipError as e:
        return e.code


def _keyring_selected(embedded, supplied) -> object:
    """options.keyring supersedes the embedded one when its epoch is >=."""
    if supplied is None:
        return embedded, None
    try:
        check_keyring_body(supplied["body"])
    except Exception:
        return embedded, "KEYRING_STALE"
    if supplied["body"]["epoch"] >= embedded["body"]["epoch"]:
        return supplied, None
    return embedded, None


def _check_keyring_trust(kr_envelope, root_keys) -> bool:
    """Root signature + keyring role, verified against locally pinned roots."""
    if not isinstance(kr_envelope, dict) or kr_envelope.get("kind") != "keyring":
        return False
    try:
        check_keyring_body(kr_envelope["body"])
    except Exception:
        return False
    key = find_key(root_keys, kr_envelope["key_id"])
    if key is None or "keyring" not in key["roles"]:
        return False
    return verify_envelope(kr_envelope, "keyring", key) == "VALID"


def current(cert, status, keyring, now, min_keyring_epoch=0, keyring_observed_at=None) -> tuple:
    """(current, reasons) — QUALIFIES / NOT_QUALIFIED / UNKNOWN.

    cert: Signed<Certificate> (integrity already established by caller).
    status: Signed<Status> | None. keyring: Signed<Keyring> selected body holder.
    """
    reasons = []
    cb = cert["body"]
    keys = keyring["body"]["keys"]

    # explicit expiry / revocation / nonqualifying band
    if now >= cb["expires_at"]:
        return "NOT_QUALIFIED", ["CERT_EXPIRED"]
    skey = find_key(keys, cert["key_id"])
    if skey is None:
        reasons.append("KEY_UNKNOWN")
        return "UNKNOWN", reasons
    if skey["revoked"]:
        return "NOT_QUALIFIED", ["KEY_REVOKED"]

    if cb["band"] == "F":
        return "NOT_QUALIFIED", ["BAND_NOT_QUALIFYING"]

    # status freshness and binding
    if status is None:
        return "UNKNOWN", ["STATUS_MISSING"]
    try:
        check_status_body(status["body"])
    except Exception:
        return "UNKNOWN", ["STATUS_MISMATCH"]
    if status["kind"] != "status":
        return "UNKNOWN", ["STATUS_MISMATCH"]
    sk = find_key(keys, status["key_id"])
    if sk is None or "status" not in sk["roles"]:
        return "UNKNOWN", ["KEY_UNKNOWN"]
    if verify_envelope(status, "status", sk) != "VALID":
        return "UNKNOWN", ["STATUS_MISMATCH"]
    sb = status["body"]
    if sb["certificate_id"] != cb["certificate_id"] or sb["certificate_hash"] != canonical_hash(cert):
        return "UNKNOWN", ["STATUS_MISMATCH"]
    # independently recompute qualifies
    expected_q = sb["state"] == "ACTIVE" and cb["band"] != "F" and now < cb["expires_at"]
    if sb["state"] == "REVOKED":
        return "NOT_QUALIFIED", ["CERT_REVOKED"]
    if sb["state"] == "EXPIRED":
        return "NOT_QUALIFIED", ["CERT_EXPIRED"]
    if not (sb["as_of"] <= now < sb["valid_until"]):
        return "UNKNOWN", ["STATUS_STALE"]
    if sb["qualifies"] != expected_q:
        return "UNKNOWN", ["STATUS_MISMATCH"]

    # keyring freshness: 0 <= now - max(issued_at, observed_at or 0) < 60
    kb = keyring["body"]
    if kb["epoch"] < min_keyring_epoch:
        return "UNKNOWN", ["KEYRING_STALE"]
    if now > kb["valid_until"]:
        return "UNKNOWN", ["KEYRING_STALE"]
    freshness_base = max(kb["issued_at"], keyring_observed_at or 0)
    if not (0 <= now - freshness_base < 60):
        return "UNKNOWN", ["KEYRING_STALE"]
    if sb["qualifies"]:
        return "QUALIFIES", []
    return "NOT_QUALIFIED", ["BAND_NOT_QUALIFYING"] if cb["band"] == "F" else []


def verify_pack(data: bytes, options: dict) -> dict:
    """Offline pack verification. See spec §7.5 for the exact signature."""
    now = options["now"]
    root_keys = options["root_keys"]
    status = options.get("status")
    supplied_keyring = options.get("keyring")
    min_epoch = options.get("min_keyring_epoch", 0)
    observed_at = options.get("keyring_observed_at")

    out = {"integrity": "INVALID", "band": None, "coverage": "none", "current": "UNKNOWN", "reasons": []}

    # 1. ZIP bounds: names/sizes before any extraction
    code = zip_check(data)
    if code != "VALID":
        out["reasons"] = [code]
        return out
    try:
        files = extract(data, read_directory(data))
    except ZipError as e:
        out["reasons"] = [e.code]
        return out

    # 2. parse + schema-check all JSON members
    try:
        cert = _parse_json(files["certificate.json"])
        release = _parse_json(files["release.json"])
        checkpoint = _parse_json(files["checkpoint.json"])
        keyring = _parse_json(files["keyring.json"])
        manifest_env = _parse_json(files["manifest.json"])
        result = _parse_json(files["result.json"])
        target = _parse_json(files["target.json"])
        cases = _parse_json(files["cases.json"])
        audit_lines = [ln for ln in files["audit.jsonl"].split(b"\n") if ln]
        audit = [_parse_json(ln) for ln in audit_lines]
    except (JsonError, KeyError):
        out["reasons"] = ["PACK_ENTRY_INVALID"]
        return out

    return _verify_parsed(files, cert, release, checkpoint, keyring, manifest_env,
                          result, target, cases, audit, now, root_keys, status,
                          supplied_keyring, min_epoch, observed_at)


def _verify_parsed(files, cert, release, checkpoint, keyring, manifest_env,
                   result, target, cases, audit, now, root_keys, status,
                   supplied_keyring, min_epoch, observed_at):
    out = {"integrity": "INVALID", "band": None, "coverage": "none", "current": "UNKNOWN", "reasons": []}

    try:
        check_certificate_body(cert["body"]) if isinstance(cert, dict) else None
        from .schema import check_signed, SIGNED_BODY_VALIDATORS
        check_signed(cert, SIGNED_BODY_VALIDATORS["certificate"], "certificate")
        check_signed(release, SIGNED_BODY_VALIDATORS["release"], "release")
        check_signed(checkpoint, SIGNED_BODY_VALIDATORS["checkpoint"], "checkpoint")
        check_signed(keyring, SIGNED_BODY_VALIDATORS["keyring"], "keyring")
        check_signed(manifest_env, SIGNED_BODY_VALIDATORS["pack"], "pack")
        check_result(result)
        check_target(target)
        if not isinstance(cases, list) or len(cases) != 120:
            raise SchemaError("cases")
        for c in cases:
            check_case(c)
        for e in audit:
            check_audit_entry(e)
    except (SchemaError, KeyError, TypeError):
        out["reasons"] = ["PACK_ENTRY_INVALID"]
        return out

    # keyring trust chain: embedded and supplied must be root-signed
    if not _check_keyring_trust(keyring, root_keys):
        out["reasons"] = ["KEY_UNKNOWN"]
        return out
    if supplied_keyring is not None and not _check_keyring_trust(supplied_keyring, root_keys):
        out["reasons"] = ["KEYRING_STALE"]
        return out
    keyring_sel, kerr = _keyring_selected(keyring, supplied_keyring)
    if kerr:
        out["reasons"] = [kerr]
        return out
    keys = keyring_sel["body"]["keys"]

    # signature verification under the selected keyring / roots
    r = _sig_verify(release, "release", root_keys)
    if r != "VALID":
        out["reasons"] = [r]
        return out
    for env, kind in ((cert, "certificate"), (manifest_env, "pack"), (checkpoint, "checkpoint")):
        r = _sig_verify(env, kind, keys)
        if r != "VALID":
            out["reasons"] = ["MANIFEST_INVALID" if kind == "pack" else r]
            return out

    # manifest binds every other file
    mb = manifest_env["body"]
    if mb["certificate_hash"] != canonical_hash(cert):
        out["reasons"] = ["MANIFEST_INVALID"]
        return out
    declared = {f["path"]: f for f in mb["files"]}
    if set(declared) != set(files.keys()) - {"manifest.json"}:
        out["reasons"] = ["MANIFEST_INVALID"]
        return out
    for name, blob in files.items():
        if name == "manifest.json":
            continue
        f = declared[name]
        from .canon import blob_hash
        if f["bytes"] != len(blob) or f["hash"] != blob_hash(blob):
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out
    # disclosure set consistency
    has_private = any(n in PRIVATE_EXTRA for n in files)
    if mb["disclosure"] == "public-redacted" and has_private:
        out["reasons"] = ["PACK_PATH_INVALID"]
        return out
    if mb["disclosure"] == "private-full" and set(PRIVATE_EXTRA) - set(files):
        out["reasons"] = ["PACK_PATH_INVALID"]
        return out

    # certificate/result/release/target binding
    cb = cert["body"]
    if (cb["release_hash"] != canonical_hash(release)
            or cb["target_hash"] != canonical_hash(target)
            or cb["result_hash"] != canonical_hash(result)
            or cb["scope_lines"] != release["body"]["scope_lines"]):
        out["reasons"] = ["MANIFEST_INVALID"]
        return out

    # cases match the release's pinned case hashes
    listing = {}
    for s in release["body"]["suites"]:
        for c in s["cases"]:
            listing[c["case_id"]] = c["case_hash"]
    if len(listing) != 120 or {c["case_id"] for c in cases} != set(listing):
        out["reasons"] = ["PACK_ENTRY_INVALID"]
        return out
    for c in cases:
        if canonical_hash(c) != listing[c["case_id"]]:
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out

    # committed totals recompute to the band (summary path always checked)
    try:
        recomputed = grade(result["families"], release["body"]["rubric"])
    except Exception:
        out["reasons"] = ["PACK_ENTRY_INVALID"]
        return out
    if recomputed != result["grade"] or result["grade"]["band"] != cb["band"]:
        out["reasons"] = ["MANIFEST_INVALID"]
        return out
    if result["release_hash"] != canonical_hash(release) or result["target_hash"] != canonical_hash(target):
        out["reasons"] = ["MANIFEST_INVALID"]
        return out

    # audit prefix through certificate.evidence_head + checkpoint anchor
    rc = verify_against_checkpoint(audit, checkpoint)
    if rc != "VALID":
        out["reasons"] = [rc]
        return out
    if audit and audit[-1]["hash"] != cb["evidence_head"]:
        out["reasons"] = ["HEAD_MISMATCH"]
        return out

    # coverage: full-replay only when evidence + transcript present and the
    # pinned oracle is implemented by this verifier
    coverage = "summary-only"
    if has_private:
        if release["body"]["oracle_hash"] not in SUPPORTED_ORACLE_HASHES:
            out["reasons"] = ["ORACLE_UNSUPPORTED"]
            return out
        evidence = _parse_json(files["evidence.json"])
        transcript = files["transcript.bin"]
        from .canon import blob_hash
        rt = evidence["raw_transcript"]
        if rt["hash"] != blob_hash(transcript) or rt["bytes"] != len(transcript):
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out
        if canonical_hash(evidence) != result["evidence_hash"]:
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out
        # replay every observation through the closed oracles + reset reduction
        from .mock import reduce_state, reset_state_hash
        bodies = {c["case_id"]: c for c in cases}
        for t in evidence["trials"]:
            case = bodies[t["case_id"]]
            obs = t["observation"]
            if canonical_hash(obs) != t["observation_hash"]:
                out["reasons"] = ["HASH_MISMATCH"]
                return out
            if obs["before_state_hash"] != reset_state_hash(case["fixture"]):
                out["reasons"] = ["RESET_MISMATCH"]
                return out
            if obs["after_state_hash"] != canonical_hash(reduce_state(case["fixture"], obs["executed_calls"])):
                out["reasons"] = ["RESET_MISMATCH"]
                return out
        fams = family_results(release["body"], cases, evidence["trials"])
        if fams != result["families"]:
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out
        if reproducibility_hash(result["release_hash"], result["target_hash"], evidence["trials"]) != result["reproducibility_hash"]:
            out["reasons"] = ["PACK_ENTRY_INVALID"]
            return out
        coverage = "full-replay"

    out["integrity"] = "VALID"
    out["band"] = cb["band"]
    out["coverage"] = coverage
    cur, reasons = current(cert, status, keyring_sel, now, min_epoch, observed_at)
    out["current"] = cur
    out["reasons"] = reasons
    return out
