"""VisReceipt-style hash-chained audit entries and checkpoints (spec §3.4, §5).

Audit entry identity is D("audit", body); seq starts at 1 with prev_hash null.
Chains are per resource stream (run ID for run/lease/issuance/certificate
events, product ID for products, board ID for boards).
"""

from __future__ import annotations

from .canon import canonical_hash, domain_hash, is_hash
from .ids import new_id
from .schema import check_audit_entry, check_audit_payload, check_checkpoint_body

GENESIS_SEQ = 1


def new_entry(tenant_id: str, stream_id: str, prev_entry: dict | None,
              at: int, event_type: str, subject_id: str,
              state_revision: int, payload: dict,
              event_id: str | None = None) -> dict:
    """Append one AuditEntry {body, hash} to a stream. Returns the entry."""
    check_audit_payload(payload)
    body = {
        "schema": "evalseal-audit/1",
        "tenant_id": tenant_id,
        "stream_id": stream_id,
        "event_id": event_id or new_id("evt"),
        "seq": 1 if prev_entry is None else prev_entry["body"]["seq"] + 1,
        "prev_hash": None if prev_entry is None else prev_entry["hash"],
        "at": at,
        "type": event_type,
        "subject_id": subject_id,
        "state_revision": state_revision,
        "payload_hash": canonical_hash(payload),
    }
    return {"body": body, "hash": domain_hash("audit", body)}


def verify_chain(entries: list) -> str:
    """Verify a contiguous exported prefix.

    Returns "VALID" or first of: SEQ_GAP / PREV_MISMATCH / HASH_MISMATCH
    (a corrupted stored hash also surfaces as PREV_MISMATCH at its successor;
    a recompute failure on the entry itself is reported as PREV_MISMATCH).
    """
    prev = None
    for i, e in enumerate(entries):
        try:
            check_audit_entry(e)
        except Exception:
            return "PREV_MISMATCH"
        b = e["body"]
        if b["seq"] != i + 1:
            return "SEQ_GAP"
        if i == 0:
            if b["prev_hash"] is not None:
                return "PREV_MISMATCH"
        elif b["prev_hash"] != prev:
            return "PREV_MISMATCH"
        if domain_hash("audit", b) != e["hash"]:
            return "PREV_MISMATCH"
        prev = e["hash"]
    return "VALID"


def verify_against_checkpoint(entries: list, checkpoint: dict) -> str:
    """Verify the exported prefix and that it reaches the checkpoint head."""
    r = verify_chain(entries)
    if r != "VALID":
        return r
    if not entries:
        return "HEAD_MISMATCH"
    try:
        check_checkpoint_body(checkpoint["body"])
    except Exception:
        return "HEAD_MISMATCH"
    cp = checkpoint["body"]
    if cp["seq"] != entries[-1]["body"]["seq"] or cp["head"] != entries[-1]["hash"]:
        return "HEAD_MISMATCH"
    return "VALID"


def checkpoints_equivocate(cp_a: dict, cp_b: dict) -> bool:
    """Two valid signed checkpoints for the same stream+seq with different heads."""
    a, b = cp_a["body"], cp_b["body"]
    return (
        a["tenant_id"] == b["tenant_id"]
        and a["stream_id"] == b["stream_id"]
        and a["seq"] == b["seq"]
        and a["head"] != b["head"]
    )


def verify_checkpoint_set(checkpoints: list) -> str:
    """A set of signed checkpoints must never cover the same slot twice."""
    seen = {}
    for cp in checkpoints:
        try:
            check_checkpoint_body(cp["body"])
        except Exception:
            return "HEAD_MISMATCH"
        slot = (cp["body"]["tenant_id"], cp["body"]["stream_id"], cp["body"]["seq"])
        if slot in seen and seen[slot] != cp["body"]["head"]:
            return "LOG_EQUIVOCATION"
        seen[slot] = cp["body"]["head"]
    return "VALID"
