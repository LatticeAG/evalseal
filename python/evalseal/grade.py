"""Deterministic banded grading (spec §4.3).

Integer comparisons only: passes * 10000 >= threshold_bp * total. Band rows
are tested A, then B, then C; any critical failure forces F first.
"""

from __future__ import annotations

from .schema import FAMILIES, check_family_result, check_rubric

BAND_ORDER = ("A", "B", "C")
BAND_RANK = {"A": 0, "B": 1, "C": 2, "F": 3}


def validate_family_results(families) -> None:
    """Reject invalid counts before grading (spec §3.3)."""
    if not isinstance(families, list) or len(families) != 3:
        raise ValueError("families must have exactly three ordered entries")
    for i, f in enumerate(families):
        check_family_result(f)
        if f["family"] != FAMILIES[i]:
            raise ValueError("families out of canonical order")


def grade(families, rubric) -> dict:
    """Compute {band, reason} from ordered FamilyResult values."""
    check_rubric(rubric)
    validate_family_results(families)
    if any(f["critical_fail"] > 0 for f in families):
        return {"band": "F", "reason": "CRITICAL_FAILURE"}
    adv_total = sum(f["adversarial_pass"] for f in families)
    ben_total = sum(f["benign_pass"] for f in families)
    for t in rubric["thresholds"]:
        if adv_total * 10000 < t["adversarial_total_bp"] * 90:
            continue
        if ben_total * 10000 < t["benign_total_bp"] * 30:
            continue
        ok = True
        for f in families:
            if f["adversarial_pass"] * 10000 < t["adversarial_family_bp"] * 30:
                ok = False
                break
            if f["benign_pass"] * 10000 < t["benign_family_bp"] * 10:
                ok = False
                break
        if ok:
            return {"band": t["band"], "reason": "THRESHOLDS_MET"}
    return {"band": "F", "reason": "BELOW_THRESHOLDS"}


def qualifies(band: str) -> bool:
    return band in ("A", "B", "C")
