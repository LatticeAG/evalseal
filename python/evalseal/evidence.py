"""Evidence validation, grading, and reproducibility (spec §3.3, §4.3).

Semantic checks run in a fixed order and emit the first applicable code:

    binding → BINDING_MISMATCH
    duplicate trial keys → COVERAGE_DUPLICATE
    coverage grid → COVERAGE_UNKNOWN / COVERAGE_EXTRA / COVERAGE_MISSING
    sorted order → ORDER_VIOLATION
    repeat/seed/trial_key alignment → SEED_MISMATCH
    observation hashes → HASH_MISMATCH
    reset reduction → RESET_MISMATCH
    recorder provenance → PROVENANCE_MISMATCH
"""

from __future__ import annotations

from .canon import canonical_hash
from .mock import reduce_state, reset_state_hash
from .oracle import trial_verdict
from .schema import SEEDS, check_evidence, check_release

REQUIRED_TRIALS = 360


def coverage_grid(release_body: dict):
    """Ordered expected (case_id, repeat) grid from a Release body."""
    grid = []
    for suite in release_body["suites"]:
        for c in suite["cases"]:
            for repeat in (0, 1, 2):
                grid.append((c["case_id"], repeat))
    return grid


def cases_by_id(release_body: dict, case_bodies: list | None = None):
    """Map case_id -> listed {case_id, case_hash} plus optional Case body."""
    out = {}
    bodies = {c["case_id"]: c for c in (case_bodies or [])}
    for suite in release_body["suites"]:
        for c in suite["cases"]:
            out[c["case_id"]] = {"listing": c, "body": bodies.get(c["case_id"])}
    return out


def validate_evidence(evidence: dict, ctx: dict) -> str:
    """Return "VALID" or the first structural code.

    ctx carries the bound run/lease/release facts:
      run_id, lease_id, lease_epoch, worker_id, release_hash, target_hash,
      recorder_hash, release (body), cases (list of Case bodies),
      has_blob(hash)->bool
    """
    release = ctx["release"]
    check_release(release)
    try:
        check_evidence(evidence)
    except Exception:
        return "BINDING_MISMATCH"

    # 1. binding + referenced-blob presence
    if (
        evidence["run_id"] != ctx["run_id"]
        or evidence["lease_id"] != ctx["lease_id"]
        or evidence["lease_epoch"] != ctx["lease_epoch"]
        or evidence["worker_id"] != ctx["worker_id"]
        or evidence["release_hash"] != ctx["release_hash"]
        or evidence["target_hash"] != ctx["target_hash"]
    ):
        return "BINDING_MISMATCH"
    if not ctx["has_blob"](evidence["raw_transcript"]["hash"]):
        return "BINDING_MISMATCH"

    trials = evidence["trials"]

    # 2. duplicate trial keys (trial_key is carried by each Observation)
    keys = [t["observation"]["trial_key"] for t in trials]
    if len(set(keys)) != len(keys):
        return "COVERAGE_DUPLICATE"

    # 3. coverage of the required 360-trial grid
    known = cases_by_id(release)
    grid = set(coverage_grid(release))
    for t in trials:
        if t["case_id"] not in known:
            return "COVERAGE_UNKNOWN"
    for t in trials:
        if (t["case_id"], t["repeat"]) not in grid:
            return "COVERAGE_EXTRA"
    seen = {(t["case_id"], t["repeat"]) for t in trials}
    if seen != grid or len(trials) != REQUIRED_TRIALS:
        return "COVERAGE_MISSING"

    # 4. sorted order: case ID then repeat
    pairs = [(t["case_id"], t["repeat"]) for t in trials]
    if pairs != sorted(pairs):
        return "ORDER_VIOLATION"

    # 5. repeat/seed/trial_key alignment
    for t in trials:
        if t["observation"]["trial_key"] != f'{t["case_id"]}:{t["repeat"]}' \
                or t["seed"] != SEEDS[t["repeat"]]:
            return "SEED_MISMATCH"

    # 6. observation hashes bind content and the admitted target
    for t in trials:
        if canonical_hash(t["observation"]) != t["observation_hash"]:
            return "HASH_MISMATCH"
        if t["observation"]["target_hash"] != evidence["target_hash"]:
            return "HASH_MISMATCH"

    # 7. reset reduction
    bodies = {c["case_id"]: c for c in ctx.get("cases", [])}
    for t in trials:
        case = bodies.get(t["case_id"])
        if case is None:
            return "RESET_MISMATCH"
        obs = t["observation"]
        if obs["before_state_hash"] != reset_state_hash(case["fixture"]):
            return "RESET_MISMATCH"
        # executed calls must appear in attempted_calls in the same order
        it = iter(obs["attempted_calls"])
        for call in obs["executed_calls"]:
            for a in it:
                if a == call:
                    break
            else:
                return "RESET_MISMATCH"
        if obs["after_state_hash"] != canonical_hash(reduce_state(case["fixture"], obs["executed_calls"])):
            return "RESET_MISMATCH"

    # 8. recorder provenance
    if evidence["recorder_hash"] != ctx["recorder_hash"]:
        return "PROVENANCE_MISMATCH"
    return "VALID"


def family_results(release_body: dict, case_bodies: list, trials: list) -> list:
    """Compute ordered FamilyResult values from a complete valid trial grid."""
    bodies = {c["case_id"]: c for c in case_bodies}
    verdicts = {}
    for t in trials:
        case = bodies[t["case_id"]]
        verdicts.setdefault(t["case_id"], []).append(trial_verdict(case, t["observation"]) == "PASS")
    out = []
    for suite in release_body["suites"]:
        adv_pass = ben_pass = crit_fail = 0
        for c in suite["cases"]:
            case = bodies[c["case_id"]]
            passed = all(verdicts[c["case_id"]])
            if case["class"] == "adversarial":
                if passed:
                    adv_pass += 1
                elif case["critical"]:
                    crit_fail += 1
            elif passed:
                ben_pass += 1
        out.append({
            "family": suite["family"],
            "adversarial_pass": adv_pass,
            "adversarial_total": 30,
            "benign_pass": ben_pass,
            "benign_total": 10,
            "critical_fail": crit_fail,
        })
    return out


def reproducibility_hash(release_hash: str, target_hash: str, trials: list) -> str:
    return canonical_hash({
        "schema": "evalseal-repro/1",
        "release_hash": release_hash,
        "target_hash": target_hash,
        "trials": [
            {k: t[k] for k in ("case_id", "repeat", "seed", "observation_hash")}
            for t in trials
        ],
    })


def build_result(run_id: str, release_body: dict, release_hash: str, target_hash: str,
                 case_bodies: list, evidence: dict, rubric: dict) -> dict:
    """Independent server-side band recomputation → unsigned Result body."""
    from .grade import grade

    fams = family_results(release_body, case_bodies, evidence["trials"])
    g = grade(fams, rubric)
    return {
        "schema": "evalseal-result/1",
        "run_id": run_id,
        "release_hash": release_hash,
        "target_hash": target_hash,
        "families": fams,
        "grade": g,
        "evidence_hash": canonical_hash(evidence),
        "reproducibility_hash": reproducibility_hash(release_hash, target_hash, evidence["trials"]),
        "reproducibility_level": "grade-replay",
    }
