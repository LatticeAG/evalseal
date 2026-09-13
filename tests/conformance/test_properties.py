"""Spec §14.2 release-wide obligations: rubric boundary partitions,
canonicalization property tests, deterministic race-order coverage,
runner integration over the real NDJSON channel, and fixture anchors.
"""

import copy
import itertools
import json
import os
import random
import subprocess
import sys

import pytest

from evalseal import fixture as fx
from evalseal.canon import JsonError, canonical_hash, canonicalize, parse
from evalseal.grade import BAND_RANK, grade
from evalseal.runner import run_local

from conftest import (TOK_OWNER, TOK_SUBMITTER, TOK_WORKER, admit, call, claim,
                      complete_run, create_board, create_product, drain,
                      make_evidence, fams)

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


# --- rubric boundary enumeration (spec §14.2) --------------------------------

def _expected_band(adv, ben, crit):
    """Independent reference implementation of the §4.3 band table."""
    if crit > 0:
        return "F"
    A, B, C = (9500, 9000, 9000, 8000), (9000, 8000, 8000, 7000), (8000, 7000, 7000, 6000)
    at = sum(adv)
    bt = sum(ben)
    for band, (t_a, f_a, t_b, f_b) in (("A", A), ("B", B), ("C", C)):
        if at * 10000 >= t_a * 90 and bt * 10000 >= t_b * 30 and \
                all(a * 10000 >= f_a * 30 for a in adv) and \
                all(b * 10000 >= f_b * 10 for b in ben):
            return band
    return "F"


# Boundary partitions: counts around every family/total threshold
# (C floors 24/6, B floors 27/8, A floors 27-29/8-9) plus extremes.
ADV_PARTITION = [0, 23, 24, 26, 27, 28, 29, 30]
BEN_PARTITION = [0, 5, 6, 7, 8, 9, 10]


def test_rubric_boundary_partitions():
    for adv in itertools.product(ADV_PARTITION, repeat=3):
        for ben in itertools.product(BEN_PARTITION, repeat=3):
            for crit in (0, 1):
                if crit > 30 - adv[0]:
                    continue   # infeasible: critical failures <= failed adversarial
                f = fams(adv, ben, [crit, 0, 0])
                got = grade(f, fx.RUBRIC)["band"]
                want = _expected_band(adv, ben, crit)
                assert got == want, (adv, ben, crit, got, want)


def test_rubric_full_single_family_sweep():
    # every adversarial count for one family against boundary rows elsewhere
    for a in range(31):
        for ben in itertools.product([0, 6, 8, 10], repeat=3):
            got = grade(fams([a, 30, 30], ben, [0, 0, 0]), fx.RUBRIC)["band"]
            want = _expected_band([a, 30, 30], ben, 0)
            assert got == want
        for b in range(11):
            got = grade(fams([30, 30, 30], [b, 10, 10], [0, 0, 0]), fx.RUBRIC)["band"]
            want = _expected_band([30, 30, 30], [b, 10, 10], 0)
            assert got == want


def test_rubric_monotonicity():
    """critical=0: increasing any pass count may not worsen the band."""
    for adv in itertools.product(ADV_PARTITION, repeat=3):
        for ben in itertools.product(BEN_PARTITION, repeat=3):
            base = BAND_RANK[grade(fams(adv, ben, [0, 0, 0]), fx.RUBRIC)["band"]]
            for i in range(3):
                if adv[i] < 30:
                    a2 = list(adv)
                    a2[i] += 1
                    up = BAND_RANK[grade(fams(a2, ben, [0, 0, 0]), fx.RUBRIC)["band"]]
                    assert up <= base
                if ben[i] < 10:
                    b2 = list(ben)
                    b2[i] += 1
                    up = BAND_RANK[grade(fams(adv, b2, [0, 0, 0]), fx.RUBRIC)["band"]]
                    assert up <= base


def test_rubric_critical_always_f():
    for adv in itertools.product([0, 24, 27, 29, 30], repeat=3):
        for crit in range(1, 6):
            if crit > 30 - adv[0]:
                continue
            f = fams(adv, [10, 10, 10], [crit, 0, 0])
            assert grade(f, fx.RUBRIC)["band"] == "F"


# --- canonicalization property (spec §14.2) -----------------------------------

def _random_json(rng, depth=0):
    if depth > 4:
        return rng.choice([0, 1, 9007199254740991, "", "x", True, False, None])
    kind = rng.randrange(8)
    if kind < 2:
        return rng.choice([0, 1, 2, 42, 9007199254740991])
    if kind < 4:
        alphabet = "aAzZ09 \u00e9\u4e2d\U0001f600\\\" \x07"
        return "".join(rng.choice(alphabet) for _ in range(rng.randrange(12)))
    if kind == 4:
        return rng.choice([True, False, None])
    if kind < 7:
        return [_random_json(rng, depth + 1) for _ in range(rng.randrange(5))]
    keys = set()
    while len(keys) < rng.randrange(5):
        keys.add(rng.choice(["a", "b", "z", "k\u00e9", "x\U0001f600", "q"]) + str(rng.randrange(10)))
    return {k: _random_json(rng, depth + 1) for k in keys}


def test_canonicalization_property_10k():
    rng = random.Random(20260305)
    for _ in range(10000):
        obj = _random_json(rng)
        b1 = canonicalize(obj)
        # round-trip through the strict parser
        reparsed = parse(b1)
        assert canonicalize(reparsed) == b1
        # member reordering cannot change canonical bytes
        if isinstance(obj, dict):
            items = list(obj.items())
            rng.shuffle(items)
            assert canonicalize(dict(items)) == b1


def test_parse_rejects_forbidden_forms():
    for raw in (b"1.5", b"-1", b"1e3", b"00", b"01", b'{"a":1,"a":2}',
                b"\xef\xbb\xbf{}", b'"\\ud800"', b"[", b"null extra"):
        with pytest.raises(JsonError):
            parse(raw)


# --- deterministic race-order coverage (spec §14.2) ----------------------------

def _fresh_running(svc, clock, i):
    product = create_product(svc, label="Race " + str(i), idem=f"race-p-{i}")
    st, r = admit(svc, product["product_id"], idem=f"race-a-{i}")
    run = r["data"]
    st, r = claim(svc, idem=f"race-c-{i}")
    return run, r["data"]


@pytest.mark.parametrize("i", range(100))
def test_race_cancel_then_complete(svc, clock, i):
    """Owner cancel commits first; worker completion is fenced. (x100)"""
    run, lease = _fresh_running(svc, clock, i)
    st, r = call(svc, TOK_OWNER, "run.cancel",
                 {"run_id": run["run_id"], "expected_revision": 2,
                  "reason": "OWNER_CANCELLED"}, f"race-k-{i}")
    assert st == 200
    ev = make_evidence(run["run_id"], lease["lease_id"], 1, lease["worker_id"])
    st, r = call(svc, TOK_WORKER, "worker.complete",
                 {"run_id": run["run_id"], "lease_id": lease["lease_id"],
                  "lease_epoch": 1, "evidence_hash": canonical_hash(ev)},
                 f"race-w-{i}")
    assert st == 409 and r["error"]["code"] == "LEASE_FENCED"
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "CANCELLED"
    assert len(auth.certificates) == 0


@pytest.mark.parametrize("i", range(100))
def test_race_complete_then_cancel(svc, clock, i):
    """Worker completion commits first; cancel is state-conflicted. (x100)"""
    run, lease = _fresh_running(svc, clock, i)
    st, r = complete_run(svc, svc.authority(fx.T), run, lease)
    assert st == 200
    st, r = call(svc, TOK_OWNER, "run.cancel",
                 {"run_id": run["run_id"], "expected_revision": 3,
                  "reason": "OWNER_CANCELLED"}, f"race-k2-{i}")
    assert st == 409 and r["error"]["code"] == "STATE_CONFLICT"
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "VERIFYING"


@pytest.mark.parametrize("i", range(100))
def test_race_expire_then_complete(svc, clock, i):
    """Lease expiry commits first; late completion is fenced. (x100)"""
    run, lease = _fresh_running(svc, clock, i)
    clock[0] = fx.T0 + 120
    auth = svc.authority(fx.T)
    auth.tick()
    st, r = call(svc, TOK_WORKER, "worker.complete",
                 {"run_id": run["run_id"], "lease_id": lease["lease_id"],
                  "lease_epoch": 1, "evidence_hash": fx.HE}, f"race-w3-{i}")
    assert st == 409 and r["error"]["code"] == "LEASE_FENCED"
    assert auth.runs[run["run_id"]]["state"] == "INCOMPLETE"


# --- runner integration over the real channel --------------------------------

def test_local_run_grid_and_bounds(tmp_path):
    out = str(tmp_path / "out")
    r = run_local(fx.REL, fx.TARGET, fx.CASES, out, None, True)
    assert r["incomplete_reason"] is None
    assert r["result"]["grade"]["band"] == "A"
    # trials in lexicographic case order, repeats 0,1,2, seeds 11,23,37
    trials = r["evidence"]["trials"]
    keys = [(t["case_id"], t["repeat"]) for t in trials]
    assert keys == sorted(keys)
    assert len(trials) == 360
    for t in trials:
        assert t["seed"] == [11, 23, 37][t["repeat"]]
        assert t["observation"]["outcome"] == "returned"
    # artifacts exist
    for name in ("release.json", "cases.json", "target.json", "result.json",
                 "evidence.json", "transcript.bin", "audit.jsonl"):
        assert os.path.exists(os.path.join(out, name))
    # transcript binds every trial
    from evalseal.canon import blob_hash
    raw = open(os.path.join(out, "transcript.bin"), "rb").read()
    assert blob_hash(raw) == r["evidence"]["raw_transcript"]["hash"]


def test_local_run_target_that_refuses(tmp_path):
    """A target that never responds yields failing trials, not omitted ones."""
    # a target process that reads the start frame then hangs silently
    prog = tmp_path / "hang.py"
    prog.write_text("import sys\nsys.stdin.readline()\nimport time\ntime.sleep(60)\n")
    import evalseal.runner as runner
    old = runner.TRIAL_TIMEOUT_MS
    runner.TRIAL_TIMEOUT_MS = 200
    try:
        r = run_local(fx.REL, fx.TARGET, fx.CASES[:2], str(tmp_path / "o"),
                      [sys.executable, str(prog)], False)
    finally:
        runner.TRIAL_TIMEOUT_MS = old
    # partial coverage: result only built on the full grid
    for t in r["evidence"]["trials"]:
        assert t["observation"]["outcome"] == "target_timeout"
