"""Conformance fixtures: a fully provisioned in-process reference Service.

Service-level vectors drive Service.handle/post_commands directly with real
HTTP-shaped inputs — the same dispatch the reference server exposes. Time is
controlled through a mutable clock.
"""

from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

from evalseal import fixture as fx  # noqa: E402
from evalseal.canon import canonical_hash, canonicalize, parse  # noqa: E402
from evalseal.errors import ApiError  # noqa: E402
from evalseal.mock import RECORDER_HASH  # noqa: E402
from evalseal.service import Service  # noqa: E402

TOK_OWNER = "tok-owner"
TOK_SUBMITTER = "tok-submitter"
TOK_READER = "tok-reader"
TOK_B = "tok-tenant-b-reader"
TOK_OPERATOR = "tok-operator"
TOK_WORKER = "tok-worker"
TENANT_B = fx.idof("tnt", "B")


@pytest.fixture
def clock():
    return [fx.T0]


@pytest.fixture
def svc(clock):
    s = Service(
        now_fn=lambda: clock[0],
        issuer_sign=lambda kind, key_id, body: fx.sign_envelope(kind, key_id, body, fx.SK),
        issuer_key_id=fx.K,
    )
    s.install_keyring(fx.KEYRING, fx.K)
    s.install_release(fx.RELEASE, fx.CASES, {"fixture.json": fx.SOURCE})
    s.install_target(fx.T, {"tenant_id": fx.T, "target_ref": "target-fixture",
                            "target": copy.deepcopy(fx.TARGET)})
    s.install_target(TENANT_B, {"tenant_id": TENANT_B, "target_ref": "target-fixture",
                                "target": copy.deepcopy(fx.TARGET)})
    s.install_principal(TOK_OWNER, {"principal_id": "owner-1", "tenant_id": fx.T, "role": "owner"})
    s.install_principal(TOK_SUBMITTER, {"principal_id": "sub-1", "tenant_id": fx.T, "role": "submitter"})
    s.install_principal(TOK_READER, {"principal_id": "reader-1", "tenant_id": fx.T, "role": "reader"})
    s.install_principal(TOK_B, {"principal_id": "reader-b", "tenant_id": TENANT_B, "role": "reader"})
    s.install_principal(TOK_OPERATOR, {"principal_id": "op-1", "tenant_id": None, "role": "issuer-operator"})
    s.install_worker(
        {"worker_id": fx.W, "tenant_id": fx.T, "recorder_hash": RECORDER_HASH,
         "identity_env": "EVALSEAL_WORKER_TOKEN", "capacity": 1},
        TOK_WORKER)
    return s


def call(svc: Service, token: str, op: str, args: dict, idem: str):
    """POST /v1/commands; returns (http_status, parsed_body)."""
    body = canonicalize({"op": op, "args": args})
    headers = {"authorization": "Bearer " + token, "idempotency-key": idem}
    r = svc.post_commands(body, headers)
    return r.status, parse(r.body)


def get(svc: Service, path: str, token: str | None = None, headers_extra=None):
    headers = {}
    if token is not None:
        headers["authorization"] = "Bearer " + token
    headers.update(headers_extra or {})
    r = svc.handle("GET", path, headers, b"")
    try:
        return r.status, parse(r.body)
    except Exception:
        return r.status, r.body


def put_blob(svc: Service, run_id: str, token: str, data: bytes, lease_id: str, epoch: int):
    headers = {
        "authorization": "Bearer " + token,
        "content-length": str(len(data)),
        "x-lease-id": lease_id,
        "x-lease-epoch": str(epoch),
    }
    r = svc.handle("PUT", f"/v1/runs/{run_id}/blobs/sha256:" +
                   __import__("hashlib").sha256(data).hexdigest(), headers, data)
    return r.status, parse(r.body)


def create_product(svc, token=TOK_OWNER, label="Example Agent", ref="target-fixture", idem="pc-1"):
    st, r = call(svc, token, "product.create", {"label": label, "target_ref": ref}, idem)
    assert st == 200, r
    return r["data"]


def create_board(svc, token=TOK_OWNER, label="Internal Tests", idem="bc-1"):
    st, r = call(svc, token, "board.create", {"label": label}, idem)
    assert st == 200, r
    return r["data"]


def admit(svc, product_id, track="public", board_id=None, idem="admit-1",
          token=TOK_SUBMITTER, prior=None):
    st, r = call(svc, token, "run.create", {
        "product_id": product_id, "release_hash": fx.HR, "track": track,
        "board_id": board_id, "prior_certificate_id": prior}, idem)
    return st, r


def claim(svc, idem="claim-1"):
    return call(svc, TOK_WORKER, "worker.claim", {"capacity": 1}, idem)


def make_evidence(run_id, lease_id, epoch=1, worker_id=None, mutate=None):
    """Evidence bound to an actual run/lease, reusing fixture trials."""
    trials = copy.deepcopy(fx.TRIALS)
    if mutate:
        mutate(trials)
    ev = {
        "schema": "evalseal-evidence/1", "run_id": run_id, "lease_id": lease_id,
        "lease_epoch": epoch, "worker_id": worker_id or fx.W,
        "release_hash": fx.HR, "target_hash": fx.HT,
        "trials": trials,
        "raw_transcript": {"hash": fx.EVIDENCE["raw_transcript"]["hash"],
                           "bytes": fx.EVIDENCE["raw_transcript"]["bytes"],
                           "media_type": "application/octet-stream"},
        "recorder_hash": RECORDER_HASH,
        "started_at": fx.T0, "finished_at": fx.T0 + 60,
    }
    return ev


def complete_run(svc, auth, run, lease, mutate=None):
    """Upload transcript+evidence blobs and call worker.complete."""
    run_id, lease_id, epoch = run["run_id"], lease["lease_id"], lease["epoch"]
    st, _ = put_blob(svc, run_id, TOK_WORKER, fx.RAW, lease_id, epoch)
    assert st == 200
    ev = make_evidence(run_id, lease_id, epoch, lease["worker_id"], mutate)
    st, _ = put_blob(svc, run_id, TOK_WORKER, canonicalize(ev), lease_id, epoch)
    assert st == 200
    st, r = call(svc, TOK_WORKER, "worker.complete",
                 {"run_id": run_id, "lease_id": lease_id, "lease_epoch": epoch,
                  "evidence_hash": canonical_hash(ev)}, "complete-" + run_id)
    return st, r


def drain(auth) -> None:
    """Deliver all pending outbox items (issuance then index projections)."""
    while auth.process_outbox():
        pass


def finish_run(svc, clock, track="public", board_id=None, product=None,
               label="Example Agent", idem_prefix="fr"):
    """Admit → claim → upload → complete → outbox → COMPLETED. Returns (run, cert_id)."""
    product = product or create_product(svc, label=label, idem=idem_prefix + "-p")
    st, r = admit(svc, product["product_id"], track, board_id, idem=idem_prefix + "-a")
    assert st == 200, r
    run = r["data"]
    st, r = claim(svc, idem=idem_prefix + "-c")
    assert st == 200 and r["data"], r
    lease = r["data"]
    st, r = complete_run(svc, svc.authority(product["tenant_id"]), run, lease)
    assert st == 200, r
    auth = svc.authority(product["tenant_id"])
    drain(auth)
    run = auth.runs[run["run_id"]]
    return run, run["certificate_id"]


def evidence_ctx(run_id=None, lease_id=None, has_blob=None):
    return {
        "run_id": run_id or fx.R, "lease_id": lease_id or fx.L, "lease_epoch": 1,
        "worker_id": fx.W, "release_hash": fx.HR, "target_hash": fx.HT,
        "release": fx.REL, "cases": fx.CASES,
        "recorder_hash": fx.OPAQUE,
        "has_blob": has_blob or (lambda h: h == fx.EVIDENCE["raw_transcript"]["hash"]),
    }


def fams(adv, ben, crit):
    return [
        {"family": f, "adversarial_pass": a, "adversarial_total": 30,
         "benign_pass": b, "benign_total": 10, "critical_fail": c}
        for f, a, b, c in zip(("poisoning", "injection", "approval-bypass"), adv, ben, crit)
    ]


def g(adv, ben, crit):
    """Vector shorthand g([adv],[ben],crit_total) — spreads a shared critical count."""
    from evalseal.grade import grade
    if isinstance(crit, int):
        crit = [crit, 0, 0]
    return grade(fams(adv, ben, crit), fx.RUBRIC)
