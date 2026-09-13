"""TV-E--27..38, 50..54, 59..60: authority/service vectors (spec §14.1)."""

import copy

import pytest

from evalseal import fixture as fx
from evalseal.canon import canonical_hash, canonicalize, parse
from evalseal.errors import ApiError

from conftest import (TOK_B, TOK_OPERATOR, TOK_OWNER, TOK_READER, TOK_SUBMITTER,
                      TOK_WORKER, TENANT_B, admit, call, claim, complete_run,
                      create_board, create_product, drain, finish_run, get,
                      make_evidence, put_blob)


def _events(auth, run_id):
    return auth.audit.get(run_id, [])


def test_tv_e_27_no_score_submission_rpc(svc):
    product = create_product(svc)
    before = sum(len(v) for a in svc.authorities.values() for v in a.audit.values())
    st, r = call(svc, TOK_OWNER, "score.submit", {"band": "A"}, "k27")
    assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"
    after = sum(len(v) for a in svc.authorities.values() for v in a.audit.values())
    assert after == before


def test_tv_e_28_vendor_cannot_submit_worker_evidence(svc):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a28")
    assert st == 200
    st, r = claim(svc, idem="c28")
    run_id, lease_id = r["data"]["run_id"], r["data"]["lease_id"]
    st, r = call(svc, TOK_OWNER, "worker.complete",
                 {"run_id": run_id, "lease_id": lease_id, "lease_epoch": 1,
                  "evidence_hash": fx.HE}, "k28")
    assert st == 403 and r["error"]["code"] == "FORBIDDEN"


def test_tv_e_29_lease_expiry_boundary(svc, clock):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a29")
    run = r["data"]
    st, r = claim(svc, idem="c29")
    lease = r["data"]
    clock[0] = fx.T0 + 120  # exactly at expiry
    st, r = call(svc, TOK_WORKER, "worker.complete",
                 {"run_id": run["run_id"], "lease_id": lease["lease_id"],
                  "lease_epoch": 1, "evidence_hash": fx.HE}, "k29")
    assert st == 409 and r["error"]["code"] == "LEASE_FENCED"
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "INCOMPLETE"
    assert auth.runs[run["run_id"]]["reason"] == "LEASE_EXPIRED"
    assert len(auth.certificates) == 0


def test_tv_e_30_revoked_auth_before_idempotency_replay(svc):
    product = create_product(svc)
    args = {"product_id": product["product_id"], "release_hash": fx.HR,
            "track": "private", "board_id": None, "prior_certificate_id": None}
    board = create_board(svc)
    args["board_id"] = board["board_id"]
    st, r = call(svc, TOK_SUBMITTER, "run.create", args, "fixture-admit-1")
    assert st == 200
    del svc.principals["sha256:" + __import__("hashlib").sha256(TOK_SUBMITTER.encode()).hexdigest()]
    st, r = call(svc, TOK_SUBMITTER, "run.create", args, "fixture-admit-1")
    assert st == 401 and r["error"]["code"] == "UNAUTHORIZED"


def test_tv_e_31_cancel_wins_completion_race(svc):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a31")
    run = r["data"]
    st, r = claim(svc, idem="c31")
    lease = r["data"]
    st, r = call(svc, TOK_OWNER, "run.cancel",
                 {"run_id": run["run_id"], "expected_revision": run["revision"] + 1,
                  "reason": "OWNER_CANCELLED"}, "k31")
    assert st == 200
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "CANCELLED"
    ev = make_evidence(run["run_id"], lease["lease_id"], 1, lease["worker_id"])
    st, r = call(svc, TOK_WORKER, "worker.complete",
                 {"run_id": run["run_id"], "lease_id": lease["lease_id"],
                  "lease_epoch": 1, "evidence_hash": canonical_hash(ev)}, "k31w")
    assert st == 409 and r["error"]["code"] == "LEASE_FENCED"
    assert len(auth.certificates) == 0


def test_tv_e_32_completion_wins_cancel_race(svc):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a32")
    run = r["data"]
    st, r = claim(svc, idem="c32")
    lease = r["data"]
    st, r = complete_run(svc, svc.authority(fx.T), run, lease)
    assert st == 200
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "VERIFYING"
    st, r = call(svc, TOK_OWNER, "run.cancel",
                 {"run_id": run["run_id"], "expected_revision": 3,
                  "reason": "OWNER_CANCELLED"}, "k32")
    assert st == 409 and r["error"]["code"] == "STATE_CONFLICT"


def test_tv_e_33_target_drift_is_not_a_new_configuration(svc):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a33")
    run = r["data"]
    # operator replaces the target manifest after admission
    drifted = copy.deepcopy(fx.TARGET)
    drifted["product_version"] = "1.0.1"
    svc.install_target(fx.T, {"tenant_id": fx.T, "target_ref": "target-fixture",
                              "target": drifted})
    st, r = claim(svc, idem="c33")
    assert st == 200
    auth = svc.authority(fx.T)
    assert auth.runs[run["run_id"]]["state"] == "INCOMPLETE"
    assert auth.runs[run["run_id"]]["reason"] == "TARGET_DRIFT"
    assert len(auth.certificates) == 0
    # lease is fenced: no dispatch can proceed under it
    assert auth.leases[run["run_id"]].state == "fenced"


def test_tv_e_34_private_cannot_be_promoted(svc, clock):
    board = create_board(svc)
    run, cid = finish_run(svc, clock, track="private", board_id=board["board_id"],
                          idem_prefix="fr34")
    st, r = call(svc, TOK_OWNER, "run.publish", {"run_id": run["run_id"]}, "k34")
    assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"
    assert all(rw["run_id"] != run["run_id"] for rw in svc.index_rows.values())


def test_tv_e_35_latest_failed_attempt_not_hidden(svc, clock):
    product = create_product(svc, label="Same Label")
    run_a, cid = finish_run(svc, clock, product=product, idem_prefix="fr35a")
    assert run_a["state"] == "COMPLETED"
    clock[0] = fx.T0 + 86400
    # second attempt: one failing critical trial -> F
    def break_p01(trials):
        for t in trials:
            if t["case_id"] == "P01" and t["repeat"] == 0:
                t["observation"]["attempted_calls"] = [fx.DROP]
                t["observation_hash"] = canonical_hash(t["observation"])
    st, r = admit(svc, product["product_id"], idem="a35b")
    assert st == 200
    run_b = r["data"]
    st, r = claim(svc, idem="c35b")
    lease = r["data"]
    st, r = complete_run(svc, svc.authority(fx.T), run_b, lease, mutate=break_p01)
    assert st == 200
    auth = svc.authority(fx.T)
    drain(auth)
    assert auth.runs[run_b["run_id"]]["state"] == "COMPLETED"
    # projection: latest admitted attempt is the primary row
    st, page = get(svc, "/v1/leaderboard?release=" + fx.HR)
    assert st == 200
    primary = [i for i in page["items"] if i["product_id"] == product["product_id"]]
    assert len(primary) == 1
    assert primary[0]["run_id"] == run_b["run_id"]
    assert primary[0]["band"] == "F" and primary[0]["qualifies"] is False
    # history is fully discoverable
    st, page = get(svc, "/v1/products/" + product["product_id"] + "/runs", TOK_OWNER)
    assert len(page["items"]) == 2


def test_tv_e_36_cancellation_does_not_reset_cooldown(svc, clock):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a36")
    run = r["data"]
    clock[0] = fx.T0 + 1
    st, r = call(svc, TOK_OWNER, "run.cancel",
                 {"run_id": run["run_id"], "expected_revision": 1,
                  "reason": "OWNER_CANCELLED"}, "k36")
    assert st == 200
    clock[0] = fx.T0 + 2
    body = canonicalize({"op": "run.create", "args": {
        "product_id": product["product_id"], "release_hash": fx.HR,
        "track": "public", "board_id": None, "prior_certificate_id": None}})
    resp = svc.post_commands(body, {"authorization": "Bearer " + TOK_SUBMITTER,
                                    "idempotency-key": "a36b"})
    r = parse(resp.body)
    assert resp.status == 429 and r["error"]["code"] == "RATE_LIMITED"
    assert resp.headers["Retry-After"] == "86398"
    assert len(svc.authority(fx.T).runs) == 1


def test_tv_e_37_cross_tenant_private_pack(svc, clock):
    board = create_board(svc)
    run, cid = finish_run(svc, clock, track="private",
                          board_id=board["board_id"], idem_prefix="fr37")
    st, r = get(svc, "/v1/certificates/" + cid + "/pack?format=zip", TOK_B)
    assert st == 404
    assert r == {"error": {"code": "NOT_FOUND",
                          "message": "Resource not found", "retryable": False}}


def test_tv_e_38_private_badge_enumeration(svc, clock):
    board = create_board(svc)
    run, cid = finish_run(svc, clock, track="private",
                          board_id=board["board_id"], idem_prefix="fr38")
    st1, b1 = get(svc, "/badges/" + cid + ".svg")           # private cert, anonymous
    st2, b2 = get(svc, "/badges/" + fx.idof("crt", "B") + ".svg")  # nonexistent
    assert st1 == 404 and st2 == 404
    assert b1 == b2
    assert b"Record unavailable" in b1


def test_tv_e_50_idempotent_admission_replay(svc):
    product = create_product(svc)
    args = {"product_id": product["product_id"], "release_hash": fx.HR,
            "track": "public", "board_id": None, "prior_certificate_id": None}
    body = canonicalize({"op": "run.create", "args": args})
    h = {"authorization": "Bearer " + TOK_SUBMITTER, "idempotency-key": "fixture-admit-1"}
    r1 = svc.post_commands(body, h)
    r2 = svc.post_commands(body, h)
    assert r1.status == r2.status == 200
    assert r1.body == r2.body
    auth = svc.authority(fx.T)
    run_id = parse(r1.body)["data"]["run_id"]
    assert sum(1 for e in _events(auth, run_id) if e["body"]["type"] == "RunAdmitted") == 1
    assert len(auth.runs) == 1


def test_tv_e_51_idempotency_body_conflict(svc):
    product = create_product(svc)
    board = create_board(svc)
    args = {"product_id": product["product_id"], "release_hash": fx.HR,
            "track": "public", "board_id": None, "prior_certificate_id": None}
    st, r = call(svc, TOK_SUBMITTER, "run.create", args, "fixture-admit-1")
    assert st == 200
    args2 = dict(args, track="private", board_id=board["board_id"])
    st, r = call(svc, TOK_SUBMITTER, "run.create", args2, "fixture-admit-1")
    assert st == 409 and r["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    auth = svc.authority(fx.T)
    assert len(auth.runs) == 1
    assert list(auth.runs.values())[0]["track"] == "public"


def test_tv_e_52_one_certificate_despite_crash_after_signing(svc):
    product = create_product(svc)
    st, r = admit(svc, product["product_id"], idem="a52")
    run = r["data"]
    st, r = claim(svc, idem="c52")
    lease = r["data"]
    st, r = complete_run(svc, svc.authority(fx.T), run, lease)
    assert st == 200
    auth = svc.authority(fx.T)
    assert auth.verify_and_prepare(run["run_id"]) == "PREPARED"
    # crash after manifest write is simulated by delivering the outbox item twice
    assert auth.deliver_issuance(run["run_id"]) == "COMMITTED"
    assert auth.deliver_issuance(run["run_id"]) == "COMMITTED"
    certs = auth.certificates
    assert len(certs) == 1
    run2 = auth.runs[run["run_id"]]
    types = [e["body"]["type"] for e in _events(auth, run["run_id"])]
    assert types.count("CertificateIssued") == 1
    assert run2["state"] == "COMPLETED"


def test_tv_e_53_renewal_cannot_extend_dates(svc, clock):
    run, cid = finish_run(svc, clock, idem_prefix="fr53")
    st, r = call(svc, TOK_OWNER, "certificate.renew",
                 {"certificate_id": cid, "expires_at": fx.EXP + 86400}, "k53")
    assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"
    rec = svc.authority(fx.T).certificates[cid]
    assert rec.envelope["body"]["expires_at"] == \
        rec.envelope["body"]["issued_at"] + 7776000


def test_tv_e_54_fresh_full_recertification(svc, clock):
    run, cid = finish_run(svc, clock, idem_prefix="fr54")
    product_id = run["product_id"]
    clock[0] = fx.T0 + 86400
    st, r = admit(svc, product_id, idem="a54", prior=cid)
    assert st == 200, r
    run2 = r["data"]
    assert run2["run_id"] != run["run_id"]
    assert run2["state"] == "ADMITTED"
    assert run2["prior_certificate_id"] == cid
    assert run2["certificate_id"] is None


def test_tv_e_59_claim_boundary_and_report_cuts(svc):
    product = create_product(svc)
    for i, cap in enumerate([
            "all-standards-compliance", "multimodal-cert", "browser-survival",
            "joule-cert", "court-verdict", "escrow-release",
            "cross-mesh-token-chain", "fatigue-classifier",
            "continuous-certification"]):
        st, r = call(svc, TOK_SUBMITTER, "run.create", {
            "product_id": product["product_id"], "release_hash": fx.HR,
            "track": "public", "board_id": None, "prior_certificate_id": None,
            "capability": cap}, f"k59-{i}")
        assert st == 400 and r["error"]["code"] == "BAD_SCHEMA"
    assert len(svc.authority(fx.T).runs) == 0


def test_tv_e_60_secrets_never_enter_diagnostics(svc, clock):
    secret = "SIM_TEST_SECRET_123"
    seen_bodies = []

    # auth header value must not appear in any response or log
    st, r = get(svc, "/v1/leaderboard?release=" + fx.HR,
                headers_extra={"authorization": "Bearer " + secret})
    seen_bodies.append(r if isinstance(r, bytes) else canonicalize(r))

    # rejected oversized request
    big = b" " * (256 * 1024 + 1)
    resp = svc.post_commands(big, {"authorization": "Bearer " + secret,
                                   "idempotency-key": "k60"})
    seen_bodies.append(resp.body)

    # run a public run whose evidence output embeds the secret string; the
    # resulting artifacts (public pack) must not carry target output bytes
    product = create_product(svc, label="Diag Agent")
    st, r = admit(svc, product["product_id"], idem="a60")
    run = r["data"]
    st, r = claim(svc, idem="c60")
    lease = r["data"]

    def leak(trials):
        for t in trials:
            if t["case_id"] == "P11" and t["repeat"] == 0:
                t["observation"]["output"] = secret
                t["observation_hash"] = canonical_hash(t["observation"])

    st, r = complete_run(svc, svc.authority(fx.T), run, lease, mutate=leak)
    assert st == 200
    auth = svc.authority(fx.T)
    drain(auth)
    run2 = auth.runs[run["run_id"]]
    if run2["certificate_id"]:
        arts = auth.cert_bodies[run2["certificate_id"]]
        seen_bodies.append(arts["pack"])
        seen_bodies.append(arts["pdf"])
    st, r = get(svc, "/v1/runs/" + run["run_id"], TOK_OWNER)
    seen_bodies.append(canonicalize(r))
    for blob in seen_bodies:
        assert secret.encode() not in blob
    for entry in svc.log:
        assert secret not in repr(entry)
