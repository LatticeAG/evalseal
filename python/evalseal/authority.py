"""Local reference tenant authority (spec §2.1 TenantAuthority, §5, §6).

The authoritative state machine for one tenant: products, boards, runs,
leases, certificates, per-stream audit chains, idempotency, the issuance
outbox, and admission/cooldown guards. The hosted deployment runs this logic
inside a SQLite-backed Durable Object; the OSS core ships it as an in-process
authority used by the reference service, the conformance suite, and
`worker serve` development loops. Transactions are modeled by single
synchronous commits — no external call is made while state is mutating.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json as jsonlib
from dataclasses import dataclass, field

from . import audit as auditmod
from .canon import JsonError, canonical_hash, canonicalize, domain_hash, parse
from .errors import ApiError
from .evidence import build_result, validate_evidence
from .grade import qualifies as band_qualifies
from .ids import new_id
from .render import pack_files, pack_zip, render_pdf
from .schema import check_command, check_evidence, SchemaError
from .sign import sign_envelope

CERT_TTL = 7776000          # 90 days
STATUS_TTL = 60
CLAIM_WINDOW = 600          # admitted_at + 600
LEASE_SECONDS = 120
WALL_CAP = 14400            # four wall-clock hours
RUNNING_CAP = 4
ADMITTED_CAP = 20
COOLDOWN = 86400
SNAPSHOT_TTL = 300
MAX_EVIDENCE_BYTES = 336 * 1024 * 1024
MAX_BLOB_BYTES = 448 * 1024 * 1024
MAX_RETAINED_PER_RUN = 832 * 1024 * 1024

ROLE_ORDER = {"reader": 0, "submitter": 1, "owner": 2}


def cohort_key(release_hash: str) -> str:
    return canonical_hash({
        "release_hash": release_hash,
        "profile": "text-tools-en-v1",
        "revision_assurance": "provider-declared",
    })


@dataclass
class Lease:
    run_id: str
    lease_id: str
    epoch: int
    worker_id: str
    expires_at: int
    wall_deadline: int
    state: str = "held"          # held | consumed | fenced


@dataclass
class CertRecord:
    envelope: dict
    revision: int
    state: str                   # ACTIVE | EXPIRED | REVOKED
    expires_at: int
    reason: str | None = None


class LocalSigner:
    """In-process IssuerSigner equivalent (spec §7.6).

    Closed {kind,key_id,body,body_hash} input; reserves (slot,body_hash,key_id)
    durably before signing and never signs a second body in a reserved slot.
    The hosted IssuerSigner is a separate service binding — see hosted.py.
    """

    def __init__(self, sign_fn):
        self._sign = sign_fn      # (kind, key_id, body) -> envelope
        self.slots: dict[str, dict] = {}

    def sign(self, req: dict) -> dict:
        for k in ("kind", "key_id", "body", "body_hash"):
            if k not in req or len(req) != 4:
                raise ApiError("BAD_SCHEMA")
        kind, key_id, body, body_hash = req["kind"], req["key_id"], req["body"], req["body_hash"]
        if kind not in ("certificate", "pack", "checkpoint", "status"):
            raise ApiError("BAD_SCHEMA")
        if domain_hash(kind, body) != body_hash:
            raise ApiError("HASH_MISMATCH")
        slot = self._slot(kind, body, body_hash)
        cur = self.slots.get(slot)
        if cur is not None:
            if cur["body_hash"] != body_hash or cur["key_id"] != key_id:
                raise ApiError("STATE_CONFLICT")
            return cur["envelope"]
        env = self._sign(kind, key_id, body)
        if env["body_hash"] != body_hash:
            raise ApiError("UNAVAILABLE")
        self.slots[slot] = {"body_hash": body_hash, "key_id": key_id, "envelope": env}
        return env

    @staticmethod
    def _slot(kind: str, body: dict, body_hash: str) -> str:
        if kind == "certificate":
            return "certificate/" + body["certificate_id"]
        if kind == "pack":
            return "pack/" + body["certificate_hash"] + "/" + body["disclosure"]
        if kind == "checkpoint":
            return "checkpoint/%s/%s/%s" % (body["tenant_id"], body["stream_id"], body["seq"])
        if kind == "status":
            return "status/%s/%s/%s" % (body["certificate_id"], body["head"], body["as_of"])
        return kind + "/" + body_hash


class Authority:
    """One tenant's authoritative store + transitions."""

    def __init__(self, service, tenant_id: str):
        self.service = service
        self.tenant_id = tenant_id
        self.products: dict[str, dict] = {}
        self.boards: dict[str, dict] = {}
        self.runs: dict[str, dict] = {}
        self.run_targets: dict[str, dict] = {}          # run_id -> frozen Target
        self.run_evidence: dict[str, dict] = {}         # run_id -> Evidence body
        self.leases: dict[str, Lease] = {}              # run_id -> Lease
        self.certificates: dict[str, CertRecord] = {}
        self.cert_bodies: dict[str, dict] = {}          # cert_id -> artifacts for pack
        self.audit: dict[str, list] = {}                # stream_id -> [AuditEntry]
        self.payloads: dict[str, dict] = {}             # event_id -> AuditPayload
        self.heads: dict[str, dict] = {}                # stream_id -> last entry
        self.checkpoints: dict[tuple, dict] = {}        # (stream_id, seq) -> Signed<Checkpoint>
        self.idem: dict[tuple, dict] = {}
        self.outbox: dict[str, dict] = {}
        self.blobs: dict[tuple, dict] = {}              # (run_id, hash) -> {bytes, retained_until}
        self.prepared: dict[str, dict] = {}             # run_id -> issuance prep

    # -- utilities ---------------------------------------------------------

    def now(self) -> int:
        return self.service.now()

    def _append(self, stream_id: str, at: int, typ: str, subject_id: str,
                revision: int, payload: dict) -> dict:
        prev = self.heads.get(stream_id)
        entry = auditmod.new_entry(self.tenant_id, stream_id, prev, at, typ,
                                   subject_id, revision, payload)
        self.audit.setdefault(stream_id, []).append(entry)
        self.payloads[entry["body"]["event_id"]] = payload
        self.heads[stream_id] = entry
        return entry

    def _enqueue(self, dedupe: str, kind: str, body: dict) -> None:
        if dedupe not in self.outbox:
            self.outbox[dedupe] = {"kind": kind, "body": body, "state": "pending",
                                   "attempts": 0, "next_at": self.now()}

    def _emit_checkpoint(self, stream_id: str) -> None:
        head = self.heads[stream_id]
        seq = head["body"]["seq"]
        slot = (stream_id, seq)
        if slot in self.checkpoints:
            return  # unchanged head reuses its original envelope/time
        body = {"schema": "evalseal-checkpoint/1", "tenant_id": self.tenant_id,
                "stream_id": stream_id, "seq": seq, "head": head["hash"], "at": self.now()}
        self.checkpoints[slot] = self.service.signer.sign({
            "kind": "checkpoint", "key_id": self.service.issuer_key_id,
            "body": body, "body_hash": domain_hash("checkpoint", body)})

    # -- maintenance -------------------------------------------------------

    def tick(self) -> None:
        """Lazy expiry sweeps equivalent to DO alarms (spec §5.1, §5.3)."""
        now = self.now()
        for run in list(self.runs.values()):
            if run["state"] == "ADMITTED" and now >= run["admitted_at"] + CLAIM_WINDOW:
                self._transition(run, "INCOMPLETE", "NO_CAPACITY")
            elif run["state"] == "RUNNING":
                lease = self.leases.get(run["run_id"])
                if lease is not None and lease.state == "held":
                    if now >= lease.wall_deadline:
                        self._transition(run, "INCOMPLETE", "WALL_CAP")
                    elif now >= lease.expires_at:
                        self._transition(run, "INCOMPLETE", "LEASE_EXPIRED")
            elif run["state"] == "VERIFYING":
                if not self.service.release_active(run["release_hash"]):
                    self._transition(run, "INCOMPLETE", "RELEASE_UNAVAILABLE")
        for cert in list(self.certificates.values()):
            if cert.state == "ACTIVE" and now >= cert.expires_at:
                self._cert_expire(cert)

    def _cert_expire(self, cert: CertRecord) -> None:
        cert.state = "EXPIRED"
        cert.revision += 1
        run = self.runs.get(cert.envelope["body"]["run_id"])
        if run is not None:
            self._append(run["run_id"], self.now(), "CertificateExpired",
                         cert.envelope["body"]["certificate_id"], cert.revision,
                         {"request_hash": None, "before": "ACTIVE", "after": "EXPIRED",
                          "object_hash": canonical_hash(cert.envelope), "reason": "EXPIRED"})

    def _transition(self, run: dict, new_state: str, reason: str | None,
                    request_hash: str | None = None, object_hash: str | None = None,
                    subject: str | None = None, event: str | None = None,
                    extra=None) -> dict:
        """Commit a run transition + audit event + revision increment."""
        before = run["state"]
        run["state"] = new_state
        run["revision"] += 1
        if new_state in ("INCOMPLETE", "CANCELLED", "COMPLETED"):
            run["finished_at"] = self.now()
        run["reason"] = reason
        payload = {"request_hash": request_hash, "before": before, "after": new_state,
                   "object_hash": object_hash or canonical_hash(run), "reason": reason}
        typ = event or {
            "INCOMPLETE": "RunIncomplete", "CANCELLED": "RunCancelled",
        }.get(new_state)
        entry = self._append(run["run_id"], self.now(), typ,
                             subject or run["run_id"], run["revision"], payload)
        if extra:
            extra(run)
        if run["track"] == "public":
            self._enqueue("index:" + run["run_id"] + ":" + str(entry["body"]["seq"]),
                          "index", {"run_id": run["run_id"], "tenant_id": self.tenant_id})
        return run

    # -- command dispatch --------------------------------------------------

    def command(self, principal: dict, request: dict, request_hash: str) -> tuple:
        """Execute a validated Command; returns (reply, http_status)."""
        op, args = request["op"], request["args"]
        handler = getattr(self, "_op_" + op.replace(".", "_"), None)
        if handler is None:
            raise ApiError("BAD_SCHEMA")
        self._authorize(principal, request)
        return handler(principal, args, request_hash)

    def _authorize(self, principal: dict, request: dict) -> None:
        op = request["op"]
        if principal.get("worker"):
            if not op.startswith("worker."):
                raise ApiError("FORBIDDEN")
            return
        role = principal["role"]
        need = {
            "product.create": "submitter", "run.create": "submitter",
            "board.create": "owner", "run.cancel": "owner",
        }.get(op)
        if op == "certificate.revoke":
            if request["args"]["reason"] == "WITHDRAWN":
                need = "owner"
            else:
                if role != "issuer-operator":
                    raise ApiError("FORBIDDEN")
                return
        if op.startswith("worker."):
            raise ApiError("FORBIDDEN")
        if need and ROLE_ORDER.get(role, -1) < ROLE_ORDER[need]:
            raise ApiError("FORBIDDEN")

    # -- ops ---------------------------------------------------------------

    def _op_product_create(self, principal, args, request_hash):
        if args["target_ref"] not in self.service.target_refs(self.tenant_id):
            raise ApiError("NOT_FOUND")
        product = {"product_id": new_id("prd"), "tenant_id": self.tenant_id,
                   "label": args["label"], "target_ref": args["target_ref"],
                   "created_at": self.now()}
        e = self._append(product["product_id"], self.now(), "ProductCreated",
                         product["product_id"], 1,
                         {"request_hash": request_hash, "before": None,
                          "after": "registered", "object_hash": canonical_hash(product),
                          "reason": None})
        self.products[product["product_id"]] = product
        return {"op": "product.create", "data": product, "event_seq": e["body"]["seq"]}, 200

    def _op_board_create(self, principal, args, request_hash):
        board = {"board_id": new_id("brd"), "tenant_id": self.tenant_id,
                 "label": args["label"], "visibility": "private",
                 "created_at": self.now()}
        e = self._append(board["board_id"], self.now(), "BoardCreated",
                         board["board_id"], 1,
                         {"request_hash": request_hash, "before": None,
                          "after": "private-active", "object_hash": canonical_hash(board),
                          "reason": None})
        self.boards[board["board_id"]] = board
        return {"op": "board.create", "data": board, "event_seq": e["body"]["seq"]}, 200

    def _op_run_create(self, principal, args, request_hash):
        now = self.now()
        product = self.products.get(args["product_id"])
        if product is None:
            raise ApiError("NOT_FOUND")
        release = self.service.releases.get(args["release_hash"])
        if release is None:
            raise ApiError("NOT_FOUND")
        if not self.service.release_active(args["release_hash"]):
            raise ApiError("RELEASE_UNAVAILABLE")
        track = args["track"]
        if track == "public" and args["board_id"] is not None:
            raise ApiError("BAD_SCHEMA")
        if track == "private":
            board = self.boards.get(args["board_id"] or "")
            if board is None:
                raise ApiError("NOT_FOUND")
        prior = None
        if args["prior_certificate_id"] is not None:
            rec = self.certificates.get(args["prior_certificate_id"])
            if rec is None:
                raise ApiError("NOT_FOUND")
            cb = rec.envelope["body"]
            if cb["product_id"] != product["product_id"] or cb["track"] != track:
                raise ApiError("BAD_REFERENCE")
            prior = cb["certificate_id"]
        # admission guards
        for r in self.runs.values():
            if r["product_id"] == product["product_id"] and r["state"] in ("ADMITTED", "RUNNING", "VERIFYING"):
                raise ApiError("LIMIT_EXCEEDED", retry_after=60)
        if sum(1 for r in self.runs.values() if r["state"] == "ADMITTED") >= ADMITTED_CAP:
            raise ApiError("LIMIT_EXCEEDED", retry_after=60)
        if track == "public":
            ck = cohort_key(args["release_hash"])
            last = max(
                (r["admitted_at"] for r in self.runs.values()
                 if r["product_id"] == product["product_id"] and r["track"] == "public"
                 and cohort_key(r["release_hash"]) == ck),
                default=None,
            )
            if last is not None and now - last < COOLDOWN:
                raise ApiError("RATE_LIMITED", retry_after=COOLDOWN - (now - last))
        target = self.service.target_for(self.tenant_id, product["target_ref"])
        if target is None:
            raise ApiError("NOT_FOUND")
        run = {"run_id": new_id("run"), "product_id": product["product_id"],
               "release_hash": args["release_hash"], "target_hash": canonical_hash(target),
               "track": track, "board_id": args["board_id"] if track == "private" else None,
               "state": "ADMITTED", "revision": 1, "admitted_at": now,
               "finished_at": None, "reason": None,
               "certificate_id": None, "prior_certificate_id": prior}
        self.runs[run["run_id"]] = run
        self.run_targets[run["run_id"]] = target
        e = self._append(run["run_id"], now, "RunAdmitted", run["run_id"], 1,
                         {"request_hash": request_hash, "before": None,
                          "after": "ADMITTED", "object_hash": canonical_hash(run),
                          "reason": None})
        if track == "public":
            self._enqueue("index:" + run["run_id"] + ":1", "index",
                          {"run_id": run["run_id"], "tenant_id": self.tenant_id})
        return {"op": "run.create", "data": run, "event_seq": e["body"]["seq"]}, 200

    def _op_run_cancel(self, principal, args, request_hash):
        run = self.runs.get(args["run_id"])
        if run is None:
            raise ApiError("NOT_FOUND")
        if run["state"] not in ("ADMITTED", "RUNNING"):
            raise ApiError("STATE_CONFLICT")
        if args["expected_revision"] != run["revision"]:
            raise ApiError("REVISION_CONFLICT")
        lease = self.leases.get(run["run_id"])
        if lease is not None and lease.state == "held":
            lease.state = "fenced"
        self._transition(run, "CANCELLED", "OWNER_CANCELLED", request_hash=request_hash)
        return {"op": "run.cancel", "data": dict(run), "event_seq": self.heads[run["run_id"]]["body"]["seq"]}, 200

    def _op_certificate_revoke(self, principal, args, request_hash):
        rec = self.certificates.get(args["certificate_id"])
        if rec is None:
            raise ApiError("NOT_FOUND")
        if rec.state == "REVOKED":
            raise ApiError("STATE_CONFLICT")
        if args["expected_revision"] != rec.revision:
            raise ApiError("REVISION_CONFLICT")
        reason = args["reason"]
        if reason != "WITHDRAWN" and principal["role"] != "issuer-operator":
            raise ApiError("FORBIDDEN")
        before = rec.state
        rec.state = "REVOKED"
        rec.reason = reason
        rec.revision += 1
        cid = rec.envelope["body"]["certificate_id"]
        run = self.runs.get(rec.envelope["body"]["run_id"])
        stream = run["run_id"] if run else cid
        e = self._append(stream, self.now(), "CertificateRevoked", cid, rec.revision,
                         {"request_hash": request_hash, "before": before,
                          "after": "REVOKED", "object_hash": canonical_hash(rec.envelope),
                          "reason": reason})
        self._emit_checkpoint(stream)
        if rec.envelope["body"]["track"] == "public" and run is not None:
            self._enqueue("index:" + run["run_id"] + ":" + str(e["body"]["seq"]),
                          "index", {"run_id": run["run_id"], "tenant_id": self.tenant_id})
        return {"op": "certificate.revoke",
                "data": {"certificate_id": cid, "revision": rec.revision,
                         "state": "REVOKED", "reason": reason},
                "event_seq": e["body"]["seq"]}, 200

    # -- worker ops ----------------------------------------------------------

    def _bound_lease(self, principal, args) -> Lease:
        """Resolve the lease named by WorkerBound and check worker binding."""
        lease = self.leases.get(args["run_id"])
        if lease is None or lease.lease_id != args["lease_id"]:
            raise ApiError("LEASE_FENCED")
        if lease.worker_id != principal["worker_id"]:
            raise ApiError("FORBIDDEN")
        return lease

    def _check_lease_live(self, lease: Lease, epoch: int) -> None:
        run = self.runs[lease.run_id]
        now = self.now()
        if lease.state != "held" or lease.epoch != epoch:
            raise ApiError("LEASE_FENCED")
        if run["state"] != "RUNNING":
            raise ApiError("LEASE_FENCED")
        if now >= lease.wall_deadline:
            self._fence_and_incomplete(lease, "WALL_CAP")
            raise ApiError("LEASE_FENCED")
        if now >= lease.expires_at:
            self._fence_and_incomplete(lease, "LEASE_EXPIRED")
            raise ApiError("LEASE_FENCED")

    def _fence_and_incomplete(self, lease: Lease, reason: str) -> None:
        lease.state = "fenced"
        run = self.runs[lease.run_id]
        if run["state"] == "RUNNING":
            self._transition(run, "INCOMPLETE", reason)

    def _op_worker_claim(self, principal, args, request_hash):
        reg = self.service.worker_registry_entry(principal["worker_id"])
        if reg is None or reg["tenant_id"] != self.tenant_id:
            raise ApiError("FORBIDDEN")
        self.tick()
        held = sum(1 for l in self.leases.values()
                   if l.worker_id == principal["worker_id"] and l.state == "held")
        if held >= reg["capacity"]:
            return {"op": "worker.claim", "data": None, "event_seq": None}, 200
        running = sum(1 for r in self.runs.values() if r["state"] == "RUNNING")
        if running >= RUNNING_CAP:
            return {"op": "worker.claim", "data": None, "event_seq": None}, 200
        now = self.now()
        candidates = [r for r in self.runs.values()
                      if r["state"] == "ADMITTED" and now < r["admitted_at"] + CLAIM_WINDOW
                      and self.service.release_active(r["release_hash"])]
        if not candidates:
            return {"op": "worker.claim", "data": None, "event_seq": None}, 200
        run = min(candidates, key=lambda r: (r["admitted_at"], r["run_id"]))
        lease = Lease(run_id=run["run_id"], lease_id=new_id("lse"), epoch=1,
                      worker_id=principal["worker_id"], expires_at=now + LEASE_SECONDS,
                      wall_deadline=now + WALL_CAP)
        self.leases[run["run_id"]] = lease
        lease_body = {"run_id": run["run_id"], "lease_id": lease.lease_id,
                      "epoch": 1, "worker_id": lease.worker_id,
                      "expires_at": lease.expires_at,
                      "target": self.run_targets[run["run_id"]],
                      "release_hash": run["release_hash"]}
        self._transition(run, "RUNNING", None, request_hash=request_hash,
                         object_hash=canonical_hash(lease_body), event="RunClaimed")
        # Re-resolve the product's target alias: a manifest that no longer
        # matches the bytes admitted ends the run before any trial dispatch
        # (spec §3.3 "a mismatch before a trial ends the run").
        product = self.products.get(run["product_id"])
        current = self.service.target_for(self.tenant_id, product["target_ref"]) if product else None
        if current is None or canonical_hash(current) != run["target_hash"]:
            lease.state = "fenced"
            self._transition(run, "INCOMPLETE", "TARGET_DRIFT")
            e = self.heads[run["run_id"]]
            return {"op": "worker.claim", "data": None, "event_seq": e["body"]["seq"]}, 200
        e = self.heads[run["run_id"]]
        return {"op": "worker.claim", "data": lease_body, "event_seq": e["body"]["seq"]}, 200

    def _op_worker_heartbeat(self, principal, args, request_hash):
        lease = self._bound_lease(principal, args)
        self._check_lease_live(lease, args["lease_epoch"])
        now = self.now()
        lease.epoch += 1
        lease.expires_at = now + LEASE_SECONDS
        run = self.runs[lease.run_id]
        run["revision"] += 1
        self._append(run["run_id"], now, "LeaseRenewed", lease.lease_id,
                     run["revision"],
                     {"request_hash": request_hash, "before": "RUNNING", "after": "RUNNING",
                      "object_hash": canonical_hash({"lease_id": lease.lease_id, "epoch": lease.epoch,
                                                     "expires_at": lease.expires_at}),
                      "reason": None})
        e = self.heads[run["run_id"]]
        return {"op": "worker.heartbeat",
                "data": {"expires_at": lease.expires_at, "epoch": lease.epoch,
                         "revision": run["revision"]},
                "event_seq": e["body"]["seq"]}, 200

    def _op_worker_complete(self, principal, args, request_hash):
        lease = self._bound_lease(principal, args)
        self._check_lease_live(lease, args["lease_epoch"])
        blob = self.blobs.get((lease.run_id, args["evidence_hash"]))
        if blob is None:
            raise ApiError("HASH_MISMATCH")
        if blob["bytes"] > MAX_EVIDENCE_BYTES:
            raise ApiError("LIMIT_EXCEEDED", retry_after=0)
        try:
            evidence = parse(blob["data"])
            check_evidence(evidence)
        except (JsonError, SchemaError):
            raise ApiError("EVIDENCE_INVALID") from None
        if canonical_hash(evidence) != args["evidence_hash"]:
            raise ApiError("HASH_MISMATCH")
        if evidence["lease_epoch"] != args["lease_epoch"]:
            raise ApiError("LEASE_FENCED")
        run = self.runs[lease.run_id]
        self.run_evidence[run["run_id"]] = evidence
        run["evidence_hash"] = args["evidence_hash"]
        lease.state = "consumed"
        self._transition(run, "VERIFYING", None, request_hash=request_hash,
                         object_hash=canonical_hash(evidence), event="EvidenceAccepted")
        self._emit_checkpoint(run["run_id"])
        self._enqueue("issuance:" + run["run_id"], "issuance", {"run_id": run["run_id"]})
        e = self.heads[run["run_id"]]
        return {"op": "worker.complete", "data": dict(run), "event_seq": e["body"]["seq"]}, 200

    def _op_worker_fail(self, principal, args, request_hash):
        lease = self._bound_lease(principal, args)
        self._check_lease_live(lease, args["lease_epoch"])
        self._fence_and_incomplete(lease, args["reason"])
        run = self.runs[lease.run_id]
        e = self.heads[run["run_id"]]
        return {"op": "worker.fail", "data": dict(run), "event_seq": e["body"]["seq"]}, 200

    # -- issuance pipeline ---------------------------------------------------

    def process_outbox(self) -> int:
        """Deliver pending outbox items; returns the number processed."""
        done = 0
        for key, item in list(self.outbox.items()):
            if item["state"] == "pending" and item["next_at"] <= self.now():
                if item["kind"] == "issuance":
                    self.deliver_issuance(item["body"]["run_id"])
                elif item["kind"] == "index":
                    self.service.project_run(self.tenant_id, item["body"]["run_id"])
                item["state"] = "committed"
                done += 1
        return done

    def verify_and_prepare(self, run_id: str) -> str:
        """VERIFYING: validate evidence, freeze all issuance bytes once."""
        run = self.runs[run_id]
        if run["state"] != "VERIFYING":
            return "SKIP"
        if run_id in self.prepared:
            return "PREPARED"
        if not self.service.release_active(run["release_hash"]):
            self._transition(run, "INCOMPLETE", "RELEASE_UNAVAILABLE")
            return "INCOMPLETE"
        release = self.service.releases[run["release_hash"]]
        cases = self.service.release_cases(run["release_hash"])
        evidence = self.run_evidence[run_id]
        lease = self.leases[run_id]
        reg = self.service.worker_registry_entry(lease.worker_id)
        code = validate_evidence(evidence, {
            "run_id": run_id, "lease_id": lease.lease_id, "lease_epoch": evidence["lease_epoch"],
            "worker_id": lease.worker_id, "release_hash": run["release_hash"],
            "target_hash": run["target_hash"], "release": release["body"],
            "cases": cases,
            "recorder_hash": reg["recorder_hash"] if reg else evidence["recorder_hash"],
            "has_blob": lambda h: (run_id, h) in self.blobs,
        })
        if code != "VALID":
            self._transition(run, "INCOMPLETE", "EVIDENCE_INVALID")
            return "INCOMPLETE"
        result = build_result(run_id, release["body"], run["release_hash"],
                              run["target_hash"], cases, evidence, release["body"]["rubric"])
        cert_id = new_id("crt")
        issued_at = self.now()
        head = self.heads[run_id]["hash"]
        target = self.run_targets[run_id]
        product = self.products[run["product_id"]]
        cert_body = {
            "schema": "evalseal-certificate/1", "certificate_id": cert_id,
            "run_id": run_id, "product_id": run["product_id"],
            "product_label": product["label"],
            "product_version": target["product_version"],
            "track": run["track"], "release_hash": run["release_hash"],
            "target_hash": run["target_hash"], "result_hash": canonical_hash(result),
            "reproducibility_hash": result["reproducibility_hash"],
            "evidence_head": head, "band": result["grade"]["band"],
            "qualification": "CERTIFIED" if band_qualifies(result["grade"]["band"]) else "NOT_CERTIFIED",
            "issued_at": issued_at, "expires_at": issued_at + CERT_TTL,
            "scope_lines": release["body"]["scope_lines"],
            "prior_certificate_id": run["prior_certificate_id"],
        }
        self.prepared[run_id] = {"cert_body": cert_body, "result": result}
        payload_obj = {"certificate_id": cert_id,
                       "result_hash": canonical_hash(result), "issued_at": issued_at}
        run["revision"] += 1
        self._append(run_id, issued_at, "IssuancePrepared", run_id, run["revision"],
                     {"request_hash": None, "before": "VERIFYING", "after": "VERIFYING",
                      "object_hash": canonical_hash(payload_obj), "reason": None})
        return "PREPARED"

    def deliver_issuance(self, run_id: str) -> str:
        """Retriable outbox work: sign cert + manifest, persist, then complete."""
        run = self.runs[run_id]
        if run["state"] == "COMPLETED":
            return "COMMITTED"          # idempotent redelivery
        if run["state"] != "VERIFYING":
            return "SKIP"
        if run_id not in self.prepared:
            r = self.verify_and_prepare(run_id)
            if r != "PREPARED":
                return r
        prep = self.prepared[run_id]
        cert_body, result = prep["cert_body"], prep["result"]
        release = self.service.releases[run["release_hash"]]
        cases = self.service.release_cases(run["release_hash"])
        target = self.run_targets[run_id]
        keyring = self.service.keyring

        def _sign_body(kind: str, body: dict) -> dict:
            # signer slots make redelivery return identical bytes
            return self.service.signer.sign({
                "kind": kind, "key_id": self.service.issuer_key_id,
                "body": body, "body_hash": domain_hash(kind, body)})

        # signer slots make redelivery return identical bytes
        cert = _sign_body("certificate", cert_body)
        pdf = render_pdf(cert, result, release)
        # the pack carries the audit prefix through evidence_head (the
        # EvidenceAccepted head); IssuancePrepared/CertificateIssued are
        # served by the live audit endpoint, not the pack
        audit_prefix = []
        for _e in self.audit[run_id]:
            audit_prefix.append(_e)
            if _e["hash"] == cert_body["evidence_head"]:
                break
        checkpoint = self._latest_checkpoint(run_id)
        disclosure = "public-redacted" if run["track"] == "public" else "private-full"
        evidence = self.run_evidence[run_id]
        transcript = self.blobs[(run_id, evidence["raw_transcript"]["hash"])]["data"] \
            if (run_id, evidence["raw_transcript"]["hash"]) in self.blobs else None
        _, manifest_body = pack_files(
            cert, result, release, target, audit_prefix, checkpoint, keyring, cases,
            disclosure=disclosure,
            evidence=evidence if disclosure == "private-full" else None,
            transcript=transcript if disclosure == "private-full" else None)
        manifest_hash = canonical_hash(_sign_body("pack", manifest_body))
        pack = pack_zip(cert, result, release, target, audit_prefix, checkpoint,
                        keyring, cases, signer=_sign_body,
                        disclosure=disclosure,
                        evidence=evidence if disclosure == "private-full" else None,
                        transcript=transcript if disclosure == "private-full" else None)
        rec = CertRecord(envelope=cert, revision=1, state="ACTIVE",
                         expires_at=cert_body["expires_at"])
        self.certificates[cert_body["certificate_id"]] = rec
        self.cert_bodies[cert_body["certificate_id"]] = {
            "result": result, "pack": pack, "pdf": pdf, "manifest_hash": manifest_hash,
            "disclosure": disclosure,
        }
        run["certificate_id"] = cert_body["certificate_id"]
        # completion transaction
        obj = {"certificate_hash": canonical_hash(cert), "manifest_hash": manifest_hash}
        run["state"] = "COMPLETED"
        run["revision"] += 1
        run["finished_at"] = self.now()
        self._append(run_id, self.now(), "CertificateIssued",
                     cert_body["certificate_id"], run["revision"],
                     {"request_hash": None, "before": "VERIFYING", "after": "COMPLETED",
                      "object_hash": canonical_hash(obj), "reason": None})
        self._emit_checkpoint(run_id)
        if run["track"] == "public":
            self._enqueue("index:" + run_id + ":" + str(self.heads[run_id]["body"]["seq"]),
                          "index", {"run_id": run_id, "tenant_id": self.tenant_id})
            self.service.publish_public_artifacts(cert_body["certificate_id"],
                                                  self.cert_bodies[cert_body["certificate_id"]])
        return "COMMITTED"

    def _latest_checkpoint(self, stream_id: str):
        cps = [cp for (s, _), cp in self.checkpoints.items() if s == stream_id]
        return max(cps, key=lambda c: c["body"]["seq"]) if cps else None

    # -- status --------------------------------------------------------------

    def cert_status(self, cert_id: str, now: int) -> dict:
        """Fresh Signed<Status> for a certificate at `now`."""
        rec = self.certificates[cert_id]
        cb = rec.envelope["body"]
        state = rec.state
        if state == "ACTIVE" and now >= rec.expires_at:
            self._cert_expire(rec)
            state = "EXPIRED"
        qualifies = state == "ACTIVE" and cb["band"] != "F" and now < rec.expires_at
        reason = rec.reason if state == "REVOKED" else ("EXPIRED" if state == "EXPIRED" else None)
        if state == "ACTIVE":
            valid_until = min(now + STATUS_TTL, rec.expires_at)
        else:
            valid_until = now + STATUS_TTL
        head = self.heads[cb["run_id"]]["hash"] if cb["run_id"] in self.heads else canonical_hash(cert_body_min(cb))
        body = {"schema": "evalseal-status/1", "certificate_id": cert_id,
                "certificate_hash": canonical_hash(rec.envelope), "state": state,
                "qualifies": qualifies, "reason": reason, "as_of": now,
                "valid_until": valid_until, "head": head}
        return self.service.signer.sign({
            "kind": "status", "key_id": self.service.issuer_key_id,
            "body": body, "body_hash": domain_hash("status", body)})

    # -- blobs ----------------------------------------------------------------

    def put_blob(self, run_id: str, digest: str, data: bytes) -> dict:
        if canonical_blob_hash(data) != digest:
            raise ApiError("HASH_MISMATCH")
        existing = self.blobs.get((run_id, digest))
        if existing is not None:
            return {"hash": digest, "bytes": len(data), "stored": True}
        total = sum(b["bytes"] for (rid, _), b in self.blobs.items() if rid == run_id)
        if total + len(data) > MAX_RETAINED_PER_RUN:
            raise ApiError("LIMIT_EXCEEDED", retry_after=0)
        self.blobs[(run_id, digest)] = {
            "bytes": len(data), "data": bytes(data),
            "retained_until": self.now() + 180 * 86400,
        }
        return {"hash": digest, "bytes": len(data), "stored": True}


def cert_body_min(cb):
    return {"certificate_id": cb["certificate_id"], "issued_at": cb["issued_at"]}


def canonical_blob_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
