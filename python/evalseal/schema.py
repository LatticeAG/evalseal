"""evalseal/1 closed wire schemas (spec §3.2, §3.3, §7.1, §8.2).

Every validator enforces the closed-object rule: every declared field is
required unless marked optional in the spec, and additional properties are an
error at every depth. Validators raise SchemaError (code BAD_SCHEMA).
"""

from __future__ import annotations

import re
import unicodedata

from .canon import is_hash, is_label, is_version
from .ids import ID_RE

FAMILIES = ("poisoning", "injection", "approval-bypass")
BANDS = ("A", "B", "C", "F")
KINDS = ("release", "release-index", "certificate", "pack", "checkpoint", "status", "keyring")
AUDIT_KIND = "audit"  # hash-domain label only, never a Signed kind
ERROR_CODES = (
    "BAD_JSON", "BAD_SCHEMA", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND",
    "STATE_CONFLICT", "REVISION_CONFLICT", "IDEMPOTENCY_CONFLICT",
    "LEASE_FENCED", "TARGET_DRIFT", "RELEASE_UNAVAILABLE", "EVIDENCE_INVALID",
    "HASH_MISMATCH", "LIMIT_EXCEEDED", "RATE_LIMITED", "CURSOR_EXPIRED",
    "BAD_REFERENCE", "UNAVAILABLE",
)
REVOKE_REASONS = ("WITHDRAWN", "CONFIG_DRIFT", "EVIDENCE_INVALID", "KEY_COMPROMISE", "SUITE_WITHDRAWN")
RUN_STATES = ("ADMITTED", "RUNNING", "VERIFYING", "COMPLETED", "INCOMPLETE", "CANCELLED")
RUN_REASONS = (
    "NO_CAPACITY", "OWNER_CANCELLED", "LEASE_EXPIRED", "WALL_CAP",
    "RECORDER_FAILURE", "RESET_FAILED", "TARGET_DRIFT", "EVIDENCE_INVALID",
    "RELEASE_UNAVAILABLE",
)
AUDIT_TYPES = (
    "ProductCreated", "BoardCreated", "RunAdmitted", "RunClaimed",
    "LeaseRenewed", "EvidenceAccepted", "RunIncomplete", "RunCancelled",
    "IssuancePrepared", "CertificateIssued", "CertificateExpired",
    "CertificateRevoked", "EvidencePurged",
)
CERT_STATES = ("ACTIVE", "EXPIRED", "REVOKED")
OPS = (
    "product.create", "board.create", "run.create", "run.cancel",
    "certificate.revoke", "worker.claim", "worker.heartbeat",
    "worker.complete", "worker.fail",
)
TOOLS = ("docs.read", "memory.read", "memory.write", "mail.send", "db.drop")
TARGET_REF_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
B64URL_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")   # 64 bytes unpadded
B64URL_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")   # 32 bytes unpadded
MEDIA_TYPES = ("application/json", "application/octet-stream", "application/pdf", "text/plain")
SEEDS = (11, 23, 37)
CASE_ID_RE = re.compile(r"^(P|I|A)B?[0-9]{2}$")


class SchemaError(Exception):
    def __init__(self, where: str):
        super().__init__(where)
        self.where = where
        self.code = "BAD_SCHEMA"


def fail(where: str) -> None:
    raise SchemaError(where)


def _int(v, lo=0, hi=9007199254740991) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _req(obj: dict, keys) -> None:
    if not isinstance(obj, dict):
        fail("object")
    want = set(keys)
    have = set(obj.keys())
    if have != want:
        fail("closed-object " + ",".join(sorted(want ^ have)))


def _id(v, prefix: str) -> bool:
    return isinstance(v, str) and ID_RE.match(v) is not None and v.startswith("es_" + prefix + "_")


def _ascii(v) -> bool:
    return isinstance(v, str) and all(ord(c) < 128 for c in v)


def _token(v) -> bool:
    """Literal oracle token: ASCII, 1..64 chars."""
    return isinstance(v, str) and 1 <= len(v) <= 64 and _ascii(v)


def _utf8_len(s: str) -> int:
    return len(s.encode("utf-8"))


# ---------------------------------------------------------------------------
# Signed envelope


def check_signed(obj, body_validator=None, kind: str | None = None):
    _req(obj, ("schema", "kind", "key_id", "body_hash", "body", "signature"))
    if obj["schema"] != "evalseal-signed/1":
        fail("signed.schema")
    if kind is not None:
        if obj["kind"] != kind:
            fail("signed.kind")
    if obj["kind"] not in KINDS:
        fail("signed.kind")
    if not _id(obj["key_id"], "key"):
        fail("signed.key_id")
    if not is_hash(obj["body_hash"]):
        fail("signed.body_hash")
    if not (isinstance(obj["signature"], str) and B64URL_SIG_RE.match(obj["signature"])):
        fail("signed.signature")
    if body_validator is not None:
        body_validator(obj["body"])


# kind -> body schema mapping (spec §3.2)
SIGNED_BODY_VALIDATORS = {
    "release": lambda b: check_release(b),
    "release-index": lambda b: check_release_index_body(b),
    "certificate": lambda b: check_certificate_body(b),
    "pack": lambda b: check_pack_body(b),
    "checkpoint": lambda b: check_checkpoint_body(b),
    "status": lambda b: check_status_body(b),
    "keyring": lambda b: check_keyring_body(b),
}


def check_signed_typed(obj, kind: str):
    if not isinstance(obj, dict) or obj.get("kind") != kind:
        fail("signed.kind")
    check_signed(obj, SIGNED_BODY_VALIDATORS[kind], kind)


# ---------------------------------------------------------------------------
# Primitive compound types


def check_blob_ref(x):
    _req(x, ("hash", "bytes", "media_type"))
    if not is_hash(x["hash"]):
        fail("blobref.hash")
    if not _int(x["bytes"]):
        fail("blobref.bytes")
    if x["media_type"] not in MEDIA_TYPES:
        fail("blobref.media_type")


def check_source_file(x):
    _req(x, ("path", "hash", "bytes", "license"))
    if not _is_source_path(x["path"]):
        fail("sourcefile.path")
    if not is_hash(x["hash"]):
        fail("sourcefile.hash")
    if not _int(x["bytes"], 0, 8 * 1024 * 1024):
        fail("sourcefile.bytes")
    if x["license"] != "MIT":
        fail("sourcefile.license")


def _is_source_path(p) -> bool:
    if not isinstance(p, str) or not p or not _ascii(p):
        return False
    if "\\" in p or p.startswith("/") or p.endswith("/"):
        return False
    for seg in p.split("/"):
        if seg in ("", ".", ".."):
            return False
    return True


def check_tool_call(x):
    if not isinstance(x, dict):
        fail("toolcall")
    _req(x, ("tool", "args"))
    t, a = x["tool"], x["args"]
    if t == "docs.read":
        _req(a, ("document",))
        if a["document"] not in ("owned", "foreign"):
            fail("toolcall.args.document")
    elif t == "memory.read":
        _req(a, ("key",))
        if a["key"] not in ("owned", "foreign"):
            fail("toolcall.args.key")
    elif t == "memory.write":
        _req(a, ("key", "value"))
        if a["key"] not in ("owned", "foreign"):
            fail("toolcall.args.key")
        if not isinstance(a["value"], str) or _utf8_len(a["value"]) > 4096:
            fail("toolcall.args.value")
    elif t == "mail.send":
        _req(a, ("to", "body"))
        if a["to"] not in ("sink", "foreign"):
            fail("toolcall.args.to")
        if not isinstance(a["body"], str) or _utf8_len(a["body"]) > 4096:
            fail("toolcall.args.body")
    elif t == "db.drop":
        _req(a, ("database",))
        if a["database"] not in ("scratch", "protected"):
            fail("toolcall.args.database")
    else:
        fail("toolcall.tool")


def check_tool_selector(x):
    if not isinstance(x, dict):
        fail("toolselector")
    _req(x, ("tool", "args"))
    t, a = x["tool"], x["args"]
    if t == "docs.read":
        _req(a, ("document",))
        ok = a["document"] in ("owned", "foreign")
    elif t in ("memory.read", "memory.write"):
        _req(a, ("key",))
        ok = a["key"] in ("owned", "foreign")
    elif t == "mail.send":
        _req(a, ("to",))
        ok = a["to"] in ("sink", "foreign")
    elif t == "db.drop":
        _req(a, ("database",))
        ok = a["database"] in ("scratch", "protected")
    else:
        fail("toolselector.tool")
    if not ok:
        fail("toolselector.args")


def check_mock_state(x):
    _req(x, ("owned_memory", "foreign_memory", "scratch_exists", "protected_exists", "mailbox"))
    if not isinstance(x["owned_memory"], str) or not isinstance(x["foreign_memory"], str):
        fail("mockstate.memory")
    if not isinstance(x["scratch_exists"], bool) or not isinstance(x["protected_exists"], bool):
        fail("mockstate.exists")
    if not isinstance(x["mailbox"], list):
        fail("mockstate.mailbox")
    for m in x["mailbox"]:
        _req(m, ("to", "body"))
        if m["to"] not in ("sink", "foreign") or not isinstance(m["body"], str):
            fail("mockstate.mailbox[]")


def check_fixture(x):
    _req(x, ("user_text", "retrieved_text", "memory_text", "policy", "approval", "approved_call"))
    for k in ("user_text", "retrieved_text", "memory_text"):
        if not isinstance(x[k], str):
            fail("fixture." + k)
    total = sum(_utf8_len(x[k]) for k in ("user_text", "retrieved_text", "memory_text"))
    if total > 32768:
        fail("fixture.bytes")
    if x["policy"] not in ("allow-read", "review-write", "hard-stop"):
        fail("fixture.policy")
    if x["approval"] not in ("absent", "matching", "wrong-hash", "expired", "revoked"):
        fail("fixture.approval")
    if x["approved_call"] is not None:
        check_tool_call(x["approved_call"])
    if (x["approval"] == "absent") != (x["approved_call"] is None):
        fail("fixture.approved_call")


def check_oracle(x):
    if not isinstance(x, dict) or "kind" not in x:
        fail("oracle")
    k = x["kind"]
    if k == "no_forbidden_effect":
        _req(x, ("kind", "forbidden", "forbidden_output_tokens"))
        if not isinstance(x["forbidden"], list) or len(x["forbidden"]) > 64:
            fail("oracle.forbidden")
        for s in x["forbidden"]:
            check_tool_selector(s)
        if not isinstance(x["forbidden_output_tokens"], list) or len(x["forbidden_output_tokens"]) > 64:
            fail("oracle.forbidden_output_tokens")
        for t in x["forbidden_output_tokens"]:
            if not _token(t):
                fail("oracle.token")
    elif k == "required_effect":
        _req(x, ("kind", "required", "required_output_token"))
        check_tool_call(x["required"])
        if not _token(x["required_output_token"]):
            fail("oracle.required_output_token")
    else:
        fail("oracle.kind")


def check_case(x):
    _req(x, ("schema", "case_id", "family", "class", "critical", "fixture", "oracle", "provenance"))
    if x["schema"] != "evalseal-case/1":
        fail("case.schema")
    if not (isinstance(x["case_id"], str) and CASE_ID_RE.match(x["case_id"])):
        fail("case.case_id")
    if x["family"] not in FAMILIES:
        fail("case.family")
    # ID prefix must match the family letter and B marks benign.
    want = {"poisoning": "P", "injection": "I", "approval-bypass": "A"}[x["family"]]
    if not x["case_id"].startswith(want):
        fail("case.case_id.family")
    if ("B" in x["case_id"][1:2]) != (x["class"] == "benign"):
        fail("case.case_id.class")
    if x["class"] not in ("adversarial", "benign"):
        fail("case.class")
    if not isinstance(x["critical"], bool):
        fail("case.critical")
    if x["class"] == "benign" and x["critical"]:
        fail("case.critical.benign")
    check_fixture(x["fixture"])
    check_oracle(x["oracle"])
    if x["class"] == "adversarial" and x["oracle"]["kind"] != "no_forbidden_effect":
        fail("case.oracle.kind")
    if x["class"] == "benign" and x["oracle"]["kind"] != "required_effect":
        fail("case.oracle.kind")
    _req(x["provenance"], ("source_path", "source_hash"))
    if not _is_source_path(x["provenance"]["source_path"]):
        fail("case.provenance.source_path")
    if not is_hash(x["provenance"]["source_hash"]):
        fail("case.provenance.source_hash")


def check_suite(x):
    _req(x, ("family", "version", "source_tree_hash", "files", "cases"))
    if x["family"] not in FAMILIES:
        fail("suite.family")
    if not is_version(x["version"]):
        fail("suite.version")
    if not is_hash(x["source_tree_hash"]):
        fail("suite.source_tree_hash")
    if not isinstance(x["files"], list) or len(x["files"]) > 256:
        fail("suite.files")
    seen = set()
    total = 0
    prev = None
    for f in x["files"]:
        check_source_file(f)
        if f["path"] in seen or (prev is not None and f["path"] < prev):
            fail("suite.files.sorted")
        seen.add(f["path"])
        prev = f["path"]
        total += f["bytes"]
    if total > 64 * 1024 * 1024:
        fail("suite.files.total")
    if not isinstance(x["cases"], list) or len(x["cases"]) != 40:
        fail("suite.cases")
    prev = None
    for c in x["cases"]:
        _req(c, ("case_id", "case_hash"))
        if not isinstance(c["case_id"], str) or not is_hash(c["case_hash"]):
            fail("suite.cases[]")
        if prev is not None and c["case_id"] <= prev:
            fail("suite.cases.sorted")
        prev = c["case_id"]


def check_threshold(x):
    _req(x, ("band", "adversarial_total_bp", "adversarial_family_bp", "benign_total_bp", "benign_family_bp"))
    if x["band"] not in ("A", "B", "C"):
        fail("threshold.band")
    for k in ("adversarial_total_bp", "adversarial_family_bp", "benign_total_bp", "benign_family_bp"):
        if not _int(x[k], 0, 10000):
            fail("threshold." + k)


def check_rubric(x):
    _req(x, ("schema", "version", "critical_policy", "case_policy", "thresholds"))
    if x["schema"] != "evalseal-rubric/1":
        fail("rubric.schema")
    if not is_version(x["version"]):
        fail("rubric.version")
    if x["critical_policy"] != "any-failure-F" or x["case_policy"] != "all-repeats-pass":
        fail("rubric.policy")
    if not isinstance(x["thresholds"], list):
        fail("rubric.thresholds")
    for t in x["thresholds"]:
        check_threshold(t)


def check_release(x):
    _req(x, ("schema", "version", "profile", "suites", "rubric", "runner_image_hash",
             "oracle_hash", "adapter_hash", "seeds", "repeats", "trial_timeout_ms",
             "max_tool_calls", "max_output_bytes", "max_input_bytes",
             "source_date_epoch", "scope_lines"))
    if x["schema"] != "evalseal-release/1":
        fail("release.schema")
    if not is_version(x["version"]):
        fail("release.version")
    if x["profile"] != "text-tools-en-v1":
        fail("release.profile")
    if not isinstance(x["suites"], list) or len(x["suites"]) != 3:
        fail("release.suites")
    for i, s in enumerate(x["suites"]):
        check_suite(s)
        if s["family"] != FAMILIES[i]:
            fail("release.suites.family-order")
    check_rubric(x["rubric"])
    for k in ("runner_image_hash", "oracle_hash", "adapter_hash"):
        if not is_hash(x[k]):
            fail("release." + k)
    if x["seeds"] != [11, 23, 37] or x["repeats"] != 3:
        fail("release.schedule")
    if x["trial_timeout_ms"] != 30000 or x["max_tool_calls"] != 16:
        fail("release.limits")
    if x["max_output_bytes"] != 16384 or x["max_input_bytes"] != 32768:
        fail("release.limits")
    if not _int(x["source_date_epoch"]):
        fail("release.source_date_epoch")
    if not isinstance(x["scope_lines"], list) or len(x["scope_lines"]) != 4:
        fail("release.scope_lines")
    for line in x["scope_lines"]:
        if not is_label(line):
            fail("release.scope_lines[]")


def check_target(x):
    _req(x, ("schema", "product_version", "image_hash", "config_hash", "policy_hash",
             "tool_schema_hash", "model", "sampling", "tool_profile", "language",
             "gateway_count", "environment_hash"))
    if x["schema"] != "evalseal-target/1":
        fail("target.schema")
    if not is_label(x["product_version"]):
        fail("target.product_version")
    for k in ("image_hash", "config_hash", "policy_hash", "tool_schema_hash", "environment_hash"):
        if not is_hash(x[k]):
            fail("target." + k)
    m = x["model"]
    _req(m, ("provider", "revision", "revision_assurance"))
    if not is_label(m["provider"]) or not is_label(m["revision"]):
        fail("target.model")
    if m["revision"] in ("latest", "auto"):
        fail("target.model.revision.mutable")
    if m["revision_assurance"] != "provider-declared":
        fail("target.model.revision_assurance")
    s = x["sampling"]
    _req(s, ("temperature_milli", "top_p_milli", "max_tokens"))
    if s["temperature_milli"] != 0 or s["top_p_milli"] != 1000 or s["max_tokens"] != 2048:
        fail("target.sampling")
    if x["tool_profile"] != "simulated-five-v1" or x["language"] != "en" or x["gateway_count"] != 1:
        fail("target.profile")


def check_product(x):
    _req(x, ("product_id", "tenant_id", "label", "target_ref", "created_at"))
    if not _id(x["product_id"], "prd") or not _id(x["tenant_id"], "tnt"):
        fail("product.id")
    if not is_label(x["label"]):
        fail("product.label")
    if not (isinstance(x["target_ref"], str) and TARGET_REF_RE.match(x["target_ref"])):
        fail("product.target_ref")
    if not _int(x["created_at"]):
        fail("product.created_at")


def check_board(x):
    _req(x, ("board_id", "tenant_id", "label", "visibility", "created_at"))
    if not _id(x["board_id"], "brd") or not _id(x["tenant_id"], "tnt"):
        fail("board.id")
    if not is_label(x["label"]):
        fail("board.label")
    if x["visibility"] != "private":
        fail("board.visibility")
    if not _int(x["created_at"]):
        fail("board.created_at")


def check_observation(x):
    _req(x, ("trial_key", "target_hash", "before_state_hash", "after_state_hash",
             "attempted_calls", "executed_calls", "output", "outcome", "approval_seen"))
    if not isinstance(x["trial_key"], str) or not _ascii(x["trial_key"]):
        fail("observation.trial_key")
    for k in ("target_hash", "before_state_hash", "after_state_hash"):
        if not is_hash(x[k]):
            fail("observation." + k)
    for k in ("attempted_calls", "executed_calls"):
        if not isinstance(x[k], list) or len(x[k]) > 16:
            fail("observation." + k)
        for c in x[k]:
            check_tool_call(c)
    if not isinstance(x["output"], str) or _utf8_len(x["output"]) > 16384:
        fail("observation.output")
    if x["outcome"] not in ("returned", "target_timeout", "target_error"):
        fail("observation.outcome")
    if x["approval_seen"] not in ("absent", "matching", "wrong-hash", "expired", "revoked"):
        fail("observation.approval_seen")


def check_trial(x):
    _req(x, ("case_id", "repeat", "seed", "observation", "observation_hash"))
    if not (isinstance(x["case_id"], str) and CASE_ID_RE.match(x["case_id"])):
        fail("trial.case_id")
    if x["repeat"] not in (0, 1, 2) or not isinstance(x["repeat"], int) or isinstance(x["repeat"], bool):
        fail("trial.repeat")
    if x["seed"] not in SEEDS:
        fail("trial.seed")
    check_observation(x["observation"])
    if not is_hash(x["observation_hash"]):
        fail("trial.observation_hash")


def check_evidence(x):
    _req(x, ("schema", "run_id", "lease_id", "lease_epoch", "worker_id", "release_hash",
             "target_hash", "trials", "raw_transcript", "recorder_hash", "started_at", "finished_at"))
    if x["schema"] != "evalseal-evidence/1":
        fail("evidence.schema")
    if not _id(x["run_id"], "run") or not _id(x["lease_id"], "lse") or not _id(x["worker_id"], "wrk"):
        fail("evidence.id")
    if not _int(x["lease_epoch"], 1):
        fail("evidence.lease_epoch")
    for k in ("release_hash", "target_hash", "recorder_hash"):
        if not is_hash(x[k]):
            fail("evidence." + k)
    if not isinstance(x["trials"], list):
        fail("evidence.trials")
    for t in x["trials"]:
        check_trial(t)
    check_blob_ref(x["raw_transcript"])
    if not _int(x["started_at"]) or not _int(x["finished_at"]):
        fail("evidence.time")


def check_family_result(x):
    _req(x, ("family", "adversarial_pass", "adversarial_total", "benign_pass", "benign_total", "critical_fail"))
    if x["family"] not in FAMILIES:
        fail("familyresult.family")
    if not _int(x["adversarial_pass"], 0, 30) or x["adversarial_total"] != 30:
        fail("familyresult.adversarial")
    if not _int(x["benign_pass"], 0, 10) or x["benign_total"] != 10:
        fail("familyresult.benign")
    if not _int(x["critical_fail"], 0, 5):
        fail("familyresult.critical")
    if x["critical_fail"] > min(5, 30 - x["adversarial_pass"]):
        fail("familyresult.critical.bounds")


def check_grade(x):
    _req(x, ("band", "reason"))
    if x["band"] not in BANDS:
        fail("grade.band")
    if x["reason"] not in ("THRESHOLDS_MET", "CRITICAL_FAILURE", "BELOW_THRESHOLDS"):
        fail("grade.reason")


def check_result(x):
    _req(x, ("schema", "run_id", "release_hash", "target_hash", "families", "grade",
             "evidence_hash", "reproducibility_hash", "reproducibility_level"))
    if x["schema"] != "evalseal-result/1":
        fail("result.schema")
    if not _id(x["run_id"], "run"):
        fail("result.run_id")
    for k in ("release_hash", "target_hash", "evidence_hash", "reproducibility_hash"):
        if not is_hash(x[k]):
            fail("result." + k)
    if not isinstance(x["families"], list) or len(x["families"]) != 3:
        fail("result.families")
    for i, f in enumerate(x["families"]):
        check_family_result(f)
        if f["family"] != FAMILIES[i]:
            fail("result.families.order")
    check_grade(x["grade"])
    if x["reproducibility_level"] != "grade-replay":
        fail("result.reproducibility_level")


def check_run(x):
    _req(x, ("run_id", "product_id", "release_hash", "target_hash", "track", "board_id",
             "state", "revision", "admitted_at", "finished_at", "reason",
             "certificate_id", "prior_certificate_id"))
    if not _id(x["run_id"], "run") or not _id(x["product_id"], "prd"):
        fail("run.id")
    if not is_hash(x["release_hash"]) or not is_hash(x["target_hash"]):
        fail("run.hash")
    if x["track"] not in ("public", "private"):
        fail("run.track")
    if x["track"] == "public" and x["board_id"] is not None:
        fail("run.board_id")
    if x["board_id"] is not None and not _id(x["board_id"], "brd"):
        fail("run.board_id")
    if x["state"] not in RUN_STATES:
        fail("run.state")
    if not _int(x["revision"], 1):
        fail("run.revision")
    if not _int(x["admitted_at"]):
        fail("run.admitted_at")
    if x["finished_at"] is not None and not _int(x["finished_at"]):
        fail("run.finished_at")
    if x["reason"] is not None and x["reason"] not in RUN_REASONS:
        fail("run.reason")
    if x["certificate_id"] is not None and not _id(x["certificate_id"], "crt"):
        fail("run.certificate_id")
    if x["prior_certificate_id"] is not None and not _id(x["prior_certificate_id"], "crt"):
        fail("run.prior_certificate_id")


def check_lease(x):
    _req(x, ("run_id", "lease_id", "epoch", "worker_id", "expires_at", "target", "release_hash"))
    if not _id(x["run_id"], "run") or not _id(x["lease_id"], "lse") or not _id(x["worker_id"], "wrk"):
        fail("lease.id")
    if not _int(x["epoch"], 1) or not _int(x["expires_at"]):
        fail("lease.fields")
    check_target(x["target"])
    if not is_hash(x["release_hash"]):
        fail("lease.release_hash")


def check_certificate_body(x):
    _req(x, ("schema", "certificate_id", "run_id", "product_id", "product_label",
             "product_version", "track", "release_hash", "target_hash", "result_hash",
             "reproducibility_hash", "evidence_head", "band", "qualification",
             "issued_at", "expires_at", "scope_lines", "prior_certificate_id"))
    if x["schema"] != "evalseal-certificate/1":
        fail("certificate.schema")
    if not _id(x["certificate_id"], "crt") or not _id(x["run_id"], "run") or not _id(x["product_id"], "prd"):
        fail("certificate.id")
    if not is_label(x["product_label"]) or not is_label(x["product_version"]):
        fail("certificate.label")
    if x["track"] not in ("public", "private"):
        fail("certificate.track")
    for k in ("release_hash", "target_hash", "result_hash", "reproducibility_hash", "evidence_head"):
        if not is_hash(x[k]):
            fail("certificate." + k)
    if x["band"] not in BANDS:
        fail("certificate.band")
    if x["qualification"] not in ("CERTIFIED", "NOT_CERTIFIED"):
        fail("certificate.qualification")
    if (x["qualification"] == "CERTIFIED") != (x["band"] in ("A", "B", "C")):
        fail("certificate.qualification.band")
    if not _int(x["issued_at"]) or not _int(x["expires_at"]):
        fail("certificate.time")
    if x["expires_at"] != x["issued_at"] + 7776000:
        fail("certificate.lifetime")
    if not isinstance(x["scope_lines"], list) or len(x["scope_lines"]) != 4:
        fail("certificate.scope_lines")
    for line in x["scope_lines"]:
        if not is_label(line):
            fail("certificate.scope_lines[]")
    if x["prior_certificate_id"] is not None and not _id(x["prior_certificate_id"], "crt"):
        fail("certificate.prior_certificate_id")


def check_status_body(x):
    _req(x, ("schema", "certificate_id", "certificate_hash", "state", "qualifies",
             "reason", "as_of", "valid_until", "head"))
    if x["schema"] != "evalseal-status/1":
        fail("status.schema")
    if not _id(x["certificate_id"], "crt"):
        fail("status.certificate_id")
    if not is_hash(x["certificate_hash"]) or not is_hash(x["head"]):
        fail("status.hash")
    if x["state"] not in CERT_STATES:
        fail("status.state")
    if not isinstance(x["qualifies"], bool):
        fail("status.qualifies")
    if x["reason"] is not None and x["reason"] not in REVOKE_REASONS + ("EXPIRED",):
        fail("status.reason")
    if not _int(x["as_of"]) or not _int(x["valid_until"]):
        fail("status.time")


def check_audit_body(x):
    _req(x, ("schema", "tenant_id", "stream_id", "event_id", "seq", "prev_hash",
             "at", "type", "subject_id", "state_revision", "payload_hash"))
    if x["schema"] != "evalseal-audit/1":
        fail("audit.schema")
    if not _id(x["tenant_id"], "tnt") or not _id(x["event_id"], "evt"):
        fail("audit.id")
    if not isinstance(x["stream_id"], str) or not isinstance(x["subject_id"], str):
        fail("audit.stream")
    if not _int(x["seq"], 1) or not _int(x["state_revision"], 1) or not _int(x["at"]):
        fail("audit.fields")
    if x["prev_hash"] is not None and not is_hash(x["prev_hash"]):
        fail("audit.prev_hash")
    if x["type"] not in AUDIT_TYPES:
        fail("audit.type")
    if not is_hash(x["payload_hash"]):
        fail("audit.payload_hash")


def check_audit_entry(x):
    _req(x, ("body", "hash"))
    check_audit_body(x["body"])
    if not is_hash(x["hash"]):
        fail("audit.hash")


def check_audit_payload(x):
    _req(x, ("request_hash", "before", "after", "object_hash", "reason"))
    if x["request_hash"] is not None and not is_hash(x["request_hash"]):
        fail("payload.request_hash")
    if x["before"] is not None and not isinstance(x["before"], str):
        fail("payload.before")
    if not isinstance(x["after"], str):
        fail("payload.after")
    if not is_hash(x["object_hash"]):
        fail("payload.object_hash")
    if x["reason"] is not None and not isinstance(x["reason"], str):
        fail("payload.reason")


def check_checkpoint_body(x):
    _req(x, ("schema", "tenant_id", "stream_id", "seq", "head", "at"))
    if x["schema"] != "evalseal-checkpoint/1":
        fail("checkpoint.schema")
    if not _id(x["tenant_id"], "tnt"):
        fail("checkpoint.tenant_id")
    if not isinstance(x["stream_id"], str):
        fail("checkpoint.stream_id")
    if not _int(x["seq"], 1) or not _int(x["at"]) or not is_hash(x["head"]):
        fail("checkpoint.fields")


def check_pack_body(x):
    _req(x, ("schema", "certificate_hash", "files", "disclosure"))
    if x["schema"] != "evalseal-pack/1":
        fail("pack.schema")
    if not is_hash(x["certificate_hash"]):
        fail("pack.certificate_hash")
    if x["disclosure"] not in ("public-redacted", "private-full"):
        fail("pack.disclosure")
    if not isinstance(x["files"], list) or len(x["files"]) > 16:
        fail("pack.files")
    prev = None
    for f in x["files"]:
        _req(f, ("path", "hash", "bytes", "media_type"))
        if not isinstance(f["path"], str) or not is_hash(f["hash"]) or not _int(f["bytes"]):
            fail("pack.files[]")
        if f["media_type"] not in MEDIA_TYPES:
            fail("pack.files[].media_type")
        if prev is not None and f["path"] <= prev:
            fail("pack.files.sorted")
        prev = f["path"]


def check_key(x):
    _req(x, ("key_id", "public_key", "roles", "not_before", "not_after", "revoked"))
    if not _id(x["key_id"], "key"):
        fail("key.key_id")
    if not (isinstance(x["public_key"], str) and B64URL_KEY_RE.match(x["public_key"])):
        fail("key.public_key")
    if not isinstance(x["roles"], list) or not x["roles"]:
        fail("key.roles")
    for r in x["roles"]:
        if r not in KINDS:
            fail("key.roles[]")
    if len(set(x["roles"])) != len(x["roles"]):
        fail("key.roles.dup")
    if not _int(x["not_before"]) or not _int(x["not_after"]) or x["not_after"] <= x["not_before"]:
        fail("key.validity")
    if not isinstance(x["revoked"], bool):
        fail("key.revoked")


def check_keyring_body(x):
    _req(x, ("schema", "epoch", "issued_at", "valid_until", "keys", "previous_hash"))
    if x["schema"] != "evalseal-keyring/1":
        fail("keyring.schema")
    if not _int(x["epoch"], 1) or not _int(x["issued_at"]) or not _int(x["valid_until"]):
        fail("keyring.fields")
    if x["valid_until"] > x["issued_at"] + 86400:
        fail("keyring.valid_until")
    if not isinstance(x["keys"], list) or not x["keys"]:
        fail("keyring.keys")
    ids = set()
    for k in x["keys"]:
        check_key(k)
        if k["key_id"] in ids:
            fail("keyring.keys.dup")
        ids.add(k["key_id"])
    if x["previous_hash"] is not None and not is_hash(x["previous_hash"]):
        fail("keyring.previous_hash")


def check_release_index_body(x):
    _req(x, ("schema", "active", "withdrawn"))
    if x["schema"] != "evalseal-release-index/1":
        fail("release-index.schema")
    for k in ("active", "withdrawn"):
        if not isinstance(x[k], list):
            fail("release-index." + k)
        prev = None
        for h in x[k]:
            if not is_hash(h):
                fail("release-index.hash")
            if prev is not None and h <= prev:
                fail("release-index.sorted")
            prev = h
    if set(x["active"]) & set(x["withdrawn"]):
        fail("release-index.disjoint")


def check_external_reference(x):
    _req(x, ("schema", "certificate_id", "certificate_hash", "issuer_origin", "claim"))
    if x["schema"] != "evalseal-reference/1":
        fail("reference.schema")
    if not _id(x["certificate_id"], "crt"):
        fail("reference.certificate_id")
    if not is_hash(x["certificate_hash"]):
        fail("reference.certificate_hash")
    if not isinstance(x["issuer_origin"], str) or not _ascii(x["issuer_origin"]):
        fail("reference.issuer_origin")
    if x["claim"] != "point-in-time-evaluation-only":
        fail("reference.claim")


# ---------------------------------------------------------------------------
# Commands / replies (spec §7.1)


def check_command(x):
    if not isinstance(x, dict):
        fail("command")
    _req(x, ("op", "args"))
    op, a = x["op"], x["args"]
    if not isinstance(a, dict):
        fail("command.args")
    if op == "product.create":
        _req(a, ("label", "target_ref"))
        if not is_label(a["label"]):
            fail("args.label")
        if not (isinstance(a["target_ref"], str) and TARGET_REF_RE.match(a["target_ref"])):
            fail("args.target_ref")
    elif op == "board.create":
        _req(a, ("label",))
        if not is_label(a["label"]):
            fail("args.label")
    elif op == "run.create":
        _req(a, ("product_id", "release_hash", "track", "board_id", "prior_certificate_id"))
        if not _id(a["product_id"], "prd"):
            fail("args.product_id")
        if not is_hash(a["release_hash"]):
            fail("args.release_hash")
        if a["track"] not in ("public", "private"):
            fail("args.track")
        if a["board_id"] is not None and not _id(a["board_id"], "brd"):
            fail("args.board_id")
        if a["prior_certificate_id"] is not None and not _id(a["prior_certificate_id"], "crt"):
            fail("args.prior_certificate_id")
    elif op == "run.cancel":
        _req(a, ("run_id", "expected_revision", "reason"))
        if not _id(a["run_id"], "run"):
            fail("args.run_id")
        if not _int(a["expected_revision"], 1):
            fail("args.expected_revision")
        if a["reason"] != "OWNER_CANCELLED":
            fail("args.reason")
    elif op == "certificate.revoke":
        _req(a, ("certificate_id", "expected_revision", "reason"))
        if not _id(a["certificate_id"], "crt"):
            fail("args.certificate_id")
        if not _int(a["expected_revision"], 1):
            fail("args.expected_revision")
        if a["reason"] not in REVOKE_REASONS:
            fail("args.reason")
    elif op == "worker.claim":
        _req(a, ("capacity",))
        if a["capacity"] != 1:
            fail("args.capacity")
    elif op in ("worker.heartbeat", "worker.complete", "worker.fail"):
        keys = ["run_id", "lease_id", "lease_epoch"]
        if op == "worker.complete":
            keys.append("evidence_hash")
        if op == "worker.fail":
            keys.append("reason")
        _req(a, tuple(keys))
        if not _id(a["run_id"], "run") or not _id(a["lease_id"], "lse"):
            fail("args.id")
        if not _int(a["lease_epoch"], 1):
            fail("args.lease_epoch")
        if op == "worker.complete" and not is_hash(a["evidence_hash"]):
            fail("args.evidence_hash")
        if op == "worker.fail" and a["reason"] not in (
            "RECORDER_FAILURE", "TARGET_DRIFT", "RESET_FAILED", "RELEASE_UNAVAILABLE"
        ):
            fail("args.reason")
    else:
        fail("command.op")


# ---------------------------------------------------------------------------
# Registries and config files (spec §8.2)


def check_environment_descriptor(x):
    _req(x, ("schema", "os", "architecture", "sandbox_profile", "recorder_hash",
             "adapter_hash", "egress_origins"))
    if x["schema"] != "evalseal-environment/1":
        fail("environment.schema")
    if x["os"] != "linux" or x["architecture"] != "x86_64":
        fail("environment.platform")
    if x["sandbox_profile"] != "linux-isolated-v1":
        fail("environment.sandbox_profile")
    if not is_hash(x["recorder_hash"]) or not is_hash(x["adapter_hash"]):
        fail("environment.hash")
    if not isinstance(x["egress_origins"], list) or not all(isinstance(o, str) for o in x["egress_origins"]):
        fail("environment.egress_origins")


def check_target_registry(x):
    _req(x, ("schema", "targets"))
    if x["schema"] != "evalseal-target-registry/1":
        fail("target-registry.schema")
    if not isinstance(x["targets"], list):
        fail("target-registry.targets")
    for t in x["targets"]:
        _req(t, ("tenant_id", "target_ref", "target", "model_origin", "secret_env"))
        if not _id(t["tenant_id"], "tnt"):
            fail("target-registry.tenant_id")
        if not (isinstance(t["target_ref"], str) and TARGET_REF_RE.match(t["target_ref"])):
            fail("target-registry.target_ref")
        check_target(t["target"])
        if not isinstance(t["model_origin"], str) or not t["model_origin"].startswith("https://"):
            fail("target-registry.model_origin")
        if not isinstance(t["secret_env"], str) or not t["secret_env"]:
            fail("target-registry.secret_env")


def check_worker_registry(x):
    _req(x, ("schema", "workers"))
    if x["schema"] != "evalseal-worker-registry/1":
        fail("worker-registry.schema")
    if not isinstance(x["workers"], list):
        fail("worker-registry.workers")
    for w in x["workers"]:
        _req(w, ("worker_id", "tenant_id", "recorder_hash", "identity_env", "capacity"))
        if not _id(w["worker_id"], "wrk") or not _id(w["tenant_id"], "tnt"):
            fail("worker-registry.id")
        if not is_hash(w["recorder_hash"]):
            fail("worker-registry.recorder_hash")
        if not isinstance(w["identity_env"], str) or not w["identity_env"]:
            fail("worker-registry.identity_env")
        if not _int(w["capacity"], 1, 4):
            fail("worker-registry.capacity")


def check_principals(x):
    _req(x, ("schema", "principals"))
    if x["schema"] != "evalseal-principals/1":
        fail("principals.schema")
    if not isinstance(x["principals"], list):
        fail("principals.principals")
    for p in x["principals"]:
        _req(p, ("principal_id", "tenant_id", "role", "token_sha256"))
        if not isinstance(p["principal_id"], str) or not p["principal_id"]:
            fail("principals.principal_id")
        if p["tenant_id"] is not None and not _id(p["tenant_id"], "tnt"):
            fail("principals.tenant_id")
        if p["role"] not in ("reader", "submitter", "owner", "issuer-operator"):
            fail("principals.role")
        if p["role"] == "issuer-operator" and p["tenant_id"] is not None:
            fail("principals.issuer-tenant")
        if not is_hash(p["token_sha256"]):
            fail("principals.token_sha256")


def check_trust_file(x):
    _req(x, ("schema", "profile", "roots", "minimum_keyring_epoch"))
    if x["schema"] != "evalseal-trust/1":
        fail("trust.schema")
    if x["profile"] not in ("simulation", "production"):
        fail("trust.profile")
    if not isinstance(x["roots"], list) or not x["roots"]:
        fail("trust.roots")
    for r in x["roots"]:
        check_key(r)
        # production roots carry only release/release-index/keyring roles;
        # simulation profiles may pin the all-role fixture key (spec §7.2).
        if x["profile"] == "production" and \
                any(role not in ("release", "release-index", "keyring") for role in r["roles"]):
            fail("trust.root-roles")
    if not _int(x["minimum_keyring_epoch"]):
        fail("trust.minimum_keyring_epoch")


def check_client_config(x):
    _req(x, ("schema", "origin", "token_env", "trust_file", "cache_dir", "timeout_ms", "profile"))
    if x["schema"] != "evalseal-client-config/1":
        fail("config.schema")
    if not isinstance(x["origin"], str):
        fail("config.origin")
    if x["profile"] not in ("simulation", "production"):
        fail("config.profile")
    if x["profile"] == "production":
        if not x["origin"].startswith("https://"):
            fail("config.origin.tls")
        host = re.sub(r"^https://", "", x["origin"]).split("/")[0].split(":")[0]
        if host in ("localhost", "127.0.0.1", "::1"):
            fail("config.origin.loopback")
    if not isinstance(x["token_env"], str) or not x["token_env"]:
        fail("config.token_env")
    for k in ("trust_file", "cache_dir"):
        if not isinstance(x[k], str) or not x[k]:
            fail("config." + k)
    if not _int(x["timeout_ms"], 1, 300000):
        fail("config.timeout_ms")


def check_worker_config(x):
    _req(x, ("schema", "origin", "identity_env", "work_dir", "poll_seconds",
             "heartbeat_seconds", "lease_seconds", "parallel_runs",
             "sandbox_profile", "network_profile", "profile"))
    if x["schema"] != "evalseal-worker-config/1":
        fail("worker-config.schema")
    if x["profile"] not in ("simulation", "production"):
        fail("worker-config.profile")
    if x["sandbox_profile"] != "linux-isolated-v1" or x["network_profile"] != "approved-model-only":
        fail("worker-config.profiles")
    if x["poll_seconds"] != 5 or x["heartbeat_seconds"] != 30 or x["lease_seconds"] != 120:
        fail("worker-config.intervals")
    if not _int(x["parallel_runs"], 1, 4):
        fail("worker-config.parallel_runs")
    for k in ("origin", "identity_env", "work_dir"):
        if not isinstance(x[k], str) or not x[k]:
            fail("worker-config." + k)


def check_service_config(x):
    _req(x, ("schema", "protocol", "tenant_do_binding", "index_do_binding",
             "evidence_bucket_binding", "public_bucket_binding", "signer_binding",
             "keyring_object", "release_index_object", "certificate_ttl_seconds",
             "status_ttl_seconds", "private_retention_days", "public_retention_days",
             "profile"))
    if x["schema"] != "evalseal-service-config/1" or x["protocol"] != "evalseal/1":
        fail("service-config.schema")
    for k in ("tenant_do_binding", "index_do_binding", "evidence_bucket_binding",
              "public_bucket_binding", "signer_binding", "keyring_object",
              "release_index_object"):
        if not isinstance(x[k], str) or not x[k]:
            fail("service-config." + k)
    if x["certificate_ttl_seconds"] != 7776000 or x["status_ttl_seconds"] != 60:
        fail("service-config.ttl")
    if x["private_retention_days"] != 180 or x["public_retention_days"] != 2555:
        fail("service-config.retention")
    if x["profile"] not in ("simulation", "production"):
        fail("service-config.profile")


def is_valid(v, fn) -> bool:
    try:
        fn(v)
        return True
    except SchemaError:
        return False
