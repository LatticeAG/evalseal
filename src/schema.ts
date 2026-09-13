/** evalseal/1 closed wire schemas (spec §3.2, §3.3, §7.1, §8.2).
 * Closed-object rule: declared fields required, additional properties error. */

import { isHash, isLabel, isVersion } from "./canon.js";
import { isId } from "./ids.js";

export const FAMILIES = ["poisoning", "injection", "approval-bypass"] as const;
export const BANDS = ["A", "B", "C", "F"] as const;
export const KINDS = ["release", "release-index", "certificate", "pack", "checkpoint", "status", "keyring"] as const;
export const REVOKE_REASONS = ["WITHDRAWN", "CONFIG_DRIFT", "EVIDENCE_INVALID", "KEY_COMPROMISE", "SUITE_WITHDRAWN"] as const;
export const RUN_STATES = ["ADMITTED", "RUNNING", "VERIFYING", "COMPLETED", "INCOMPLETE", "CANCELLED"] as const;
export const RUN_REASONS = [
  "NO_CAPACITY", "OWNER_CANCELLED", "LEASE_EXPIRED", "WALL_CAP",
  "RECORDER_FAILURE", "RESET_FAILED", "TARGET_DRIFT", "EVIDENCE_INVALID",
  "RELEASE_UNAVAILABLE",
] as const;
export const AUDIT_TYPES = [
  "ProductCreated", "BoardCreated", "RunAdmitted", "RunClaimed",
  "LeaseRenewed", "EvidenceAccepted", "RunIncomplete", "RunCancelled",
  "IssuancePrepared", "CertificateIssued", "CertificateExpired",
  "CertificateRevoked", "EvidencePurged",
] as const;
export const CERT_STATES = ["ACTIVE", "EXPIRED", "REVOKED"] as const;
export const SEEDS = [11, 23, 37] as const;
export const TOOLS = ["docs.read", "memory.read", "memory.write", "mail.send", "db.drop"] as const;
export const MEDIA_TYPES = ["application/json", "application/octet-stream", "application/pdf", "text/plain"] as const;

const TARGET_REF_RE = /^[a-z][a-z0-9-]{0,62}$/;
const CASE_ID_RE = /^(P|I|A)B?[0-9]{2}$/;
const B64URL_SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const B64URL_KEY_RE = /^[A-Za-z0-9_-]{43}$/;

export class SchemaError extends Error {
  where: string;
  code = "BAD_SCHEMA";
  constructor(where: string) { super(where); this.where = where; }
}

export function fail(where: string): never { throw new SchemaError(where); }

function isInt(v: unknown, lo = 0, hi = 9007199254740991): boolean {
  return typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi;
}

type Obj = Record<string, unknown>;

function req(obj: unknown, keys: string[]): asserts obj is Obj {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) fail("object");
  const want = new Set(keys);
  const have = new Set(Object.keys(obj as Obj));
  if (want.size !== have.size || [...want].some(k => !have.has(k))) {
    fail("closed-object " + [...want].filter(k => !have.has(k)).concat([...have].filter(k => !want.has(k))).sort().join(","));
  }
}

function isAscii(v: unknown): v is string {
  return typeof v === "string" && [...v].every(c => c.charCodeAt(0) < 128);
}

function isToken(v: unknown): boolean {
  return typeof v === "string" && v.length >= 1 && v.length <= 64 && isAscii(v);
}

const utf8Len = (s: string) => Buffer.byteLength(s, "utf8");

// -- signed envelopes --------------------------------------------------------

export function checkSigned(obj: unknown, bodyValidator?: (b: unknown) => void, kind?: string) {
  req(obj, ["schema", "kind", "key_id", "body_hash", "body", "signature"]);
  const o = obj as Obj;
  if (o.schema !== "evalseal-signed/1") fail("signed.schema");
  if (kind !== undefined && o.kind !== kind) fail("signed.kind");
  if (!KINDS.includes(o.kind as never)) fail("signed.kind");
  if (!isId(o.key_id, "key")) fail("signed.key_id");
  if (!isHash(o.body_hash)) fail("signed.body_hash");
  if (typeof o.signature !== "string" || !B64URL_SIG_RE.test(o.signature)) fail("signed.signature");
  if (bodyValidator) bodyValidator(o.body);
}

export const SIGNED_BODY_VALIDATORS: Record<string, (b: unknown) => void> = {
  "release": checkRelease,
  "release-index": checkReleaseIndexBody,
  "certificate": checkCertificateBody,
  "pack": checkPackBody,
  "checkpoint": checkCheckpointBody,
  "status": checkStatusBody,
  "keyring": checkKeyringBody,
};

export function checkSignedTyped(obj: unknown, kind: string) {
  if (typeof obj !== "object" || obj === null || (obj as Obj).kind !== kind) fail("signed.kind");
  checkSigned(obj, SIGNED_BODY_VALIDATORS[kind], kind);
}

// -- primitive compounds ------------------------------------------------------

function isSourcePath(p: unknown): boolean {
  if (typeof p !== "string" || !p || !isAscii(p)) return false;
  if (p.includes("\\") || p.startsWith("/") || p.endsWith("/")) return false;
  return p.split("/").every(seg => seg !== "" && seg !== "." && seg !== "..");
}

export function checkBlobRef(x: unknown) {
  req(x, ["hash", "bytes", "media_type"]);
  const o = x as Obj;
  if (!isHash(o.hash)) fail("blobref.hash");
  if (!isInt(o.bytes)) fail("blobref.bytes");
  if (!MEDIA_TYPES.includes(o.media_type as never)) fail("blobref.media_type");
}

export function checkSourceFile(x: unknown) {
  req(x, ["path", "hash", "bytes", "license"]);
  const o = x as Obj;
  if (!isSourcePath(o.path)) fail("sourcefile.path");
  if (!isHash(o.hash)) fail("sourcefile.hash");
  if (!isInt(o.bytes, 0, 8 * 1024 * 1024)) fail("sourcefile.bytes");
  if (o.license !== "MIT") fail("sourcefile.license");
}

export function checkToolCall(x: unknown) {
  if (typeof x !== "object" || x === null) fail("toolcall");
  req(x, ["tool", "args"]);
  const o = x as Obj;
  const t = o.tool, a = o.args as Obj;
  if (t === "docs.read") {
    req(a, ["document"]);
    if (a.document !== "owned" && a.document !== "foreign") fail("toolcall.args.document");
  } else if (t === "memory.read") {
    req(a, ["key"]);
    if (a.key !== "owned" && a.key !== "foreign") fail("toolcall.args.key");
  } else if (t === "memory.write") {
    req(a, ["key", "value"]);
    if (a.key !== "owned" && a.key !== "foreign") fail("toolcall.args.key");
    if (typeof a.value !== "string" || utf8Len(a.value) > 4096) fail("toolcall.args.value");
  } else if (t === "mail.send") {
    req(a, ["to", "body"]);
    if (a.to !== "sink" && a.to !== "foreign") fail("toolcall.args.to");
    if (typeof a.body !== "string" || utf8Len(a.body) > 4096) fail("toolcall.args.body");
  } else if (t === "db.drop") {
    req(a, ["database"]);
    if (a.database !== "scratch" && a.database !== "protected") fail("toolcall.args.database");
  } else fail("toolcall.tool");
}

export function checkToolSelector(x: unknown) {
  if (typeof x !== "object" || x === null) fail("toolselector");
  req(x, ["tool", "args"]);
  const o = x as Obj;
  const t = o.tool, a = o.args as Obj;
  let ok: boolean;
  if (t === "docs.read") { req(a, ["document"]); ok = a.document === "owned" || a.document === "foreign"; }
  else if (t === "memory.read" || t === "memory.write") { req(a, ["key"]); ok = a.key === "owned" || a.key === "foreign"; }
  else if (t === "mail.send") { req(a, ["to"]); ok = a.to === "sink" || a.to === "foreign"; }
  else if (t === "db.drop") { req(a, ["database"]); ok = a.database === "scratch" || a.database === "protected"; }
  else fail("toolselector.tool");
  if (!ok!) fail("toolselector.args");
}

export function checkMockState(x: unknown) {
  req(x, ["owned_memory", "foreign_memory", "scratch_exists", "protected_exists", "mailbox"]);
  const o = x as Obj;
  if (typeof o.owned_memory !== "string" || typeof o.foreign_memory !== "string") fail("mockstate.memory");
  if (typeof o.scratch_exists !== "boolean" || typeof o.protected_exists !== "boolean") fail("mockstate.exists");
  if (!Array.isArray(o.mailbox)) fail("mockstate.mailbox");
  for (const m of o.mailbox as Obj[]) {
    req(m, ["to", "body"]);
    if ((m.to !== "sink" && m.to !== "foreign") || typeof m.body !== "string") fail("mockstate.mailbox[]");
  }
}

export function checkFixture(x: unknown) {
  req(x, ["user_text", "retrieved_text", "memory_text", "policy", "approval", "approved_call"]);
  const o = x as Obj;
  for (const k of ["user_text", "retrieved_text", "memory_text"]) {
    if (typeof o[k] !== "string") fail("fixture." + k);
  }
  const total = ["user_text", "retrieved_text", "memory_text"].reduce((n, k) => n + utf8Len(o[k] as string), 0);
  if (total > 32768) fail("fixture.bytes");
  if (!["allow-read", "review-write", "hard-stop"].includes(o.policy as string)) fail("fixture.policy");
  if (!["absent", "matching", "wrong-hash", "expired", "revoked"].includes(o.approval as string)) fail("fixture.approval");
  if (o.approved_call !== null) checkToolCall(o.approved_call);
  if ((o.approval === "absent") !== (o.approved_call === null)) fail("fixture.approved_call");
}

export function checkOracle(x: unknown) {
  if (typeof x !== "object" || x === null || !("kind" in (x as Obj))) fail("oracle");
  const o = x as Obj;
  if (o.kind === "no_forbidden_effect") {
    req(o, ["kind", "forbidden", "forbidden_output_tokens"]);
    if (!Array.isArray(o.forbidden) || o.forbidden.length > 64) fail("oracle.forbidden");
    for (const s of o.forbidden) checkToolSelector(s);
    if (!Array.isArray(o.forbidden_output_tokens) || o.forbidden_output_tokens.length > 64) fail("oracle.forbidden_output_tokens");
    for (const t of o.forbidden_output_tokens) if (!isToken(t)) fail("oracle.token");
  } else if (o.kind === "required_effect") {
    req(o, ["kind", "required", "required_output_token"]);
    checkToolCall(o.required);
    if (!isToken(o.required_output_token)) fail("oracle.required_output_token");
  } else fail("oracle.kind");
}

export function checkCase(x: unknown) {
  req(x, ["schema", "case_id", "family", "class", "critical", "fixture", "oracle", "provenance"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-case/1") fail("case.schema");
  if (typeof o.case_id !== "string" || !CASE_ID_RE.test(o.case_id)) fail("case.case_id");
  if (!FAMILIES.includes(o.family as never)) fail("case.family");
  const want = { poisoning: "P", injection: "I", "approval-bypass": "A" }[o.family as string];
  if (!(o.case_id as string).startsWith(want!)) fail("case.case_id.family");
  if (((o.case_id as string)[1] === "B") !== (o.class === "benign")) fail("case.case_id.class");
  if (o.class !== "adversarial" && o.class !== "benign") fail("case.class");
  if (typeof o.critical !== "boolean") fail("case.critical");
  if (o.class === "benign" && o.critical) fail("case.critical.benign");
  checkFixture(o.fixture);
  checkOracle(o.oracle);
  if (o.class === "adversarial" && (o.oracle as Obj).kind !== "no_forbidden_effect") fail("case.oracle.kind");
  if (o.class === "benign" && (o.oracle as Obj).kind !== "required_effect") fail("case.oracle.kind");
  req(o.provenance, ["source_path", "source_hash"]);
  const p = o.provenance as Obj;
  if (!isSourcePath(p.source_path)) fail("case.provenance.source_path");
  if (!isHash(p.source_hash)) fail("case.provenance.source_hash");
}

export function checkSuite(x: unknown) {
  req(x, ["family", "version", "source_tree_hash", "files", "cases"]);
  const o = x as Obj;
  if (!FAMILIES.includes(o.family as never)) fail("suite.family");
  if (!isVersion(o.version)) fail("suite.version");
  if (!isHash(o.source_tree_hash)) fail("suite.source_tree_hash");
  if (!Array.isArray(o.files) || o.files.length > 256) fail("suite.files");
  const seen = new Set<string>();
  let total = 0, prev: string | null = null;
  for (const f of o.files as Obj[]) {
    checkSourceFile(f);
    if (seen.has(f.path as string) || (prev !== null && (f.path as string) < prev)) fail("suite.files.sorted");
    seen.add(f.path as string);
    prev = f.path as string;
    total += f.bytes as number;
  }
  if (total > 64 * 1024 * 1024) fail("suite.files.total");
  if (!Array.isArray(o.cases) || o.cases.length !== 40) fail("suite.cases");
  prev = null;
  for (const c of o.cases as Obj[]) {
    req(c, ["case_id", "case_hash"]);
    if (typeof c.case_id !== "string" || !isHash(c.case_hash)) fail("suite.cases[]");
    if (prev !== null && c.case_id <= prev) fail("suite.cases.sorted");
    prev = c.case_id;
  }
}

export function checkThreshold(x: unknown) {
  req(x, ["band", "adversarial_total_bp", "adversarial_family_bp", "benign_total_bp", "benign_family_bp"]);
  const o = x as Obj;
  if (!["A", "B", "C"].includes(o.band as string)) fail("threshold.band");
  for (const k of ["adversarial_total_bp", "adversarial_family_bp", "benign_total_bp", "benign_family_bp"]) {
    if (!isInt(o[k], 0, 10000)) fail("threshold." + k);
  }
}

export function checkRubric(x: unknown) {
  req(x, ["schema", "version", "critical_policy", "case_policy", "thresholds"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-rubric/1") fail("rubric.schema");
  if (!isVersion(o.version)) fail("rubric.version");
  if (o.critical_policy !== "any-failure-F" || o.case_policy !== "all-repeats-pass") fail("rubric.policy");
  if (!Array.isArray(o.thresholds)) fail("rubric.thresholds");
  for (const t of o.thresholds) checkThreshold(t);
}

export function checkRelease(x: unknown) {
  req(x, ["schema", "version", "profile", "suites", "rubric", "runner_image_hash",
          "oracle_hash", "adapter_hash", "seeds", "repeats", "trial_timeout_ms",
          "max_tool_calls", "max_output_bytes", "max_input_bytes",
          "source_date_epoch", "scope_lines"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-release/1") fail("release.schema");
  if (!isVersion(o.version)) fail("release.version");
  if (o.profile !== "text-tools-en-v1") fail("release.profile");
  if (!Array.isArray(o.suites) || o.suites.length !== 3) fail("release.suites");
  (o.suites as Obj[]).forEach((s, i) => {
    checkSuite(s);
    if (s.family !== FAMILIES[i]) fail("release.suites.family-order");
  });
  checkRubric(o.rubric);
  for (const k of ["runner_image_hash", "oracle_hash", "adapter_hash"]) {
    if (!isHash(o[k])) fail("release." + k);
  }
  if (JSON.stringify(o.seeds) !== "[11,23,37]" || o.repeats !== 3) fail("release.schedule");
  if (o.trial_timeout_ms !== 30000 || o.max_tool_calls !== 16) fail("release.limits");
  if (o.max_output_bytes !== 16384 || o.max_input_bytes !== 32768) fail("release.limits");
  if (!isInt(o.source_date_epoch)) fail("release.source_date_epoch");
  if (!Array.isArray(o.scope_lines) || o.scope_lines.length !== 4) fail("release.scope_lines");
  for (const line of o.scope_lines) if (!isLabel(line)) fail("release.scope_lines[]");
}

export function checkTarget(x: unknown) {
  req(x, ["schema", "product_version", "image_hash", "config_hash", "policy_hash",
          "tool_schema_hash", "model", "sampling", "tool_profile", "language",
          "gateway_count", "environment_hash"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-target/1") fail("target.schema");
  if (!isLabel(o.product_version)) fail("target.product_version");
  for (const k of ["image_hash", "config_hash", "policy_hash", "tool_schema_hash", "environment_hash"]) {
    if (!isHash(o[k])) fail("target." + k);
  }
  const m = o.model as Obj;
  req(m, ["provider", "revision", "revision_assurance"]);
  if (!isLabel(m.provider) || !isLabel(m.revision)) fail("target.model");
  if (m.revision === "latest" || m.revision === "auto") fail("target.model.revision.mutable");
  if (m.revision_assurance !== "provider-declared") fail("target.model.revision_assurance");
  const s = o.sampling as Obj;
  req(s, ["temperature_milli", "top_p_milli", "max_tokens"]);
  if (s.temperature_milli !== 0 || s.top_p_milli !== 1000 || s.max_tokens !== 2048) fail("target.sampling");
  if (o.tool_profile !== "simulated-five-v1" || o.language !== "en" || o.gateway_count !== 1) fail("target.profile");
}

export function checkProduct(x: unknown) {
  req(x, ["product_id", "tenant_id", "label", "target_ref", "created_at"]);
  const o = x as Obj;
  if (!isId(o.product_id, "prd") || !isId(o.tenant_id, "tnt")) fail("product.id");
  if (!isLabel(o.label)) fail("product.label");
  if (typeof o.target_ref !== "string" || !TARGET_REF_RE.test(o.target_ref)) fail("product.target_ref");
  if (!isInt(o.created_at)) fail("product.created_at");
}

export function checkBoard(x: unknown) {
  req(x, ["board_id", "tenant_id", "label", "visibility", "created_at"]);
  const o = x as Obj;
  if (!isId(o.board_id, "brd") || !isId(o.tenant_id, "tnt")) fail("board.id");
  if (!isLabel(o.label)) fail("board.label");
  if (o.visibility !== "private") fail("board.visibility");
  if (!isInt(o.created_at)) fail("board.created_at");
}

export function checkObservation(x: unknown) {
  req(x, ["trial_key", "target_hash", "before_state_hash", "after_state_hash",
          "attempted_calls", "executed_calls", "output", "outcome", "approval_seen"]);
  const o = x as Obj;
  if (typeof o.trial_key !== "string" || !isAscii(o.trial_key)) fail("observation.trial_key");
  for (const k of ["target_hash", "before_state_hash", "after_state_hash"]) {
    if (!isHash(o[k])) fail("observation." + k);
  }
  for (const k of ["attempted_calls", "executed_calls"]) {
    if (!Array.isArray(o[k]) || (o[k] as unknown[]).length > 16) fail("observation." + k);
    for (const c of o[k] as unknown[]) checkToolCall(c);
  }
  if (typeof o.output !== "string" || utf8Len(o.output) > 16384) fail("observation.output");
  if (!["returned", "target_timeout", "target_error"].includes(o.outcome as string)) fail("observation.outcome");
  if (!["absent", "matching", "wrong-hash", "expired", "revoked"].includes(o.approval_seen as string)) fail("observation.approval_seen");
}

export function checkTrial(x: unknown) {
  req(x, ["case_id", "repeat", "seed", "observation", "observation_hash"]);
  const o = x as Obj;
  if (typeof o.case_id !== "string" || !CASE_ID_RE.test(o.case_id)) fail("trial.case_id");
  if (!isInt(o.repeat) || ![0, 1, 2].includes(o.repeat as number)) fail("trial.repeat");
  if (!SEEDS.includes(o.seed as never)) fail("trial.seed");
  checkObservation(o.observation);
  if (!isHash(o.observation_hash)) fail("trial.observation_hash");
}

export function checkEvidence(x: unknown) {
  req(x, ["schema", "run_id", "lease_id", "lease_epoch", "worker_id", "release_hash",
          "target_hash", "trials", "raw_transcript", "recorder_hash", "started_at", "finished_at"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-evidence/1") fail("evidence.schema");
  if (!isId(o.run_id, "run") || !isId(o.lease_id, "lse") || !isId(o.worker_id, "wrk")) fail("evidence.id");
  if (!isInt(o.lease_epoch, 1)) fail("evidence.lease_epoch");
  for (const k of ["release_hash", "target_hash", "recorder_hash"]) {
    if (!isHash(o[k])) fail("evidence." + k);
  }
  if (!Array.isArray(o.trials)) fail("evidence.trials");
  for (const t of o.trials) checkTrial(t);
  checkBlobRef(o.raw_transcript);
  if (!isInt(o.started_at) || !isInt(o.finished_at)) fail("evidence.time");
}

export function checkFamilyResult(x: unknown) {
  req(x, ["family", "adversarial_pass", "adversarial_total", "benign_pass", "benign_total", "critical_fail"]);
  const o = x as Obj;
  if (!FAMILIES.includes(o.family as never)) fail("familyresult.family");
  if (!isInt(o.adversarial_pass, 0, 30) || o.adversarial_total !== 30) fail("familyresult.adversarial");
  if (!isInt(o.benign_pass, 0, 10) || o.benign_total !== 10) fail("familyresult.benign");
  if (!isInt(o.critical_fail, 0, 5)) fail("familyresult.critical");
  if ((o.critical_fail as number) > Math.min(5, 30 - (o.adversarial_pass as number))) fail("familyresult.critical.bounds");
}

export function checkGrade(x: unknown) {
  req(x, ["band", "reason"]);
  const o = x as Obj;
  if (!BANDS.includes(o.band as never)) fail("grade.band");
  if (!["THRESHOLDS_MET", "CRITICAL_FAILURE", "BELOW_THRESHOLDS"].includes(o.reason as string)) fail("grade.reason");
}

export function checkResult(x: unknown) {
  req(x, ["schema", "run_id", "release_hash", "target_hash", "families", "grade",
          "evidence_hash", "reproducibility_hash", "reproducibility_level"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-result/1") fail("result.schema");
  if (!isId(o.run_id, "run")) fail("result.run_id");
  for (const k of ["release_hash", "target_hash", "evidence_hash", "reproducibility_hash"]) {
    if (!isHash(o[k])) fail("result." + k);
  }
  if (!Array.isArray(o.families) || o.families.length !== 3) fail("result.families");
  (o.families as Obj[]).forEach((f, i) => {
    checkFamilyResult(f);
    if (f.family !== FAMILIES[i]) fail("result.families.order");
  });
  checkGrade(o.grade);
  if (o.reproducibility_level !== "grade-replay") fail("result.reproducibility_level");
}

export function checkRun(x: unknown) {
  req(x, ["run_id", "product_id", "release_hash", "target_hash", "track", "board_id",
          "state", "revision", "admitted_at", "finished_at", "reason",
          "certificate_id", "prior_certificate_id"]);
  const o = x as Obj;
  if (!isId(o.run_id, "run") || !isId(o.product_id, "prd")) fail("run.id");
  if (!isHash(o.release_hash) || !isHash(o.target_hash)) fail("run.hash");
  if (o.track !== "public" && o.track !== "private") fail("run.track");
  if (o.track === "public" && o.board_id !== null) fail("run.board_id");
  if (o.board_id !== null && !isId(o.board_id, "brd")) fail("run.board_id");
  if (!RUN_STATES.includes(o.state as never)) fail("run.state");
  if (!isInt(o.revision, 1)) fail("run.revision");
  if (!isInt(o.admitted_at)) fail("run.admitted_at");
  if (o.finished_at !== null && !isInt(o.finished_at)) fail("run.finished_at");
  if (o.reason !== null && !RUN_REASONS.includes(o.reason as never)) fail("run.reason");
  if (o.certificate_id !== null && !isId(o.certificate_id, "crt")) fail("run.certificate_id");
  if (o.prior_certificate_id !== null && !isId(o.prior_certificate_id, "crt")) fail("run.prior_certificate_id");
}

export function checkLease(x: unknown) {
  req(x, ["run_id", "lease_id", "epoch", "worker_id", "expires_at", "target", "release_hash"]);
  const o = x as Obj;
  if (!isId(o.run_id, "run") || !isId(o.lease_id, "lse") || !isId(o.worker_id, "wrk")) fail("lease.id");
  if (!isInt(o.epoch, 1) || !isInt(o.expires_at)) fail("lease.fields");
  checkTarget(o.target);
  if (!isHash(o.release_hash)) fail("lease.release_hash");
}

export function checkCertificateBody(x: unknown) {
  req(x, ["schema", "certificate_id", "run_id", "product_id", "product_label",
          "product_version", "track", "release_hash", "target_hash", "result_hash",
          "reproducibility_hash", "evidence_head", "band", "qualification",
          "issued_at", "expires_at", "scope_lines", "prior_certificate_id"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-certificate/1") fail("certificate.schema");
  if (!isId(o.certificate_id, "crt") || !isId(o.run_id, "run") || !isId(o.product_id, "prd")) fail("certificate.id");
  if (!isLabel(o.product_label) || !isLabel(o.product_version)) fail("certificate.label");
  if (o.track !== "public" && o.track !== "private") fail("certificate.track");
  for (const k of ["release_hash", "target_hash", "result_hash", "reproducibility_hash", "evidence_head"]) {
    if (!isHash(o[k])) fail("certificate." + k);
  }
  if (!BANDS.includes(o.band as never)) fail("certificate.band");
  if (o.qualification !== "CERTIFIED" && o.qualification !== "NOT_CERTIFIED") fail("certificate.qualification");
  if ((o.qualification === "CERTIFIED") !== (["A", "B", "C"].includes(o.band as string))) fail("certificate.qualification.band");
  if (!isInt(o.issued_at) || !isInt(o.expires_at)) fail("certificate.time");
  if ((o.expires_at as number) !== (o.issued_at as number) + 7776000) fail("certificate.lifetime");
  if (!Array.isArray(o.scope_lines) || o.scope_lines.length !== 4) fail("certificate.scope_lines");
  for (const line of o.scope_lines) if (!isLabel(line)) fail("certificate.scope_lines[]");
  if (o.prior_certificate_id !== null && !isId(o.prior_certificate_id, "crt")) fail("certificate.prior_certificate_id");
}

export function checkStatusBody(x: unknown) {
  req(x, ["schema", "certificate_id", "certificate_hash", "state", "qualifies",
          "reason", "as_of", "valid_until", "head"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-status/1") fail("status.schema");
  if (!isId(o.certificate_id, "crt")) fail("status.certificate_id");
  if (!isHash(o.certificate_hash) || !isHash(o.head)) fail("status.hash");
  if (!CERT_STATES.includes(o.state as never)) fail("status.state");
  if (typeof o.qualifies !== "boolean") fail("status.qualifies");
  if (o.reason !== null && !(REVOKE_REASONS as readonly string[]).concat("EXPIRED").includes(o.reason as string)) fail("status.reason");
  if (!isInt(o.as_of) || !isInt(o.valid_until)) fail("status.time");
}

export function checkAuditBody(x: unknown) {
  req(x, ["schema", "tenant_id", "stream_id", "event_id", "seq", "prev_hash",
          "at", "type", "subject_id", "state_revision", "payload_hash"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-audit/1") fail("audit.schema");
  if (!isId(o.tenant_id, "tnt") || !isId(o.event_id, "evt")) fail("audit.id");
  if (typeof o.stream_id !== "string" || typeof o.subject_id !== "string") fail("audit.stream");
  if (!isInt(o.seq, 1) || !isInt(o.state_revision, 1) || !isInt(o.at)) fail("audit.fields");
  if (o.prev_hash !== null && !isHash(o.prev_hash)) fail("audit.prev_hash");
  if (!AUDIT_TYPES.includes(o.type as never)) fail("audit.type");
  if (!isHash(o.payload_hash)) fail("audit.payload_hash");
}

export function checkAuditEntry(x: unknown) {
  req(x, ["body", "hash"]);
  checkAuditBody((x as Obj).body);
  if (!isHash((x as Obj).hash)) fail("audit.hash");
}

export function checkAuditPayload(x: unknown) {
  req(x, ["request_hash", "before", "after", "object_hash", "reason"]);
  const o = x as Obj;
  if (o.request_hash !== null && !isHash(o.request_hash)) fail("payload.request_hash");
  if (o.before !== null && typeof o.before !== "string") fail("payload.before");
  if (typeof o.after !== "string") fail("payload.after");
  if (!isHash(o.object_hash)) fail("payload.object_hash");
  if (o.reason !== null && typeof o.reason !== "string") fail("payload.reason");
}

export function checkCheckpointBody(x: unknown) {
  req(x, ["schema", "tenant_id", "stream_id", "seq", "head", "at"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-checkpoint/1") fail("checkpoint.schema");
  if (!isId(o.tenant_id, "tnt")) fail("checkpoint.tenant_id");
  if (typeof o.stream_id !== "string") fail("checkpoint.stream_id");
  if (!isInt(o.seq, 1) || !isInt(o.at) || !isHash(o.head)) fail("checkpoint.fields");
}

export function checkPackBody(x: unknown) {
  req(x, ["schema", "certificate_hash", "files", "disclosure"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-pack/1") fail("pack.schema");
  if (!isHash(o.certificate_hash)) fail("pack.certificate_hash");
  if (o.disclosure !== "public-redacted" && o.disclosure !== "private-full") fail("pack.disclosure");
  if (!Array.isArray(o.files) || o.files.length > 16) fail("pack.files");
  let prev: string | null = null;
  for (const f of o.files as Obj[]) {
    req(f, ["path", "hash", "bytes", "media_type"]);
    if (typeof f.path !== "string" || !isHash(f.hash) || !isInt(f.bytes)) fail("pack.files[]");
    if (!MEDIA_TYPES.includes(f.media_type as never)) fail("pack.files[].media_type");
    if (prev !== null && f.path <= prev) fail("pack.files.sorted");
    prev = f.path;
  }
}

export function checkKey(x: unknown) {
  req(x, ["key_id", "public_key", "roles", "not_before", "not_after", "revoked"]);
  const o = x as Obj;
  if (!isId(o.key_id, "key")) fail("key.key_id");
  if (typeof o.public_key !== "string" || !B64URL_KEY_RE.test(o.public_key)) fail("key.public_key");
  if (!Array.isArray(o.roles) || o.roles.length === 0) fail("key.roles");
  for (const r of o.roles) if (!KINDS.includes(r as never)) fail("key.roles[]");
  if (new Set(o.roles).size !== o.roles.length) fail("key.roles.dup");
  if (!isInt(o.not_before) || !isInt(o.not_after) || (o.not_after as number) <= (o.not_before as number)) fail("key.validity");
  if (typeof o.revoked !== "boolean") fail("key.revoked");
}

export function checkKeyringBody(x: unknown) {
  req(x, ["schema", "epoch", "issued_at", "valid_until", "keys", "previous_hash"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-keyring/1") fail("keyring.schema");
  if (!isInt(o.epoch, 1) || !isInt(o.issued_at) || !isInt(o.valid_until)) fail("keyring.fields");
  if ((o.valid_until as number) > (o.issued_at as number) + 86400) fail("keyring.valid_until");
  if (!Array.isArray(o.keys) || o.keys.length === 0) fail("keyring.keys");
  const ids = new Set<string>();
  for (const k of o.keys) {
    checkKey(k);
    if (ids.has((k as Obj).key_id as string)) fail("keyring.keys.dup");
    ids.add((k as Obj).key_id as string);
  }
  if (o.previous_hash !== null && !isHash(o.previous_hash)) fail("keyring.previous_hash");
}

export function checkReleaseIndexBody(x: unknown) {
  req(x, ["schema", "active", "withdrawn"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-release-index/1") fail("release-index.schema");
  for (const k of ["active", "withdrawn"]) {
    if (!Array.isArray(o[k])) fail("release-index." + k);
    let prev: string | null = null;
    for (const h of o[k] as unknown[]) {
      if (!isHash(h)) fail("release-index.hash");
      if (prev !== null && (h as string) <= prev) fail("release-index.sorted");
      prev = h as string;
    }
  }
  const act = new Set(o.active as string[]);
  if ((o.withdrawn as string[]).some(h => act.has(h))) fail("release-index.disjoint");
}

export function checkExternalReference(x: unknown) {
  req(x, ["schema", "certificate_id", "certificate_hash", "issuer_origin", "claim"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-reference/1") fail("reference.schema");
  if (!isId(o.certificate_id, "crt")) fail("reference.certificate_id");
  if (!isHash(o.certificate_hash)) fail("reference.certificate_hash");
  if (typeof o.issuer_origin !== "string" || !isAscii(o.issuer_origin)) fail("reference.issuer_origin");
  if (o.claim !== "point-in-time-evaluation-only") fail("reference.claim");
}

// -- commands -----------------------------------------------------------------

export function checkCommand(x: unknown) {
  if (typeof x !== "object" || x === null) fail("command");
  req(x, ["op", "args"]);
  const o = x as Obj;
  const a = o.args;
  if (typeof a !== "object" || a === null) fail("command.args");
  const op = o.op;
  if (op === "product.create") {
    req(a, ["label", "target_ref"]);
    if (!isLabel((a as Obj).label)) fail("args.label");
    const tr = (a as Obj).target_ref;
    if (typeof tr !== "string" || !TARGET_REF_RE.test(tr)) fail("args.target_ref");
  } else if (op === "board.create") {
    req(a, ["label"]);
    if (!isLabel((a as Obj).label)) fail("args.label");
  } else if (op === "run.create") {
    req(a, ["product_id", "release_hash", "track", "board_id", "prior_certificate_id"]);
    const aa = a as Obj;
    if (!isId(aa.product_id, "prd")) fail("args.product_id");
    if (!isHash(aa.release_hash)) fail("args.release_hash");
    if (aa.track !== "public" && aa.track !== "private") fail("args.track");
    if (aa.board_id !== null && !isId(aa.board_id, "brd")) fail("args.board_id");
    if (aa.prior_certificate_id !== null && !isId(aa.prior_certificate_id, "crt")) fail("args.prior_certificate_id");
  } else if (op === "run.cancel") {
    req(a, ["run_id", "expected_revision", "reason"]);
    const aa = a as Obj;
    if (!isId(aa.run_id, "run")) fail("args.run_id");
    if (!isInt(aa.expected_revision, 1)) fail("args.expected_revision");
    if (aa.reason !== "OWNER_CANCELLED") fail("args.reason");
  } else if (op === "certificate.revoke") {
    req(a, ["certificate_id", "expected_revision", "reason"]);
    const aa = a as Obj;
    if (!isId(aa.certificate_id, "crt")) fail("args.certificate_id");
    if (!isInt(aa.expected_revision, 1)) fail("args.expected_revision");
    if (!REVOKE_REASONS.includes(aa.reason as never)) fail("args.reason");
  } else if (op === "worker.claim") {
    req(a, ["capacity"]);
    if ((a as Obj).capacity !== 1) fail("args.capacity");
  } else if (op === "worker.heartbeat" || op === "worker.complete" || op === "worker.fail") {
    const keys = ["run_id", "lease_id", "lease_epoch"];
    if (op === "worker.complete") keys.push("evidence_hash");
    if (op === "worker.fail") keys.push("reason");
    req(a, keys);
    const aa = a as Obj;
    if (!isId(aa.run_id, "run") || !isId(aa.lease_id, "lse")) fail("args.id");
    if (!isInt(aa.lease_epoch, 1)) fail("args.lease_epoch");
    if (op === "worker.complete" && !isHash(aa.evidence_hash)) fail("args.evidence_hash");
    if (op === "worker.fail" && !["RECORDER_FAILURE", "TARGET_DRIFT", "RESET_FAILED", "RELEASE_UNAVAILABLE"].includes(aa.reason as string)) fail("args.reason");
  } else fail("command.op");
}

// -- registries and config files (spec §8.2) -----------------------------------

export function checkEnvironmentDescriptor(x: unknown) {
  req(x, ["schema", "os", "architecture", "sandbox_profile", "recorder_hash",
          "adapter_hash", "egress_origins"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-environment/1") fail("environment.schema");
  if (o.os !== "linux" || o.architecture !== "x86_64") fail("environment.platform");
  if (o.sandbox_profile !== "linux-isolated-v1") fail("environment.sandbox_profile");
  if (!isHash(o.recorder_hash) || !isHash(o.adapter_hash)) fail("environment.hash");
  if (!Array.isArray(o.egress_origins) || !(o.egress_origins as unknown[]).every(e => typeof e === "string")) fail("environment.egress_origins");
}

export function checkTargetRegistry(x: unknown) {
  req(x, ["schema", "targets"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-target-registry/1") fail("target-registry.schema");
  if (!Array.isArray(o.targets)) fail("target-registry.targets");
  for (const t of o.targets as Obj[]) {
    req(t, ["tenant_id", "target_ref", "target", "model_origin", "secret_env"]);
    if (!isId(t.tenant_id, "tnt")) fail("target-registry.tenant_id");
    if (typeof t.target_ref !== "string" || !TARGET_REF_RE.test(t.target_ref)) fail("target-registry.target_ref");
    checkTarget(t.target);
    if (typeof t.model_origin !== "string" || !t.model_origin.startsWith("https://")) fail("target-registry.model_origin");
    if (typeof t.secret_env !== "string" || !t.secret_env) fail("target-registry.secret_env");
  }
}

export function checkWorkerRegistry(x: unknown) {
  req(x, ["schema", "workers"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-worker-registry/1") fail("worker-registry.schema");
  if (!Array.isArray(o.workers)) fail("worker-registry.workers");
  for (const w of o.workers as Obj[]) {
    req(w, ["worker_id", "tenant_id", "recorder_hash", "identity_env", "capacity"]);
    if (!isId(w.worker_id, "wrk") || !isId(w.tenant_id, "tnt")) fail("worker-registry.id");
    if (!isHash(w.recorder_hash)) fail("worker-registry.recorder_hash");
    if (typeof w.identity_env !== "string" || !w.identity_env) fail("worker-registry.identity_env");
    if (!isInt(w.capacity, 1, 4)) fail("worker-registry.capacity");
  }
}

export function checkPrincipals(x: unknown) {
  req(x, ["schema", "principals"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-principals/1") fail("principals.schema");
  if (!Array.isArray(o.principals)) fail("principals.principals");
  for (const p of o.principals as Obj[]) {
    req(p, ["principal_id", "tenant_id", "role", "token_sha256"]);
    if (typeof p.principal_id !== "string" || !p.principal_id) fail("principals.principal_id");
    if (p.tenant_id !== null && !isId(p.tenant_id, "tnt")) fail("principals.tenant_id");
    if (!["reader", "submitter", "owner", "issuer-operator"].includes(p.role as string)) fail("principals.role");
    if (p.role === "issuer-operator" && p.tenant_id !== null) fail("principals.issuer-tenant");
    if (!isHash(p.token_sha256)) fail("principals.token_sha256");
  }
}

export function checkTrustFile(x: unknown) {
  req(x, ["schema", "profile", "roots", "minimum_keyring_epoch"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-trust/1") fail("trust.schema");
  if (o.profile !== "simulation" && o.profile !== "production") fail("trust.profile");
  if (!Array.isArray(o.roots) || o.roots.length === 0) fail("trust.roots");
  for (const r of o.roots as Obj[]) {
    checkKey(r);
    if (o.profile === "production" &&
        (r.roles as string[]).some(role => !["release", "release-index", "keyring"].includes(role))) {
      fail("trust.root-roles");
    }
  }
  if (!isInt(o.minimum_keyring_epoch)) fail("trust.minimum_keyring_epoch");
}

export function checkClientConfig(x: unknown) {
  req(x, ["schema", "origin", "token_env", "trust_file", "cache_dir", "timeout_ms", "profile"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-client-config/1") fail("config.schema");
  if (typeof o.origin !== "string") fail("config.origin");
  if (o.profile !== "simulation" && o.profile !== "production") fail("config.profile");
  if (o.profile === "production") {
    if (!(o.origin as string).startsWith("https://")) fail("config.origin.tls");
    const host = (o.origin as string).replace(/^https:\/\//, "").split("/")[0]!.split(":")[0]!;
    if (["localhost", "127.0.0.1", "::1"].includes(host)) fail("config.origin.loopback");
  }
  if (typeof o.token_env !== "string" || !o.token_env) fail("config.token_env");
  for (const k of ["trust_file", "cache_dir"]) {
    if (typeof o[k] !== "string" || !o[k]) fail("config." + k);
  }
  if (!isInt(o.timeout_ms, 1, 300000)) fail("config.timeout_ms");
}

export function checkWorkerConfig(x: unknown) {
  req(x, ["schema", "origin", "identity_env", "work_dir", "poll_seconds",
          "heartbeat_seconds", "lease_seconds", "parallel_runs",
          "sandbox_profile", "network_profile", "profile"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-worker-config/1") fail("worker-config.schema");
  if (o.profile !== "simulation" && o.profile !== "production") fail("worker-config.profile");
  if (o.sandbox_profile !== "linux-isolated-v1" || o.network_profile !== "approved-model-only") fail("worker-config.profiles");
  if (o.poll_seconds !== 5 || o.heartbeat_seconds !== 30 || o.lease_seconds !== 120) fail("worker-config.intervals");
  if (!isInt(o.parallel_runs, 1, 4)) fail("worker-config.parallel_runs");
  for (const k of ["origin", "identity_env", "work_dir"]) {
    if (typeof o[k] !== "string" || !o[k]) fail("worker-config." + k);
  }
}

export function checkServiceConfig(x: unknown) {
  req(x, ["schema", "protocol", "tenant_do_binding", "index_do_binding",
          "evidence_bucket_binding", "public_bucket_binding", "signer_binding",
          "keyring_object", "release_index_object", "certificate_ttl_seconds",
          "status_ttl_seconds", "private_retention_days", "public_retention_days",
          "profile"]);
  const o = x as Obj;
  if (o.schema !== "evalseal-service-config/1" || o.protocol !== "evalseal/1") fail("service-config.schema");
  for (const k of ["tenant_do_binding", "index_do_binding", "evidence_bucket_binding",
                   "public_bucket_binding", "signer_binding", "keyring_object",
                   "release_index_object"]) {
    if (typeof o[k] !== "string" || !o[k]) fail("service-config." + k);
  }
  if (o.certificate_ttl_seconds !== 7776000 || o.status_ttl_seconds !== 60) fail("service-config.ttl");
  if (o.private_retention_days !== 180 || o.public_retention_days !== 2555) fail("service-config.retention");
  if (o.profile !== "simulation" && o.profile !== "production") fail("service-config.profile");
}

export function isValid(v: unknown, fn: (x: unknown) => void): boolean {
  try { fn(v); return true; } catch (e) { if (e instanceof SchemaError) return false; throw e; }
}
