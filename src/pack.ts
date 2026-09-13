/** Attestation pack offline verification (spec §9.2, §9.4, §7.5). */

import { verifyAgainstCheckpoint } from "./audit.js";
import { blobHash, canonicalHash, domainHash, JsonError, parse } from "./canon.js";
import { familyResults, reproducibilityHash } from "./evidence.js";
import { grade } from "./grade.js";
import { reduceState, resetStateHash } from "./mock.js";
import {
  SchemaError, checkAuditEntry, checkCase,
  checkKeyringBody, checkResult, checkStatusBody,
  checkTarget, checkSigned, SIGNED_BODY_VALIDATORS,
} from "./schema.js";
import { pubFromRaw, unb64u, verifyBytes } from "./sign.js";
import { PRIVATE_EXTRA, readDirectory, extract, ZipError } from "./zipio.js";

export const ORACLE_IMPL = { schema: "evalseal-oracle-impl/1", name: "evalseal-closed-oracle", version: "1.0.0" };
export const SUPPORTED_ORACLE_HASHES = new Set([canonicalHash(ORACLE_IMPL as never)]);

export function findKey(keys: any[], keyId: string): any | null {
  return keys.find(k => k.key_id === keyId) ?? null;
}

export function verifyWithKey(envelope: any, kind: string, key: any): string {
  // verify_envelope equivalent: schema, key_id match, body_hash, signature
  try { checkSigned(envelope, SIGNED_BODY_VALIDATORS[kind], kind); } catch (e) {
    if (e instanceof SchemaError) return "BAD_SCHEMA";
    throw e;
  }
  if (envelope.key_id !== key.key_id) return "KEY_UNKNOWN";
  if (domainHash(kind, envelope.body) !== envelope.body_hash) return "HASH_MISMATCH";
  const pub = unb64u(key.public_key);
  const sig = unb64u(envelope.signature);
  if (sig.length !== 64) return "SIGNATURE_INVALID";
  const msg = Buffer.from(`evalseal/1/signature\n${kind}\n${key.key_id}\n${envelope.body_hash}`, "utf8");
  return verifyEnvelopeRaw(pub, msg, sig) ? "VALID" : "SIGNATURE_INVALID";
}

function verifyEnvelopeRaw(pub: Buffer, msg: Buffer, sig: Buffer): boolean {
  return verifyBytes(pubFromRaw(pub), msg, sig);
}

function sigVerify(envelope: any, kind: string, keys: any[]): string {
  if (typeof envelope !== "object" || envelope === null || envelope.kind !== kind) {
    return kind === "pack" ? "MANIFEST_INVALID" : "BAD_SCHEMA";
  }
  try { checkSigned(envelope, SIGNED_BODY_VALIDATORS[kind], kind); } catch (e) {
    if (e instanceof SchemaError) return kind === "pack" ? "MANIFEST_INVALID" : "BAD_SCHEMA";
    throw e;
  }
  if (domainHash(kind, envelope.body) !== envelope.body_hash) return "HASH_MISMATCH";
  const key = findKey(keys, envelope.key_id);
  if (key === null) return "KEY_UNKNOWN";
  if (!key.roles.includes(kind)) return "KEY_UNKNOWN";
  return verifyWithKey(envelope, kind, key);
}

export function zipCheck(data: Buffer): string {
  try { readDirectory(data); return "VALID"; } catch (e) {
    if (e instanceof ZipError) return e.code;
    throw e;
  }
}

function keyringSelected(embedded: any, supplied: any): [any, string | null] {
  if (supplied == null) return [embedded, null];
  try { checkKeyringBody(supplied.body); } catch { return [embedded, "KEYRING_STALE"]; }
  if (supplied.body.epoch >= embedded.body.epoch) return [supplied, null];
  return [embedded, null];
}

function checkKeyringTrust(krEnvelope: any, rootKeys: any[]): boolean {
  if (typeof krEnvelope !== "object" || krEnvelope === null || krEnvelope.kind !== "keyring") return false;
  try { checkKeyringBody(krEnvelope.body); } catch { return false; }
  const key = findKey(rootKeys, krEnvelope.key_id);
  if (key === null || !key.roles.includes("keyring")) return false;
  return verifyWithKey(krEnvelope, "keyring", key) === "VALID";
}

export function current(cert: any, status: any, keyring: any, now: number,
                        minKeyringEpoch = 0, keyringObservedAt?: number): [string, string[]] {
  const cb = cert.body;
  const keys = keyring.body.keys;
  if (now >= cb.expires_at) return ["NOT_QUALIFIED", ["CERT_EXPIRED"]];
  const skey = findKey(keys, cert.key_id);
  if (skey === null) return ["UNKNOWN", ["KEY_UNKNOWN"]];
  if (skey.revoked) return ["NOT_QUALIFIED", ["KEY_REVOKED"]];
  if (cb.band === "F") return ["NOT_QUALIFIED", ["BAND_NOT_QUALIFYING"]];

  if (status === null || status === undefined) return ["UNKNOWN", ["STATUS_MISSING"]];
  try { checkStatusBody(status.body); } catch { return ["UNKNOWN", ["STATUS_MISMATCH"]]; }
  if (status.kind !== "status") return ["UNKNOWN", ["STATUS_MISMATCH"]];
  const sk = findKey(keys, status.key_id);
  if (sk === null || !sk.roles.includes("status")) return ["UNKNOWN", ["KEY_UNKNOWN"]];
  if (verifyWithKey(status, "status", sk) !== "VALID") return ["UNKNOWN", ["STATUS_MISMATCH"]];
  const sb = status.body;
  if (sb.certificate_id !== cb.certificate_id || sb.certificate_hash !== canonicalHash(cert)) {
    return ["UNKNOWN", ["STATUS_MISMATCH"]];
  }
  const expectedQ = sb.state === "ACTIVE" && cb.band !== "F" && now < cb.expires_at;
  if (sb.state === "REVOKED") return ["NOT_QUALIFIED", ["CERT_REVOKED"]];
  if (sb.state === "EXPIRED") return ["NOT_QUALIFIED", ["CERT_EXPIRED"]];
  if (!(sb.as_of <= now && now < sb.valid_until)) return ["UNKNOWN", ["STATUS_STALE"]];
  if (sb.qualifies !== expectedQ) return ["UNKNOWN", ["STATUS_MISMATCH"]];

  const kb = keyring.body;
  if (kb.epoch < minKeyringEpoch) return ["UNKNOWN", ["KEYRING_STALE"]];
  if (now > kb.valid_until) return ["UNKNOWN", ["KEYRING_STALE"]];
  const freshnessBase = Math.max(kb.issued_at, keyringObservedAt ?? 0);
  if (!(0 <= now - freshnessBase && now - freshnessBase < 60)) return ["UNKNOWN", ["KEYRING_STALE"]];
  if (sb.qualifies) return ["QUALIFIES", []];
  return ["NOT_QUALIFIED", cb.band === "F" ? ["BAND_NOT_QUALIFYING"] : []];
}

export interface VerifyOptions {
  now: number;
  root_keys: any[];
  status?: any;
  keyring?: any;
  min_keyring_epoch?: number;
  keyring_observed_at?: number | undefined;
}

export function verifyPack(data: Buffer, options: VerifyOptions) {
  const now = options.now;
  const rootKeys = options.root_keys;
  const status = options.status ?? null;
  const suppliedKeyring = options.keyring ?? null;
  const minEpoch = options.min_keyring_epoch ?? 0;
  const observedAt = options.keyring_observed_at;

  const out: any = { integrity: "INVALID", band: null, coverage: "none", current: "UNKNOWN", reasons: [] };

  const code = zipCheck(data);
  if (code !== "VALID") { out.reasons = [code]; return out; }
  let files: Map<string, Buffer>;
  try { files = extract(data, readDirectory(data)); } catch (e) {
    if (e instanceof ZipError) { out.reasons = [e.code]; return out; }
    throw e;
  }

  let cert: any, release: any, checkpoint: any, keyring: any, manifestEnv: any,
      result: any, target: any, cases: any, audit: any[];
  try {
    cert = parse(files.get("certificate.json")!);
    release = parse(files.get("release.json")!);
    checkpoint = parse(files.get("checkpoint.json")!);
    keyring = parse(files.get("keyring.json")!);
    manifestEnv = parse(files.get("manifest.json")!);
    result = parse(files.get("result.json")!);
    target = parse(files.get("target.json")!);
    cases = parse(files.get("cases.json")!);
    audit = files.get("audit.jsonl")!.toString("utf8").split("\n").filter(l => l)
      .map(l => parse(Buffer.from(l, "utf8")));
  } catch (e) {
    if (e instanceof JsonError) { out.reasons = ["PACK_ENTRY_INVALID"]; return out; }
    throw e;
  }

  try {
    checkSigned(cert, SIGNED_BODY_VALIDATORS["certificate"], "certificate");
    checkSigned(release, SIGNED_BODY_VALIDATORS["release"], "release");
    checkSigned(checkpoint, SIGNED_BODY_VALIDATORS["checkpoint"], "checkpoint");
    checkSigned(keyring, SIGNED_BODY_VALIDATORS["keyring"], "keyring");
    checkSigned(manifestEnv, SIGNED_BODY_VALIDATORS["pack"], "pack");
    checkResult(result);
    checkTarget(target);
    if (!Array.isArray(cases) || cases.length !== 120) throw new SchemaError("cases");
    for (const c of cases) checkCase(c);
    for (const e of audit) checkAuditEntry(e);
  } catch (e) {
    if (e instanceof SchemaError) { out.reasons = ["PACK_ENTRY_INVALID"]; return out; }
    throw e;
  }

  if (!checkKeyringTrust(keyring, rootKeys)) { out.reasons = ["KEY_UNKNOWN"]; return out; }
  if (suppliedKeyring !== null && !checkKeyringTrust(suppliedKeyring, rootKeys)) {
    out.reasons = ["KEYRING_STALE"]; return out;
  }
  const [keyringSel, kerr] = keyringSelected(keyring, suppliedKeyring);
  if (kerr) { out.reasons = [kerr]; return out; }
  const keys = keyringSel.body.keys;


  let r = sigVerify(release, "release", rootKeys);
  if (r !== "VALID") { out.reasons = [r]; return out; }
  for (const [env, kind] of [[cert, "certificate"], [manifestEnv, "pack"], [checkpoint, "checkpoint"]] as const) {
    r = sigVerify(env, kind, keys);
    if (r !== "VALID") { out.reasons = [kind === "pack" ? "MANIFEST_INVALID" : r]; return out; }
  }

  const mb = manifestEnv.body;
  if (mb.certificate_hash !== canonicalHash(cert)) { out.reasons = ["MANIFEST_INVALID"]; return out; }
  const declared = new Map<string, any>(mb.files.map((f: any) => [f.path, f]));
  const fileNames = new Set([...files.keys()].filter(n => n !== "manifest.json"));
  if (declared.size !== fileNames.size || [...declared.keys()].some(k => !fileNames.has(k))) {
    out.reasons = ["MANIFEST_INVALID"]; return out;
  }
  for (const [name, blob] of files) {
    if (name === "manifest.json") continue;
    const f = declared.get(name)!;
    if (f.bytes !== blob.length || f.hash !== blobHash(blob)) {
      out.reasons = ["PACK_ENTRY_INVALID"]; return out;
    }
  }
  const hasPrivate = [...files.keys()].some(n => PRIVATE_EXTRA.includes(n));
  if (mb.disclosure === "public-redacted" && hasPrivate) { out.reasons = ["PACK_PATH_INVALID"]; return out; }
  if (mb.disclosure === "private-full" && PRIVATE_EXTRA.some(n => !files.has(n))) {
    out.reasons = ["PACK_PATH_INVALID"]; return out;
  }

  const cb = cert.body;
  if (cb.release_hash !== canonicalHash(release) ||
      cb.target_hash !== canonicalHash(target) ||
      cb.result_hash !== canonicalHash(result) ||
      JSON.stringify(cb.scope_lines) !== JSON.stringify(release.body.scope_lines)) {
    out.reasons = ["MANIFEST_INVALID"]; return out;
  }

  const listing = new Map<string, string>();
  for (const s of release.body.suites) for (const c of s.cases) listing.set(c.case_id, c.case_hash);
  if (listing.size !== 120 || cases.some((c: any) => !listing.has(c.case_id))) {
    out.reasons = ["PACK_ENTRY_INVALID"]; return out;
  }
  for (const c of cases) {
    if (canonicalHash(c) !== listing.get(c.case_id)) { out.reasons = ["PACK_ENTRY_INVALID"]; return out; }
  }

  let recomputed;
  try { recomputed = grade(result.families, release.body.rubric); } catch {
    out.reasons = ["PACK_ENTRY_INVALID"]; return out;
  }
  if (JSON.stringify(recomputed) !== JSON.stringify(result.grade) || result.grade.band !== cb.band) {
    out.reasons = ["MANIFEST_INVALID"]; return out;
  }
  if (result.release_hash !== canonicalHash(release) || result.target_hash !== canonicalHash(target)) {
    out.reasons = ["MANIFEST_INVALID"]; return out;
  }

  const rc = verifyAgainstCheckpoint(audit, checkpoint);
  if (rc !== "VALID") { out.reasons = [rc]; return out; }
  if (audit.length && audit[audit.length - 1].hash !== cb.evidence_head) {
    out.reasons = ["HEAD_MISMATCH"]; return out;
  }

  let coverage = "summary-only";
  if (hasPrivate) {
    if (!SUPPORTED_ORACLE_HASHES.has(release.body.oracle_hash)) {
      out.reasons = ["ORACLE_UNSUPPORTED"]; return out;
    }
    const evidence = parse(files.get("evidence.json")!);
    const transcript = files.get("transcript.bin")!;
    const rt = evidence.raw_transcript;
    if (rt.hash !== blobHash(transcript) || rt.bytes !== transcript.length) {
      out.reasons = ["PACK_ENTRY_INVALID"]; return out;
    }
    if (canonicalHash(evidence) !== result.evidence_hash) {
      out.reasons = ["PACK_ENTRY_INVALID"]; return out;
    }
    const bodies = new Map(cases.map((c: any) => [c.case_id, c]));
    for (const t of evidence.trials) {
      const kase = bodies.get(t.case_id);
      const obs = t.observation;
      if (canonicalHash(obs) !== t.observation_hash) { out.reasons = ["HASH_MISMATCH"]; return out; }
      if (obs.before_state_hash !== resetStateHash(kase.fixture)) { out.reasons = ["RESET_MISMATCH"]; return out; }
      if (obs.after_state_hash !== canonicalHash(reduceState(kase.fixture, obs.executed_calls) as never)) {
        out.reasons = ["RESET_MISMATCH"]; return out;
      }
    }
    const fams = familyResults(release.body, cases, evidence.trials);
    if (JSON.stringify(fams) !== JSON.stringify(result.families)) {
      out.reasons = ["PACK_ENTRY_INVALID"]; return out;
    }
    if (reproducibilityHash(result.release_hash, result.target_hash, evidence.trials) !== result.reproducibility_hash) {
      out.reasons = ["PACK_ENTRY_INVALID"]; return out;
    }
    coverage = "full-replay";
  }

  out.integrity = "VALID";
  out.band = cb.band;
  out.coverage = coverage;
  const [cur, reasons] = current(cert, status, keyringSel, now, minEpoch, observedAt);
  out.current = cur;
  out.reasons = reasons;
  return out;
}
