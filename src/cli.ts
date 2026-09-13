/** evalseal CLI (spec §8). Same contract as `python -m evalseal`. */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { canonicalize, canonicalHash, isHash, JsonError, parse, blobHash } from "./canon.js";
import { ApiError } from "./errors.js";
import { loadClientConfig, loadTrust } from "./config.js";

export const VERSION = "1.0.0-draft.1";
export const PROTOCOL = "evalseal/1";

const GLOBAL_FLAGS: Record<string, string> = {
  "--config": "value", "--json": "bool", "--offline": "bool",
  "--timeout-ms": "value", "--help": "bool", "--version": "bool",
};

type Spec = { pos: string[]; flags: Record<string, string> };

const CMD_SPECS: Record<string, Spec> = {
  "suite lock": { pos: ["SOURCE"], flags: { "--version": "value", "--out": "value", "--source-date-epoch": "value" } },
  "suite verify": { pos: ["LOCK"], flags: { "--source": "value", "--trust": "value" } },
  "suite sign": { pos: ["LOCK"], flags: { "--key-env": "value", "--out": "value" } },
  "release index": { pos: [], flags: { "--active": "value", "--withdrawn": "value", "--key-env": "value", "--out": "value" } },
  "keyring issue": { pos: [], flags: { "--keys": "value", "--epoch": "value", "--valid-seconds": "value", "--key-env": "value", "--out": "value", "--previous-keyring": "value" } },
  "run local": { pos: [], flags: { "--lock": "value", "--target": "value", "--out": "value", "--simulation": "bool", "--adapter": "value" } },
  "run submit": { pos: [], flags: { "--product": "value", "--release": "value", "--track": "value", "--board": "value", "--prior-certificate": "value", "--idempotency-key": "value" } },
  "run status": { pos: ["ID"], flags: { "--wait": "bool", "--poll-seconds": "value" } },
  "run cancel": { pos: ["ID"], flags: { "--revision": "value", "--idempotency-key": "value" } },
  "product create": { pos: [], flags: { "--label": "value", "--target-ref": "value", "--idempotency-key": "value" } },
  "board create": { pos: [], flags: { "--label": "value", "--idempotency-key": "value" } },
  "certificate get": { pos: ["ID"], flags: { "--status": "bool" } },
  "certificate revoke": { pos: ["ID"], flags: { "--revision": "value", "--reason": "value", "--idempotency-key": "value" } },
  "pack download": { pos: ["ID"], flags: { "--out": "value", "--format": "value", "--replace": "bool" } },
  "pack verify": { pos: ["PATH"], flags: { "--trust": "value", "--status-file": "value", "--keyring-file": "value", "--now": "value" } },
  "leaderboard": { pos: [], flags: { "--release": "value", "--board": "value", "--limit": "value", "--cursor": "value" } },
  "audit verify": { pos: ["PATH"], flags: { "--checkpoint": "value", "--trust": "value", "--keyring-file": "value" } },
  "worker serve": { pos: [], flags: { "--worker-config": "value", "--once": "bool" } },
  "serve": { pos: [], flags: { "--bind": "value", "--provision": "value" } },
};

const NETWORK_COMMANDS = new Set([
  "run submit", "run status", "run cancel", "product create", "board create",
  "certificate get", "certificate revoke", "pack download", "leaderboard", "worker serve",
]);

const REQUIRED: Record<string, string[]> = {
  "suite lock": ["--version", "--out"],
  "suite verify": ["--trust"],
  "suite sign": ["--key-env", "--out"],
  "release index": ["--key-env", "--out"],
  "keyring issue": ["--keys", "--epoch", "--valid-seconds", "--key-env", "--out"],
  "run local": ["--lock", "--target", "--out"],
  "run submit": ["--product", "--release", "--track", "--idempotency-key"],
  "run cancel": ["--revision", "--idempotency-key"],
  "product create": ["--label", "--target-ref", "--idempotency-key"],
  "board create": ["--label", "--idempotency-key"],
  "certificate revoke": ["--revision", "--reason", "--idempotency-key"],
  "pack download": ["--out"],
  "pack verify": ["--trust"],
  "audit verify": ["--trust"],
  "worker serve": ["--worker-config"],
};

export class UsageError extends Error {}

function usage(): string {
  const lines = [`evalseal ${VERSION} — protocol evalseal/1`, "",
    "usage: evalseal [--config PATH] [--json] [--offline] [--timeout-ms N] <command>", ""];
  for (const cmd of Object.keys(CMD_SPECS).sort()) {
    const spec = CMD_SPECS[cmd]!;
    const pos = spec.pos.map(p => `<${p}>`).join(" ");
    lines.push("  " + cmd + (pos ? " " + pos : ""));
  }
  return lines.join("\n");
}

interface Globals {
  config: string | null; json: boolean; offline: boolean;
  timeout_ms: string; help: boolean; version: boolean;
}

export function parseArgv(argv: string[]): [Globals, string | null, Record<string, unknown>, string[]] {
  const g: Globals = { config: null, json: false, offline: false, timeout_ms: "30000", help: false, version: false };
  const flags: Record<string, unknown> = {};
  const pos: string[] = [];
  let cmd: string | null = null;
  const seenGlobal = new Set<string>();
  const specKey = (k: string) => k.slice(2).replace(/-/g, "_") as keyof Globals;
  const specNames = Object.keys(CMD_SPECS);
  let i = 0;
  while (i < argv.length) {
    const tok = argv[i]!;
    if (tok === "--") { pos.push(...argv.slice(i + 1)); break; }
    if (cmd === null && tok in GLOBAL_FLAGS) {
      const kind = GLOBAL_FLAGS[tok]!;
      if (seenGlobal.has(tok) && kind === "value") throw new UsageError("repeated flag " + tok);
      seenGlobal.add(tok);
      if (kind === "bool") { (g as any)[specKey(tok)] = true; i += 1; }
      else {
        if (i + 1 >= argv.length) throw new UsageError("missing value for " + tok);
        (g as any)[specKey(tok)] = argv[i + 1]!; i += 2;
      }
      continue;
    }
    if (cmd === null) {
      if (specNames.includes(tok)) { cmd = tok; i += 1; continue; }
      if (i + 1 < argv.length && specNames.includes(tok + " " + argv[i + 1])) {
        cmd = tok + " " + argv[i + 1]; i += 2; continue;
      }
      throw new UsageError("unknown command " + tok);
    }
    const spec = CMD_SPECS[cmd]!;
    if (tok.startsWith("--")) {
      if (!(tok in spec.flags)) {
        if (tok in GLOBAL_FLAGS) {
          const kind = GLOBAL_FLAGS[tok]!;
          if (kind === "bool") { (g as any)[specKey(tok)] = true; i += 1; continue; }
          if (i + 1 >= argv.length) throw new UsageError("missing value for " + tok);
          (g as any)[specKey(tok)] = argv[i + 1]!; i += 2; continue;
        }
        throw new UsageError("unknown flag " + tok);
      }
      const kind = spec.flags[tok]!;
      if (tok in flags) throw new UsageError("repeated flag " + tok);
      if (kind === "bool") { flags[tok] = true; i += 1; }
      else {
        if (i + 1 >= argv.length) throw new UsageError("missing value for " + tok);
        flags[tok] = argv[i + 1]!; i += 2;
      }
      continue;
    }
    pos.push(tok);
    i += 1;
  }
  return [g, cmd, flags, pos];
}

function timeoutMs(g: Globals): number {
  const t = parseInt(g.timeout_ms, 10);
  if (!Number.isInteger(t) || String(t) !== g.timeout_ms) throw new UsageError("--timeout-ms must be an integer");
  if (t < 1 || t > 300000) throw new UsageError("--timeout-ms out of range 1..300000");
  return t;
}

function seedFromEnv(name: string): Buffer {
  const raw = process.env[name];
  if (raw === undefined) throw new UsageError("environment variable " + name + " is not set");
  const v = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64url");
    if (b.length === 32) return b;
  } catch { /* fall through */ }
  throw new UsageError("environment variable " + name + " does not contain a 32-byte seed");
}

function readJson(path: string): any {
  let data: Buffer;
  try { data = readFileSync(path); } catch { throw new UsageError("file not found: " + path); }
  try { return parse(data); } catch (e) {
    if (e instanceof JsonError) throw new UsageError(`${path}: ${e.code}`);
    throw e;
  }
}

function writeAtomic(path: string, data: Buffer, replace = false): void {
  if (existsSync(path) && !replace) {
    throw new UsageError("refusing to overwrite existing file: " + path + " (use --replace)");
  }
  const tmp = path + ".tmp";
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

const emit = (g: Globals, obj: unknown) => {
  if (g.json) process.stdout.write(canonicalize(obj as never).toString("utf8") + "\n");
  else process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
};

function exitFor(err: ApiError): number {
  const table: Record<string, number> = {
    UNAUTHORIZED: 3, FORBIDDEN: 3,
    REVISION_CONFLICT: 7, IDEMPOTENCY_CONFLICT: 7, STATE_CONFLICT: 7,
    LEASE_FENCED: 7, CURSOR_EXPIRED: 7,
    RATE_LIMITED: 6, LIMIT_EXCEEDED: 6, UNAVAILABLE: 6, RELEASE_UNAVAILABLE: 6,
    HASH_MISMATCH: 5, EVIDENCE_INVALID: 5, TARGET_DRIFT: 5,
  };
  return table[err.code] ?? 2;
}

// -- handlers -----------------------------------------------------------------

async function cmdSuiteLock(_g: Globals, flags: any, pos: string[]) {
  const { lockSource } = await import("./importer.js");
  const sde = flags["--source-date-epoch"] ? parseInt(flags["--source-date-epoch"], 10) : 0;
  const lock = lockSource(pos[0]!, flags["--version"], sde);
  writeAtomic(flags["--out"], canonicalize(lock));
  return [{ lock_hash: canonicalHash(lock.release), case_count: lock.cases.length, trial_count: 360, official: false }, 0] as const;
}

async function cmdSuiteVerify(_g: Globals, flags: any, pos: string[]) {
  const { verifyLock } = await import("./importer.js");
  const { findKey, verifyWithKey } = await import("./pack.js");
  const lock = readJson(pos[0]!);
  const count = verifyLock(lock, flags["--source"]);
  const trust = loadTrustRequired(flags);
  const env = lock.release;
  if (typeof env === "object" && env !== null && env.schema === "evalseal-signed/1") {
    const key = findKey(trust.roots, env.key_id ?? "");
    if (key === null || !key.roles.includes("release") ||
        verifyWithKey(env, "release", key) !== "VALID") {
      throw new ApiError("HASH_MISMATCH");
    }
  }
  return [{ valid: true, cases: count }, 0] as const;
}

async function signCmd(g: Globals, flags: any, pos: string[], kind: "release" | "release-index" | "keyring", buildBody?: () => any) {
  const { privFromSeed, publicKeyBytes, b64u, makeSigner } = await import("./sign.js");
  const { keyIdForPublicKey, isTestKey } = await import("./keys.js");
  const cfg = loadCfg(g);
  const seed = seedFromEnv(flags["--key-env"]);
  const priv = privFromSeed(seed);
  const pk = b64u(publicKeyBytes(priv));
  if (isTestKey(pk) && cfg.profile !== "simulation") {
    throw new UsageError("refusing public test key outside simulation profile");
  }
  const keyId = keyIdForPublicKey(pk);
  const signer = makeSigner(keyId, seed);
  const body = buildBody ? buildBody() : readJson(pos[0]!).release;
  const env = signer(kind, body);
  writeAtomic(flags["--out"], canonicalize(env as never));
  return { keyId, env };
}

async function cmdSuiteSign(g: Globals, flags: any, pos: string[]) {
  const lock = readJson(pos[0]!);
  const { keyId, env } = await signCmd(g, flags, pos, "release", () => lock.release);
  return [{ signed: true, key_id: keyId, release_hash: canonicalHash(env as never), official: false }, 0] as const;
}

async function cmdReleaseIndex(g: Globals, flags: any, _pos: string[]) {
  const { checkReleaseIndexBody } = await import("./schema.js");
  const act = (flags["--active"] ?? "").split(",").filter(Boolean);
  const wd = (flags["--withdrawn"] ?? "").split(",").filter(Boolean);
  if ([...act, ...wd].some((h: string) => !isHash(h))) {
    throw new UsageError("release index entries must be sha256 digests");
  }
  const body = { schema: "evalseal-release-index/1", active: [...new Set(act)].sort(), withdrawn: [...new Set(wd)].sort() };
  if ((body.withdrawn as string[]).some(h => (body.active as string[]).includes(h))) {
    throw new UsageError("active and withdrawn must be disjoint");
  }
  checkReleaseIndexBody(body);
  const { keyId, env } = await signCmd(g, flags, [], "release-index", () => body);
  return [{ signed: true, key_id: keyId, index_hash: canonicalHash(env as never) }, 0] as const;
}

async function cmdKeyringIssue(g: Globals, flags: any, _pos: string[]) {
  const { checkKey, checkKeyringBody } = await import("./schema.js");
  const { isTestKey } = await import("./keys.js");
  const cfg = loadCfg(g);
  const keysDoc = readJson(flags["--keys"]);
  const keys = keysDoc?.keys;
  if (!Array.isArray(keys) || !keys.length) throw new UsageError("--keys file must be {keys: Key[]}");
  for (const k of keys) {
    checkKey(k);
    if (isTestKey(k.public_key) && cfg.profile !== "simulation") {
      throw new UsageError("refusing public test key outside simulation profile");
    }
  }
  const epoch = parseInt(flags["--epoch"], 10);
  const valid = parseInt(flags["--valid-seconds"], 10);
  if (!(valid > 0 && valid <= 86400)) throw new UsageError("--valid-seconds must be 1..86400");
  let prevHash = null;
  if ("--previous-keyring" in flags) prevHash = canonicalHash(readJson(flags["--previous-keyring"]));
  const issued = Math.floor(Date.now() / 1000);
  const body = { schema: "evalseal-keyring/1", epoch, issued_at: issued, valid_until: issued + valid, keys, previous_hash: prevHash };
  checkKeyringBody(body);
  const { keyId, env } = await signCmd(g, flags, [], "keyring", () => body);
  return [{ signed: true, key_id: keyId, epoch, keyring_hash: canonicalHash(env as never) }, 0] as const;
}

async function cmdRunLocal(g: Globals, flags: any, _pos: string[]) {
  const { runLocal } = await import("./runner.js");
  const lock = readJson(flags["--lock"]);
  const target = readJson(flags["--target"]);
  const sim = Boolean(flags["--simulation"]);
  const adapter = flags["--adapter"] ? String(flags["--adapter"]).split(/\s+/) : null;
  if (adapter === null && !sim) throw new UsageError("run local requires --simulation or --adapter CMD");
  const out = await runLocal(lock.release, target, lock.cases, flags["--out"], adapter, sim);
  if (out.incomplete_reason) return [{ official: false, incomplete: out.incomplete_reason }, 6] as const;
  const band = out.result.grade.band;
  const code = ["A", "B", "C"].includes(band) ? 0 : 4;
  if (sim) process.stderr.write("simulation profile — not an official certification\n");
  return [{ official: false, result: out.result }, code] as const;
}

function loadCfg(g: Globals) {
  return loadClientConfig(g.config, {});
}

function loadTrustRequired(flags: any) {
  if (!flags["--trust"]) throw new UsageError("--trust ROOTS is required");
  return loadTrust(flags["--trust"]);
}

function tokenOf(cfg: any): string {
  const tok = process.env[cfg.token_env];
  if (tok === undefined) throw new UsageError("environment variable " + cfg.token_env + " is not set");
  return tok;
}

async function call(cfg: any, request: any, idemKey: string, g: Globals) {
  const { command } = await import("./client.js");
  return command(cfg.origin, request, { token_env: cfg.token_env, idempotency_key: idemKey, timeout_ms: timeoutMs(g) });
}

async function cmdProductCreate(g: Globals, flags: any, _pos: string[]) {
  const cfg = loadCfg(g);
  return [await call(cfg, { op: "product.create", args: { label: flags["--label"], target_ref: flags["--target-ref"] } },
    flags["--idempotency-key"], g), 0] as const;
}

async function cmdBoardCreate(g: Globals, flags: any, _pos: string[]) {
  const cfg = loadCfg(g);
  return [await call(cfg, { op: "board.create", args: { label: flags["--label"] } },
    flags["--idempotency-key"], g), 0] as const;
}

async function cmdRunSubmit(g: Globals, flags: any, _pos: string[]) {
  const cfg = loadCfg(g);
  const track = flags["--track"];
  if (track === "private" && !("--board" in flags)) {
    throw new UsageError("--board is required for --track private");
  }
  const args = {
    product_id: flags["--product"], release_hash: flags["--release"],
    track, board_id: flags["--board"] ?? null,
    prior_certificate_id: flags["--prior-certificate"] ?? null,
  };
  if (track === "public") {
    process.stderr.write("warning: public admission is irrevocably public; failed, incomplete, and cancelled attempts remain discoverable\n");
  }
  return [await call(cfg, { op: "run.create", args }, flags["--idempotency-key"], g), 0] as const;
}

async function cmdRunStatus(g: Globals, flags: any, pos: string[]) {
  const cfg = loadCfg(g);
  const token = tokenOf(cfg);
  const { getJson } = await import("./client.js");
  const wait = Boolean(flags["--wait"]);
  const poll = parseInt(flags["--poll-seconds"] ?? "5", 10);
  if (poll < 5 || poll > 60) throw new UsageError("--poll-seconds must be 5..60");
  const deadline = Date.now() + timeoutMs(g);
  for (;;) {
    const run = await getJson(cfg.origin, "/v1/runs/" + pos[0], token, timeoutMs(g));
    if (!wait || ["COMPLETED", "INCOMPLETE", "CANCELLED"].includes(run.state)) {
      return [run, run.state === "INCOMPLETE" ? 6 : 0] as const;
    }
    if (Date.now() >= deadline) throw new ApiError("UNAVAILABLE");
    await new Promise(r => setTimeout(r, poll * 1000));
  }
}

async function cmdRunCancel(g: Globals, flags: any, pos: string[]) {
  const cfg = loadCfg(g);
  return [await call(cfg, {
    op: "run.cancel",
    args: { run_id: pos[0], expected_revision: parseInt(flags["--revision"], 10), reason: "OWNER_CANCELLED" },
  }, flags["--idempotency-key"], g), 0] as const;
}

async function cmdCertificateGet(g: Globals, flags: any, pos: string[]) {
  const cfg = loadCfg(g);
  const { getJson } = await import("./client.js");
  const path = "/v1/certificates/" + pos[0] + (flags["--status"] ? "/status" : "");
  return [await getJson(cfg.origin, path, tokenOf(cfg), timeoutMs(g)), 0] as const;
}

async function cmdCertificateRevoke(g: Globals, flags: any, pos: string[]) {
  const cfg = loadCfg(g);
  return [await call(cfg, {
    op: "certificate.revoke",
    args: {
      certificate_id: pos[0], expected_revision: parseInt(flags["--revision"], 10),
      reason: flags["--reason"],
    },
  }, flags["--idempotency-key"], g), 0] as const;
}

async function cmdPackDownload(g: Globals, flags: any, pos: string[]) {
  const cfg = loadCfg(g);
  const { getBytes } = await import("./client.js");
  const fmt = flags["--format"] ?? "zip";
  if (fmt !== "zip" && fmt !== "pdf") throw new UsageError("--format must be zip or pdf");
  const data = await getBytes(cfg.origin, `/v1/certificates/${pos[0]}/pack?format=${fmt}`, tokenOf(cfg), timeoutMs(g));
  writeAtomic(flags["--out"], data, Boolean(flags["--replace"]));
  return [{ path: flags["--out"], bytes: data.length, hash: blobHash(data) }, 0] as const;
}

async function cmdPackVerify(g: Globals, flags: any, pos: string[]) {
  const { verifyPack } = await import("./pack.js");
  const path = pos[0]!;
  if (path.toLowerCase().endsWith(".pdf")) throw new UsageError("pack verify accepts the ZIP pack only");
  const data = readFileSync(path);
  const trust = loadTrustRequired(flags);
  const status = flags["--status-file"] ? readJson(flags["--status-file"]) : null;
  const keyring = flags["--keyring-file"] ? readJson(flags["--keyring-file"]) : null;
  let now = flags["--now"] ? parseInt(flags["--now"], 10) : null;
  if (now === null) {
    if (g.offline) throw new UsageError("--offline requires --now for pack verify");
    now = Math.floor(Date.now() / 1000);
  }
  const keyringObserved = keyring !== null && !g.offline ? Math.floor(Date.now() / 1000) : undefined;
  const v = verifyPack(data, {
    root_keys: trust.roots, now, status, keyring,
    min_keyring_epoch: trust.minimum_keyring_epoch,
    keyring_observed_at: keyringObserved,
  });
  let code: number = { QUALIFIES: 0, NOT_QUALIFIED: 4, UNKNOWN: 8 }[v.current as string]!;
  if (v.integrity !== "VALID") code = 5;
  return [v, code] as const;
}

function printTable(page: any) {
  console.log(`snapshot ${page.snapshot_at}  lag ${page.index_lag_seconds}s`);
  for (const r of page.items) {
    console.log(`${String(r.label).padEnd(24)} ${String(r.state).padEnd(10)} ${String(r.band ?? "-").padEnd(2)} ` +
      `${String(r.status).padEnd(8)} ${r.qualifies ? "qualifies" : ""}`);
  }
  if (page.next_cursor) console.log("next: " + page.next_cursor);
}

async function cmdLeaderboard(g: Globals, flags: any, _pos: string[]) {
  const cfg = loadCfg(g);
  const { getJson } = await import("./client.js");
  let page: any;
  if ("--board" in flags) {
    let q = "?limit=" + (flags["--limit"] ?? "25");
    if (flags["--release"]) q += "&release=" + flags["--release"];
    if (flags["--cursor"]) q += "&cursor=" + flags["--cursor"];
    page = await getJson(cfg.origin, "/v1/boards/" + flags["--board"] + q, tokenOf(cfg), timeoutMs(g));
  } else {
    const rel = flags["--release"];
    if (!rel) throw new UsageError("--release is required");
    let q = "?release=" + rel + "&limit=" + (flags["--limit"] ?? "25");
    if (flags["--cursor"]) q += "&cursor=" + flags["--cursor"];
    page = await getJson(cfg.origin, "/v1/leaderboard" + q, null, timeoutMs(g));
  }
  if (!g.json) { printTable(page); return [null, 0] as const; }
  return [page, 0] as const;
}

async function cmdAuditVerify(g: Globals, flags: any, pos: string[]) {
  const { verifyAgainstCheckpoint } = await import("./audit.js");
  const { findKey, verifyWithKey } = await import("./pack.js");
  const trust = loadTrustRequired(flags);
  const data = readFileSync(pos[0]!);
  let entries: any[] | null = null;
  let cp: any = flags["--checkpoint"] ? readJson(flags["--checkpoint"]) : null;
  const stripped = data.toString("utf8").trim();
  if (stripped.startsWith("{")) {
    const doc = parse(Buffer.from(stripped, "utf8"));
    entries = doc.entries;
    cp = cp ?? doc.checkpoint;
  } else {
    const lines = data.toString("utf8").split("\n").filter(l => l.trim());
    try { entries = lines.map(l => parse(Buffer.from(l, "utf8"))); } catch (e) {
      if (e instanceof JsonError) throw new UsageError("audit input must be audit.jsonl or an AuditPage JSON");
      throw e;
    }
  }
  if (entries === null) throw new UsageError("audit input must be audit.jsonl or an AuditPage JSON");
  if (cp === null) throw new UsageError("audit verify requires a checkpoint (--checkpoint or embedded)");
  let key = findKey(trust.roots, cp.key_id ?? "");
  if (key === null && flags["--keyring-file"]) {
    const kr = readJson(flags["--keyring-file"]);
    key = findKey(kr.body.keys, cp.key_id ?? "");
  }
  if (key === null || verifyWithKey(cp, "checkpoint", key) !== "VALID") throw new ApiError("HASH_MISMATCH");
  const r = verifyAgainstCheckpoint(entries, cp);
  if (r !== "VALID") return [{ valid: false, code: r }, 5] as const;
  return [{ valid: true, entries: entries.length, head: entries[entries.length - 1]!.hash }, 0] as const;
}

async function cmdWorkerServe(g: Globals, flags: any, _pos: string[]) {
  const { checkWorkerConfig } = await import("./schema.js");
  const cfg = readJson(flags["--worker-config"]);
  try { checkWorkerConfig(cfg); } catch (e) {
    throw new UsageError("invalid worker config: " + (e as Error).message);
  }
  const { serve } = await import("./worker.js");
  const code = await serve(cfg, { once: Boolean(flags["--once"]), offline: g.offline });
  return [null, code] as const;
}

async function cmdServe(_g: Globals, _flags: any, _pos: string[]): Promise<readonly [any, number]> {
  throw new UsageError("serve is not part of the TypeScript reference CLI; use python -m evalseal serve");
}

const HANDLERS: Record<string, (g: Globals, f: any, p: string[]) => Promise<readonly [any, number]>> = {
  "suite lock": cmdSuiteLock,
  "suite verify": cmdSuiteVerify,
  "suite sign": cmdSuiteSign,
  "release index": cmdReleaseIndex,
  "keyring issue": cmdKeyringIssue,
  "run local": cmdRunLocal,
  "run submit": cmdRunSubmit,
  "run status": cmdRunStatus,
  "run cancel": cmdRunCancel,
  "product create": cmdProductCreate,
  "board create": cmdBoardCreate,
  "certificate get": cmdCertificateGet,
  "certificate revoke": cmdCertificateRevoke,
  "pack download": cmdPackDownload,
  "pack verify": cmdPackVerify,
  "leaderboard": cmdLeaderboard,
  "audit verify": cmdAuditVerify,
  "worker serve": cmdWorkerServe,
  "serve": cmdServe,
};

export async function main(argv?: string[]): Promise<number> {
  argv = argv ?? process.argv.slice(2);
  let g: Globals, cmd: string | null, flags: Record<string, unknown>, pos: string[];
  try { [g, cmd, flags, pos] = parseArgv(argv); } catch (e) {
    if (e instanceof UsageError) { process.stderr.write("usage error: " + e.message + "\n"); return 2; }
    throw e;
  }
  if (g.help) { process.stdout.write(usage() + "\n"); return 0; }
  if (g.version) { process.stdout.write(VERSION + "\n"); return 0; }
  if (cmd === null) { process.stderr.write(usage() + "\n"); return 2; }
  try { timeoutMs(g); } catch (e) {
    if (e instanceof UsageError) { process.stderr.write("usage error: " + e.message + "\n"); return 2; }
    throw e;
  }
  if (g.offline && NETWORK_COMMANDS.has(cmd)) {
    process.stderr.write("--offline: " + cmd + " requires network\n");
    return 2;
  }
  const spec = CMD_SPECS[cmd]!;
  if (pos.length !== spec.pos.length) {
    process.stderr.write(`usage error: expected ${spec.pos.length} positional arguments\n`);
    return 2;
  }
  const missing = (REQUIRED[cmd] ?? []).filter(f => !(f in flags));
  if (missing.length) {
    process.stderr.write("usage error: missing required flags " + missing.join(" ") + "\n");
    return 2;
  }
  try {
    const [result, code] = await HANDLERS[cmd]!(g, flags, pos);
    if (result !== null) emit(g, result);
    return code;
  } catch (e) {
    if (e instanceof ApiError) {
      process.stderr.write("error " + e.code + ": " + ApiError.MESSAGES[e.code] + "\n");
      if (e.retryAfter !== null) process.stderr.write("retry-after: " + e.retryAfter + "\n");
      return exitFor(e);
    }
    if (e instanceof UsageError) {
      process.stderr.write("usage error: " + e.message + "\n");
      return 2;
    }
    throw e;
  }
}
