/** Worker loop for the reference service (spec §4.4, §8.1 worker serve). */

import { spawn } from "node:child_process";
import { join } from "node:path";
import { blobHash, canonicalHash, canonicalize, JsonError, parse } from "./canon.js";
import { ApiError } from "./errors.js";
import { RECORDER_HASH } from "./mock.js";
import { runTrial } from "./runner.js";
import { checkCase } from "./schema.js";

async function req(origin: string, path: string, token: string,
                   method = "GET", body?: Buffer | any, extra: Record<string, string> = {}): Promise<[number, Buffer]> {
  const headers: Record<string, string> = { "Authorization": "Bearer " + token, ...extra };
  let data: Buffer | undefined;
  if (body !== undefined) {
    data = Buffer.isBuffer(body) ? body : canonicalize(body);
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = String(data.length);
  }
  let res: Response;
  try {
    res = await fetch(origin.replace(/\/$/, "") + path, {
      method, headers, signal: AbortSignal.timeout(30000),
      ...(data !== undefined ? { body: data } : {}),
    });
  } catch { throw new ApiError("UNAVAILABLE"); }
  return [res.status, Buffer.from(await res.arrayBuffer())];
}

async function cmd(origin: string, token: string, op: string, args: any, idem: string) {
  const [status, data] = await req(origin, "/v1/commands", token, "POST", { op, args }, { "Idempotency-Key": idem });
  let obj: any;
  try { obj = parse(data); } catch (e) {
    if (e instanceof JsonError) throw new ApiError("UNAVAILABLE");
    throw e;
  }
  if (status !== 200) throw new ApiError(obj.error.code);
  return obj;
}

async function fetchRelease(origin: string, token: string, releaseHash: string) {
  const [status, data] = await req(origin, "/v1/releases/" + releaseHash, token);
  if (status !== 200) throw new ApiError("RELEASE_UNAVAILABLE");
  return parse(data);
}

async function fetchCase(origin: string, token: string, releaseHash: string, caseId: string) {
  const [status, data] = await req(origin, `/v1/releases/${releaseHash}/cases/${caseId}`, token);
  if (status !== 200) throw new ApiError("RELEASE_UNAVAILABLE");
  return parse(data);
}

async function uploadBlob(origin: string, token: string, runId: string, data: Buffer,
                          leaseId: string, epoch: number): Promise<string> {
  const digest = blobHash(data);
  const [status, body] = await req(origin, `/v1/runs/${runId}/blobs/${digest}`, token, "PUT", data,
    { "X-Lease-ID": leaseId, "X-Lease-Epoch": String(epoch), "Content-Type": "application/octet-stream" });
  if (status !== 200) {
    let code = "UNAVAILABLE";
    try { code = (parse(body) as any).error.code; } catch { /* keep */ }
    throw new ApiError(code);
  }
  return digest;
}

export async function executeClaim(origin: string, token: string, cfg: any, claim: any): Promise<string> {
  const runId = claim.run_id, leaseId = claim.lease_id;
  let epoch = claim.epoch;
  const workerId = claim.worker_id;
  const releaseHash = claim.release_hash;
  const release: any = await fetchRelease(origin, token, releaseHash);
  const caseIds: string[] = release.body.suites.flatMap((s: any) => s.cases.map((c: any) => c.case_id));
  caseIds.sort();
  const cases: any[] = [];
  for (const cid of caseIds) cases.push(await fetchCase(origin, token, releaseHash, cid));
  for (const c of cases) checkCase(c);

  const adapter = [process.execPath, join(import.meta.dirname, "simtarget.js")];
  const targetHash = canonicalHash(claim.target);
  const trials: any[] = [];
  const transcript: any[] = [];
  const started = Math.floor(Date.now() / 1000);
  let incomplete: string | null = null;
  let lastHb = Date.now();
  outer:
  for (const kase of cases) {
    for (const repeat of [0, 1, 2]) {
      if (Date.now() - lastHb > (cfg.heartbeat_seconds ?? 30) * 1000) {
        const hb = await cmd(origin, token, "worker.heartbeat",
          { run_id: runId, lease_id: leaseId, lease_epoch: epoch }, `hb:${leaseId}:${epoch}`);
        epoch = hb.data.epoch;
        lastHb = Date.now();
      }
      const proc = spawn(adapter[0]!, adapter.slice(1), {
        stdio: ["pipe", "pipe", "ignore"],
        env: { ...process.env, EVALSEAL_SIMULATION: cfg.profile === "simulation" ? "1" : "0" },
      });
      try {
        trials.push(await runTrial(proc, kase, repeat, targetHash, transcript));
      } catch {
        incomplete = "TARGET_DRIFT";
        break outer;
      } finally {
        proc.kill("SIGKILL");
      }
    }
  }

  const raw = Buffer.concat(transcript.map(r => Buffer.concat([canonicalize(r), Buffer.from("\n")])));
  if (incomplete) {
    await cmd(origin, token, "worker.fail",
      { run_id: runId, lease_id: leaseId, lease_epoch: epoch, reason: incomplete }, "fail:" + leaseId);
    return incomplete;
  }

  const evidence = {
    schema: "evalseal-evidence/1", run_id: runId, lease_id: leaseId,
    lease_epoch: epoch, worker_id: workerId,
    release_hash: releaseHash, target_hash: targetHash,
    trials,
    raw_transcript: { hash: blobHash(raw), bytes: raw.length, media_type: "application/octet-stream" },
    recorder_hash: RECORDER_HASH,
    started_at: started, finished_at: Math.floor(Date.now() / 1000),
  };
  await uploadBlob(origin, token, runId, raw, leaseId, epoch);
  const evHash = await uploadBlob(origin, token, runId, canonicalize(evidence), leaseId, epoch);
  await cmd(origin, token, "worker.complete",
    { run_id: runId, lease_id: leaseId, lease_epoch: epoch, evidence_hash: evHash }, "complete:" + leaseId);
  return "COMPLETED";
}

export async function serve(cfg: any, opts: { once?: boolean; offline?: boolean } = {}): Promise<number> {
  if (opts.offline) {
    process.stderr.write("--offline: worker serve requires network\n");
    return 2;
  }
  const origin = (cfg.origin as string).replace(/\/$/, "");
  const token = process.env[cfg.identity_env];
  if (token === undefined) {
    process.stderr.write("environment variable " + cfg.identity_env + " is not set\n");
    return 2;
  }
  const heartbeat = Math.min(cfg.heartbeat_seconds ?? 30, 30) * 1000;
  for (;;) {
    let claim: any;
    try {
      claim = await cmd(origin, token, "worker.claim", { capacity: 1 }, "poll:" + Date.now());
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.code === "UNAUTHORIZED") { process.stderr.write("worker auth rejected\n"); return 3; }
        process.stderr.write("poll failed: " + e.code + "\n");
        if (opts.once) return 6;
        await new Promise(r => setTimeout(r, heartbeat));
        continue;
      }
      throw e;
    }
    const data = claim.data;
    if (data === null || data === undefined) {
      if (opts.once) return 0;
      await new Promise(r => setTimeout(r, heartbeat));
      continue;
    }
    let outcome: string;
    try {
      outcome = await executeClaim(origin, token, cfg, data);
    } catch (e) {
      if (e instanceof ApiError && e.code === "LEASE_FENCED") outcome = "LEASE_FENCED";
      else if (e instanceof ApiError) {
        process.stderr.write("run " + data.run_id + " failed: " + e.code + "\n");
        if (opts.once) return 6;
        await new Promise(r => setTimeout(r, heartbeat));
        continue;
      } else throw e;
    }
    process.stderr.write("run " + data.run_id + ": " + outcome + "\n");
    if (opts.once) return outcome === "COMPLETED" ? 0 : 6;
  }
}
