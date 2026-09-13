/** Local runner: NDJSON target channel, recorder, evidence assembly (§4.4, §7.6). */

import { spawn, ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { blobHash, canonicalHash, canonicalize, JsonError, parse } from "./canon.js";
import { buildResult } from "./evidence.js";
import { newId } from "./ids.js";
import { Recorder, RECORDER_HASH } from "./mock.js";
import { SchemaError, checkRelease, checkTarget, checkToolCall } from "./schema.js";

export const MAX_FRAME = 32768;
export const MAX_OUTPUT = 16384;
export const MAX_CALLS = 16;
export const TRIAL_TIMEOUT_MS = 30000;

class ChannelError extends Error {}

/** Read one LF-terminated frame with a deadline; resolves Buffer or throws. */
function readLine(proc: ChildProcess, timeoutMs: number, buf: { data: Buffer }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new ChannelError("timeout")); }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buf.data = Buffer.concat([buf.data, chunk]);
      if (buf.data.length > MAX_FRAME) { cleanup(); reject(new ChannelError("oversize-frame")); return; }
      const nl = buf.data.indexOf(0x0a);
      if (nl >= 0) {
        const line = buf.data.subarray(0, nl + 1);
        buf.data = buf.data.subarray(nl + 1);
        cleanup();
        resolve(line);
      }
    };
    const onEnd = () => { cleanup(); reject(new ChannelError("eof")); };
    const onErr = (e: Error) => { cleanup(); reject(e); };
    const cleanup = () => {
      clearTimeout(timer);
      proc.stdout!.off("data", onData);
      proc.stdout!.off("end", onEnd);
      proc.stdout!.off("close", onEnd);
      proc.stdout!.off("error", onErr);
    };
    // consume any buffered bytes first
    if (buf.data.indexOf(0x0a) >= 0) { onData(Buffer.alloc(0)); return; }
    proc.stdout!.on("data", onData);
    proc.stdout!.on("end", onEnd);
    proc.stdout!.on("close", onEnd);
    proc.stdout!.on("error", onErr);
  });
}

function writeFrame(proc: ChildProcess, obj: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    proc.stdin!.write(Buffer.concat([canonicalize(obj as never), Buffer.from("\n")]),
      e => e ? reject(e) : resolve());
  });
}

export async function runTrial(proc: ChildProcess, kase: any, repeat: number,
                               targetHash: string, transcript: any[]): Promise<any> {
  const fixture = kase.fixture;
  const seed = [11, 23, 37][repeat]!;
  const rec = new Recorder(fixture);
  const cid = kase.case_id;
  const trialKey = `${cid}:${repeat}`;
  transcript.push({ type: "trial", case_id: cid, repeat, seed });

  const start = {
    type: "start", user_text: fixture.user_text,
    retrieved_text: fixture.retrieved_text,
    memory_text: fixture.memory_text, seed,
  };
  await writeFrame(proc, start);
  transcript.push(start);

  let output = "", outcome = "returned", abort: string | null = null;
  const deadline = Date.now() + TRIAL_TIMEOUT_MS;
  const buf = { data: Buffer.alloc(0) };
  let calls = 0;
  for (; calls < MAX_CALLS; calls++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { outcome = "target_timeout"; abort = "timeout"; break; }
    let line: Buffer;
    try {
      line = await readLine(proc, remaining, buf);
    } catch (e) {
      if (e instanceof ChannelError && e.message === "timeout") { outcome = "target_timeout"; abort = "timeout"; }
      else { outcome = "target_error"; abort = "target_error"; }
      break;
    }
    let frame: any;
    try { frame = parse(line); } catch (e) {
      if (e instanceof JsonError) { outcome = "target_error"; abort = "target_error"; break; }
      throw e;
    }
    if (typeof frame !== "object" || frame === null ||
        !(("type" in frame && "call" in frame && Object.keys(frame).length === 2) ||
          ("type" in frame && "output" in frame && Object.keys(frame).length === 2))) {
      outcome = "target_error"; abort = "target_error"; break;
    }
    if (frame.type === "final") {
      const out = frame.output;
      if (typeof out !== "string") { outcome = "target_error"; abort = "target_error"; break; }
      if (Buffer.byteLength(out, "utf8") > MAX_OUTPUT) {
        // bytes[:MAX_OUTPUT].decode("utf-8", "ignore"): drop a truncated tail char
        const truncated = Buffer.from(out, "utf8").subarray(0, MAX_OUTPUT).toString("utf8");
        output = truncated.endsWith("") ? truncated.slice(0, -1) : truncated;
        outcome = "target_error"; abort = "output_limit";
      } else output = out;
      transcript.push({ type: "final", output });
      break;
    }
    if (frame.type === "call") {
      try { checkToolCall(frame.call); } catch (e) {
        if (e instanceof SchemaError) { outcome = "target_error"; abort = "target_error"; break; }
        throw e;
      }
      const result = rec.handleCall(frame.call);
      transcript.push({ type: "call", call: frame.call });
      transcript.push(result);
      await writeFrame(proc, result);
      continue;
    }
    outcome = "target_error"; abort = "target_error"; break;
  }
  if (calls >= MAX_CALLS && abort === null) { outcome = "target_error"; abort = "call_limit"; }
  if (abort) transcript.push({ type: "abort", reason: abort });

  const obs = {
    trial_key: trialKey, target_hash: targetHash,
    before_state_hash: rec.beforeHash(), after_state_hash: rec.afterHash(),
    attempted_calls: rec.attempted, executed_calls: rec.executed,
    output, outcome, approval_seen: rec.approvalSeen,
  };
  return { case_id: cid, repeat, seed, observation: obs, observation_hash: canonicalHash(obs) };
}

export interface RunLocalOut {
  official: boolean;
  result: any;
  evidence: any;
  incomplete_reason: string | null;
}

export async function runLocal(release: any, target: any, cases: any[], outDir: string,
                               adapterCmd: string[] | null, simulation: boolean,
                               wallCapS = 14400): Promise<RunLocalOut> {
  checkRelease(release);
  checkTarget(target);
  const targetHash = canonicalHash(target);
  const releaseHash = canonicalHash(release);

  if (adapterCmd === null) {
    adapterCmd = [process.execPath, join(import.meta.dirname, "simtarget.js")];
  }

  const trials: any[] = [];
  const transcript: any[] = [];
  const started = Math.floor(Date.now() / 1000);
  const wallDeadline = Date.now() + wallCapS * 1000;
  let incompleteReason: string | null = null;
  const grid: Array<[any, number]> = cases.flatMap(c => [0, 1, 2].map(r => [c, r] as [any, number]));
  for (const [kase, repeat] of grid) {
    if (Date.now() > wallDeadline) { incompleteReason = "WALL_CAP"; break; }
    const proc = spawn(adapterCmd[0]!, adapterCmd.slice(1), {
      stdio: ["pipe", "pipe", "ignore"],
      env: { ...process.env, EVALSEAL_SIMULATION: simulation ? "1" : "0" },
    });
    try {
      trials.push(await runTrial(proc, kase, repeat, targetHash, transcript));
    } finally {
      proc.kill("SIGKILL");
    }
  }

  const raw = Buffer.concat(transcript.map(r => Buffer.concat([canonicalize(r), Buffer.from("\n")])));
  const evidence = {
    schema: "evalseal-evidence/1", run_id: newId("run"),
    lease_id: newId("lse"), lease_epoch: 1, worker_id: newId("wrk"),
    release_hash: releaseHash, target_hash: targetHash,
    trials,
    raw_transcript: { hash: blobHash(raw), bytes: raw.length, media_type: "application/octet-stream" },
    recorder_hash: RECORDER_HASH,
    started_at: started, finished_at: Math.floor(Date.now() / 1000),
  };
  let result = null;
  const expected = 3 * release.suites.reduce((n: number, s: any) => n + s.cases.length, 0);
  if (incompleteReason === null && trials.length === expected) {
    result = buildResult(evidence.run_id, release, releaseHash, targetHash,
                         cases, evidence, release.rubric);
  }

  mkdirSync(outDir, { recursive: true });
  const w = (name: string, data: Buffer) => {
    const tmp = join(outDir, "." + name + ".tmp");
    writeFileSync(tmp, data);
    renameSync(tmp, join(outDir, name));
  };
  w("release.json", canonicalize(release));
  w("cases.json", canonicalize(cases));
  w("target.json", canonicalize(target));
  if (result !== null) w("result.json", canonicalize(result));
  w("evidence.json", canonicalize(evidence));
  w("transcript.bin", raw);
  w("audit.jsonl", Buffer.alloc(0));
  return { official: false, result, evidence, incomplete_reason: incompleteReason };
}
