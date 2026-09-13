/** Cross-language integration: the TS client/worker against the Python
 * reference service over real HTTP. Covers the service-level vectors that do
 * not require time control (the deterministic-clock halves live in
 * tests/conformance against the in-process Service). */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as fx from "../../../src/fixture.js";
import { canonicalize, canonicalHash, parse } from "../../../src/canon.js";
import { serve as workerServe } from "../../../src/worker.js";
import { verifyPack } from "../../../src/pack.js";

const HERE = dirname(fileURLToPath(import.meta.url));
// compiled layout: dist-test/tests/ts/integration -> repo root is four levels up
const ROOT = join(HERE, "..", "..", "..", "..");
const PYDIR = join(ROOT, "python");

const TOK_OWNER = "tok-owner";
const TOK_SUBMITTER = "tok-submitter";
const TOK_READER = "tok-reader";
const TOK_B = "tok-tenant-b-reader";
const TOK_WORKER = "tok-worker";

let ORIGIN = "";
let server: ChildProcess | null = null;
let tmp = "";

function pythonBin(): string {
  const venv = join(ROOT, ".venv", "bin", "python");
  return existsSync(venv) ? venv : "python3";
}

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), "evalseal-it-"));
  const prov = join(tmp, "provision.json");
  const r = spawnSync(pythonBin(), [join(ROOT, "tests", "ts", "provision.py")],
    { env: { ...process.env, PYTHONPATH: PYDIR } });
  if (r.status !== 0) throw new Error("provision failed: " + r.stderr.toString());
  writeFileSync(prov, r.stdout);

  server = spawn(pythonBin(), ["-m", "evalseal", "serve", "--provision", prov,
    "--bind", "127.0.0.1:0"],
    { env: { ...process.env, PYTHONPATH: PYDIR } });
  ORIGIN = await new Promise<string>((resolve, reject) => {
    let buf = "";
    server!.stderr!.on("data", (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/[\d.]+:\d+/);
      if (m) resolve(m[0]);
    });
    server!.on("exit", () => reject(new Error("server exited: " + buf)));
    setTimeout(() => reject(new Error("server start timeout: " + buf)), 15000);
  });
});

after(() => { server?.kill("SIGKILL"); });

async function cmd(token: string, op: string, args: any, idem: string): Promise<[number, any]> {
  const res = await fetch(ORIGIN + "/v1/commands", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + token,
      "Idempotency-Key": idem,
      "Content-Type": "application/json",
    },
    body: canonicalize({ op, args }),
  });
  return [res.status, parse(Buffer.from(await res.arrayBuffer()))];
}

async function get(path: string, token?: string): Promise<[number, any, Headers]> {
  const res = await fetch(ORIGIN + path,
    token ? { headers: { Authorization: "Bearer " + token } } : {});
  const buf = Buffer.from(await res.arrayBuffer());
  try { return [res.status, parse(buf), res.headers]; }
  catch { return [res.status, buf, res.headers]; }
}

const workerCfg = () => ({
  schema: "evalseal-worker-config/1",
  origin: ORIGIN,
  identity_env: "EVALSEAL_WORKER_TOKEN",
  work_dir: tmp,
  poll_seconds: 5, heartbeat_seconds: 30, lease_seconds: 120,
  parallel_runs: 1,
  sandbox_profile: "linux-isolated-v1",
  network_profile: "approved-model-only",
  profile: "simulation",
});

async function runToCompletion(productId: string, track: string, boardId: string | null,
                               idemPrefix: string, prior: string | null = null) {
  const [st, r] = await cmd(TOK_SUBMITTER, "run.create", {
    product_id: productId, release_hash: fx.HR, track,
    board_id: boardId, prior_certificate_id: prior,
  }, idemPrefix + "-a");
  assert.equal(st, 200, JSON.stringify(r));
  const run = r.data;
  process.env["EVALSEAL_WORKER_TOKEN"] = TOK_WORKER;
  const code = await workerServe(workerCfg(), { once: true });
  assert.equal(code, 0, "worker.once");
  const [st2, view] = await get(`/v1/runs/${run.run_id}`, TOK_READER);
  assert.equal(st2, 200);
  return { run: view, certId: view.certificate_id as string };
}

// --- vectors ----------------------------------------------------------------

test("test_tv_e_06_id_prefix_confusion_over_wire", async () => {
  const [st, r] = await cmd(TOK_OWNER, "run.cancel",
    { run_id: fx.P, expected_revision: 1, reason: "OWNER_CANCELLED" }, "it-06");
  assert.equal(st, 400);
  assert.equal(r.error.code, "BAD_SCHEMA");
});

test("test_tv_e_27_no_score_submission_rpc", async () => {
  const [st, r] = await cmd(TOK_SUBMITTER, "score.submit",
    { run_id: fx.R, band: "A" }, "it-27");
  assert.equal(st, 400);
  assert.equal(r.error.code, "BAD_SCHEMA");
});

test("test_tv_e_28_vendor_cannot_call_worker_ops", async () => {
  const [st, r] = await cmd(TOK_OWNER, "worker.complete",
    { run_id: fx.R, lease_id: fx.L, lease_epoch: 1, evidence_hash: fx.HE }, "it-28");
  assert.equal(st, 403);
  assert.equal(r.error.code, "FORBIDDEN");
});

test("test_tv_e_31_cancel_then_complete_is_fenced", async () => {
  const [st, pr] = await cmd(TOK_OWNER, "product.create",
    { label: "Race Target", target_ref: "target-fixture" }, "it-31-p");
  assert.equal(st, 200);
  const [st2, rr] = await cmd(TOK_SUBMITTER, "run.create", {
    product_id: pr.data.product_id, release_hash: fx.HR, track: "public",
    board_id: null, prior_certificate_id: null,
  }, "it-31-a");
  assert.equal(st2, 200);
  const [st3, cr] = await cmd(TOK_WORKER, "worker.claim", { capacity: 1 }, "it-31-c");
  assert.equal(st3, 200);
  const lease = cr.data;
  assert.ok(lease);
  const [st4] = await cmd(TOK_OWNER, "run.cancel",
    { run_id: rr.data.run_id, expected_revision: 2, reason: "OWNER_CANCELLED" }, "it-31-k");
  assert.equal(st4, 200);
  const ev = { schema: "evalseal-evidence/1", trials: [] };  // placeholder hash only
  const [st5, r5] = await cmd(TOK_WORKER, "worker.complete", {
    run_id: rr.data.run_id, lease_id: lease.lease_id, lease_epoch: 1,
    evidence_hash: canonicalHash(ev),
  }, "it-31-w");
  assert.equal(st5, 409);
  assert.equal(r5.error.code, "LEASE_FENCED");
});

test("test_tv_e_34_run_publish_is_not_a_command", async () => {
  const [st, r] = await cmd(TOK_OWNER, "run.publish",
    { run_id: fx.R, scope: "public" }, "it-34");
  assert.equal(st, 400);
  assert.equal(r.error.code, "BAD_SCHEMA");
});

test("test_tv_e_47_ssrf_target_ref_rejected", async () => {
  for (const ref of ["http://169.254.169.254/latest", "http://127.0.0.1:1/x",
                     "file:///etc/passwd", "gopher://x"]) {
    const [st, r] = await cmd(TOK_OWNER, "product.create",
      { label: "ssrf", target_ref: ref }, "it-47-" + ref.length + ref.charCodeAt(0));
    assert.equal(st, 400, ref);
    assert.equal(r.error.code, "BAD_SCHEMA");
  }
});

test("test_tv_e_50_idempotent_replay_returns_same_object", async () => {
  const args = { label: "Idem Product", target_ref: "target-fixture" };
  const [st1, r1] = await cmd(TOK_OWNER, "product.create", args, "it-50");
  const [st2, r2] = await cmd(TOK_OWNER, "product.create", args, "it-50");
  assert.equal(st1, 200);
  assert.equal(st2, 200);
  assert.equal(r1.data.product_id, r2.data.product_id);
  assert.equal(r1.event_seq, r2.event_seq);
});

test("test_tv_e_51_idempotency_conflict", async () => {
  const [st1] = await cmd(TOK_OWNER, "product.create",
    { label: "One", target_ref: "target-fixture" }, "it-51");
  assert.equal(st1, 200);
  const [st2, r2] = await cmd(TOK_OWNER, "product.create",
    { label: "Two", target_ref: "target-fixture" }, "it-51");
  assert.equal(st2, 409);
  assert.equal(r2.error.code, "IDEMPOTENCY_CONFLICT");
});

test("test_tv_e_53_certificate_renew_is_not_a_command", async () => {
  const [st, r] = await cmd(TOK_OWNER, "certificate.renew",
    { certificate_id: fx.C }, "it-53");
  assert.equal(st, 400);
  assert.equal(r.error.code, "BAD_SCHEMA");
});

test("test_tv_e_59_capability_claims_have_no_rpc_field", async () => {
  const [st, r] = await cmd(TOK_OWNER, "product.create",
    { label: "x", target_ref: "target-fixture", capability_claims: ["stops all malware"] },
    "it-59");
  assert.equal(st, 400);
  assert.equal(r.error.code, "BAD_SCHEMA");
});

test("test_tv_e_60_secrets_never_appear_in_diagnostics", async () => {
  const secret = "tok-supersecret-9f8e7d";
  const res = await fetch(ORIGIN + "/v1/commands", {
    method: "POST",
    headers: { "Authorization": "Bearer " + secret, "Idempotency-Key": "it-60",
               "Content-Type": "application/json" },
    body: canonicalize({ op: "product.create", args: { label: "x", target_ref: "target-fixture" } }),
  });
  const text = await res.text();
  assert.equal(res.status, 401);
  assert.ok(!text.includes(secret));
});

let privateCertId = "";
let privateProductId = "";
let privateBoardId = "";

test("test_tv_e_37_38_private_track_visibility_and_badge", { timeout: 240000 }, async () => {
  const [st, br] = await cmd(TOK_OWNER, "board.create",
    { label: "Internal Tests" }, "it-38-b");
  assert.equal(st, 200);
  const boardId = br.data.board_id;
  const [st2, pr] = await cmd(TOK_OWNER, "product.create",
    { label: "Private Agent", target_ref: "target-fixture" }, "it-38-p");
  assert.equal(st2, 200);
  const { run, certId } = await runToCompletion(pr.data.product_id, "private", boardId, "it-38");
  privateCertId = certId;
  privateProductId = pr.data.product_id;
  privateBoardId = boardId;
  assert.equal(run.state, "COMPLETED");
  assert.ok(certId.startsWith("es_crt"));

  // owner sees the cert + private-full pack; tenant B and anonymous get 404
  const [st3, cert] = await get(`/v1/certificates/${certId}`, TOK_OWNER);
  assert.equal(st3, 200);
  assert.equal(cert.certificate.body.track, "private");
  const [st4] = await get(`/v1/certificates/${certId}`, TOK_B);
  assert.equal(st4, 404);
  const [st5] = await get(`/v1/certificates/${certId}`);
  assert.equal(st5, 401);  // anonymous: auth fails before the visibility check
  const [st6] = await get(`/v1/certificates/${certId}/status`, TOK_B);
  assert.equal(st6, 404);
  // badge endpoint cannot enumerate private certificates: identical body to
  // a nonexistent cert
  const [st7, badge] = await get(`/badges/${certId}.svg`);
  assert.equal(st7, 404);
  const [st7b, badgeNone] = await get(`/badges/${fx.idof("crt", "B")}.svg`);
  assert.equal(st7b, 404);
  assert.ok(String(badge).includes("Record unavailable"));
  assert.equal(String(badge), String(badgeNone));
  // private run is invisible on the public leaderboard and to tenant B
  const [st8, lb] = await get(`/v1/leaderboard?release=${encodeURIComponent(fx.HR)}`);
  assert.equal(st8, 200);
  assert.ok(!lb.items.some((i: any) => i.certificate_id === certId));
  const [st9, board] = await get(`/v1/boards/${boardId}`, TOK_OWNER);
  assert.equal(st9, 200);
  assert.ok(board.items.some((i: any) => i.certificate_id === certId));
  const [st10] = await get(`/v1/boards/${boardId}`, TOK_B);
  assert.equal(st10, 404);
  // private pack contains evidence + transcript (full disclosure). The
  // simulation release pins oracle_hash to an opaque fixture value rather
  // than a supported closed-oracle implementation, so full-replay must fail
  // closed as ORACLE_UNSUPPORTED (never partial coverage).
  const res = await fetch(`${ORIGIN}/v1/certificates/${certId}/pack`,
    { headers: { Authorization: "Bearer " + TOK_OWNER } });
  assert.equal(res.status, 200);
  const pack = Buffer.from(await res.arrayBuffer());
  const keyringObservedAt = Math.floor(Date.now() / 1000);
  const [st11, keyring] = await get("/v1/keys");
  assert.equal(st11, 200);
  const [st12, status] = await get(`/v1/certificates/${certId}/status`, TOK_OWNER);
  assert.equal(st12, 200);
  const v = verifyPack(pack, {
    root_keys: keyring.body.keys, now: keyringObservedAt,
    status, keyring, min_keyring_epoch: 1, keyring_observed_at: keyringObservedAt,
  });
  assert.equal(v.integrity, "INVALID");
  assert.deepEqual(v.reasons, ["ORACLE_UNSUPPORTED"]);
});

test("test_tv_e_35_52_54_public_track_e2e_leaderboard_recert", { timeout: 240000 }, async () => {
  const [st, pr] = await cmd(TOK_OWNER, "product.create",
    { label: "Public Agent", target_ref: "target-fixture" }, "it-52-p");
  assert.equal(st, 200);
  const { run, certId } = await runToCompletion(pr.data.product_id, "public", null, "it-52");
  assert.equal(run.state, "COMPLETED");
  const [st2, cert] = await get(`/v1/certificates/${certId}`);
  assert.equal(st2, 200);
  assert.equal(cert.certificate.body.band, "A");
  assert.equal(cert.status.body.state, "ACTIVE");

  // public leaderboard row: latest qualifying certificate for the product
  const [st3, lb] = await get(`/v1/leaderboard?release=${encodeURIComponent(fx.HR)}`);
  assert.equal(st3, 200);
  const row = lb.items.find((i: any) => i.certificate_id === certId);
  assert.ok(row, "leaderboard row");
  assert.equal(row.band, "A");
  assert.equal(row.qualifies, true);

  // public pack is redacted: summary-only, no trial list
  const res = await fetch(`${ORIGIN}/v1/certificates/${certId}/pack`);
  assert.equal(res.status, 200);
  const pack = Buffer.from(await res.arrayBuffer());
  const [, keyring] = await get("/v1/keys");
  const [, status] = await get(`/v1/certificates/${certId}/status`);
  const v = verifyPack(pack, {
    root_keys: keyring.body.keys, now: Math.floor(Date.now() / 1000),
    status, keyring, min_keyring_epoch: 1,
    keyring_observed_at: Math.floor(Date.now() / 1000),
  });
  assert.equal(v.integrity, "VALID");
  assert.equal(v.coverage, "summary-only");
  assert.equal(v.current, "QUALIFIES");

  // badge is public and carries full scope lines
  const [st6, badge] = await get(`/badges/${certId}.svg`);
  assert.equal(st6, 200);
  for (const s of fx.SCOPE) assert.ok(String(badge).includes(s), s);

  // certificate page is served publicly
  const [st7, page] = await get(`/certificates/${certId}`);
  assert.equal(st7, 200);
  assert.ok(String(page).includes("EvalSeal"));

  // TV-E--54: recert admission — cooldown makes a second public admit rate-limited
  const [st8, r8] = await cmd(TOK_SUBMITTER, "run.create", {
    product_id: pr.data.product_id, release_hash: fx.HR, track: "public",
    board_id: null, prior_certificate_id: null,
  }, "it-54-a");
  assert.equal(st8, 429);
  assert.equal(r8.error.code, "RATE_LIMITED");

  // TV-E--54: private recert with prior_certificate_id works (no public
  // cooldown) — must reference a same-track cert on the same product
  const [st10, rr] = await cmd(TOK_SUBMITTER, "run.create", {
    product_id: privateProductId, release_hash: fx.HR, track: "private",
    board_id: privateBoardId, prior_certificate_id: privateCertId,
  }, "it-54-a2");
  assert.equal(st10, 200, JSON.stringify(rr));
  assert.equal(rr.data.prior_certificate_id, privateCertId);
  assert.equal(rr.data.state, "ADMITTED");
  // cancel it so it does not hold the single-concurrency slot for other runs
  const [st11] = await cmd(TOK_OWNER, "run.cancel",
    { run_id: rr.data.run_id, expected_revision: 1, reason: "OWNER_CANCELLED" }, "it-54-k");
  assert.equal(st11, 200);

  // TV-E--32: completion committed first — cancel on COMPLETED run conflicts
  const [st12, r12] = await cmd(TOK_OWNER, "run.cancel",
    { run_id: run.run_id, expected_revision: run.revision, reason: "OWNER_CANCELLED" }, "it-32-k");
  assert.equal(st12, 409);
  assert.equal(r12.error.code, "STATE_CONFLICT");

  // audit trail endpoint serves the run's hash chain + checkpoint
  const [st13, audit] = await get(`/v1/runs/${run.run_id}/audit`, TOK_READER);
  assert.equal(st13, 200);
  assert.ok(audit.entries.length >= 5);
  assert.ok(audit.checkpoint.kind === "checkpoint");
  assert.ok(audit.checkpoint.body.schema === "evalseal-checkpoint/1");
});
