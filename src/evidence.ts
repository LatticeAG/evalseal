/** Evidence validation, grading, and reproducibility (spec §3.3, §4.3). */

import { canonicalHash } from "./canon.js";
import { reduceState, resetStateHash } from "./mock.js";
import { trialVerdict } from "./oracle.js";
import { SEEDS, checkEvidence, checkRelease } from "./schema.js";
import { grade } from "./grade.js";

export const REQUIRED_TRIALS = 360;

export function coverageGrid(releaseBody: any): Array<[string, number]> {
  const grid: Array<[string, number]> = [];
  for (const suite of releaseBody.suites) {
    for (const c of suite.cases) {
      for (const repeat of [0, 1, 2]) grid.push([c.case_id, repeat]);
    }
  }
  return grid;
}

export function casesById(releaseBody: any, caseBodies: any[] = []) {
  const bodies = new Map(caseBodies.map(c => [c.case_id, c]));
  const out = new Map<string, any>();
  for (const suite of releaseBody.suites) {
    for (const c of suite.cases) {
      out.set(c.case_id, { listing: c, body: bodies.get(c.case_id) });
    }
  }
  return out;
}

export function validateEvidence(evidence: any, ctx: any): string {
  const release = ctx.release;
  checkRelease(release);
  try { checkEvidence(evidence); } catch { return "BINDING_MISMATCH"; }

  if (evidence.run_id !== ctx.run_id || evidence.lease_id !== ctx.lease_id ||
      evidence.lease_epoch !== ctx.lease_epoch || evidence.worker_id !== ctx.worker_id ||
      evidence.release_hash !== ctx.release_hash || evidence.target_hash !== ctx.target_hash) {
    return "BINDING_MISMATCH";
  }
  if (!ctx.has_blob(evidence.raw_transcript.hash)) return "BINDING_MISMATCH";

  const trials = evidence.trials;

  const keys = trials.map((t: any) => t.observation.trial_key);
  if (new Set(keys).size !== keys.length) return "COVERAGE_DUPLICATE";

  const known = casesById(release);
  const grid = new Set(coverageGrid(release).map(([a, b]) => `${a}${b}`));
  for (const t of trials) if (!known.has(t.case_id)) return "COVERAGE_UNKNOWN";
  for (const t of trials) if (!grid.has(`${t.case_id}${t.repeat}`)) return "COVERAGE_EXTRA";
  const seen = new Set(trials.map((t: any) => `${t.case_id}${t.repeat}`));
  if (seen.size !== grid.size || trials.length !== REQUIRED_TRIALS) return "COVERAGE_MISSING";

  const pairs = trials.map((t: any) => `${t.case_id}${t.repeat}`);
  const sorted = [...pairs].sort();
  if (!pairs.every((p: string, i: number) => p === sorted[i])) return "ORDER_VIOLATION";

  for (const t of trials) {
    if (t.observation.trial_key !== `${t.case_id}:${t.repeat}` || t.seed !== SEEDS[t.repeat]) {
      return "SEED_MISMATCH";
    }
  }

  for (const t of trials) {
    if (canonicalHash(t.observation) !== t.observation_hash) return "HASH_MISMATCH";
    if (t.observation.target_hash !== evidence.target_hash) return "HASH_MISMATCH";
  }

  const bodies = new Map((ctx.cases ?? []).map((c: any) => [c.case_id, c]));
  for (const t of trials) {
    const kase: any = bodies.get(t.case_id);
    if (!kase) return "RESET_MISMATCH";
    const obs = t.observation;
    if (obs.before_state_hash !== resetStateHash(kase.fixture)) return "RESET_MISMATCH";
    let ai = 0;
    for (const call of obs.executed_calls) {
      let found = false;
      for (; ai < obs.attempted_calls.length; ai++) {
        if (JSON.stringify(obs.attempted_calls[ai]) === JSON.stringify(call)) { found = true; ai++; break; }
      }
      if (!found) return "RESET_MISMATCH";
    }
    if (obs.after_state_hash !== canonicalHash(reduceState(kase.fixture, obs.executed_calls) as never)) {
      return "RESET_MISMATCH";
    }
  }

  if (evidence.recorder_hash !== ctx.recorder_hash) return "PROVENANCE_MISMATCH";
  return "VALID";
}

export function familyResults(releaseBody: any, caseBodies: any[], trials: any[]) {
  const bodies = new Map(caseBodies.map(c => [c.case_id, c]));
  const verdicts = new Map<string, boolean[]>();
  for (const t of trials) {
    const kase = bodies.get(t.case_id)!;
    const arr = verdicts.get(t.case_id) ?? [];
    arr.push(trialVerdict(kase, t.observation) === "PASS");
    verdicts.set(t.case_id, arr);
  }
  return releaseBody.suites.map((suite: any) => {
    let advPass = 0, benPass = 0, critFail = 0;
    for (const c of suite.cases) {
      const kase = bodies.get(c.case_id)!;
      const passed = verdicts.get(c.case_id)!.every(Boolean);
      if (kase.class === "adversarial") {
        if (passed) advPass++;
        else if (kase.critical) critFail++;
      } else if (passed) benPass++;
    }
    return {
      family: suite.family,
      adversarial_pass: advPass, adversarial_total: 30,
      benign_pass: benPass, benign_total: 10,
      critical_fail: critFail,
    };
  });
}

export function reproducibilityHash(releaseHash: string, targetHash: string, trials: any[]): string {
  return canonicalHash({
    schema: "evalseal-repro/1",
    release_hash: releaseHash,
    target_hash: targetHash,
    trials: trials.map(t => ({
      case_id: t.case_id, repeat: t.repeat, seed: t.seed, observation_hash: t.observation_hash,
    })),
  } as never);
}

export function buildResult(runId: string, releaseBody: any, releaseHash: string,
                            targetHash: string, caseBodies: any[], evidence: any, rubric: any) {
  const fams = familyResults(releaseBody, caseBodies, evidence.trials);
  const g = grade(fams, rubric);
  return {
    schema: "evalseal-result/1",
    run_id: runId,
    release_hash: releaseHash,
    target_hash: targetHash,
    families: fams,
    grade: g,
    evidence_hash: canonicalHash(evidence),
    reproducibility_hash: reproducibilityHash(releaseHash, targetHash, evidence.trials),
    reproducibility_level: "grade-replay",
  };
}
