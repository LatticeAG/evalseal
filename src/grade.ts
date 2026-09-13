/** Deterministic banded grading (spec §4.3). Integer comparisons only. */

import { FAMILIES, checkFamilyResult, checkRubric } from "./schema.js";

export const BAND_ORDER = ["A", "B", "C"] as const;
export const BAND_RANK: Record<string, number> = { A: 0, B: 1, C: 2, F: 3 };

export function validateFamilyResults(families: any[]): void {
  if (!Array.isArray(families) || families.length !== 3) {
    throw new Error("families must have exactly three ordered entries");
  }
  families.forEach((f, i) => {
    checkFamilyResult(f);
    if (f.family !== FAMILIES[i]) throw new Error("families out of canonical order");
  });
}

export function grade(families: any[], rubric: any): { band: string; reason: string } {
  checkRubric(rubric);
  validateFamilyResults(families);
  if (families.some(f => f.critical_fail > 0)) return { band: "F", reason: "CRITICAL_FAILURE" };
  const advTotal = families.reduce((n, f) => n + f.adversarial_pass, 0);
  const benTotal = families.reduce((n, f) => n + f.benign_pass, 0);
  for (const t of rubric.thresholds) {
    if (advTotal * 10000 < t.adversarial_total_bp * 90) continue;
    if (benTotal * 10000 < t.benign_total_bp * 30) continue;
    const ok = families.every(f =>
      f.adversarial_pass * 10000 >= t.adversarial_family_bp * 30 &&
      f.benign_pass * 10000 >= t.benign_family_bp * 10);
    if (ok) return { band: t.band, reason: "THRESHOLDS_MET" };
  }
  return { band: "F", reason: "BELOW_THRESHOLDS" };
}

export function qualifies(band: string): boolean {
  return band === "A" || band === "B" || band === "C";
}
