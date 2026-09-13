/** Hash-chained audit entries and checkpoints (spec §3.4, §5). */

import { canonicalHash, domainHash } from "./canon.js";
import { newId } from "./ids.js";
import { checkAuditEntry, checkAuditPayload, checkCheckpointBody } from "./schema.js";

export const GENESIS_SEQ = 1;

export function newEntry(tenantId: string, streamId: string, prevEntry: any,
                         at: number, eventType: string, subjectId: string,
                         stateRevision: number, payload: any, eventId?: string) {
  checkAuditPayload(payload);
  const body = {
    schema: "evalseal-audit/1",
    tenant_id: tenantId,
    stream_id: streamId,
    event_id: eventId ?? newId("evt"),
    seq: prevEntry == null ? 1 : prevEntry.body.seq + 1,
    prev_hash: prevEntry == null ? null : prevEntry.hash,
    at,
    type: eventType,
    subject_id: subjectId,
    state_revision: stateRevision,
    payload_hash: canonicalHash(payload),
  };
  return { body, hash: domainHash("audit", body) };
}

export function verifyChain(entries: any[]): string {
  let prev: string | null = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    try { checkAuditEntry(e); } catch { return "PREV_MISMATCH"; }
    const b = e.body;
    if (b.seq !== i + 1) return "SEQ_GAP";
    if (i === 0) {
      if (b.prev_hash !== null) return "PREV_MISMATCH";
    } else if (b.prev_hash !== prev) return "PREV_MISMATCH";
    if (domainHash("audit", b) !== e.hash) return "PREV_MISMATCH";
    prev = e.hash;
  }
  return "VALID";
}

export function verifyAgainstCheckpoint(entries: any[], checkpoint: any): string {
  const r = verifyChain(entries);
  if (r !== "VALID") return r;
  if (!entries.length) return "HEAD_MISMATCH";
  try { checkCheckpointBody(checkpoint.body); } catch { return "HEAD_MISMATCH"; }
  const cp = checkpoint.body;
  if (cp.seq !== entries[entries.length - 1].body.seq || cp.head !== entries[entries.length - 1].hash) {
    return "HEAD_MISMATCH";
  }
  return "VALID";
}

export function checkpointsEquivocate(cpA: any, cpB: any): boolean {
  const a = cpA.body, b = cpB.body;
  return a.tenant_id === b.tenant_id && a.stream_id === b.stream_id &&
    a.seq === b.seq && a.head !== b.head;
}

export function verifyCheckpointSet(checkpoints: any[]): string {
  const seen = new Map<string, string>();
  for (const cp of checkpoints) {
    try { checkCheckpointBody(cp.body); } catch { return "HEAD_MISMATCH"; }
    const slot = `${cp.body.tenant_id}${cp.body.stream_id}${cp.body.seq}`;
    if (seen.has(slot) && seen.get(slot) !== cp.body.head) return "LOG_EQUIVOCATION";
    seen.set(slot, cp.body.head);
  }
  return "VALID";
}
