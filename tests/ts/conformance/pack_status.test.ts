/** TV-E--39..46, 48, 49, 58, 61: status semantics, packs, audit, zip bounds. */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fx from "../../../src/fixture.js";
import { canonicalHash, domainHash } from "../../../src/canon.js";
import { checkpointsEquivocate, verifyAgainstCheckpoint, verifyCheckpointSet } from "../../../src/audit.js";
import { current, verifyPack, zipCheck } from "../../../src/pack.js";
import { badgeLines, renderBadgeUnknown, renderPage } from "../../../src/render.js";
import { crc32 } from "../../../src/zipio.js";

const ROOTS = fx.KEYRING.body.keys;
const KEY = ROOTS[0];

function packOpts(kw: any = {}) {
  return {
    root_keys: ROOTS, now: fx.T0 + 70, status: null,
    keyring: null, min_keyring_epoch: 1, keyring_observed_at: fx.T0 + 65,
    ...kw,
  };
}

test("test_tv_e_39_expiry_exact_boundary", () => {
  const status = fx.signed("status", { ...fx.STATUS.body, as_of: fx.EXP + 59, valid_until: fx.EXP + 119 });
  const [cur, reasons] = current(fx.CERT, status, fx.KEYRING, fx.EXP + 60, 1);
  assert.equal(cur, "NOT_QUALIFIED");
  assert.deepEqual(reasons, ["CERT_EXPIRED"]);
});

test("test_tv_e_40_offline_signature_is_not_current_certification", () => {
  const pack = fx.packBytes();
  const v = verifyPack(pack, packOpts({ status: null, keyring_observed_at: undefined }));
  assert.deepEqual(v, {
    integrity: "VALID", band: "A", coverage: "summary-only",
    current: "UNKNOWN", reasons: ["STATUS_MISSING"],
  });
});

test("test_tv_e_41_public_redaction_limits_replay_claims", () => {
  const pack = fx.packBytes();
  const st = fx.finalStatus();
  const status = fx.signed("status", { ...st.body, as_of: fx.T0 + 70, valid_until: fx.T0 + 130 });
  const v = verifyPack(pack, packOpts({ status }));
  assert.equal(v.integrity, "VALID");
  assert.equal(v.coverage, "summary-only");
  assert.equal(v.current, "QUALIFIES");
});

test("test_tv_e_42_expired_status_cannot_remain_green", () => {
  const status = fx.signed("status", { ...fx.STATUS.body, as_of: fx.T0 + 60, valid_until: fx.T0 + 120 });
  const [cur, reasons] = current(fx.CERT, status, fx.KEYRING, fx.T0 + 120, 1);
  assert.equal(cur, "UNKNOWN");
  assert.deepEqual(reasons, ["STATUS_STALE"]);
  assert.ok(renderBadgeUnknown(fx.CERT, fx.T0 + 120).includes("STATUS UNKNOWN"));
});

test("test_tv_e_43_compromised_signing_key", () => {
  const key2 = { ...KEY, revoked: true };
  const kr2 = fx.signed("keyring", {
    schema: "evalseal-keyring/1", epoch: 2, issued_at: fx.T0 + 65,
    valid_until: fx.T0 + 86400, keys: [key2],
    previous_hash: canonicalHash(fx.KEYRING),
  });
  const status = fx.signed("status", { ...fx.finalStatus().body, as_of: fx.T0 + 70, valid_until: fx.T0 + 130 });
  const [cur, reasons] = current(fx.CERT, status, kr2, fx.T0 + 70, 1);
  assert.equal(cur, "NOT_QUALIFIED");
  assert.deepEqual(reasons, ["KEY_REVOKED"]);
});

test("test_tv_e_44_missing_audit_predecessor", () => {
  assert.equal(verifyAgainstCheckpoint([fx.AUDIT[0], fx.AUDIT[2]], fx.CHECKPOINT), "SEQ_GAP");
});

test("test_tv_e_45_observed_signed_fork", () => {
  const altHead = domainHash("audit", { ...fx.AUDIT[2].body, at: fx.T0 + 61 });
  const cp2 = fx.signed("checkpoint", { ...fx.CHECKPOINT.body, head: altHead });
  assert.ok(checkpointsEquivocate(fx.CHECKPOINT, cp2));
  assert.equal(verifyCheckpointSet([fx.CHECKPOINT, cp2]), "LOG_EQUIVOCATION");
});

test("test_tv_e_46_renderer_treats_markup_as_text", () => {
  const cert = fx.signed("certificate", { ...fx.CERT_BODY, product_label: "<script>alert(1)</script>" });
  const page = renderPage(cert, fx.RESULT, fx.STATUS, fx.RELEASE);
  assert.ok(page.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(!page.includes("<script>"));
});

function handZip(name: Buffer, declaredSize: number, payload: Buffer): Buffer {
  const crc = crc32(payload);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(declaredSize, 18);
  local.writeUInt32LE(declaredSize, 22);
  local.writeUInt16LE(name.length, 26);
  const localFull = Buffer.concat([local, name, payload]);
  const cdir = Buffer.alloc(46);
  cdir.writeUInt32LE(0x02014b50, 0);
  cdir.writeUInt16LE(20, 4);
  cdir.writeUInt16LE(20, 6);
  cdir.writeUInt32LE(crc, 16);
  cdir.writeUInt32LE(declaredSize, 20);
  cdir.writeUInt32LE(declaredSize, 24);
  cdir.writeUInt16LE(name.length, 28);
  const cdirFull = Buffer.concat([cdir, name]);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdirFull.length, 12);
  eocd.writeUInt32LE(localFull.length, 16);
  return Buffer.concat([localFull, cdirFull, eocd]);
}

test("test_tv_e_48_pack_traversal", () => {
  const data = handZip(Buffer.from("../certificate.json"), 1, Buffer.from("x"));
  assert.equal(zipCheck(data), "PACK_PATH_INVALID");
});

test("test_tv_e_49_archive_bomb_bound", () => {
  const data = handZip(Buffer.from("report.pdf"), 33554433, Buffer.from("x"));
  assert.equal(zipCheck(data), "PACK_SIZE_LIMIT");
});

test("test_tv_e_58_full_badge_scope_cannot_be_shortened", () => {
  const lines = badgeLines(fx.CERT, fx.STATUS);
  for (const s of fx.SCOPE) assert.ok(lines.includes(s));
  const joined = lines.join("\n");
  assert.ok(joined.includes(fx.HT));
  assert.ok(joined.includes("Expiry:"));
  assert.ok(joined.includes("/certificates/" + fx.C));
});

test("test_tv_e_61_fresh_forged_status_cannot_refresh_old_keyring", () => {
  const status = fx.signed("status", { ...fx.STATUS.body, as_of: fx.T0 + 3600, valid_until: fx.T0 + 3660 });
  const [cur, reasons] = current(fx.CERT, status, fx.KEYRING, fx.T0 + 3600, 1, undefined);
  assert.equal(cur, "UNKNOWN");
  assert.deepEqual(reasons, ["KEYRING_STALE"]);
});
