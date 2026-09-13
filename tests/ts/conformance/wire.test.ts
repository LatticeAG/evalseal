/** TV-E--01..09: canonicalization, parsing, signatures (spec §14.1). */

import { test } from "node:test";
import assert from "node:assert/strict";

import * as fx from "../../../src/fixture.js";
import { JsonError, canonicalHash, canonicalize, parse } from "../../../src/canon.js";
import { SchemaError, checkCommand } from "../../../src/schema.js";
import { verifyWithKey } from "../../../src/pack.js";

const KEY = fx.KEYRING.body.keys[0];

test("test_tv_e_01_canonical_object_hash", () => {
  assert.equal(canonicalHash({}),
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
});

test("test_tv_e_02_key_order_is_not_identity", () => {
  assert.equal(canonicalHash({ b: 2, a: 1 }), canonicalHash({ a: 1, b: 2 }));
  assert.deepEqual(canonicalize({ b: 2, a: 1 }), Buffer.from('{"a":1,"b":2}'));
});

test("test_tv_e_03_duplicate_json_member", () => {
  assert.throws(() => parse(Buffer.from('{"track":"private","track":"public"}')),
    (e: any) => e instanceof JsonError && e.code === "BAD_JSON");
});

test("test_tv_e_04_unsafe_numeric_domain", () => {
  assert.throws(() => parse(Buffer.from('{"revision":9007199254740992}')),
    (e: any) => e instanceof JsonError && e.code === "BAD_SCHEMA");
});

test("test_tv_e_05_negative_zero_rejected", () => {
  assert.throws(() => parse(Buffer.from('{"revision":-0}')),
    (e: any) => e instanceof JsonError && e.code === "BAD_SCHEMA");
});

test("test_tv_e_06_id_prefix_confusion", () => {
  // es_prd_* where a run ID is required: rejected at schema validation
  assert.throws(() => checkCommand({
    op: "run.cancel",
    args: { run_id: fx.P, expected_revision: 1, reason: "OWNER_CANCELLED" },
  }), (e: any) => e instanceof SchemaError);
});

test("test_tv_e_07_valid_domain_bound_certificate_signature", () => {
  assert.equal(verifyWithKey(fx.CERT, "certificate", KEY), "VALID");
});

test("test_tv_e_08_signed_body_mutation", () => {
  const env = JSON.parse(JSON.stringify(fx.CERT));
  env.body.band = "B";
  assert.equal(verifyWithKey(env, "certificate", KEY), "HASH_MISMATCH");
});

test("test_tv_e_09_cross_role_signature_substitution", () => {
  const env = JSON.parse(JSON.stringify(fx.CERT));
  env.kind = "release";
  assert.equal(verifyWithKey(env, "release", KEY), "BAD_SCHEMA");
});
