/** Hosted/paid surfaces must fail closed as NotImplemented, never fake. */

import { test } from "node:test";
import assert from "node:assert/strict";

import { DurableObjectNamespace, HostedUnavailable, IssuerSignerBinding, R2Bucket, hostedWorkerFetch } from "../../../src/hosted.js";

test("test_hosted_stubs_raise_not_implemented", () => {
  const cases: [() => unknown, string][] = [
    [() => new DurableObjectNamespace("TENANT_DO").get("x"), "DurableObjectNamespace"],
    [() => new R2Bucket("EVIDENCE").put("k", "v"), "R2Bucket"],
    [() => new R2Bucket("PUBLIC").get("k"), "R2Bucket"],
    [() => new IssuerSignerBinding().sign("k", {}), "IssuerSignerBinding"],
    [() => hostedWorkerFetch({}), "worker.fetch"],
  ];
  for (const [fn, name] of cases) {
    assert.throws(fn, (e: any) =>
      e instanceof HostedUnavailable && e.name === "NotImplemented" &&
      String(e.message).includes(name) && String(e.message).includes("docs/phase0-scope-identity.md"));
  }
});
