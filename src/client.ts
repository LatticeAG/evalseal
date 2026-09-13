/** Public client functions (spec §7.5). */

import { canonicalize, parse } from "./canon.js";
import { ApiError } from "./errors.js";

export async function command(origin: string, request: any,
                              options: { token_env: string; idempotency_key: string; timeout_ms?: number }): Promise<any> {
  const token = process.env[options.token_env];
  if (token === undefined) throw new ApiError("UNAUTHORIZED");
  const res = await fetch(origin.replace(/\/$/, "") + "/v1/commands", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token,
      "Idempotency-Key": options.idempotency_key,
    },
    body: canonicalize(request),
    signal: AbortSignal.timeout(options.timeout_ms ?? 30000),
  }).catch(() => { throw new ApiError("UNAVAILABLE"); });
  const data = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    try {
      const err: any = parse(data);
      const ae = new ApiError(err.error.code);
      const ra = res.headers.get("retry-after");
      if (ra !== null) ae.retryAfter = parseInt(ra, 10);
      throw ae;
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError("UNAVAILABLE");
    }
  }
  return parse(data);
}

async function get(origin: string, path: string, token: string | null,
                   timeoutMs: number, asJson: true): Promise<any>;
async function get(origin: string, path: string, token: string | null,
                   timeoutMs: number, asJson: false): Promise<Buffer>;
async function get(origin: string, path: string, token: string | null,
                   timeoutMs: number, asJson: boolean): Promise<any> {
  const headers: Record<string, string> = {};
  if (token !== null) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(origin.replace(/\/$/, "") + path, {
    headers, signal: AbortSignal.timeout(timeoutMs),
  }).catch(() => { throw new ApiError("UNAVAILABLE"); });
  const data = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    try {
      const err: any = parse(data);
      const ae = new ApiError(err.error.code);
      const ra = res.headers.get("retry-after");
      if (ra !== null) ae.retryAfter = parseInt(ra, 10);
      throw ae;
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError("UNAVAILABLE");
    }
  }
  return asJson ? parse(data) : data;
}

export const getJson = (origin: string, path: string, token: string | null, timeoutMs = 30000) =>
  get(origin, path, token, timeoutMs, true);
export const getBytes = (origin: string, path: string, token: string | null, timeoutMs = 30000) =>
  get(origin, path, token, timeoutMs, false);
