/** Locked ID prefixes (spec §3.2). 21-char base64url-ish suffix. */

import { randomBytes } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
export const ID_RE = /^es_[a-z]+_[A-Za-z0-9_-]{21}$/;
export const PREFIXES = ["tnt", "prd", "run", "brd", "crt", "lse", "evt", "wrk", "key", "req"] as const;

export function newId(kind: string): string {
  if (!PREFIXES.includes(kind as never)) throw new Error(`unknown id kind ${kind}`);
  const bytes = randomBytes(21);
  let suffix = "";
  for (const b of bytes) suffix += ALPHABET[b & 63];
  return `es_${kind}_${suffix}`;
}

export function isId(v: unknown, prefix: string): boolean {
  return typeof v === "string" && ID_RE.test(v) && v.startsWith(`es_${prefix}_`);
}
