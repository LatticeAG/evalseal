/**
 * evalseal/1 canonical wire rules (spec §3.1, §3.4).
 *
 * J(x)      RFC 8785 UTF-8 bytes
 * B(b)      "sha256:" + hex(SHA-256(b))
 * H(x)      B(J(x))
 * D(kind,x) B(UTF8("evalseal/1/" + kind + "\n") || J(x))
 */

import { createHash } from "node:crypto";

export const MAX_JSON_BYTES = 256 * 1024;
export const MAX_DEPTH = 24;
export const MAX_MEMBERS = 512;
export const MAX_ELEMENTS = 4096;
export const MAX_SAFE_INTEGER = 9007199254740991;

export class JsonError extends Error {
  code: string;
  constructor(code: string, message = "") {
    super(message || code);
    this.code = code;
  }
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

const ESCAPES: Record<number, string> = {
  0x08: "\\b", 0x09: "\\t", 0x0a: "\\n", 0x0c: "\\f", 0x0d: "\\r",
  0x22: '\\"', 0x5c: "\\\\",
};

function utf16Key(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}

function emitString(s: string, out: number[]): void {
  out.push(0x22);
  for (const ch of s) {
    const o = ch.codePointAt(0)!;
    const esc = ESCAPES[o];
    if (esc !== undefined) {
      for (const c of esc) out.push(c.charCodeAt(0));
    } else if (o < 0x20) {
      for (const c of `\\u${o.toString(16).padStart(4, "0")}`) out.push(c.charCodeAt(0));
    } else {
      for (const b of Buffer.from(ch, "utf8")) out.push(b);
    }
  }
  out.push(0x22);
}

function emit(value: Json, out: number[]): void {
  if (value === null) { out.push(...[...'null'].map(c => c.charCodeAt(0))); return; }
  if (value === true) { out.push(...[...'true'].map(c => c.charCodeAt(0))); return; }
  if (value === false) { out.push(...[...'false'].map(c => c.charCodeAt(0))); return; }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > MAX_SAFE_INTEGER) {
      throw new JsonError("BAD_SCHEMA", "number outside protocol scalar domain");
    }
    for (const c of String(value)) out.push(c.charCodeAt(0));
    return;
  }
  if (typeof value === "string") { emitString(value, out); return; }
  if (Array.isArray(value)) {
    out.push(0x5b);
    value.forEach((v, i) => { if (i) out.push(0x2c); emit(v, out); });
    out.push(0x5d);
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => {
      const ka = utf16Key(a), kb = utf16Key(b);
      for (let i = 0; i < Math.min(ka.length, kb.length); i++) {
        if (ka[i] !== kb[i]) return ka[i]! - kb[i]!;
      }
      return ka.length - kb.length;
    });
    out.push(0x7b);
    keys.forEach((k, i) => {
      if (i) out.push(0x2c);
      emitString(k, out);
      out.push(0x3a);
      emit((value as Record<string, Json>)[k]!, out);
    });
    out.push(0x7d);
    return;
  }
  throw new JsonError("BAD_SCHEMA", `value of type ${typeof value} is outside the scalar domain`);
}

/** RFC 8785 canonical JSON bytes. */
export function canonicalize(value: any): Buffer {
  const out: number[] = [];
  emit(value as Json, out);
  return Buffer.from(out);
}

class Parser {
  pos = 0;
  constructor(private s: string) {}

  ws(): void {
    while (this.pos < this.s.length && " \t\n\r".includes(this.s[this.pos]!)) this.pos++;
  }

  value(depth = 0): Json {
    this.ws();
    if (this.pos >= this.s.length) throw new JsonError("BAD_JSON", "unexpected end of input");
    if (depth >= MAX_DEPTH) throw new JsonError("BAD_JSON", "depth limit exceeded");
    const ch = this.s[this.pos]!;
    if (ch === "{") return this.obj(depth);
    if (ch === "[") return this.arr(depth);
    if (ch === '"') return this.string();
    if (ch === "t" && this.s.startsWith("true", this.pos)) { this.pos += 4; return true; }
    if (ch === "f" && this.s.startsWith("false", this.pos)) { this.pos += 5; return false; }
    if (ch === "n" && this.s.startsWith("null", this.pos)) { this.pos += 4; return null; }
    if (ch === "-" || (ch >= "0" && ch <= "9")) return this.number();
    throw new JsonError("BAD_JSON", "unexpected character");
  }

  number(): number {
    const s = this.s;
    const start = this.pos;
    if (s[this.pos] === "-") {
      this.pos++;
      if (this.pos >= s.length || !/[0-9]/.test(s[this.pos]!)) throw new JsonError("BAD_JSON", "malformed number");
    }
    if (s[this.pos] === "0") {
      this.pos++;
      if (this.pos < s.length && /[0-9]/.test(s[this.pos]!)) throw new JsonError("BAD_JSON", "leading zero");
    } else {
      while (this.pos < s.length && /[0-9]/.test(s[this.pos]!)) this.pos++;
    }
    let frac = false;
    if (this.pos < s.length && s[this.pos] === ".") {
      frac = true;
      this.pos++;
      if (this.pos >= s.length || !/[0-9]/.test(s[this.pos]!)) throw new JsonError("BAD_JSON", "malformed fraction");
      while (this.pos < s.length && /[0-9]/.test(s[this.pos]!)) this.pos++;
    }
    if (this.pos < s.length && (s[this.pos] === "e" || s[this.pos] === "E")) {
      frac = true;
      this.pos++;
      if (this.pos < s.length && (s[this.pos] === "+" || s[this.pos] === "-")) this.pos++;
      if (this.pos >= s.length || !/[0-9]/.test(s[this.pos]!)) throw new JsonError("BAD_JSON", "malformed exponent");
      while (this.pos < s.length && /[0-9]/.test(s[this.pos]!)) this.pos++;
    }
    const token = s.slice(start, this.pos);
    if (frac || token.startsWith("-")) {
      throw new JsonError("BAD_SCHEMA", "number outside protocol scalar domain");
    }
    const value = Number(token);
    if (value > MAX_SAFE_INTEGER) throw new JsonError("BAD_SCHEMA", "integer exceeds 2^53-1");
    return value;
  }

  string(): string {
    const s = this.s;
    this.pos++;
    const parts: string[] = [];
    for (;;) {
      if (this.pos >= s.length) throw new JsonError("BAD_JSON", "unterminated string");
      const ch = s[this.pos]!;
      if (ch === '"') { this.pos++; return parts.join(""); }
      const o = ch.codePointAt(0)!;
      if (o < 0x20) throw new JsonError("BAD_JSON", "unescaped control character");
      if (ch === "\\") {
        this.pos++;
        if (this.pos >= s.length) throw new JsonError("BAD_JSON", "unterminated escape");
        const e = s[this.pos]!;
        this.pos++;
        if ('"\\/'.includes(e)) parts.push(e);
        else if (e === "b") parts.push("\b");
        else if (e === "f") parts.push("\f");
        else if (e === "n") parts.push("\n");
        else if (e === "r") parts.push("\r");
        else if (e === "t") parts.push("\t");
        else if (e === "u") parts.push(this.uEscape());
        else throw new JsonError("BAD_JSON", "invalid escape");
      } else {
        parts.push(ch);
        this.pos++;
      }
    }
  }

  uEscape(): string {
    const s = this.s;
    if (this.pos + 4 > s.length) throw new JsonError("BAD_JSON", "truncated \\u escape");
    const cp = parseInt(s.slice(this.pos, this.pos + 4), 16);
    if (Number.isNaN(cp)) throw new JsonError("BAD_JSON", "invalid \\u escape");
    this.pos += 4;
    if (cp >= 0xd800 && cp <= 0xdbff) {
      if (s.slice(this.pos, this.pos + 2) === "\\u") {
        const lo = parseInt(s.slice(this.pos + 2, this.pos + 6), 16);
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          this.pos += 6;
          return String.fromCodePoint(0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00));
        }
      }
      throw new JsonError("BAD_JSON", "lone surrogate");
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) throw new JsonError("BAD_JSON", "lone surrogate");
    return String.fromCodePoint(cp);
  }

  obj(depth: number): Record<string, Json> {
    this.pos++;
    const out: Record<string, Json> = {};
    this.ws();
    if (this.pos < this.s.length && this.s[this.pos] === "}") { this.pos++; return out; }
    for (;;) {
      this.ws();
      if (this.pos >= this.s.length || this.s[this.pos] !== '"') throw new JsonError("BAD_JSON", "object key must be a string");
      const key = this.string();
      this.ws();
      if (this.pos >= this.s.length || this.s[this.pos] !== ":") throw new JsonError("BAD_JSON", "missing ':'");
      this.pos++;
      if (key in out) throw new JsonError("BAD_JSON", "duplicate object member");
      out[key] = this.value(depth + 1);
      if (Object.keys(out).length > MAX_MEMBERS) throw new JsonError("BAD_JSON", "member limit exceeded");
      this.ws();
      if (this.pos >= this.s.length) throw new JsonError("BAD_JSON", "unterminated object");
      if (this.s[this.pos] === ",") { this.pos++; continue; }
      if (this.s[this.pos] === "}") { this.pos++; return out; }
      throw new JsonError("BAD_JSON", "expected ',' or '}'");
    }
  }

  arr(depth: number): Json[] {
    this.pos++;
    const out: Json[] = [];
    this.ws();
    if (this.pos < this.s.length && this.s[this.pos] === "]") { this.pos++; return out; }
    for (;;) {
      out.push(this.value(depth + 1));
      if (out.length > MAX_ELEMENTS) throw new JsonError("BAD_JSON", "array element limit exceeded");
      this.ws();
      if (this.pos >= this.s.length) throw new JsonError("BAD_JSON", "unterminated array");
      if (this.s[this.pos] === ",") { this.pos++; continue; }
      if (this.s[this.pos] === "]") { this.pos++; return out; }
      throw new JsonError("BAD_JSON", "expected ',' or ']'");
    }
  }
}

/** Strict JSON parse per spec §3.1. */
export function parse(data: Buffer | Uint8Array): any {
  if (!Buffer.isBuffer(data) && !(data instanceof Uint8Array)) {
    throw new JsonError("BAD_JSON", "body is not bytes");
  }
  const bytes = Buffer.from(data);
  if (bytes.length > MAX_JSON_BYTES) throw new JsonError("BAD_JSON", "request exceeds 256 KiB");
  if (bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) {
    throw new JsonError("BAD_JSON", "byte-order mark is not permitted");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new JsonError("BAD_JSON", "invalid UTF-8");
  }
  const p = new Parser(text);
  const value = p.value();
  p.ws();
  if (p.pos !== text.length) throw new JsonError("BAD_JSON", "trailing content");
  return value;
}

// -- hash domains ------------------------------------------------------------

export const SHA256_PREFIX = "sha256:";
export const HASH_LEN = 7 + 64;

export function sha256Hex(data: Buffer | Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function blobHash(data: Buffer | Uint8Array): string {
  return SHA256_PREFIX + sha256Hex(data);
}

export function canonicalHash(value: any): string {
  return blobHash(canonicalize(value));
}

export function domainHash(kind: string, body: any): string {
  return blobHash(Buffer.concat([Buffer.from(`evalseal/1/${kind}\n`, "utf8"), canonicalize(body)]));
}

export function signatureMessage(kind: string, keyId: string, bodyHash: string): Buffer {
  return Buffer.from(`evalseal/1/signature\n${kind}\n${keyId}\n${bodyHash}`, "utf8");
}

export function isHash(s: unknown): boolean {
  return typeof s === "string" && s.length === HASH_LEN && s.startsWith(SHA256_PREFIX) &&
    /^[0-9a-f]{64}$/.test(s.slice(7));
}

export function isLabel(s: unknown): boolean {
  if (typeof s !== "string" || s.length < 1 || s.length > 80) return false;
  if (s.normalize("NFC") !== s) return false;
  for (const ch of s) {
    if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u.test(ch)) return false;
  }
  return true;
}

export function isVersion(s: unknown): boolean {
  if (typeof s !== "string") return false;
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  return parts.every(p => p.length > 0 && !(p.length > 1 && p[0] === "0") && /^[0-9]+$/.test(p));
}
