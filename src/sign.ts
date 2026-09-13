/** Ed25519 signing + verification (spec §3.3). Raw seeds / keys are base64url. */

import { createPrivateKey, createPublicKey, randomBytes, sign as cryptoSign, verify as cryptoVerify, KeyObject } from "node:crypto";
import { canonicalHash, domainHash, signatureMessage } from "./canon.js";
import { isId, newId } from "./ids.js";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function b64u(b: Buffer | Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}
export function unb64u(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export function privFromSeed(seed: Buffer | Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

export function pubFromRaw(raw: Buffer | Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
}

export function publicKeyBytes(priv: KeyObject): Buffer {
  const der = createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  return der.subarray(der.length - 32);
}

export function signBytes(priv: KeyObject, msg: Buffer): Buffer {
  return cryptoSign(null, msg, priv);
}

export function verifyBytes(pub: KeyObject, msg: Buffer, sig: Buffer): boolean {
  try { return cryptoVerify(null, msg, pub, sig); } catch { return false; }
}

export interface Signed { schema: string; kind: string; key_id: string; body_hash: string; body: any; signature: string; }
export interface Signer { (kind: string, body: unknown): Signed; }

export function makeSigner(keyId: string, seed: Buffer | Uint8Array): Signer {
  const priv = privFromSeed(seed);
  return (kind, body) => {
    const bodyHash = domainHash(kind, body);
    const sig = signBytes(priv, signatureMessage(kind, keyId, bodyHash));
    return { schema: "evalseal-signed/1", kind, key_id: keyId, body_hash: bodyHash, body, signature: b64u(sig) };
  };
}

export function envelopeHash(signed: Signed): string {
  return canonicalHash(signed as never);
}

/** Verify an evalseal-signed/1 envelope against a raw Ed25519 public key. */
export function verifyEnvelope(signed: Signed, rawPub: Buffer | Uint8Array, kind?: string): boolean {
  if (signed.schema !== "evalseal-signed/1") return false;
  if (kind !== undefined && signed.kind !== kind) return false;
  if (!isId(signed.key_id, "key")) return false;
  if (domainHash(signed.kind, signed.body) !== signed.body_hash) return false;
  const sig = unb64u(signed.signature);
  if (sig.length !== 64) return false;
  return verifyBytes(pubFromRaw(rawPub), signatureMessage(signed.kind, signed.key_id, signed.body_hash), sig);
}

export function newKey(): { key_id: string; seed: Buffer; publicKey: Buffer } {
  // simulation helper: derive key_id deterministically from public bytes
  const seed = randomBytes(32);
  const priv = privFromSeed(seed);
  const pub = publicKeyBytes(priv);
  return { key_id: newId("key"), seed: Buffer.from(seed), publicKey: pub };
}
