/** Operator key helpers. */

import { sha256Hex } from "./canon.js";
import { unb64u, b64u } from "./sign.js";

// RFC 8032 test seed used by the spec fixture — never a production credential.
export const RFC8032_TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
export const RFC8032_TEST_PUBLIC_B64 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

export function keyIdForPublicKey(publicKeyB64: string): string {
  const digest = Buffer.from(sha256Hex(unb64u(publicKeyB64)), "hex");
  return "es_key_" + b64u(digest).slice(0, 21);
}

export function isTestKey(publicKeyB64: string): boolean {
  return publicKeyB64 === RFC8032_TEST_PUBLIC_B64;
}
