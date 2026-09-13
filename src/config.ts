/** Client/worker/trust configuration loading (spec §8.2). */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { JsonError, parse } from "./canon.js";
import { SchemaError, checkClientConfig, checkTrustFile } from "./schema.js";

export const USER_CONFIG = join(homedir(), ".config", "devin", "evalseal.json");
export const PROJECT_CONFIG = join(".devin", "evalseal.json");

const SECRET_KEYS = new Set(["token", "password", "private_key"]);
const CLIENT_KEYS = new Set(["schema", "origin", "token_env", "trust_file", "cache_dir", "timeout_ms", "profile"]);

export class ConfigError extends Error {}

function loadJsonFile(path: string): any | null {
  let data: Buffer;
  try { data = readFileSync(path); } catch { return null; }
  try { return parse(data); } catch (e) {
    if (e instanceof JsonError) throw new ConfigError(`${path}: ${e.code}`);
    throw e;
  }
}

function checkSecretFields(obj: unknown, where: string): void {
  if (typeof obj === "object" && obj !== null && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      if (SECRET_KEYS.has(k.toLowerCase())) {
        throw new ConfigError(`${where}: secret-looking field '${k}' is not permitted`);
      }
      checkSecretFields(v, where);
    }
  } else if (Array.isArray(obj)) {
    for (const v of obj) checkSecretFields(v, where);
  }
}

export function loadClientConfig(configPath: string | null, flags: Record<string, unknown>) {
  const merged: Record<string, unknown> = {
    schema: "evalseal-client-config/1",
    origin: "https://evalseal.test",
    token_env: "EVALSEAL_TOKEN",
    trust_file: "trust.json",
    cache_dir: "cache/evalseal",
    timeout_ms: 30000,
    profile: "simulation",
  };
  let userTrust: string | undefined;
  for (const path of [USER_CONFIG, configPath ?? PROJECT_CONFIG]) {
    const data = loadJsonFile(path);
    if (data === null || data === undefined) continue;
    if (typeof data !== "object" || Array.isArray(data)) {
      throw new ConfigError(`${path}: config must be an object`);
    }
    for (const k of Object.keys(data)) {
      if (!CLIENT_KEYS.has(k)) throw new ConfigError(`${path}: unknown field '${k}'`);
    }
    checkSecretFields(data, path);
    if (path === USER_CONFIG && "trust_file" in data) userTrust = data.trust_file;
    const copy = { ...data };
    if (path !== USER_CONFIG && "trust_file" in copy && userTrust) copy.trust_file = userTrust;
    Object.assign(merged, copy);
  }
  for (const [k, v] of Object.entries(flags)) {
    if (v !== null && v !== undefined) merged[k] = v;
  }
  try { checkClientConfig(merged); } catch (e) {
    if (e instanceof SchemaError) throw new ConfigError(`client config invalid: ${e.where}`);
    throw e;
  }
  return merged as any;
}

export function loadTrust(path: string) {
  const data = loadJsonFile(path);
  if (data === null) throw new ConfigError(`${path}: not found`);
  try { checkTrustFile(data); } catch (e) {
    if (e instanceof SchemaError) throw new ConfigError(`${path}: invalid trust file (${e.where})`);
    throw e;
  }
  return data;
}
