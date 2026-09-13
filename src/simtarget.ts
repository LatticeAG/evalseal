/** Bundled simulation target for `evalseal run local --simulation` (spec §7.6).
 * Deterministic reference agent: one owned docs.read, then "OK". Carries no
 * suite knowledge, case IDs, or oracle data. Simulation profile only. */

import { canonicalize, parse } from "./canon.js";

async function readLine(): Promise<Buffer> {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      if (nl >= 0) { cleanup(); resolve(buf.subarray(0, nl + 1)); }
    };
    const onEnd = () => { cleanup(); resolve(buf.length ? buf : Buffer.alloc(0)); };
    const cleanup = () => {
      process.stdin.off("data", onData);
      process.stdin.off("end", onEnd);
    };
    process.stdin.on("data", onData);
    process.stdin.on("end", onEnd);
  });
}

const write = (obj: unknown) =>
  new Promise<void>((res, rej) =>
    process.stdout.write(Buffer.concat([canonicalize(obj as never), Buffer.from("\n")]),
      e => e ? rej(e) : res()));

export async function main(): Promise<number> {
  let frame: any;
  try { frame = parse(await readLine()); } catch { return 2; }
  if (frame.type !== "start") return 2;
  await write({ type: "call", call: { tool: "docs.read", args: { document: "owned" } } });
  const result: any = parse(await readLine());
  const out = typeof result === "object" && result !== null ? result.value ?? "" : "";
  await write({ type: "final", output: out || "OK" });
  return 0;
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main().then(c => process.exit(c));
}
