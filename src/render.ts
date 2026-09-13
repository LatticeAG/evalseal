/** Deterministic byte renderers (spec §9.3, §10). Pure serializers over closed objects. */

import { blobHash, canonicalHash, canonicalize } from "./canon.js";
import { writePack } from "./zipio.js";
import type { Signer } from "./sign.js";

export const NOTICE1 = "Issuer-attested test observations; not accredited standards compliance";
export const NOTICE2 = "Current status must be checked; this PDF is a dated record";
export const RETENTION = "Retention: private evidence 180 days; public record 2555 days minimum.";

export function utc(t: number): string {
  return new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function fields(cert: any, result: any, release: any): string[] {
  const c = cert.body, rel = release.body;
  const lines = [
    "EvalSeal assessment",
    "Qualification: " + c.qualification,
    "Band: " + c.band,
    "Product: " + c.product_label + " / " + c.product_version,
    "Issuer key: " + cert.key_id,
    "Issued: " + utc(c.issued_at),
    "Expiry: " + utc(c.expires_at),
    "Target: " + c.target_hash,
    "Release: " + c.release_hash,
  ];
  lines.push(...rel.suites.map((s: any) => "Suite: " + s.family + " / " + s.version));
  lines.push("Runner: " + rel.runner_image_hash, "Oracle: " + rel.oracle_hash);
  lines.push(...result.families.map((f: any) =>
    `${f.family}: adversarial ${f.adversarial_pass}/30; benign ${f.benign_pass}/10; critical failures ${f.critical_fail}/5`));
  return [...lines,
    "Reproducibility: " + c.reproducibility_hash,
    "Evidence head: " + c.evidence_head,
    ...c.scope_lines,
    RETENTION,
    "Verification path: /certificates/" + c.certificate_id,
  ];
}

const safe = (s: string) =>
  [...s].map(ch => {
    const o = ch.codePointAt(0)!;
    return o >= 32 && o <= 126 ? ch : `[U+${o.toString(16).toUpperCase().padStart(4, "0")}]`;
  }).join("");

/** textwrap.wrap(line, width, break_long_words=True, break_on_hyphens=False) */
export function textWrap(line: string, width: number): string[] {
  const chunks = line.split(/(\s+)/).filter(c => c.length > 0).reverse();
  const lines: string[] = [];
  while (chunks.length) {
    const cur: string[] = [];
    let curLen = 0;
    if (chunks[chunks.length - 1]!.trim() === "" && lines.length) chunks.pop();
    while (chunks.length) {
      const l = chunks[chunks.length - 1]!.length;
      if (curLen + l <= width) { cur.push(chunks.pop()!); curLen += l; }
      else break;
    }
    if (chunks.length && chunks[chunks.length - 1]!.length > width) {
      const spaceLeft = Math.max(1, width - curLen);
      const chunk = chunks[chunks.length - 1]!;
      cur.push(chunk.slice(0, spaceLeft));
      chunks[chunks.length - 1] = chunk.slice(spaceLeft);
    }
    if (cur.length && cur[cur.length - 1]!.trim() === "") cur.pop();
    if (cur.length) lines.push(cur.join(""));
  }
  return lines;
}

export function renderPdf(cert: any, result: any, release: any): Buffer {
  const lines: string[] = [];
  for (const line of fields(cert, result, release)) {
    lines.push(...textWrap(safe(line), 80));
  }
  const chunks: string[][] = [];
  for (let i = 0; i < lines.length; i += 55) chunks.push(lines.slice(i, i + 55));
  const objects = new Map<number, Buffer>();
  objects.set(1, Buffer.from("<< /Type /Catalog /Pages 2 0 R >>"));
  objects.set(3, Buffer.from("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"));
  const kids = chunks.map((_, i) => `${4 + 2 * i} 0 R`).join(" ");
  objects.set(2, Buffer.from(`<< /Type /Pages /Kids [${kids}] /Count ${chunks.length} >>`));
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  chunks.forEach((chunk, i) => {
    const page = 4 + 2 * i, content = 5 + 2 * i;
    const text = [...chunk, `Page ${i + 1}/${chunks.length}`, NOTICE1, NOTICE2];
    const stream = Buffer.from(
      "BT /F1 10 Tf 12 TL 40 802 Td\n" + text.map(s => "(" + esc(s) + ") Tj").join("\nT*\n") + "\nET\n", "ascii");
    objects.set(page, Buffer.from(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${content} 0 R >>`));
    objects.set(content, Buffer.concat([Buffer.from(`<< /Length ${stream.length} >>\nstream\n`), stream, Buffer.from("endstream")]));
  });
  const parts: Buffer[] = [Buffer.from("%PDF-1.4\n")];
  const offsets: number[] = [0];
  let pos = 9;
  for (let n = 1; n <= objects.size; n++) {
    offsets.push(pos);
    const obj = Buffer.concat([Buffer.from(`${n} 0 obj\n`), objects.get(n)!, Buffer.from("\nendobj\n")]);
    parts.push(obj);
    pos += obj.length;
  }
  const xref = pos;
  const tail = `xref\n0 ${offsets.length}\n0000000000 65535 f \n` +
    offsets.slice(1).map(o => `${String(o).padStart(10, "0")} 00000 n \n`).join("") +
    `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  parts.push(Buffer.from(tail));
  return Buffer.concat(parts);
}

export function packFiles(cert: any, result: any, release: any, target: any, audit: any[],
                          checkpoint: any, keyring: any, cases: any[],
                          disclosure = "public-redacted", evidence?: any, transcript?: Buffer) {
  const files = new Map<string, Buffer>([
    ["certificate.json", canonicalize(cert)],
    ["release.json", canonicalize(release)],
    ["cases.json", canonicalize(cases)],
    ["target.json", canonicalize(target)],
    ["result.json", canonicalize(result)],
    ["audit.jsonl", Buffer.concat(audit.map(e => Buffer.concat([canonicalize(e), Buffer.from("\n")])))],
    ["checkpoint.json", canonicalize(checkpoint)],
    ["keyring.json", canonicalize(keyring)],
    ["scope.txt", Buffer.from([...cert.body.scope_lines, RETENTION].join("\n") + "\n")],
    ["report.pdf", renderPdf(cert, result, release)],
  ]);
  if (disclosure === "private-full") {
    if (evidence === undefined || transcript === undefined) {
      throw new Error("private-full pack requires evidence and transcript");
    }
    files.set("evidence.json", canonicalize(evidence));
    files.set("transcript.bin", transcript);
  }
  const media = (n: string) =>
    n.endsWith(".pdf") ? "application/pdf"
      : n.endsWith(".txt") || n.endsWith(".jsonl") ? "text/plain"
      : n.endsWith(".bin") ? "application/octet-stream"
      : "application/json";
  const manifest = {
    schema: "evalseal-pack/1",
    certificate_hash: canonicalHash(cert as never),
    files: [...files.entries()].sort(([a], [b]) => a < b ? -1 : 1).map(([n, b]) =>
      ({ path: n, hash: blobHash(b), bytes: b.length, media_type: media(n) })),
    disclosure,
  };
  return { files, manifest };
}

export function packZip(cert: any, result: any, release: any, target: any, audit: any[],
                        checkpoint: any, keyring: any, cases: any[], signer?: Signer,
                        disclosure = "public-redacted", evidence?: any, transcript?: Buffer): Buffer {
  const { files, manifest } = packFiles(cert, result, release, target, audit, checkpoint,
    keyring, cases, disclosure, evidence, transcript);
  files.set("manifest.json", canonicalize(signer ? signer("pack", manifest) : manifest));
  const sorted = new Map([...files.entries()].sort(([a], [b]) => (a < b ? -1 : 1)));
  return writePack(sorted);
}

const htmlEscape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

export function renderPage(cert: any, result: any, status: any, release: any): Buffer {
  const text = [...fields(cert, result, release),
    "Status: " + status.body.state,
    "Status at: " + utc(status.body.as_of),
    NOTICE1, NOTICE2];
  return Buffer.from(
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>EvalSeal assessment</title>' +
    "<main><h1>EvalSeal assessment</h1>" +
    text.map(s => "<p>" + htmlEscape(s) + "</p>").join("") +
    "</main></html>");
}

export function badgeLines(cert: any, status: any): string[] {
  const c = cert.body, s = status.body;
  const primary = c.band === "F" ? "NOT CERTIFIED — F"
    : s.state !== "ACTIVE" ? s.state
    : c.band + " CERTIFIED";
  return [
    "EvalSeal | " + primary,
    c.product_label + " / " + c.product_version,
    "Target: " + c.target_hash,
    "Issued: " + utc(c.issued_at),
    "Expiry: " + utc(c.expires_at),
    "Status at: " + utc(s.as_of),
    ...c.scope_lines,
    "/certificates/" + c.certificate_id,
  ];
}

function badgeSvg(lines: string[]): Buffer {
  const wrapped = lines.flatMap(t => textWrap(t, 100));
  const nodes = wrapped.map((t, i) =>
    `<text x="20" y="${30 + 18 * i}" font-family="monospace" font-size="12">${htmlEscape(t)}</text>`).join("");
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="${50 + 18 * wrapped.length}" role="img">` +
    `<title>EvalSeal scoped assessment</title>${nodes}</svg>`);
}

export function renderBadge(cert: any, status: any): Buffer {
  return badgeSvg(badgeLines(cert, status));
}

export function renderBadgeUnavailable(): Buffer {
  return Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" width="960" height="68" role="img">' +
    "<title>EvalSeal scoped assessment</title>" +
    '<text x="20" y="30" font-family="monospace" font-size="12">Record unavailable</text>' +
    "</svg>");
}

export function renderBadgeUnknown(cert: any, statusTime: number): Buffer {
  const c = cert.body;
  return badgeSvg([
    "EvalSeal | STATUS UNKNOWN",
    c.product_label + " / " + c.product_version,
    "Target: " + c.target_hash,
    "Issued: " + utc(c.issued_at),
    "Expiry: " + utc(c.expires_at),
    "Status at: " + utc(statusTime),
    ...c.scope_lines,
    "/certificates/" + c.certificate_id,
  ]);
}

export function renderLeaderboard(page: any, release: any): Buffer {
  const rows = page.items.map((r: any) =>
    "<tr>" + ["label", "state", "band", "status"].map(k => `<td>${htmlEscape(String(r[k]))}</td>`).join("") + "</tr>").join("");
  const scope = release.body.scope_lines.map((s: string) => `<li>${htmlEscape(s)}</li>`).join("");
  return Buffer.from(
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>EvalSeal leaderboard</title>' +
    '<main><h1>EvalSeal leaderboard</h1><ul>' + scope + "</ul>" +
    '<table><caption>Latest public attempts</caption><thead>' +
    "<tr><th>Product</th><th>State</th><th>Band</th><th>Status</th></tr></thead>" +
    "<tbody>" + rows + "</tbody></table></main></html>");
}
