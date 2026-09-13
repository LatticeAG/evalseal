"""Deterministic byte renderers (spec §9.3, §10).

These are pure serializers over closed objects — the reference contract that
fixes PDF field names, archive metadata, and minimal HTML/SVG output.
"""

from __future__ import annotations

import datetime
import html
import io
import textwrap
import zipfile

from .canon import blob_hash, canonical_hash, canonicalize
from .sign import sign_envelope

NOTICE1 = "Issuer-attested test observations; not accredited standards compliance"
NOTICE2 = "Current status must be checked; this PDF is a dated record"
RETENTION = "Retention: private evidence 180 days; public record 2555 days minimum."


def utc(t: int) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def fields(cert: dict, result: dict, release: dict) -> list:
    c, rel = cert["body"], release["body"]
    lines = [
        "EvalSeal assessment",
        "Qualification: " + c["qualification"],
        "Band: " + c["band"],
        "Product: " + c["product_label"] + " / " + c["product_version"],
        "Issuer key: " + cert["key_id"],
        "Issued: " + utc(c["issued_at"]),
        "Expiry: " + utc(c["expires_at"]),
        "Target: " + c["target_hash"],
        "Release: " + c["release_hash"],
    ]
    lines += ["Suite: " + s["family"] + " / " + s["version"] for s in rel["suites"]]
    lines += ["Runner: " + rel["runner_image_hash"], "Oracle: " + rel["oracle_hash"]]
    lines += [
        f'{f["family"]}: adversarial {f["adversarial_pass"]}/30; benign {f["benign_pass"]}/10; critical failures {f["critical_fail"]}/5'
        for f in result["families"]
    ]
    return lines + [
        "Reproducibility: " + c["reproducibility_hash"],
        "Evidence head: " + c["evidence_head"],
    ] + c["scope_lines"] + [
        RETENTION,
        "Verification path: /certificates/" + c["certificate_id"],
    ]


def _safe(s: str) -> str:
    return "".join(ch if 32 <= ord(ch) <= 126 else f"[U+{ord(ch):04X}]" for ch in s)


def render_pdf(cert: dict, result: dict, release: dict) -> bytes:
    """Uncompressed PDF 1.4 / Courier 10pt / A4 / 40pt margins (spec §9.3)."""
    lines = [
        part
        for line in fields(cert, result, release)
        for part in textwrap.wrap(_safe(line), 80, break_long_words=True, break_on_hyphens=False)
    ]
    chunks = [lines[i : i + 55] for i in range(0, len(lines), 55)]
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"}
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(chunks)))
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(chunks)} >>".encode()
    escape = lambda s: s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    for i, chunk in enumerate(chunks):
        page, content = 4 + 2 * i, 5 + 2 * i
        text = chunk + [f"Page {i + 1}/{len(chunks)}", NOTICE1, NOTICE2]
        stream = ("BT /F1 10 Tf 12 TL 40 802 Td\n" + "\nT*\n".join("(" + escape(s) + ") Tj" for s in text) + "\nET\n").encode("ascii")
        objects[page] = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content} 0 R >>".encode()
        objects[content] = f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"endstream"
    out, offsets = bytearray(b"%PDF-1.4\n"), [0]
    for number in range(1, len(objects) + 1):
        offsets.append(len(out))
        out.extend(f"{number} 0 obj\n".encode() + objects[number] + b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    out.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode())
    out.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)


def pack_files(cert, result, release, target, audit, checkpoint, keyring, cases,
               disclosure="public-redacted", evidence=None, transcript=None) -> dict:
    """The exact attestation-pack file set (spec §9.2)."""
    files = {
        "certificate.json": canonicalize(cert),
        "release.json": canonicalize(release),
        "cases.json": canonicalize(cases),
        "target.json": canonicalize(target),
        "result.json": canonicalize(result),
        "audit.jsonl": b"".join(canonicalize(e) + b"\n" for e in audit),
        "checkpoint.json": canonicalize(checkpoint),
        "keyring.json": canonicalize(keyring),
        "scope.txt": ("\n".join(cert["body"]["scope_lines"]) + "\n" + RETENTION + "\n").encode(),
        "report.pdf": render_pdf(cert, result, release),
    }
    if disclosure == "private-full":
        if evidence is None or transcript is None:
            raise ValueError("private-full pack requires evidence and transcript")
        files["evidence.json"] = canonicalize(evidence)
        files["transcript.bin"] = transcript
    media = lambda name: (
        "application/pdf" if name.endswith(".pdf")
        else "text/plain" if name.endswith((".txt", ".jsonl"))
        else "application/octet-stream" if name.endswith(".bin")
        else "application/json"
    )
    manifest = {
        "schema": "evalseal-pack/1",
        "certificate_hash": canonical_hash(cert),
        "files": [
            {"path": n, "hash": blob_hash(b), "bytes": len(b), "media_type": media(n)}
            for n, b in sorted(files.items())
        ],
        "disclosure": disclosure,
    }
    return files, manifest


def pack_zip(cert, result, release, target, audit, checkpoint, keyring, cases,
             signer=None, disclosure="public-redacted",
             evidence=None, transcript=None) -> bytes:
    """STORE archive, sorted ASCII paths, DOS epoch, unix 0644 (spec §9.3).

    signer is a callable (kind, body) -> Signed envelope. Unsigned manifests
    are produced only for local simulation tooling.
    """
    files, manifest = pack_files(
        cert, result, release, target, audit, checkpoint, keyring, cases,
        disclosure, evidence, transcript)
    files["manifest.json"] = canonicalize(signer("pack", manifest)) if signer else canonicalize(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return output.getvalue()


def render_page(cert, result, status, release) -> bytes:
    text = fields(cert, result, release) + [
        "Status: " + status["body"]["state"],
        "Status at: " + utc(status["body"]["as_of"]),
        NOTICE1,
        NOTICE2,
    ]
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>EvalSeal assessment</title>'
        "<main><h1>EvalSeal assessment</h1>"
        + "".join("<p>" + html.escape(s) + "</p>" for s in text)
        + "</main></html>"
    ).encode()


def badge_lines(cert, status) -> list:
    """Ordered visible strings, independent of SVG styling (spec §14.1)."""
    c, s = cert["body"], status["body"]
    if c["band"] == "F":
        primary = "NOT CERTIFIED — F"
    elif s["state"] != "ACTIVE":
        primary = s["state"]
    else:
        primary = c["band"] + " CERTIFIED"
    return [
        "EvalSeal | " + primary,
        c["product_label"] + " / " + c["product_version"],
        "Target: " + c["target_hash"],
        "Issued: " + utc(c["issued_at"]),
        "Expiry: " + utc(c["expires_at"]),
        "Status at: " + utc(s["as_of"]),
    ] + c["scope_lines"] + ["/certificates/" + c["certificate_id"]]


def render_badge(cert, status) -> bytes:
    text = badge_lines(cert, status)
    lines = [p for t in text for p in textwrap.wrap(t, 100, break_long_words=True, break_on_hyphens=False)]
    nodes = "".join(
        f'<text x="20" y="{30 + 18 * i}" font-family="monospace" font-size="12">{html.escape(t)}</text>'
        for i, t in enumerate(lines)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{50 + 18 * len(lines)}" role="img">'
        f"<title>EvalSeal scoped assessment</title>{nodes}</svg>"
    ).encode()


def render_badge_unavailable() -> bytes:
    """Identical nonqualifying 404 badge for unknown or private certificates."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="960" height="68" role="img">'
        "<title>EvalSeal scoped assessment</title>"
        '<text x="20" y="30" font-family="monospace" font-size="12">Record unavailable</text>'
        "</svg>"
    ).encode()


def render_badge_unknown(cert, status_time: int) -> bytes:
    """Same layout with primary text STATUS UNKNOWN when freshness fails."""
    c = cert["body"]
    lines = [
        "EvalSeal | STATUS UNKNOWN",
        c["product_label"] + " / " + c["product_version"],
        "Target: " + c["target_hash"],
        "Issued: " + utc(c["issued_at"]),
        "Expiry: " + utc(c["expires_at"]),
        "Status at: " + utc(status_time),
    ] + c["scope_lines"] + ["/certificates/" + c["certificate_id"]]
    wrapped = [p for t in lines for p in textwrap.wrap(t, 100, break_long_words=True, break_on_hyphens=False)]
    nodes = "".join(
        f'<text x="20" y="{30 + 18 * i}" font-family="monospace" font-size="12">{html.escape(t)}</text>'
        for i, t in enumerate(wrapped)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="960" height="{50 + 18 * len(wrapped)}" role="img">'
        f"<title>EvalSeal scoped assessment</title>{nodes}</svg>"
    ).encode()


def render_leaderboard(page, release) -> bytes:
    rows = "".join(
        "<tr>" + "".join("<td>" + html.escape(str(r[k])) + "</td>" for k in ("label", "state", "band", "status")) + "</tr>"
        for r in page["items"]
    )
    scope = "".join("<li>" + html.escape(s) + "</li>" for s in release["body"]["scope_lines"])
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>EvalSeal leaderboard</title>'
        '<main><h1>EvalSeal leaderboard</h1><ul>' + scope + "</ul>"
        '<table><caption>Latest public attempts</caption><thead>'
        "<tr><th>Product</th><th>State</th><th>Band</th><th>Status</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table></main></html>"
    ).encode()
