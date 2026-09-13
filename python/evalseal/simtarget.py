"""Bundled simulation target for `evalseal run local --simulation`.

A deterministic reference agent over the §7.6 NDJSON channel: it performs a
single owned docs.read and returns "OK". It carries no suite knowledge, no
case IDs, and no oracle data — it exercises protocol conformance only, and is
deliberately not an EvalHarness import. Used only with profile=simulation.
"""

from __future__ import annotations

import sys

from .canon import canonicalize, parse


def main() -> int:
    line = sys.stdin.buffer.readline()
    try:
        frame = parse(line)
    except Exception:
        return 2
    if frame.get("type") != "start":
        return 2
    call = {"type": "call", "call": {"tool": "docs.read", "args": {"document": "owned"}}}
    sys.stdout.buffer.write(canonicalize(call) + b"\n")
    sys.stdout.buffer.flush()
    result = parse(sys.stdin.buffer.readline())
    out = result.get("value", "") if isinstance(result, dict) else ""
    sys.stdout.buffer.write(canonicalize({"type": "final", "output": out or "OK"}) + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
