"""Local runner: NDJSON target channel, recorder, evidence assembly (§4.4, §7.6).

The target channel is NDJSON over isolated stdin/stdout:

    -> {"type":"start","user_text":..,"retrieved_text":..,"memory_text":..,"seed":..}
    <- {"type":"call","call":ToolCall} | {"type":"final","output":str}
    -> {"type":"tool-result","ok":bool,"value":str,"code":"OK"|"DENIED"}

Case IDs, oracle metadata, and certification keys never enter these frames.
The supervisor (this runner) installs fixture policy/approval state per trial.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time

from .canon import blob_hash, canonical_hash, canonicalize, parse, JsonError
from .evidence import build_result, validate_evidence
from .ids import new_id
from .mock import Recorder, RECORDER_HASH
from .schema import SchemaError, check_release, check_target, check_tool_call

MAX_FRAME = 32768
MAX_OUTPUT = 16384
MAX_CALLS = 16
TRIAL_TIMEOUT_MS = 30000


class ChannelError(Exception):
    pass


def _readline(stream, deadline_ms: float, budget) -> bytes:
    """Read one LF-terminated frame with a monotonic deadline."""
    line = stream.readline()
    if not line:
        raise ChannelError("eof")
    if len(line) > MAX_FRAME:
        raise ChannelError("oversize-frame")
    return line


def run_trial(proc, case: dict, repeat: int, target_hash: str, transcript: list) -> dict:
    """Execute one trial against the spawned target; returns a Trial."""
    fixture = case["fixture"]
    seed = [11, 23, 37][repeat]
    rec = Recorder(fixture)
    cid = case["case_id"]
    trial_key = f"{cid}:{repeat}"
    transcript.append({"type": "trial", "case_id": cid, "repeat": repeat, "seed": seed})

    start = {"type": "start", "user_text": fixture["user_text"],
             "retrieved_text": fixture["retrieved_text"],
             "memory_text": fixture["memory_text"], "seed": seed}
    proc.stdin.write(canonicalize(start) + b"\n")
    proc.stdin.flush()
    transcript.append(start)

    output = ""
    outcome = "returned"
    abort = None
    deadline = time.monotonic() + TRIAL_TIMEOUT_MS / 1000
    for _ in range(MAX_CALLS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            outcome, abort = "target_timeout", "timeout"
            break
        try:
            line = _readline_with_timeout(proc, remaining)
        except TimeoutError:
            outcome, abort = "target_timeout", "timeout"
            break
        except ChannelError:
            outcome, abort = "target_error", "target_error"
            break
        try:
            frame = parse(line)
        except JsonError:
            outcome, abort = "target_error", "target_error"
            break
        if not isinstance(frame, dict) or set(frame.keys()) not in ({"type", "call"}, {"type", "output"}):
            outcome, abort = "target_error", "target_error"
            break
        if frame["type"] == "final":
            out = frame.get("output")
            if not isinstance(out, str):
                outcome, abort = "target_error", "target_error"
                break
            output = out[:MAX_OUTPUT] if len(out.encode("utf-8")) > MAX_OUTPUT else out
            if len(out.encode("utf-8")) > MAX_OUTPUT:
                output = out.encode("utf-8")[:MAX_OUTPUT].decode("utf-8", "ignore")
                outcome, abort = "target_error", "output_limit"
            transcript.append({"type": "final", "output": output})
            break
        if frame["type"] == "call":
            call = frame.get("call")
            try:
                check_tool_call(call)
            except SchemaError:
                outcome, abort = "target_error", "target_error"
                break
            result = rec.handle_call(call)
            transcript.append({"type": "call", "call": call})
            transcript.append(result)
            proc.stdin.write(canonicalize(result) + b"\n")
            proc.stdin.flush()
            continue
        outcome, abort = "target_error", "target_error"
        break
    else:
        outcome, abort = "target_error", "call_limit"
    if abort:
        transcript.append({"type": "abort", "reason": abort})

    obs = {
        "trial_key": trial_key, "target_hash": target_hash,
        "before_state_hash": rec.before_hash(), "after_state_hash": rec.after_hash(),
        "attempted_calls": rec.attempted, "executed_calls": rec.executed,
        "output": output, "outcome": outcome, "approval_seen": rec.approval_seen,
    }
    return {"case_id": cid, "repeat": repeat, "seed": seed,
            "observation": obs, "observation_hash": canonical_hash(obs)}


def _readline_with_timeout(proc, timeout_s: float) -> bytes:
    buf = []
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        import os
        import select
        r, _, _ = select.select([proc.stdout], [], [], remaining)
        if not r:
            raise TimeoutError()
        ch = os.read(proc.stdout.fileno(), 1)
        if not ch:
            raise ChannelError("eof")
        buf.append(ch)
        if ch == b"\n" or sum(map(len, buf)) > MAX_FRAME:
            break
    line = b"".join(buf)
    if len(line) > MAX_FRAME:
        raise ChannelError("oversize-frame")
    return line


def run_local(lock: dict, target: dict, cases: list, out_dir: str,
              adapter_cmd: list | None, simulation: bool,
              wall_cap_s: int = 14400) -> dict:
    """Execute the pinned grid locally and write the §9.1 artifact set."""
    import os

    release = lock
    check_release(release)
    check_target(target)
    target_hash = canonical_hash(target)
    release_hash = canonical_hash(release)

    if adapter_cmd is None:
        adapter_cmd = [sys.executable, "-m", "evalseal.simtarget"]

    trials: list = []
    transcript: list = []
    started = int(time.time())
    wall_deadline = time.monotonic() + wall_cap_s
    incomplete_reason = None
    # No cross-trial target memory is retained: every trial runs against a
    # freshly spawned target process (spec §4.4).
    grid = [(c, r) for c in cases for r in (0, 1, 2)]
    for case, repeat in grid:
        if time.monotonic() > wall_deadline:
            incomplete_reason = "WALL_CAP"
            break
        env = dict(os.environ)
        env["EVALSEAL_SIMULATION"] = "1" if simulation else "0"
        proc = subprocess.Popen(adapter_cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env)
        try:
            trials.append(run_trial(proc, case, repeat, target_hash, transcript))
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    raw = b"".join(canonicalize(r) + b"\n" for r in transcript)
    evidence = {
        "schema": "evalseal-evidence/1", "run_id": new_id("run"),
        "lease_id": new_id("lse"), "lease_epoch": 1, "worker_id": new_id("wrk"),
        "release_hash": release_hash, "target_hash": target_hash,
        "trials": trials,
        "raw_transcript": {"hash": blob_hash(raw), "bytes": len(raw),
                           "media_type": "application/octet-stream"},
        "recorder_hash": RECORDER_HASH,
        "started_at": started, "finished_at": int(time.time()),
    }
    result = None
    expected = 3 * sum(len(s["cases"]) for s in release["suites"])
    if incomplete_reason is None and len(trials) == expected:
        result = build_result(evidence["run_id"], release, release_hash, target_hash,
                              cases, evidence, release["rubric"])

    os.makedirs(out_dir, exist_ok=True)
    _w(out_dir, "release.json", canonicalize(release))
    _w(out_dir, "cases.json", canonicalize(cases))
    _w(out_dir, "target.json", canonicalize(target))
    if result is not None:
        _w(out_dir, "result.json", canonicalize(result))
    _w(out_dir, "evidence.json", canonicalize(evidence))
    _w(out_dir, "transcript.bin", raw)
    _w(out_dir, "audit.jsonl", b"")   # local runs have no authority stream
    return {"official": False, "result": result, "evidence": evidence,
            "incomplete_reason": incomplete_reason}


def _w(d: str, name: str, data: bytes) -> None:
    import os
    tmp = os.path.join(d, "." + name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, os.path.join(d, name))
