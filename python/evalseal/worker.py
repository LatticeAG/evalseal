"""Worker loop for the reference service (spec §4.4, §8.1 worker serve).

Claims admitted runs under a tenant-bound lease, executes the pinned grid
against the reference target adapter over the NDJSON channel (the same channel
as `run local`), uploads the raw transcript and evidence as
content-addressed blobs, and calls worker.complete. The worker never learns
case oracle metadata — suite knowledge stays inside the service's release
registry.

The OSS reference worker always runs the bundled `evalseal.simtarget` adapter;
production adapters are deployment infrastructure behind `adapter_hash`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from .canon import canonical_hash, canonicalize, parse, JsonError, blob_hash
from .errors import ApiError
from .mock import RECORDER_HASH
from .runner import run_trial, ChannelError
from .schema import check_case


def _req(origin: str, path: str, token: str, method="GET", body=None, extra=None):
    headers = {"Authorization": "Bearer " + token}
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else canonicalize(body)
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
    headers.update(extra or {})
    req = urllib.request.Request(origin.rstrip("/") + path, data=data,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except urllib.error.URLError:
        raise ApiError("UNAVAILABLE") from None


def _command(origin: str, token: str, op: str, args: dict, idem: str) -> dict:
    status, data, _ = _req(
        origin, "/v1/commands", token, "POST",
        {"op": op, "args": args},
        {"Idempotency-Key": idem})
    try:
        obj = parse(data)
    except JsonError:
        raise ApiError("UNAVAILABLE") from None
    if status != 200:
        raise ApiError(obj["error"]["code"])
    return obj


def _fetch_release(origin: str, token: str, release_hash: str):
    status, data, _ = _req(origin, "/v1/releases/" + release_hash, token)
    if status != 200:
        raise ApiError("RELEASE_UNAVAILABLE")
    return parse(data)


def _fetch_case(origin: str, token: str, release_hash: str, case_id: str) -> dict:
    status, data, _ = _req(origin,
                           "/v1/releases/" + release_hash + "/cases/" + case_id,
                           token)
    if status != 200:
        raise ApiError("RELEASE_UNAVAILABLE")
    return parse(data)


def _upload_blob(origin: str, token: str, run_id: str, data: bytes,
                 lease_id: str, epoch: int) -> str:
    digest = blob_hash(data)
    status, body, _ = _req(
        origin, "/v1/runs/" + run_id + "/blobs/" + digest, token, "PUT", data,
        {"X-Lease-ID": lease_id, "X-Lease-Epoch": str(epoch),
         "Content-Type": "application/octet-stream"})
    if status != 200:
        try:
            code = parse(body)["error"]["code"]
        except Exception:
            code = "UNAVAILABLE"
        raise ApiError(code)
    return digest


def execute_claim(origin: str, token: str, cfg: dict, claim: dict) -> str:
    """Run one claimed lease to evidence submission. Returns outcome string."""
    run_id, lease_id = claim["run_id"], claim["lease_id"]
    epoch = claim["epoch"]
    worker_id = claim["worker_id"]
    release_hash = claim["release_hash"]
    release = _fetch_release(origin, token, release_hash)
    case_ids = [c["case_id"] for s in release["body"]["suites"] for c in s["cases"]]
    cases = [_fetch_case(origin, token, release_hash, cid) for cid in sorted(case_ids)]
    for c in cases:
        check_case(c)

    adapter = [sys.executable, "-m", "evalseal.simtarget"]
    target_hash = canonical_hash(claim["target"])
    trials: list = []
    transcript: list = []
    started = int(time.time())
    incomplete = None
    last_hb = time.monotonic()
    for case in cases:
        for repeat in (0, 1, 2):
            if time.monotonic() - last_hb > cfg.get("heartbeat_seconds", 30):
                hb = _command(origin, token, "worker.heartbeat",
                              {"run_id": run_id, "lease_id": lease_id,
                               "lease_epoch": epoch},
                              "hb:" + lease_id + ":" + str(epoch))
                epoch = hb["data"]["epoch"]
                last_hb = time.monotonic()
            env = dict(os.environ)
            env["EVALSEAL_SIMULATION"] = "1" if cfg.get("profile") == "simulation" else "0"
            proc = subprocess.Popen(adapter, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env)
            try:
                trials.append(run_trial(proc, case, repeat, target_hash, transcript))
            except ChannelError:
                incomplete = "TARGET_DRIFT"
                break
            finally:
                try:
                    proc.kill()
                except Exception:
                    pass
        if incomplete:
            break

    raw = b"".join(canonicalize(r) + b"\n" for r in transcript)
    if incomplete:
        _command(origin, token, "worker.fail",
                 {"run_id": run_id, "lease_id": lease_id, "lease_epoch": epoch,
                  "reason": incomplete}, "fail:" + lease_id)
        return incomplete

    evidence = {
        "schema": "evalseal-evidence/1", "run_id": run_id, "lease_id": lease_id,
        "lease_epoch": epoch, "worker_id": worker_id,
        "release_hash": release_hash, "target_hash": target_hash,
        "trials": trials,
        "raw_transcript": {"hash": blob_hash(raw), "bytes": len(raw),
                           "media_type": "application/octet-stream"},
        "recorder_hash": RECORDER_HASH,
        "started_at": started, "finished_at": int(time.time()),
    }
    _upload_blob(origin, token, run_id, raw, lease_id, epoch)
    ev_hash = _upload_blob(origin, token, run_id, canonicalize(evidence), lease_id, epoch)
    _command(origin, token, "worker.complete",
             {"run_id": run_id, "lease_id": lease_id, "lease_epoch": epoch,
              "evidence_hash": ev_hash}, "complete:" + lease_id)
    return "COMPLETED"


def serve(cfg: dict, once: bool = False, offline: bool = False) -> int:
    """Poll for work; returns a process exit code."""
    if offline:
        sys.stderr.write("--offline: worker serve requires network\n")
        return 2
    origin = cfg["origin"].rstrip("/")
    token = os.environ.get(cfg["identity_env"])
    if token is None:
        sys.stderr.write("environment variable " + cfg["identity_env"] + " is not set\n")
        return 2
    heartbeat = cfg.get("heartbeat_seconds", 30)
    while True:
        try:
            claim = _command(origin, token, "worker.claim", {"capacity": 1},
                             "poll:" + str(int(time.time() * 1000)))
        except ApiError as e:
            if e.code == "UNAUTHORIZED":
                sys.stderr.write("worker auth rejected\n")
                return 3
            sys.stderr.write("poll failed: " + e.code + "\n")
            if once:
                return 6
            time.sleep(min(heartbeat, 30))
            continue
        data = claim.get("data")
        if data is None:
            if once:
                return 0
            time.sleep(min(heartbeat, 30))
            continue
        try:
            outcome = execute_claim(origin, token, cfg, data)
        except ApiError as e:
            if e.code == "LEASE_FENCED":
                outcome = "LEASE_FENCED"
            else:
                sys.stderr.write("run " + data["run_id"] + " failed: " + e.code + "\n")
                if once:
                    return 6
                time.sleep(min(heartbeat, 30))
                continue
        sys.stderr.write("run " + data["run_id"] + ": " + outcome + "\n")
        if once:
            return 0 if outcome == "COMPLETED" else 6
