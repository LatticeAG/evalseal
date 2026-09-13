"""evalseal CLI (spec §8). Same contract as `python -m evalseal` and the
`evalseal` TypeScript bin. Global flags may precede the command; `--`
terminates flag parsing; unknown commands/flags or repeated scalar flags
exit 2.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import signal
import sys
import time

from .canon import JsonError, canonical_hash, canonicalize, is_hash, parse
from .errors import ApiError
from . import config as configmod
from . import fixture as _fixture_unused  # noqa: F401  (re-exported for tests)

VERSION = "1.0.0-draft.1"
PROTOCOL = "evalseal/1"

GLOBAL_FLAGS = {
    "--config": "value", "--json": "bool", "--offline": "bool",
    "--timeout-ms": "value", "--help": "bool", "--version": "bool",
}

CMD_SPECS = {
    ("suite", "lock"): {
        "pos": ["SOURCE"],
        "flags": {"--version": "value", "--out": "value", "--source-date-epoch": "value"},
    },
    ("suite", "verify"): {
        "pos": ["LOCK"],
        "flags": {"--source": "value", "--trust": "value"},
    },
    ("suite", "sign"): {
        "pos": ["LOCK"],
        "flags": {"--key-env": "value", "--out": "value"},
    },
    ("release", "index"): {
        "pos": [],
        "flags": {"--active": "value", "--withdrawn": "value",
                  "--key-env": "value", "--out": "value"},
    },
    ("keyring", "issue"): {
        "pos": [],
        "flags": {"--keys": "value", "--epoch": "value", "--valid-seconds": "value",
                  "--key-env": "value", "--out": "value", "--previous-keyring": "value"},
    },
    ("run", "local"): {
        "pos": [],
        "flags": {"--lock": "value", "--target": "value", "--out": "value",
                  "--simulation": "bool", "--adapter": "value"},
    },
    ("run", "submit"): {
        "pos": [],
        "flags": {"--product": "value", "--release": "value", "--track": "value",
                  "--board": "value", "--prior-certificate": "value",
                  "--idempotency-key": "value"},
    },
    ("run", "status"): {
        "pos": ["ID"],
        "flags": {"--wait": "bool", "--poll-seconds": "value"},
    },
    ("run", "cancel"): {
        "pos": ["ID"],
        "flags": {"--revision": "value", "--idempotency-key": "value"},
    },
    ("product", "create"): {
        "pos": [],
        "flags": {"--label": "value", "--target-ref": "value", "--idempotency-key": "value"},
    },
    ("board", "create"): {
        "pos": [],
        "flags": {"--label": "value", "--idempotency-key": "value"},
    },
    ("certificate", "get"): {
        "pos": ["ID"],
        "flags": {"--status": "bool"},
    },
    ("certificate", "revoke"): {
        "pos": ["ID"],
        "flags": {"--revision": "value", "--reason": "value", "--idempotency-key": "value"},
    },
    ("pack", "download"): {
        "pos": ["ID"],
        "flags": {"--out": "value", "--format": "value", "--replace": "bool"},
    },
    ("pack", "verify"): {
        "pos": ["PATH"],
        "flags": {"--trust": "value", "--status-file": "value", "--keyring-file": "value",
                  "--now": "value"},
    },
    ("leaderboard",): {
        "pos": [],
        "flags": {"--release": "value", "--board": "value", "--limit": "value",
                  "--cursor": "value"},
    },
    ("audit", "verify"): {
        "pos": ["PATH"],
        "flags": {"--checkpoint": "value", "--trust": "value", "--keyring-file": "value"},
    },
    ("worker", "serve"): {
        "pos": [],
        "flags": {"--worker-config": "value", "--once": "bool"},
    },
    ("serve",): {
        "pos": [],
        "flags": {"--bind": "value", "--provision": "value"},
    },
}

NETWORK_COMMANDS = {
    ("run", "submit"), ("run", "status"), ("run", "cancel"),
    ("product", "create"), ("board", "create"),
    ("certificate", "get"), ("certificate", "revoke"),
    ("pack", "download"), ("leaderboard",), ("worker", "serve"),
}


class UsageError(Exception):
    pass


def _usage() -> str:
    lines = ["evalseal " + VERSION + " — protocol evalseal/1", "",
             "usage: evalseal [--config PATH] [--json] [--offline] [--timeout-ms N] <command>", ""]
    for cmd in sorted(CMD_SPECS):
        spec = CMD_SPECS[cmd]
        pos = " ".join("<" + p + ">" for p in spec["pos"])
        lines.append("  " + " ".join(cmd) + (" " + pos if pos else ""))
    return "\n".join(lines)


def parse_argv(argv: list):
    """Split argv into (globals, command, command-flags, positionals)."""
    g = {"config": None, "json": False, "offline": False, "timeout_ms": 30000,
         "help": False, "version": False}
    i = 0
    n = len(argv)
    cmd = None
    flags: dict = {}
    pos: list = []
    seen_global: set = set()
    while i < n:
        tok = argv[i]
        if tok == "--":
            pos.extend(argv[i + 1:])
            break
        if cmd is None and tok in GLOBAL_FLAGS:
            kind = GLOBAL_FLAGS[tok]
            if tok in seen_global and kind == "value":
                raise UsageError("repeated flag " + tok)
            seen_global.add(tok)
            if kind == "bool":
                g[tok[2:].replace("-", "_")] = True
                i += 1
            else:
                if i + 1 >= n:
                    raise UsageError("missing value for " + tok)
                g[tok[2:].replace("-", "_")] = argv[i + 1]
                i += 2
            continue
        if cmd is None:
            # command word(s)
            word = tok
            if (word,) in CMD_SPECS:
                cmd = (word,)
                i += 1
                continue
            if i + 1 < n and (word, argv[i + 1]) in CMD_SPECS:
                cmd = (word, argv[i + 1])
                i += 2
                continue
            raise UsageError("unknown command " + word)
        spec = CMD_SPECS[cmd]
        if tok.startswith("--"):
            if tok not in spec["flags"]:
                if tok in GLOBAL_FLAGS:
                    kind = GLOBAL_FLAGS[tok]
                    if kind == "bool":
                        g[tok[2:].replace("-", "_")] = True
                        i += 1
                        continue
                    if i + 1 >= n:
                        raise UsageError("missing value for " + tok)
                    g[tok[2:].replace("-", "_")] = argv[i + 1]
                    i += 2
                    continue
                raise UsageError("unknown flag " + tok)
            kind = spec["flags"][tok]
            if tok in flags:
                raise UsageError("repeated flag " + tok)
            if kind == "bool":
                flags[tok] = True
                i += 1
            else:
                if i + 1 >= n:
                    raise UsageError("missing value for " + tok)
                flags[tok] = argv[i + 1]
                i += 2
            continue
        pos.append(tok)
        i += 1
    return g, cmd, flags, pos


def _timeout(g) -> int:
    try:
        t = int(g["timeout_ms"])
    except (TypeError, ValueError):
        raise UsageError("--timeout-ms must be an integer")
    if not (1 <= t <= 300000):
        raise UsageError("--timeout-ms out of range 1..300000")
    return t


def _seed_from_env(name: str) -> bytes:
    raw = os.environ.get(name)
    if raw is None:
        raise UsageError("environment variable " + name + " is not set")
    raw = raw.strip()
    for dec in (bytes.fromhex,):
        try:
            b = dec(raw)
            if len(b) == 32:
                return b
        except ValueError:
            pass
    try:
        from .sign import b64u_decode
        b = b64u_decode(raw)
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise UsageError("environment variable " + name + " does not contain a 32-byte seed")


def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _read_json(path: str):
    try:
        return parse(_read_file(path))
    except FileNotFoundError:
        raise UsageError("file not found: " + path)
    except JsonError as e:
        raise UsageError(f"{path}: {e.code}")


def _write_atomic(path: str, data: bytes, replace: bool = False) -> None:
    if os.path.exists(path) and not replace:
        raise UsageError("refusing to overwrite existing file: " + path + " (use --replace)")
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _emit(g, obj) -> None:
    if g["json"]:
        sys.stdout.buffer.write(canonicalize(obj) + b"\n")
    else:
        sys.stdout.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def _exit_for(err: ApiError) -> int:
    return {
        "UNAUTHORIZED": 3, "FORBIDDEN": 3,
        "REVISION_CONFLICT": 7, "IDEMPOTENCY_CONFLICT": 7,
        "STATE_CONFLICT": 7, "LEASE_FENCED": 7, "CURSOR_EXPIRED": 7,
        "RATE_LIMITED": 6, "LIMIT_EXCEEDED": 6, "UNAVAILABLE": 6,
        "RELEASE_UNAVAILABLE": 6,
        "HASH_MISMATCH": 5, "EVIDENCE_INVALID": 5, "TARGET_DRIFT": 5,
    }.get(err.code, 2)


# ---------------------------------------------------------------------------
# command handlers


def cmd_suite_lock(g, flags, pos):
    from .importer import lock_source
    sde = 0
    if "--source-date-epoch" in flags:
        sde = int(flags["--source-date-epoch"])
    lock = lock_source(pos[0], flags["--version"], sde)
    out = flags["--out"]
    _write_atomic(out, canonicalize(lock))
    return {"lock_hash": canonical_hash(lock["release"]),
            "case_count": len(lock["cases"]), "trial_count": 360,
            "official": False}, 0


def cmd_suite_verify(g, flags, pos):
    from .importer import verify_lock
    lock = _read_json(pos[0])
    count = verify_lock(lock, flags.get("--source"))
    # if the lock carries a signed release, verify against trust roots
    trust = load_trust_required(flags)
    env = lock["release"]
    if isinstance(env, dict) and env.get("schema") == "evalseal-signed/1":
        from .sign import find_key, verify_envelope
        key = find_key(trust["roots"], env.get("key_id", ""))
        if key is None or "release" not in key["roles"] \
                or verify_envelope(env, "release", key) != "VALID":
            raise ApiError("HASH_MISMATCH")
    return {"valid": True, "cases": count}, 0


def cmd_suite_sign(g, flags, pos):
    from .sign import private_key_from_seed, public_key_bytes, b64u, sign_envelope, key_id_for_public_key, is_test_key
    cfg = load_cfg(g)
    lock = _read_json(pos[0])
    seed = _seed_from_env(flags["--key-env"])
    from .sign import RFC8032_TEST_SEED_HEX
    sk = private_key_from_seed(seed)
    pk = b64u(public_key_bytes(sk))
    if is_test_key(pk) and cfg["profile"] != "simulation":
        raise UsageError("refusing public test key outside simulation profile")
    key_id = key_id_for_public_key(pk)
    env = sign_envelope("release", key_id, lock["release"], sk)
    _write_atomic(flags["--out"], canonicalize(env))
    return {"signed": True, "key_id": key_id,
            "release_hash": canonical_hash(env), "official": False}, 0


def cmd_release_index(g, flags, pos):
    from .sign import private_key_from_seed, public_key_bytes, b64u, sign_envelope, key_id_for_public_key, is_test_key
    cfg = load_cfg(g)
    active = flags.get("--active", "")
    withdrawn = flags.get("--withdrawn", "")
    act = [h for h in active.split(",") if h]
    wd = [h for h in withdrawn.split(",") if h]
    if any(not is_hash(h) for h in act + wd):
        raise UsageError("release index entries must be sha256 digests")
    body = {"schema": "evalseal-release-index/1",
            "active": sorted(set(act)), "withdrawn": sorted(set(wd))}
    if set(body["active"]) & set(body["withdrawn"]):
        raise UsageError("active and withdrawn must be disjoint")
    from .schema import check_release_index_body
    check_release_index_body(body)
    seed = _seed_from_env(flags["--key-env"])
    sk = private_key_from_seed(seed)
    pk = b64u(public_key_bytes(sk))
    if is_test_key(pk) and cfg["profile"] != "simulation":
        raise UsageError("refusing public test key outside simulation profile")
    key_id = key_id_for_public_key(pk)
    env = sign_envelope("release-index", key_id, body, sk)
    _write_atomic(flags["--out"], canonicalize(env))
    return {"signed": True, "key_id": key_id,
            "index_hash": canonical_hash(env)}, 0


def cmd_keyring_issue(g, flags, pos):
    from .sign import private_key_from_seed, public_key_bytes, b64u, sign_envelope, key_id_for_public_key, is_test_key
    from .schema import check_key, check_keyring_body
    cfg = load_cfg(g)
    keys_doc = _read_json(flags["--keys"])
    keys = keys_doc.get("keys") if isinstance(keys_doc, dict) else None
    if not isinstance(keys, list) or not keys:
        raise UsageError("--keys file must be {keys: Key[]}")
    for k in keys:
        check_key(k)
        if is_test_key(k["public_key"]) and cfg["profile"] != "simulation":
            raise UsageError("refusing public test key outside simulation profile")
    epoch = int(flags["--epoch"])
    valid = int(flags["--valid-seconds"])
    if not (0 < valid <= 86400):
        raise UsageError("--valid-seconds must be 1..86400")
    prev_hash = None
    if "--previous-keyring" in flags:
        prev = _read_json(flags["--previous-keyring"])
        prev_hash = canonical_hash(prev)
    seed = _seed_from_env(flags["--key-env"])
    sk = private_key_from_seed(seed)
    pk = b64u(public_key_bytes(sk))
    if is_test_key(pk) and cfg["profile"] != "simulation":
        raise UsageError("refusing public test key outside simulation profile")
    key_id = key_id_for_public_key(pk)
    issued = int(time.time())
    body = {"schema": "evalseal-keyring/1", "epoch": epoch, "issued_at": issued,
            "valid_until": issued + valid, "keys": keys, "previous_hash": prev_hash}
    check_keyring_body(body)
    env = sign_envelope("keyring", key_id, body, sk)
    _write_atomic(flags["--out"], canonicalize(env))
    return {"signed": True, "key_id": key_id, "epoch": epoch,
            "keyring_hash": canonical_hash(env)}, 0


def cmd_run_local(g, flags, pos):
    from .runner import run_local
    from .schema import check_target, SchemaError as SE
    lock = _read_json(flags["--lock"])
    target = _read_json(flags["--target"])
    sim = bool(flags.get("--simulation"))
    adapter = shlex.split(flags["--adapter"]) if flags.get("--adapter") else None
    if adapter is None and not sim:
        raise UsageError("run local requires --simulation or --adapter CMD")
    out = run_local(lock["release"], target, lock["cases"], flags["--out"],
                    adapter, sim)
    if out["incomplete_reason"]:
        return {"official": False, "incomplete": out["incomplete_reason"]}, 6
    band = out["result"]["grade"]["band"]
    code = 0 if band in ("A", "B", "C") else 4
    if sim:
        sys.stderr.write("simulation profile — not an official certification\n")
    return {"official": False, "result": out["result"]}, code


def cmd_product_create(g, flags, pos):
    cfg = load_cfg(g)
    req = {"op": "product.create",
           "args": {"label": flags["--label"], "target_ref": flags["--target-ref"]}}
    return _call(cfg, req, flags["--idempotency-key"], g)


def cmd_board_create(g, flags, pos):
    cfg = load_cfg(g)
    req = {"op": "board.create", "args": {"label": flags["--label"]}}
    return _call(cfg, req, flags["--idempotency-key"], g)


def cmd_run_submit(g, flags, pos):
    cfg = load_cfg(g)
    track = flags["--track"]
    if track == "private" and "--board" not in flags:
        raise UsageError("--board is required for --track private")
    args = {"product_id": flags["--product"], "release_hash": flags["--release"],
            "track": track, "board_id": flags.get("--board"),
            "prior_certificate_id": flags.get("--prior-certificate")}
    req = {"op": "run.create", "args": args}
    if track == "public":
        sys.stderr.write(
            "warning: public admission is irrevocably public; failed, incomplete, "
            "and cancelled attempts remain discoverable\n")
    return _call(cfg, req, flags["--idempotency-key"], g)


def cmd_run_status(g, flags, pos):
    cfg = load_cfg(g)
    token = _token(cfg)
    wait = flags.get("--wait", False)
    poll = int(flags.get("--poll-seconds", 5))
    if not (5 <= poll <= 60):
        raise UsageError("--poll-seconds must be 5..60")
    deadline = time.monotonic() + g["timeout_ms"] / 1000

    async def go():
        while True:
            run = await _get_json(cfg, "/v1/runs/" + pos[0], token)
            if not flags.get("--wait"):
                return run
            if run["state"] in ("COMPLETED", "INCOMPLETE", "CANCELLED"):
                return run
            if time.monotonic() >= deadline:
                raise ApiError("UNAVAILABLE")
            await asyncio.sleep(poll)

    run = asyncio.run(go())
    if run["state"] == "INCOMPLETE":
        return run, 6
    return run, 0


def cmd_run_cancel(g, flags, pos):
    cfg = load_cfg(g)
    req = {"op": "run.cancel",
           "args": {"run_id": pos[0], "expected_revision": int(flags["--revision"]),
                    "reason": "OWNER_CANCELLED"}}
    return _call(cfg, req, flags["--idempotency-key"], g)


def cmd_certificate_get(g, flags, pos):
    cfg = load_cfg(g)
    token = _token(cfg)
    path = "/v1/certificates/" + pos[0] + ("/status" if flags.get("--status") else "")
    return asyncio.run(_get_json(cfg, path, token)), 0


def cmd_certificate_revoke(g, flags, pos):
    cfg = load_cfg(g)
    req = {"op": "certificate.revoke",
           "args": {"certificate_id": pos[0],
                    "expected_revision": int(flags["--revision"]),
                    "reason": flags["--reason"]}}
    return _call(cfg, req, flags["--idempotency-key"], g)


def cmd_pack_download(g, flags, pos):
    cfg = load_cfg(g)
    token = _token(cfg)
    fmt = flags.get("--format", "zip")
    if fmt not in ("zip", "pdf"):
        raise UsageError("--format must be zip or pdf")
    data = _get_bytes(cfg, "/v1/certificates/" + pos[0] + "/pack?format=" + fmt, token)
    out = flags["--out"]
    _write_atomic(out, data, bool(flags.get("--replace")))
    from .canon import blob_hash
    return {"path": out, "bytes": len(data), "hash": blob_hash(data)}, 0


def cmd_pack_verify(g, flags, pos):
    from .pack import verify_pack
    path = pos[0]
    if path.lower().endswith(".pdf"):
        raise UsageError("pack verify accepts the ZIP pack only")
    data = _read_file(path)
    trust = load_trust_required(flags)
    status = _read_json(flags["--status-file"]) if flags.get("--status-file") else None
    keyring = _read_json(flags["--keyring-file"]) if flags.get("--keyring-file") else None
    now = int(flags["--now"]) if flags.get("--now") else None
    if now is None:
        if g["offline"]:
            raise UsageError("--offline requires --now for pack verify")
        now = int(time.time())
    keyring_observed = None
    if keyring is not None and not g["offline"]:
        keyring_observed = int(time.time())
    v = verify_pack(data, {
        "root_keys": trust["roots"], "now": now, "status": status,
        "keyring": keyring,
        "min_keyring_epoch": trust["minimum_keyring_epoch"],
        "keyring_observed_at": keyring_observed,
    })
    code = {"QUALIFIES": 0, "NOT_QUALIFIED": 4, "UNKNOWN": 8}[v["current"]]
    if v["integrity"] != "VALID":
        code = 5
    return v, code


def cmd_leaderboard(g, flags, pos):
    cfg = load_cfg(g)
    token = _token(cfg)
    if "--board" in flags:
        q = "?limit=" + flags.get("--limit", "25")
        if flags.get("--release"):
            q += "&release=" + flags["--release"]
        if flags.get("--cursor"):
            q += "&cursor=" + flags["--cursor"]
        page = asyncio.run(_get_json(cfg, "/v1/boards/" + flags["--board"] + q, token))
    else:
        rel = flags.get("--release")
        if not rel:
            raise UsageError("--release is required")
        q = "?release=" + rel + "&limit=" + flags.get("--limit", "25")
        if flags.get("--cursor"):
            q += "&cursor=" + flags["--cursor"]
        page = asyncio.run(_get_json(cfg, "/v1/leaderboard" + q, None))
    if not g["json"]:
        _print_table(page)
        return None, 0
    return page, 0


def _print_table(page):
    print(f"snapshot {page['snapshot_at']}  lag {page['index_lag_seconds']}s")
    for r in page["items"]:
        print(f"{r['label']:<24} {r['state']:<10} {r['band'] or '-':<2} "
              f"{r['status']:<8} {'qualifies' if r['qualifies'] else ''}")
    if page["next_cursor"]:
        print("next: " + page["next_cursor"])


def cmd_audit_verify(g, flags, pos):
    from .audit import verify_against_checkpoint, verify_chain
    from .sign import find_key, verify_envelope
    trust = load_trust_required(flags)
    data = _read_file(pos[0])
    # input is a pack audit.jsonl or a saved AuditPage JSON
    entries = None
    cp = None
    if flags.get("--checkpoint"):
        cp = _read_json(flags["--checkpoint"])
    stripped = data.strip()
    if stripped.startswith(b"{"):
        doc = parse(stripped)
        entries = doc.get("entries")
        cp = cp or doc.get("checkpoint")
    else:
        lines = [ln for ln in data.split(b"\n") if ln.strip()]
        try:
            entries = [parse(ln) for ln in lines]
        except JsonError:
            raise UsageError("audit input must be audit.jsonl or an AuditPage JSON")
    if entries is None:
        raise UsageError("audit input must be audit.jsonl or an AuditPage JSON")
    if cp is None:
        raise UsageError("audit verify requires a checkpoint (--checkpoint or embedded)")
    key = find_key(trust["roots"], cp.get("key_id", ""))
    # checkpoints are issuer-signed: resolve via supplied keyring if not a root
    if key is None and flags.get("--keyring-file"):
        kr = _read_json(flags["--keyring-file"])
        key = find_key(kr["body"]["keys"], cp.get("key_id", ""))
    if key is None or verify_envelope(cp, "checkpoint", key) != "VALID":
        raise ApiError("HASH_MISMATCH")
    r = verify_against_checkpoint(entries, cp)
    if r != "VALID":
        return {"valid": False, "code": r}, 5
    return {"valid": True, "entries": len(entries), "head": entries[-1]["hash"]}, 0


def cmd_worker_serve(g, flags, pos):
    from .worker import serve
    cfg = _read_json(flags["--worker-config"])
    from .schema import check_worker_config
    try:
        check_worker_config(cfg)
    except Exception as e:
        raise UsageError("invalid worker config: " + str(e))
    code = serve(cfg, once=bool(flags.get("--once")), offline=g["offline"])
    return None, code


def cmd_serve(g, flags, pos):
    from .devserver import serve_forever
    bind = flags.get("--bind", "127.0.0.1:8000")
    prov = _read_json(flags["--provision"]) if flags.get("--provision") else None
    host, port_s = bind.rsplit(":", 1)
    serve_forever(host, int(port_s), prov)
    return None, 0


# ---------------------------------------------------------------------------
# helpers


def load_cfg(g) -> dict:
    return configmod.load_client_config(g["config"], {})


def load_trust_required(flags) -> dict:
    if not flags.get("--trust"):
        raise UsageError("--trust ROOTS is required")
    return configmod.load_trust(flags["--trust"])


def _token(cfg) -> str:
    tok = os.environ.get(cfg["token_env"])
    if tok is None:
        raise UsageError("environment variable " + cfg["token_env"] + " is not set")
    return tok


def _call(cfg, request, idem_key, g):
    from .client import command
    reply = asyncio.run(command(cfg["origin"], request, {
        "token_env": cfg["token_env"], "idempotency-key": idem_key,
        "idempotency_key": idem_key, "timeout_ms": g["timeout_ms"]}))
    return reply, 0


async def _get_json(cfg, path, token):
    from .client import get_json
    return await get_json(cfg["origin"], path, token, cfg["timeout_ms"])


def _get_bytes(cfg, path, token):
    from .client import get_bytes
    return get_bytes(cfg["origin"], path, token, cfg["timeout_ms"])


HANDLERS = {
    ("suite", "lock"): cmd_suite_lock,
    ("suite", "verify"): cmd_suite_verify,
    ("suite", "sign"): cmd_suite_sign,
    ("release", "index"): cmd_release_index,
    ("keyring", "issue"): cmd_keyring_issue,
    ("run", "local"): cmd_run_local,
    ("run", "submit"): cmd_run_submit,
    ("run", "status"): cmd_run_status,
    ("run", "cancel"): cmd_run_cancel,
    ("product", "create"): cmd_product_create,
    ("board", "create"): cmd_board_create,
    ("certificate", "get"): cmd_certificate_get,
    ("certificate", "revoke"): cmd_certificate_revoke,
    ("pack", "download"): cmd_pack_download,
    ("pack", "verify"): cmd_pack_verify,
    ("leaderboard",): cmd_leaderboard,
    ("audit", "verify"): cmd_audit_verify,
    ("worker", "serve"): cmd_worker_serve,
    ("serve",): cmd_serve,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        g, cmd, flags, pos = parse_argv(argv)
    except UsageError as e:
        sys.stderr.write("usage error: " + str(e) + "\n")
        return 2
    if g["help"]:
        sys.stdout.write(_usage() + "\n")
        return 0
    if g["version"]:
        sys.stdout.write(VERSION + "\n")
        return 0
    if cmd is None:
        sys.stderr.write(_usage() + "\n")
        return 2
    try:
        _timeout(g)
    except UsageError as e:
        sys.stderr.write("usage error: " + str(e) + "\n")
        return 2
    if g["offline"] and cmd in NETWORK_COMMANDS:
        sys.stderr.write("--offline: " + " ".join(cmd) + " requires network\n")
        return 2
    spec = CMD_SPECS[cmd]
    if len(pos) != len(spec["pos"]):
        sys.stderr.write("usage error: expected " + str(len(spec["pos"])) +
                         " positional arguments\n")
        return 2
    missing = [f for f, k in spec["flags"].items()
               if k == "value" and f in _REQUIRED.get(cmd, ()) and f not in flags]
    if missing:
        sys.stderr.write("usage error: missing required flags " + " ".join(missing) + "\n")
        return 2
    try:
        result, code = HANDLERS[cmd](g, flags, pos)
        if result is not None:
            _emit(g, result)
        return code
    except ApiError as e:
        sys.stderr.write("error " + e.code + ": " + e.MESSAGES[e.code] + "\n")
        if e.retry_after is not None:
            sys.stderr.write("retry-after: " + str(e.retry_after) + "\n")
        return _exit_for(e)
    except UsageError as e:
        sys.stderr.write("usage error: " + str(e) + "\n")
        return 2
    except KeyboardInterrupt:
        return 130


_REQUIRED = {
    ("suite", "lock"): ("--version", "--out"),
    ("suite", "verify"): ("--trust",),
    ("suite", "sign"): ("--key-env", "--out"),
    ("release", "index"): ("--key-env", "--out"),
    ("keyring", "issue"): ("--keys", "--epoch", "--valid-seconds", "--key-env", "--out"),
    ("run", "local"): ("--lock", "--target", "--out"),
    ("run", "submit"): ("--product", "--release", "--track", "--idempotency-key"),
    ("run", "cancel"): ("--revision", "--idempotency-key"),
    ("product", "create"): ("--label", "--target-ref", "--idempotency-key"),
    ("board", "create"): ("--label", "--idempotency-key"),
    ("certificate", "revoke"): ("--revision", "--reason", "--idempotency-key"),
    ("pack", "download"): ("--out",),
    ("pack", "verify"): ("--trust",),
    ("audit", "verify"): ("--trust",),
    ("worker", "serve"): ("--worker-config",),
}


if __name__ == "__main__":
    raise SystemExit(main())
