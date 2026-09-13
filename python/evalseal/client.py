"""Public client functions (spec §7.5).

`command` invokes only the enumerated command endpoint. Tokens come from a
named environment variable, never a literal argument.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

from .canon import canonicalize, parse, JsonError
from .errors import ApiError


async def command(origin: str, request: dict, options: dict) -> dict:
    """POST {origin}/v1/commands with bearer auth + idempotency key."""
    return await asyncio.to_thread(_command_sync, origin, request, options)


def _command_sync(origin: str, request: dict, options: dict) -> dict:
    token_env = options["token_env"]
    token = os.environ.get(token_env)
    if token is None:
        raise ApiError("UNAUTHORIZED")
    body = canonicalize(request)
    req = urllib.request.Request(
        origin.rstrip("/") + "/v1/commands",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "Idempotency-Key": options["idempotency_key"],
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=options.get("timeout_ms", 30000) / 1000) as r:
            return parse(r.read())
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            err = parse(data)
            code = err["error"]["code"]
            ae = ApiError(code)
            if "retry-after" in (h.lower() for h in e.headers.keys()):
                ae.retry_after = int(e.headers["Retry-After"])
            raise ae from None
        except (JsonError, KeyError, TypeError):
            raise ApiError("UNAVAILABLE") from None
    except urllib.error.URLError:
        raise ApiError("UNAVAILABLE") from None


async def get_json(origin: str, path: str, token: str | None, timeout_ms: int = 30000) -> dict:
    return await asyncio.to_thread(_get, origin, path, token, timeout_ms, True)


def _get(origin: str, path: str, token: str | None, timeout_ms: int, as_json: bool):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(origin.rstrip("/") + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as r:
            data = r.read()
            return parse(data) if as_json else data
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            err = parse(data)
            ae = ApiError(err["error"]["code"])
            ra = e.headers.get("Retry-After")
            if ra is not None:
                ae.retry_after = int(ra)
            raise ae from None
        except (JsonError, KeyError, TypeError):
            raise ApiError("UNAVAILABLE") from None
    except urllib.error.URLError:
        raise ApiError("UNAVAILABLE") from None


def get_bytes(origin: str, path: str, token: str | None, timeout_ms: int = 30000) -> bytes:
    return _get(origin, path, token, timeout_ms, False)
