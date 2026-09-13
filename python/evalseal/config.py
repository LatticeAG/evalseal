"""Client/worker/trust configuration loading (spec §8.2).

Closed JSON configs. Merge order: user defaults (~/.config/devin/evalseal.json)
→ project file (default .devin/evalseal.json) → explicit flags. Project config
cannot replace pinned user trust roots. Unknown fields and secret-looking
literal fields are fatal.
"""

from __future__ import annotations

import json
import os

from .canon import JsonError, parse
from .schema import SchemaError, check_client_config, check_trust_file

USER_CONFIG = os.path.expanduser("~/.config/devin/evalseal.json")
PROJECT_CONFIG = ".devin/evalseal.json"

SECRET_KEYS = ("token", "password", "private_key")
CLIENT_KEYS = {"schema", "origin", "token_env", "trust_file", "cache_dir", "timeout_ms", "profile"}


class ConfigError(Exception):
    pass


def _load_json_file(path: str):
    try:
        with open(path, "rb") as f:
            return parse(f.read())
    except FileNotFoundError:
        return None
    except JsonError as e:
        raise ConfigError(f"{path}: {e.code}") from None


def _check_secret_fields(obj, where: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in SECRET_KEYS:
                raise ConfigError(f"{where}: secret-looking field {k!r} is not permitted")
            _check_secret_fields(v, where)
    elif isinstance(obj, list):
        for v in obj:
            _check_secret_fields(v, where)


def load_client_config(config_path: str | None, flags: dict) -> dict:
    """Merged, validated client configuration."""
    merged: dict = {"schema": "evalseal-client-config/1",
                    "origin": "https://evalseal.test",
                    "token_env": "EVALSEAL_TOKEN",
                    "trust_file": "trust.json",
                    "cache_dir": "cache/evalseal",
                    "timeout_ms": 30000,
                    "profile": "simulation"}
    for path in (USER_CONFIG, config_path or PROJECT_CONFIG):
        data = _load_json_file(path)
        if data is None:
            continue
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: config must be an object")
        for k in data:
            if k not in CLIENT_KEYS:
                raise ConfigError(f"{path}: unknown field {k!r}")
        _check_secret_fields(data, path)
        # project config cannot replace a trust file pinned at user level
        if path == USER_CONFIG and "trust_file" in data:
            merged["__user_trust"] = data["trust_file"]
        if path != USER_CONFIG and "trust_file" in data and merged.get("__user_trust"):
            data = dict(data)
            data["trust_file"] = merged["__user_trust"]
        merged.update(data)
    merged.pop("__user_trust", None)
    for k, v in flags.items():
        if v is not None:
            merged[k] = v
    try:
        check_client_config(merged)
    except SchemaError as e:
        raise ConfigError(f"client config invalid: {e.where}") from None
    return merged


def load_trust(path: str) -> dict:
    data = _load_json_file(path)
    if data is None:
        raise ConfigError(f"{path}: not found")
    try:
        check_trust_file(data)
    except SchemaError as e:
        raise ConfigError(f"{path}: invalid trust file ({e.where})") from None
    return data
