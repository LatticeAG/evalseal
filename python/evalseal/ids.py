"""evalseal/1 identifier generation and validation (spec §3.1).

IDs use nanoid's URL-safe 64-character alphabet, 21 random characters from a
CSPRNG, preceded by a permanently locked type prefix:

    ^(es_tnt|es_prd|es_run|es_brd|es_crt|es_lse|es_evt|es_wrk|es_key|es_req)_[A-Za-z0-9_-]{21}$
"""

from __future__ import annotations

import re
import secrets

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
ID_RE = re.compile(r"^(es_tnt|es_prd|es_run|es_brd|es_crt|es_lse|es_evt|es_wrk|es_key|es_req)_[A-Za-z0-9_-]{21}$")

PREFIXES = ("tnt", "prd", "run", "brd", "crt", "lse", "evt", "wrk", "key", "req")


def new_id(prefix: str) -> str:
    if prefix not in PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}")
    # 21 chars, each uniform over 64 entries: 21*6=126 bits; 16 bytes = 128 bits.
    chars = []
    while len(chars) < 21:
        for b in secrets.token_bytes(16):
            chars.append(ALPHABET[b & 63])
            if len(chars) == 21:
                break
    return "es_" + prefix + "_" + "".join(chars)


def is_id(value, prefix: str | None = None) -> bool:
    if not isinstance(value, str) or not ID_RE.match(value):
        return False
    if prefix is not None:
        return value.startswith("es_" + prefix + "_")
    return True


def id_prefix(value: str) -> str | None:
    m = ID_RE.match(value) if isinstance(value, str) else None
    return m.group(1)[3:] if m else None
