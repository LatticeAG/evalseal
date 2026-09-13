"""evalseal/1 canonical wire rules (spec §3.1, §3.4).

Strict JSON parsing (duplicate-key rejection, scalar domain checks, parser
limits) plus RFC 8785 canonical serialization and the protocol hash domains:

    J(x)      RFC 8785 UTF-8 bytes
    B(b)      "sha256:" + hex(SHA-256(b))
    H(x)      B(J(x))
    D(kind,x) B(UTF8("evalseal/1/" + kind + "\n") || J(x))
"""

from __future__ import annotations

import hashlib
import unicodedata

# Parser limits (spec §3.1): JSON requests are limited to 256 KiB, depth 24,
# 512 object members, and 4096 array elements.
MAX_JSON_BYTES = 256 * 1024
MAX_DEPTH = 24
MAX_MEMBERS = 512
MAX_ELEMENTS = 4096
MAX_SAFE_INTEGER = 9007199254740991

ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class JsonError(Exception):
    """Wire parse/validation failure carrying a spec error code."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def _err(code: str, message: str) -> JsonError:
    return JsonError(code, message)


def canonicalize(value) -> bytes:
    """RFC 8785 canonical JSON bytes for a value in the protocol scalar domain.

    Numbers are non-negative integers 0..2^53-1; booleans are not numbers;
    strings are emitted as UTF-8 with the RFC 8785 escape set; object members
    sort by UTF-16 code units.
    """
    out = bytearray()
    _emit(value, out)
    return bytes(out)


def _emit_string(s: str, out: bytearray) -> None:
    out.append(0x22)
    for ch in s:
        o = ord(ch)
        esc = ESCAPES.get(o)
        if esc is not None:
            out.extend(esc.encode("ascii"))
        elif o < 0x20:
            out.extend(("\\u%04x" % o).encode("ascii"))
        else:
            out.extend(ch.encode("utf-8"))
    out.append(0x22)


def _emit(value, out: bytearray) -> None:
    if value is None:
        out.extend(b"null")
    elif value is True:
        out.extend(b"true")
    elif value is False:
        out.extend(b"false")
    elif isinstance(value, int):
        if value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError("integer outside 0..2^53-1")
        out.extend(str(value).encode("ascii"))
    elif isinstance(value, str):
        _emit_string(value, out)
    elif isinstance(value, list):
        out.append(0x5B)
        for i, item in enumerate(value):
            if i:
                out.append(0x2C)
            _emit(item, out)
        out.append(0x5D)
    elif isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_key)
        out.append(0x7B)
        for i, k in enumerate(keys):
            if i:
                out.append(0x2C)
            _emit_string(k, out)
            out.append(0x3A)
            _emit(value[k], out)
        out.append(0x7D)
    else:
        raise ValueError(f"value of type {type(value).__name__} is outside the protocol scalar domain")


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def parse(data: bytes):
    """Strict JSON parse per spec §3.1.

    Returns the decoded value. Raises JsonError("BAD_JSON") on syntax,
    encoding, duplicate-key, or parser-limit failures and
    JsonError("BAD_SCHEMA") on scalar-domain failures (fractions, -0,
    negatives, integers > 2^53-1).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _err("BAD_JSON", "body is not bytes")
    data = bytes(data)
    if len(data) > MAX_JSON_BYTES:
        raise _err("BAD_JSON", "request exceeds 256 KiB")
    if data.startswith(b"\xef\xbb\xbf"):
        raise _err("BAD_JSON", "byte-order mark is not permitted")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise _err("BAD_JSON", "invalid UTF-8") from None
    p = _Parser(text)
    value = p.value()
    p.ws()
    if p.pos != len(text):
        raise _err("BAD_JSON", "trailing content")
    return value


class _Parser:
    __slots__ = ("s", "pos")

    def __init__(self, s: str):
        self.s = s
        self.pos = 0

    def ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.pos < n and s[self.pos] in " \t\n\r":
            self.pos += 1

    def value(self, depth: int = 0):
        self.ws()
        if self.pos >= len(self.s):
            raise _err("BAD_JSON", "unexpected end of input")
        if depth >= MAX_DEPTH:
            raise _err("BAD_JSON", "depth limit exceeded")
        ch = self.s[self.pos]
        if ch == "{":
            return self.obj(depth)
        if ch == "[":
            return self.arr(depth)
        if ch == '"':
            return self.string()
        if ch == "t" and self.s.startswith("true", self.pos):
            self.pos += 4
            return True
        if ch == "f" and self.s.startswith("false", self.pos):
            self.pos += 5
            return False
        if ch == "n" and self.s.startswith("null", self.pos):
            self.pos += 4
            return None
        if ch == "-" or ch.isdigit():
            return self.number()
        raise _err("BAD_JSON", "unexpected character")

    def number(self):
        s = self.s
        start = self.pos
        if s[self.pos] == "-":
            self.pos += 1
            if self.pos >= len(s) or not s[self.pos].isdigit():
                raise _err("BAD_JSON", "malformed number")
        # integer part
        if s[self.pos] == "0":
            self.pos += 1
            if self.pos < len(s) and s[self.pos].isdigit():
                raise _err("BAD_JSON", "leading zero")
        elif s[self.pos].isdigit():
            while self.pos < len(s) and s[self.pos].isdigit():
                self.pos += 1
        frac = False
        if self.pos < len(s) and s[self.pos] == ".":
            frac = True
            self.pos += 1
            if self.pos >= len(s) or not s[self.pos].isdigit():
                raise _err("BAD_JSON", "malformed fraction")
            while self.pos < len(s) and s[self.pos].isdigit():
                self.pos += 1
        if self.pos < len(s) and s[self.pos] in "eE":
            frac = True
            self.pos += 1
            if self.pos < len(s) and s[self.pos] in "+-":
                self.pos += 1
            if self.pos >= len(s) or not s[self.pos].isdigit():
                raise _err("BAD_JSON", "malformed exponent")
            while self.pos < len(s) and s[self.pos].isdigit():
                self.pos += 1
        token = s[start : self.pos]
        if frac or token.startswith("-"):
            # fractional numbers, negative zero, and negatives are outside the
            # scalar domain (spec §3.1).
            raise _err("BAD_SCHEMA", "number outside protocol scalar domain")
        value = int(token)
        if value > MAX_SAFE_INTEGER:
            raise _err("BAD_SCHEMA", "integer exceeds 2^53-1")
        return value

    def string(self) -> str:
        s = self.s
        assert s[self.pos] == '"'
        self.pos += 1
        parts: list[str] = []
        while True:
            if self.pos >= len(s):
                raise _err("BAD_JSON", "unterminated string")
            ch = s[self.pos]
            if ch == '"':
                self.pos += 1
                return "".join(parts)
            o = ord(ch)
            if o < 0x20:
                raise _err("BAD_JSON", "unescaped control character")
            if ch == "\\":
                self.pos += 1
                if self.pos >= len(s):
                    raise _err("BAD_JSON", "unterminated escape")
                e = s[self.pos]
                self.pos += 1
                if e in '"\\/':
                    parts.append(e)
                elif e == "b":
                    parts.append("\b")
                elif e == "f":
                    parts.append("\f")
                elif e == "n":
                    parts.append("\n")
                elif e == "r":
                    parts.append("\r")
                elif e == "t":
                    parts.append("\t")
                elif e == "u":
                    parts.append(self.u_escape())
                else:
                    raise _err("BAD_JSON", "invalid escape")
            else:
                parts.append(ch)
                self.pos += 1

    def u_escape(self) -> str:
        s = self.s
        if self.pos + 4 > len(s):
            raise _err("BAD_JSON", "truncated \\u escape")
        try:
            cp = int(s[self.pos : self.pos + 4], 16)
        except ValueError:
            raise _err("BAD_JSON", "invalid \\u escape") from None
        self.pos += 4
        if 0xD800 <= cp <= 0xDBFF:
            # high surrogate must be followed by \uDC00-\uDFFF
            if s[self.pos : self.pos + 2] == "\\u":
                try:
                    lo = int(s[self.pos + 2 : self.pos + 6], 16)
                except (ValueError, IndexError):
                    lo = -1
                if 0xDC00 <= lo <= 0xDFFF:
                    self.pos += 6
                    return chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
            raise _err("BAD_JSON", "lone surrogate")
        if 0xDC00 <= cp <= 0xDFFF:
            raise _err("BAD_JSON", "lone surrogate")
        return chr(cp)

    def obj(self, depth: int):
        self.pos += 1
        out: dict = {}
        self.ws()
        if self.pos < len(self.s) and self.s[self.pos] == "}":
            self.pos += 1
            return out
        while True:
            self.ws()
            if self.pos >= len(self.s) or self.s[self.pos] != '"':
                raise _err("BAD_JSON", "object key must be a string")
            key = self.string()
            self.ws()
            if self.pos >= len(self.s) or self.s[self.pos] != ":":
                raise _err("BAD_JSON", "missing ':'")
            self.pos += 1
            if key in out:
                raise _err("BAD_JSON", "duplicate object member")
            out[key] = self.value(depth + 1)
            if len(out) > MAX_MEMBERS:
                raise _err("BAD_JSON", "member limit exceeded")
            self.ws()
            if self.pos >= len(self.s):
                raise _err("BAD_JSON", "unterminated object")
            if self.s[self.pos] == ",":
                self.pos += 1
                continue
            if self.s[self.pos] == "}":
                self.pos += 1
                return out
            raise _err("BAD_JSON", "expected ',' or '}'")

    def arr(self, depth: int):
        self.pos += 1
        out: list = []
        self.ws()
        if self.pos < len(self.s) and self.s[self.pos] == "]":
            self.pos += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            if len(out) > MAX_ELEMENTS:
                raise _err("BAD_JSON", "array element limit exceeded")
            self.ws()
            if self.pos >= len(self.s):
                raise _err("BAD_JSON", "unterminated array")
            if self.s[self.pos] == ",":
                self.pos += 1
                continue
            if self.s[self.pos] == "]":
                self.pos += 1
                return out
            raise _err("BAD_JSON", "expected ',' or ']'")


# ---------------------------------------------------------------------------
# Protocol hash domains (spec §3.4)

SHA256_PREFIX = "sha256:"
HASH_LEN = 7 + 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_hash(data: bytes) -> str:
    """B(bytes) — raw blob identity."""
    return SHA256_PREFIX + sha256_hex(data)


def canonical_hash(value) -> str:
    """H(x) — content identity of a canonicalizable value."""
    return blob_hash(canonicalize(value))


def domain_hash(kind: str, body) -> str:
    """D(kind, x) — signed-body identity (also used for audit entries)."""
    return blob_hash(b"evalseal/1/" + kind.encode("ascii") + b"\n" + canonicalize(body))


def signature_message(kind: str, key_id: str, body_hash: str) -> bytes:
    return ("evalseal/1/signature\n" + kind + "\n" + key_id + "\n" + body_hash).encode("utf-8")


def is_hash(s) -> bool:
    return (
        isinstance(s, str)
        and len(s) == HASH_LEN
        and s.startswith(SHA256_PREFIX)
        and all(c in "0123456789abcdef" for c in s[7:])
    )


def is_label(s) -> bool:
    """Human label: NFC, 1..80 scalars, no control/bidi-format/newline/invisible."""
    if not isinstance(s, str) or not (1 <= len(s) <= 80):
        return False
    if unicodedata.normalize("NFC", s) != s:
        return False
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Zl", "Zp", "Cs"):
            return False
    return True


def is_version(s) -> bool:
    if not isinstance(s, str):
        return False
    parts = s.split(".")
    if len(parts) != 3:
        return False
    for p in parts:
        if not p or (len(p) > 1 and p[0] == "0") or not p.isdigit():
            return False
    return True
