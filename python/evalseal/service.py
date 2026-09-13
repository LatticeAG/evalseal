"""Local reference service (spec §2.1, §6, §7).

Implements the evalseal/1 HTTP surface over per-tenant Authority instances:
POST /v1/commands, every enumerated read endpoint, and the bounded blob
upload endpoint. This is the OSS reference implementation used by the CLI,
the conformance suite, and `evalseal serve`; the hosted deployment runs the
same contracts on Cloudflare Workers + Durable Objects (see hosted.py).
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json as jsonlib
import time
import urllib.parse

from .canon import JsonError, canonical_hash, canonicalize, parse
from .errors import ApiError
from .ids import new_id
from .schema import check_command, SchemaError
from .authority import Authority, LocalSigner, cohort_key, canonical_blob_hash
from .render import (
    render_badge, render_badge_unavailable, render_badge_unknown,
    render_leaderboard, render_page,
)

MAX_BODY = 256 * 1024
PAGE_DEFAULT = 25
PAGE_MAX = 100
AUDIT_DEFAULT = 100
SNAPSHOT_TTL = 300


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, body: bytes, headers: dict | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}


def _json(status: int, obj, headers=None) -> Response:
    h = {"Content-Type": "application/json", "Cache-Control": "no-store"}
    h.update(headers or {})
    return Response(status, canonicalize(obj), h)


def _err(e: ApiError) -> Response:
    h = {}
    if e.retry_after is not None:
        h["Retry-After"] = str(e.retry_after)
    return _json(e.status, e.body(), h)


def casefold_label(label: str) -> str:
    """Pinned case-fold for leaderboard ordering (Unicode full case folding)."""
    return label.casefold()


class Service:
    def __init__(self, now_fn=None, issuer_sign=None, issuer_key_id: str | None = None):
        self.now_fn = now_fn or (lambda: int(time.time()))
        self.issuer_key_id = issuer_key_id
        self.sign_for = issuer_sign            # (kind, key_id, body) -> envelope
        self.signer = LocalSigner(issuer_sign) if issuer_sign else None
        self.authorities: dict[str, Authority] = {}
        self.releases: dict[str, dict] = {}            # hash -> Signed<Release>
        self._release_cases: dict[str, list] = {}      # hash -> [Case]
        self.release_sources: dict[str, dict] = {}     # hash -> {path: bytes}
        self.release_index = {"active": [], "withdrawn": []}
        self.keyring: dict | None = None               # Signed<Keyring>
        self.principals: dict[str, dict] = {}          # token_sha256 -> principal
        self.worker_tokens: dict[str, str] = {}        # token_sha256 -> worker_id
        self.workers: dict[str, dict] = {}             # worker_id -> registry entry
        self.targets: dict[str, dict] = {}             # tenant_id -> {ref: entry}
        self.public_artifacts: dict[str, dict] = {}    # cert_id -> {pack, pdf}
        self.index_rows: dict[tuple, dict] = {}        # (cohort, run_id) -> row
        self.index_projected_at = 0
        self.cursor_secret = hashlib.sha256(b"evalseal-local-cursor").digest()
        self.log: list[dict] = []
        self._snapshots: dict[str, dict] = {}

    def now(self) -> int:
        return self.now_fn()

    # -- registry provisioning -------------------------------------------------

    def authority(self, tenant_id: str) -> Authority:
        a = self.authorities.get(tenant_id)
        if a is None:
            a = Authority(self, tenant_id)
            self.authorities[tenant_id] = a
        return a

    def install_release(self, signed_release: dict, cases: list, sources: dict) -> None:
        h = canonical_hash(signed_release)
        self.releases[h] = signed_release
        self._release_cases[h] = cases
        self.release_sources[h] = sources
        if h not in self.release_index["active"] and h not in self.release_index["withdrawn"]:
            self.release_index["active"].append(h)
            self.release_index["active"].sort()

    def withdraw_release(self, release_hash: str) -> None:
        idx = self.release_index
        if release_hash in idx["active"]:
            idx["active"].remove(release_hash)
            idx["withdrawn"].append(release_hash)
            idx["withdrawn"].sort()
        # fence in-flight runs on the withdrawn release
        for auth in self.authorities.values():
            for run in list(auth.runs.values()):
                if run["release_hash"] == release_hash and run["state"] in ("ADMITTED", "RUNNING", "VERIFYING"):
                    lease = auth.leases.get(run["run_id"])
                    if lease is not None and lease.state == "held":
                        lease.state = "fenced"
                    auth._transition(run, "INCOMPLETE", "RELEASE_UNAVAILABLE")
            for rec in auth.certificates.values():
                if rec.envelope["body"]["release_hash"] == release_hash and rec.state == "ACTIVE":
                    # root-directed withdrawal revokes affected records (SUITE_WITHDRAWN)
                    rec.state = "REVOKED"
                    rec.reason = "SUITE_WITHDRAWN"
                    rec.revision += 1
                    cb = rec.envelope["body"]
                    auth._append(cb["run_id"], self.now(), "CertificateRevoked",
                                 cb["certificate_id"], rec.revision,
                                 {"request_hash": None, "before": "ACTIVE", "after": "REVOKED",
                                  "object_hash": canonical_hash(rec.envelope),
                                  "reason": "SUITE_WITHDRAWN"})

    def release_active(self, release_hash: str) -> bool:
        return release_hash in self.release_index["active"]

    def install_keyring(self, keyring: dict, issuer_key_id: str | None = None) -> None:
        self.keyring = keyring
        if issuer_key_id:
            self.issuer_key_id = issuer_key_id

    def install_principal(self, token: str, principal: dict) -> None:
        self.principals["sha256:" + hashlib.sha256(token.encode()).hexdigest()] = principal

    def install_worker(self, entry: dict, token: str) -> None:
        self.workers[entry["worker_id"]] = entry
        self.worker_tokens["sha256:" + hashlib.sha256(token.encode()).hexdigest()] = entry["worker_id"]

    def install_target(self, tenant_id: str, entry: dict) -> None:
        self.targets.setdefault(tenant_id, {})[entry["target_ref"]] = entry

    def target_refs(self, tenant_id: str):
        return set(self.targets.get(tenant_id, {}).keys())

    def target_for(self, tenant_id: str, ref: str):
        e = self.targets.get(tenant_id, {}).get(ref)
        return None if e is None else e["target"]

    def worker_registry_entry(self, worker_id: str):
        return self.workers.get(worker_id)

    def release_cases(self, release_hash: str) -> list:
        return self._release_cases.get(release_hash, [])

    # -- auth -----------------------------------------------------------------

    def authenticate(self, authorization: str | None):
        """Resolve a bearer token to a principal or worker identity."""
        if not authorization or not authorization.startswith("Bearer "):
            raise ApiError("UNAUTHORIZED")
        token = authorization[7:]
        if not token:
            raise ApiError("UNAUTHORIZED")
        digest = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
        p = self.principals.get(digest)
        if p is not None:
            return {"worker": False, "principal_id": p["principal_id"],
                    "tenant_id": p["tenant_id"], "role": p["role"]}
        w = self.worker_tokens.get(digest)
        if w is not None:
            return {"worker": True, "worker_id": w,
                    "tenant_id": self.workers[w]["tenant_id"]}
        raise ApiError("UNAUTHORIZED")

    # -- POST /v1/commands ------------------------------------------------------

    def post_commands(self, body: bytes, headers: dict) -> Response:
        req_id = new_id("req")
        base_h = {"X-Request-ID": req_id, "Cache-Control": "no-store"}
        try:
            reply, status = self._dispatch_command(body, headers)
            r = _json(status, reply)
        except ApiError as e:
            r = _err(e)
        r.headers.update(base_h)
        return r

    def _dispatch_command(self, body: bytes, headers: dict):
        if len(body) > MAX_BODY:
            raise ApiError("LIMIT_EXCEEDED", retry_after=0)
        try:
            request = parse(body)
        except JsonError as e:
            raise ApiError(e.code) from None
        principal = self.authenticate(headers.get("authorization"))
        try:
            check_command(request)
        except SchemaError:
            raise ApiError("BAD_SCHEMA") from None
        idem_key = headers.get("idempotency-key")
        if not idem_key:
            raise ApiError("BAD_SCHEMA")
        tenant_id = principal["tenant_id"]
        if tenant_id is None:
            # issuer-operator has no tenant; certificate.revoke resolves the
            # certificate's owning tenant below.
            tenant_id = self._resolve_operator_tenant(request)
            if tenant_id is None:
                raise ApiError("FORBIDDEN")
        auth = self.authority(tenant_id)
        scope = (tenant_id, principal.get("principal_id") or principal.get("worker_id"),
                 request["op"], idem_key)
        request_hash = canonical_hash(request)
        rec = auth.idem.get(scope)
        if rec is not None:
            if rec["request_hash"] != request_hash:
                raise ApiError("IDEMPOTENCY_CONFLICT")
            return rec["response"], rec["http_status"]
        reply, status = auth.command(principal, request, request_hash)
        if status == 200:
            auth.idem[scope] = {"request_hash": request_hash, "http_status": status,
                                "response": reply, "created_at": self.now()}
        return reply, status

    def _resolve_operator_tenant(self, request: dict):
        if request["op"] == "certificate.revoke":
            cid = request["args"].get("certificate_id", "")
            for tid, auth in self.authorities.items():
                if cid in auth.certificates:
                    return tid
        return None

    # -- read + upload endpoints ------------------------------------------------

    def handle(self, method: str, path: str, headers: dict, body: bytes = b"") -> Response:
        req_id = new_id("req")
        try:
            r = self._route(method.upper(), path, headers, body)
        except ApiError as e:
            r = _err(e)
        r.headers.setdefault("X-Request-ID", req_id)
        r.headers.setdefault("Cache-Control", "no-store")
        return r

    def _route(self, method: str, raw_path: str, headers: dict, body: bytes) -> Response:
        parsed = urllib.parse.urlsplit(raw_path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for k, v in query.items():
            if len(v) != 1:
                raise ApiError("BAD_SCHEMA")
        query = {k: v[0] for k, v in query.items()}

        if method == "POST" and path == "/v1/commands":
            return self.post_commands(body, headers)
        if method == "PUT":
            return self._blob_put(path, headers, body)
        if method == "GET":
            return self._get(path, query, headers)
        if method == "POST":
            raise ApiError("NOT_FOUND")
        raise ApiError("NOT_FOUND")

    # -- GETs -------------------------------------------------------------------

    def _get(self, path: str, query: dict, headers: dict) -> Response:
        self._tick_all()
        if path == "/healthz":
            self._no_query(query)
            return _json(200, {"status": "ok", "protocol": "evalseal/1"})
        if path == "/":
            return self._leaderboard_html(query)
        if path == "/v1/keys":
            self._no_query(query)
            if self.keyring is None:
                raise ApiError("NOT_FOUND")
            return _json(200, self.keyring, {"Cache-Control": "public, max-age=60",
                                             "Access-Control-Allow-Origin": "*"})
        if path == "/v1/releases":
            self._no_query(query)
            items = [self.releases[h] for h in self.release_index["active"][:100]]
            return _json(200, {"items": items}, {"Access-Control-Allow-Origin": "*"})
        if path.startswith("/v1/releases/"):
            return self._get_release(path, query)
        if path == "/v1/leaderboard":
            return self._leaderboard(query)
        if path == "/v1/products":
            principal = self.authenticate(headers.get("authorization"))
            return self._list_products(principal, query)
        if path.startswith("/v1/products/"):
            return self._get_product(path, query, headers)
        if path == "/v1/boards":
            principal = self.authenticate(headers.get("authorization"))
            return self._list_boards(principal, query)
        if path.startswith("/v1/boards/"):
            return self._get_board(path, query, headers)
        if path.startswith("/v1/runs/"):
            return self._get_run(path, query, headers)
        if path.startswith("/v1/certificates/"):
            return self._get_certificate(path, query, headers)
        if path.startswith("/certificates/"):
            return self._certificate_page(path, query, headers)
        if path.startswith("/badges/"):
            return self._badge(path, query)
        raise ApiError("NOT_FOUND")

    def _no_query(self, query):
        if query:
            raise ApiError("BAD_SCHEMA")

    def _paging(self, query, allowed, default=PAGE_DEFAULT):
        self._check_keys(query, allowed)
        limit = default
        if "limit" in query:
            try:
                limit = int(query["limit"])
            except ValueError:
                raise ApiError("BAD_SCHEMA") from None
            if not (1 <= limit <= PAGE_MAX):
                raise ApiError("BAD_SCHEMA")
        return limit, query.get("cursor")

    def _check_keys(self, query, allowed):
        for k in query:
            if k not in allowed:
                raise ApiError("BAD_SCHEMA")

    def _tenant(self, principal) -> str:
        if principal.get("worker") or principal["tenant_id"] is None:
            raise ApiError("FORBIDDEN")
        return principal["tenant_id"]

    def _visible_auth(self, auth: Authority, run: dict, headers) -> None:
        """Private resources require the owning tenant; missing == invisible."""
        if run["track"] == "public":
            return
        principal = self.authenticate(headers.get("authorization"))
        if self._tenant(principal) != auth.tenant_id:
            raise ApiError("NOT_FOUND")

    # releases

    def _get_release(self, path: str, query: dict) -> Response:
        rest = path[len("/v1/releases/"):]
        parts = rest.split("/")
        h = urllib.parse.unquote(parts[0])
        rel = self.releases.get(h)
        if len(parts) == 1:
            self._no_query(query)
            if rel is None:
                raise ApiError("NOT_FOUND")
            return _json(200, rel, {"Access-Control-Allow-Origin": "*",
                                    "Cache-Control": "public, max-age=31536000, immutable"})
        if rel is None:
            raise ApiError("NOT_FOUND")
        if len(parts) == 3 and parts[1] == "cases":
            self._no_query(query)
            cid = parts[2]
            want = None
            for s in rel["body"]["suites"]:
                for c in s["cases"]:
                    if c["case_id"] == cid:
                        want = c["case_hash"]
            if want is None:
                raise ApiError("NOT_FOUND")
            for c in self._release_cases.get(h, []):
                if c["case_id"] == cid and canonical_hash(c) == want:
                    return _json(200, c, {"Access-Control-Allow-Origin": "*",
                                          "Cache-Control": "public, max-age=31536000, immutable"})
            raise ApiError("NOT_FOUND")
        if len(parts) == 3 and parts[1] == "source":
            self._no_query(query)
            spath = parts[2]
            src = self.release_sources.get(h, {}).get(spath)
            if src is None:
                raise ApiError("NOT_FOUND")
            return Response(200, src, {"Content-Type": "application/octet-stream",
                                       "Access-Control-Allow-Origin": "*",
                                       "Cache-Control": "public, max-age=31536000, immutable"})
        raise ApiError("NOT_FOUND")

    # products

    def _list_products(self, principal, query) -> Response:
        tid = self._tenant(principal)
        limit, cursor = self._paging(query, ("limit", "cursor"))
        auth = self.authority(tid)
        items = sorted(auth.products.values(), key=lambda p: (-p["created_at"], p["product_id"]))
        page, nxt = self._page(items, limit, cursor, "products")
        return _json(200, {"items": page, "next_cursor": nxt})

    def _get_product(self, path: str, query: dict, headers) -> Response:
        parts = path.split("/")
        pid = urllib.parse.unquote(parts[3])
        principal = None
        try:
            principal = self.authenticate(headers.get("authorization"))
        except ApiError:
            principal = None
        found = None
        found_auth = None
        for tid, auth in self.authorities.items():
            if pid in auth.products:
                found, found_auth = auth.products[pid], auth
                break
        if len(parts) == 4:
            if found is None or principal is None or self._tenant(principal) != found_auth.tenant_id:
                raise ApiError("NOT_FOUND")
            self._no_query(query)
            return _json(200, found)
        if len(parts) == 5 and parts[4] == "runs":
            if found is None:
                raise ApiError("NOT_FOUND")
            limit, cursor = self._paging(query, ("limit", "cursor"))
            if principal is not None and not principal.get("worker") \
                    and principal["tenant_id"] == found_auth.tenant_id:
                runs = [r for r in found_auth.runs.values() if r["product_id"] == pid]
            else:
                runs = [r for r in found_auth.runs.values()
                        if r["product_id"] == pid and r["track"] == "public"]
            items = sorted(runs, key=lambda r: (-r["admitted_at"], r["run_id"]))
            page, nxt = self._page(items, limit, cursor, "runs")
            return _json(200, {"items": page, "next_cursor": nxt})
        raise ApiError("NOT_FOUND")

    # boards

    def _list_boards(self, principal, query) -> Response:
        tid = self._tenant(principal)
        limit, cursor = self._paging(query, ("limit", "cursor"))
        auth = self.authority(tid)
        items = sorted(auth.boards.values(), key=lambda b: (-b["created_at"], b["board_id"]))
        page, nxt = self._page(items, limit, cursor, "boards")
        return _json(200, {"items": page, "next_cursor": nxt})

    def _get_board(self, path: str, query: dict, headers) -> Response:
        parts = path.split("/")
        if len(parts) != 4:
            raise ApiError("NOT_FOUND")
        bid = urllib.parse.unquote(parts[3])
        principal = self.authenticate(headers.get("authorization"))
        tid = self._tenant(principal)
        auth = self.authority(tid)
        board = auth.boards.get(bid)
        if board is None:
            raise ApiError("NOT_FOUND")
        limit, cursor = self._paging(query, ("release", "limit", "cursor"))
        release_hash = query.get("release") or self._default_release()
        # private board page: authority-served rows for runs on this board
        runs = [r for r in auth.runs.values()
                if r["board_id"] == bid and r["release_hash"] == release_hash]
        rows = [self._row_for(auth, r) for r in
                sorted(runs, key=lambda r: (-r["admitted_at"], r["run_id"]))]
        page, nxt = self._page(rows, limit, cursor, "board:" + bid)
        return _json(200, {"snapshot_at": self.now(), "index_lag_seconds": 0,
                           "items": page, "next_cursor": nxt})

    # runs

    def _get_run(self, path: str, query: dict, headers) -> Response:
        parts = path.split("/")
        rid = urllib.parse.unquote(parts[3])
        auth, run = self._find_run(rid)
        if len(parts) == 4:
            if run is None:
                raise ApiError("NOT_FOUND")
            self._no_query(query)
            self._visible_auth(auth, run, headers)
            return _json(200, self._run_view(run))
        if len(parts) == 5 and parts[4] == "audit":
            if run is None:
                raise ApiError("NOT_FOUND")
            self._visible_auth(auth, run, headers)
            self._check_keys(query, ("after", "limit"))
            after = 0
            if "after" in query:
                try:
                    after = int(query["after"])
                except ValueError:
                    raise ApiError("BAD_SCHEMA") from None
                if after < 0:
                    raise ApiError("BAD_SCHEMA")
            limit = AUDIT_DEFAULT
            if "limit" in query:
                try:
                    limit = int(query["limit"])
                except ValueError:
                    raise ApiError("BAD_SCHEMA") from None
                if not (1 <= limit <= PAGE_MAX):
                    raise ApiError("BAD_SCHEMA")
            entries = [e for e in auth.audit.get(rid, []) if e["body"]["seq"] > after]
            page = entries[:limit]
            next_after = page[-1]["body"]["seq"] if len(entries) > limit else None
            cp = auth._latest_checkpoint(rid)
            return _json(200, {"entries": page, "checkpoint": cp, "next_after": next_after})
        if len(parts) == 5 and parts[4] == "blobs" or len(parts) == 6 and parts[4] == "blobs":
            return self._blob_get(rid, parts[5] if len(parts) == 6 else "", headers)
        raise ApiError("NOT_FOUND")

    def _find_run(self, rid: str):
        for tid, auth in self.authorities.items():
            if rid in auth.runs:
                return auth, auth.runs[rid]
        return None, None

    def _run_view(self, run: dict) -> dict:
        return {k: v for k, v in run.items() if k != "evidence_hash"}

    # certificates / status / pack / pages / badges

    def _find_cert(self, cid: str):
        for tid, auth in self.authorities.items():
            if cid in auth.certificates:
                return auth, auth.certificates[cid]
        return None, None

    def _cert_visible(self, auth, rec, headers) -> None:
        if rec.envelope["body"]["track"] == "private":
            principal = self.authenticate(headers.get("authorization"))
            if self._tenant(principal) != auth.tenant_id:
                raise ApiError("NOT_FOUND")

    def _get_certificate(self, path: str, query: dict, headers) -> Response:
        rest = path[len("/v1/certificates/"):]
        parts = rest.split("/")
        cid = urllib.parse.unquote(parts[0])
        auth, rec = self._find_cert(cid)
        if len(parts) == 1:
            self._no_query(query)
            if rec is None:
                raise ApiError("NOT_FOUND")
            self._cert_visible(auth, rec, headers)
            status = auth.cert_status(cid, self.now())
            return _json(200, {"certificate": rec.envelope, "revision": rec.revision,
                               "status": status})
        if rec is None:
            raise ApiError("NOT_FOUND")
        if parts[1] == "status" and len(parts) == 2:
            self._no_query(query)
            self._cert_visible(auth, rec, headers)
            status = auth.cert_status(cid, self.now())
            return _json(200, status, {"Cache-Control": "max-age=0, must-revalidate"})
        if parts[1] == "pack" and len(parts) == 2:
            self._check_keys(query, ("format",))
            self._cert_visible(auth, rec, headers)
            fmt = query.get("format", "zip")
            if fmt not in ("zip", "pdf"):
                raise ApiError("BAD_SCHEMA")
            arts = auth.cert_bodies.get(cid)
            if arts is None:
                raise ApiError("NOT_FOUND")
            if fmt == "pdf":
                return Response(200, arts["pdf"], {"Content-Type": "application/pdf",
                                                  "Cache-Control": "public, max-age=31536000, immutable"})
            return Response(200, arts["pack"], {"Content-Type": "application/zip",
                                                "Cache-Control": "public, max-age=31536000, immutable"})
        raise ApiError("NOT_FOUND")

    def _certificate_page(self, path: str, query: dict, headers) -> Response:
        cid = urllib.parse.unquote(path[len("/certificates/"):])
        self._no_query(query)
        auth, rec = self._find_cert(cid)
        if rec is None:
            raise ApiError("NOT_FOUND")
        self._cert_visible(auth, rec, headers)
        status = auth.cert_status(cid, self.now())
        arts = auth.cert_bodies[cid]
        release = self.releases[rec.envelope["body"]["release_hash"]]
        htmlb = render_page(rec.envelope, arts["result"], status, release)
        return Response(200, htmlb, {"Content-Type": "text/html; charset=utf-8",
                                     "Content-Security-Policy": _CSP,
                                     "X-Content-Type-Options": "nosniff",
                                     "Referrer-Policy": "no-referrer"})

    def _badge(self, path: str, query: dict) -> Response:
        if not path.endswith(".svg"):
            raise ApiError("NOT_FOUND")
        self._check_keys(query, ())  # no style/text/width/scope params exist
        cid = urllib.parse.unquote(path[len("/badges/"):-len(".svg")])
        auth, rec = self._find_cert(cid)
        h = {"Content-Type": "image/svg+xml", "Cache-Control": "max-age=0, must-revalidate",
             "Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff",
             "Referrer-Policy": "no-referrer"}
        if rec is None or rec.envelope["body"]["track"] != "public":
            return Response(404, render_badge_unavailable(), h)
        try:
            status = auth.cert_status(cid, self.now())
            sb = status["body"]
            if sb["state"] != "ACTIVE" or self.signer is None:
                badge = render_badge(rec.envelope, status)
            else:
                badge = render_badge(rec.envelope, status)
        except ApiError:
            badge = render_badge_unknown(rec.envelope, self.now())
        return Response(200, badge, h)

    # leaderboard

    def _default_release(self):
        if not self.release_index["active"]:
            raise ApiError("NOT_FOUND")
        return self.release_index["active"][-1]

    def _leaderboard(self, query: dict) -> Response:
        limit, cursor = self._paging(query, ("release", "limit", "cursor"))
        release_hash = query.get("release") or self._default_release()
        page = self._board_page(cohort_key(release_hash), limit, cursor)
        return _json(200, page, {"Access-Control-Allow-Origin": "*"})

    def _leaderboard_html(self, query: dict) -> Response:
        limit, cursor = self._paging(query, ("release", "limit", "cursor"))
        release_hash = query.get("release") or self._default_release()
        rel = self.releases.get(release_hash)
        if rel is None:
            raise ApiError("NOT_FOUND")
        page = self._board_page(cohort_key(release_hash), limit, cursor)
        return Response(200, render_leaderboard(page, rel),
                        {"Content-Type": "text/html; charset=utf-8",
                         "Access-Control-Allow-Origin": "*", "Content-Security-Policy": _CSP,
                         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})

    # -- index projection + board pages -----------------------------------------

    def project_run(self, tenant_id: str, run_id: str) -> None:
        auth = self.authority(tenant_id)
        run = auth.runs.get(run_id)
        if run is None or run["track"] != "public":
            return
        row = self._row_for(auth, run)
        self.index_rows[(cohort_key(run["release_hash"]), run_id)] = row
        self.index_projected_at = self.now()

    def _row_for(self, auth: Authority, run: dict) -> dict:
        product = auth.products.get(run["product_id"], {})
        band = None
        cert_id = run["certificate_id"]
        status = "NONE"
        qualifies = False
        if cert_id is not None and cert_id in auth.certificates:
            rec = auth.certificates[cert_id]
            band = rec.envelope["body"]["band"]
            st = rec.state
            if st == "ACTIVE" and self.now() >= rec.expires_at:
                st = "EXPIRED"
            status = st
            qualifies = st == "ACTIVE" and band in ("A", "B", "C")
        return {"product_id": run["product_id"], "label": product.get("label", ""),
                "run_id": run["run_id"], "state": run["state"], "band": band,
                "qualifies": qualifies, "status": status, "status_at": self.now(),
                "certificate_id": cert_id, "admitted_at": run["admitted_at"],
                "tenant_id": auth.tenant_id}

    @staticmethod
    def _group_rank(row: dict) -> int:
        st, band, q = row["status"], row["band"], row["qualifies"]
        state = row["state"]
        if q and st == "ACTIVE" and band in ("A", "B", "C"):
            return {"A": 0, "B": 1, "C": 2}[band]
        if state == "COMPLETED" and band == "F" and st not in ("EXPIRED", "REVOKED", "UNKNOWN"):
            return 3
        if state == "COMPLETED" or st in ("EXPIRED", "REVOKED", "UNKNOWN"):
            return 4
        if state in ("ADMITTED", "RUNNING", "VERIFYING"):
            return 5
        if state == "INCOMPLETE":
            return 6
        return 7  # CANCELLED

    def _board_page(self, cohort: str, limit: int, cursor: str | None) -> dict:
        now = self.now()
        rows = [r for (ck, _), r in self.index_rows.items() if ck == cohort]
        # primary row = latest admitted attempt per product
        primary = {}
        for r in rows:
            cur = primary.get(r["product_id"])
            if cur is None or (r["admitted_at"], r["run_id"]) > (cur["admitted_at"], cur["run_id"]):
                primary[r["product_id"]] = r
        items = sorted(
            (self._strip_row(r) for r in primary.values()),
            key=lambda r: (self._group_rank(r), casefold_label(r["label"]),
                           r["product_id"], r["run_id"]),
        )
        if cursor is not None:
            snap = self._open_cursor(cursor, cohort)
            offset = snap["offset"]
            items = snap["items"]
        else:
            offset = 0
        page = items[offset : offset + limit]
        nxt = None
        if offset + limit < len(items):
            nxt = self._make_cursor(cohort, items, offset + limit, now)
        return {"snapshot_at": now, "index_lag_seconds": max(0, now - self.index_projected_at),
                "items": page, "next_cursor": nxt}

    @staticmethod
    def _strip_row(r: dict) -> dict:
        return {k: r[k] for k in ("product_id", "label", "run_id", "state", "band",
                                  "qualifies", "status", "status_at", "certificate_id")}

    def _make_cursor(self, cohort: str, items: list, offset: int, now: int) -> str:
        key = canonical_hash({"cohort": cohort, "at": now, "items": [i["run_id"] for i in items]})
        self._snapshots[key] = {"items": items, "at": now}
        payload = canonicalize({"kind": "evalseal-cursor/1", "cohort": cohort,
                                "snapshot": key, "offset": offset, "at": now})
        mac = hmac_mod.new(self.cursor_secret, payload, hashlib.sha256).digest()
        return _b64(payload) + "." + _b64(mac)

    def _open_cursor(self, cursor: str, cohort: str) -> dict:
        try:
            raw_p, raw_m = cursor.split(".")
            payload = _unb64(raw_p)
            mac = _unb64(raw_m)
        except Exception:
            raise ApiError("CURSOR_EXPIRED") from None
        expect = hmac_mod.new(self.cursor_secret, payload, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(mac, expect):
            raise ApiError("CURSOR_EXPIRED")
        try:
            body = parse(payload)
        except JsonError:
            raise ApiError("CURSOR_EXPIRED") from None
        if body.get("kind") != "evalseal-cursor/1" or body.get("cohort") != cohort:
            raise ApiError("CURSOR_EXPIRED")
        snap = self._snapshots.get(body["snapshot"])
        if snap is None or self.now() - snap["at"] > SNAPSHOT_TTL:
            raise ApiError("CURSOR_EXPIRED")
        return {"items": snap["items"], "offset": body["offset"]}

    def _page(self, items: list, limit: int, cursor: str | None, kind: str):
        if cursor is not None:
            snap = self._open_cursor(cursor, kind)
            items, offset = snap["items"], snap["offset"]
        else:
            offset = 0
        page = items[offset : offset + limit]
        nxt = None
        if offset + limit < len(items):
            key = canonical_hash({"kind": kind, "items": len(items)})
            nxt = self._make_cursor(kind, items, offset + limit, self.now())
        return page, nxt

    # -- blobs -----------------------------------------------------------------

    def _blob_put(self, path: str, headers: dict, body: bytes) -> Response:
        parts = path.split("/")
        if len(parts) != 6 or parts[1] != "v1" or parts[2] != "runs" or parts[4] != "blobs":
            raise ApiError("NOT_FOUND")
        rid, digest = urllib.parse.unquote(parts[3]), urllib.parse.unquote(parts[5])
        if "content-length" not in headers or int(headers.get("content-length") or -1) != len(body):
            raise ApiError("LIMIT_EXCEEDED", retry_after=0)
        if len(body) > 448 * 1024 * 1024:
            raise ApiError("LIMIT_EXCEEDED", retry_after=0)
        principal = self.authenticate(headers.get("authorization"))
        if not principal.get("worker"):
            raise ApiError("FORBIDDEN")
        auth, run = self._find_run(rid)
        if run is None:
            raise ApiError("NOT_FOUND")
        lease = auth.leases.get(rid)
        if lease is None or lease.state != "held" or lease.worker_id != principal["worker_id"]:
            raise ApiError("FORBIDDEN" if lease and lease.worker_id != principal["worker_id"] else "LEASE_FENCED")
        if headers.get("x-lease-id") != lease.lease_id or \
                str(headers.get("x-lease-epoch")) != str(lease.epoch):
            raise ApiError("LEASE_FENCED")
        if self.now() >= lease.expires_at:
            auth._fence_and_incomplete(lease, "LEASE_EXPIRED")
            raise ApiError("LEASE_FENCED")
        if run["state"] != "RUNNING":
            raise ApiError("LEASE_FENCED")
        res = auth.put_blob(rid, digest, body)
        return _json(200, res)

    def _blob_get(self, rid: str, digest: str, headers) -> Response:
        auth, run = self._find_run(rid)
        if run is None:
            raise ApiError("NOT_FOUND")
        principal = self.authenticate(headers.get("authorization"))
        ok = False
        if principal.get("worker"):
            lease = auth.leases.get(rid)
            ok = lease is not None and lease.worker_id == principal["worker_id"]
        else:
            ok = principal["tenant_id"] == auth.tenant_id
        if not ok:
            raise ApiError("NOT_FOUND")
        blob = auth.blobs.get((rid, urllib.parse.unquote(digest)))
        if blob is None:
            raise ApiError("NOT_FOUND")
        return Response(200, blob["data"], {"Content-Type": "application/octet-stream"})

    # -- misc -------------------------------------------------------------------

    def _tick_all(self) -> None:
        for auth in self.authorities.values():
            auth.tick()
            auth.process_outbox()

    def publish_public_artifacts(self, cert_id: str, arts: dict) -> None:
        self.public_artifacts[cert_id] = arts


_CSP = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'"
