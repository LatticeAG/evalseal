"""Development reference server (spec §8.1 `evalseal serve`).

Serves the evalseal/1 HTTP surface from an in-memory Service over stdlib
http.server — for local smoke, conformance development, and demos. This is
not the hosted deployment (see hosted.py).

Provisioning file (evalseal-devservice/1):

    {
      "schema": "evalseal-devservice/1",
      "issuer_seed_hex": "<32-byte hex>",         // dev-only private seed
      "issuer_key_id": "es_key_...",
      "keyring": Signed<Keyring>,                 // optional
      "principals": [{"token": str, "principal_id": str,
                      "tenant_id": "es_tnt_...", "role": str}],
      "workers": [{"token": str, "entry": WorkerRegistry-entry}],
      "targets": [{"tenant_id": "es_tnt_...", "target_ref": str,
                   "target": Target}],
      "releases": [{"signed": Signed<Release>, "cases": [Case],
                    "sources": {"path": "<base64>"}}]
    }
"""

from __future__ import annotations

import base64
import hashlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .canon import domain_hash
from .errors import ApiError
from .service import Service
from .sign import private_key_from_seed, sign_envelope


def build_service(prov: dict | None) -> Service:
    if prov is None:
        prov = {}
    seed_hex = prov.get("issuer_seed_hex")
    if seed_hex:
        seed = bytes.fromhex(seed_hex)
        sk = private_key_from_seed(seed)
        key_id = prov["issuer_key_id"]

        def sign_for(kind, body):
            return sign_envelope(kind, key_id, body, sk)

        svc = Service(issuer_sign=lambda kind, key_id, body: sign_envelope(kind, key_id, body, sk),
                      issuer_key_id=key_id)
    else:
        svc = Service()
    if prov.get("keyring"):
        svc.install_keyring(prov["keyring"], prov.get("issuer_key_id"))
    for p in prov.get("principals", []):
        principal = {"principal_id": p["principal_id"], "tenant_id": p["tenant_id"],
                     "role": p["role"]}
        svc.install_principal(p["token"], principal)
    for w in prov.get("workers", []):
        svc.install_worker(w["entry"], w["token"])
    for t in prov.get("targets", []):
        svc.install_target(t["tenant_id"], t)
    for r in prov.get("releases", []):
        sources = {p: base64.b64decode(b) for p, b in r.get("sources", {}).items()}
        svc.install_release(r["signed"], r["cases"], sources)
    return svc


class _Handler(BaseHTTPRequestHandler):
    service: Service = None
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _handle(self, method: str):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 512 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        r = self.service.handle(method, self.path, headers, body)
        self.send_response(r.status)
        for k, v in r.headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(r.body)))
        self.end_headers()
        if r.body:
            self.wfile.write(r.body)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")


def serve_forever(host: str, port: int, prov: dict | None) -> None:
    svc = build_service(prov)
    _Handler.service = svc
    httpd = ThreadingHTTPServer((host, port), _Handler)
    bound_host, bound_port = httpd.server_address[:2]
    sys.stderr.write(f"evalseal reference service on http://{bound_host}:{bound_port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
