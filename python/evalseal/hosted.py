"""Hosted/paid surfaces — documented stub interfaces (spec §2.1).

The OSS core ships every client-side and verification mechanism. The paid
surface — hosted certification runs on Cloudflare Workers + Durable Objects,
private R2 evidence buckets, the isolated IssuerSigner service binding, and
private boards — is deployment infrastructure, not library code. These stubs
deliberately raise NotImplementedError rather than pretend to run server-side
primitives locally.

Reference: https://github.com/LatticeAG/evalseal/blob/main/docs/phase0-scope-identity.md#oss--hosted-split-spec-11-21
"""

from __future__ import annotations

_LINK = ("Hosted surface — runs on the deployed LatticeAG Workers/DO service. "
         "See docs/phase0-scope-identity.md (OSS/hosted split) and spec §2.1. "
         "https://github.com/LatticeAG/evalseal")


class HostedUnavailable(NotImplementedError):
    def __init__(self, what: str):
        super().__init__(f"{what}: {_LINK}")
        self.what = what


class DurableObjectNamespace:
    """Cloudflare Durable Object namespace binding placeholder."""

    def __init__(self, binding: str):
        self.binding = binding

    def get(self, _id):  # pragma: no cover - stub
        raise HostedUnavailable(f"DurableObjectNamespace({self.binding}).get")


class R2Bucket:
    """Private R2 evidence/public-artifact bucket placeholder."""

    def __init__(self, binding: str):
        self.binding = binding

    def put(self, *_a, **_kw):  # pragma: no cover - stub
        raise HostedUnavailable(f"R2Bucket({self.binding}).put")

    def get(self, *_a, **_kw):  # pragma: no cover - stub
        raise HostedUnavailable(f"R2Bucket({self.binding}).get")


class IssuerSignerBinding:
    """Isolated signer service binding (spec §7.6).

    The local equivalent used by the OSS reference service is
    `authority.LocalSigner`; production signing happens inside an isolated
    signer Durable Object reachable only through the authority's service
    binding.
    """

    def sign(self, *_a, **_kw):  # pragma: no cover - stub
        raise HostedUnavailable("IssuerSignerBinding.sign")


def hosted_worker_fetch(*_a, **_kw):  # pragma: no cover - stub
    """Cloudflare Worker fetch handler entry — deployment-only."""
    raise HostedUnavailable("worker.fetch")
