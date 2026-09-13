"""API error values (spec §7.1)."""

from __future__ import annotations


class ApiError(Exception):
    """Closed protocol error: HTTP status + spec code + fixed public message."""

    MESSAGES = {
        "BAD_JSON": "Malformed JSON body",
        "BAD_SCHEMA": "Request failed schema validation",
        "UNAUTHORIZED": "Authentication required",
        "FORBIDDEN": "Insufficient role for this operation",
        "NOT_FOUND": "Resource not found",
        "STATE_CONFLICT": "Operation not applicable to current state",
        "REVISION_CONFLICT": "Resource revision changed",
        "IDEMPOTENCY_CONFLICT": "Idempotency key reused with a different body",
        "LEASE_FENCED": "Lease is fenced, stale, or expired",
        "TARGET_DRIFT": "Target no longer matches the admitted manifest",
        "RELEASE_UNAVAILABLE": "Release is withdrawn or unreadable",
        "EVIDENCE_INVALID": "Evidence failed validation",
        "HASH_MISMATCH": "Content hash mismatch",
        "LIMIT_EXCEEDED": "Limit exceeded",
        "RATE_LIMITED": "Rate limited",
        "CURSOR_EXPIRED": "Cursor expired",
        "BAD_REFERENCE": "Invalid reference",
        "UNAVAILABLE": "Dependency unavailable",
    }

    STATUS = {
        "BAD_JSON": 400, "BAD_SCHEMA": 400, "UNAUTHORIZED": 401, "FORBIDDEN": 403,
        "NOT_FOUND": 404, "STATE_CONFLICT": 409, "REVISION_CONFLICT": 409,
        "IDEMPOTENCY_CONFLICT": 409, "LEASE_FENCED": 409, "CURSOR_EXPIRED": 409,
        "TARGET_DRIFT": 422, "RELEASE_UNAVAILABLE": 422, "EVIDENCE_INVALID": 422,
        "HASH_MISMATCH": 422, "BAD_REFERENCE": 422, "LIMIT_EXCEEDED": 413,
        "RATE_LIMITED": 429, "UNAVAILABLE": 503,
    }

    RETRYABLE = {"RATE_LIMITED", "UNAVAILABLE", "LIMIT_EXCEEDED"}

    def __init__(self, code: str, retry_after: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = self.STATUS[code]
        self.retryable = code in self.RETRYABLE
        self.retry_after = retry_after

    def body(self) -> dict:
        return {"error": {"code": self.code, "message": self.MESSAGES[self.code], "retryable": self.retryable}}
