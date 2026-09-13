/** API error values (spec §7.1). */

export class ApiError extends Error {
  static MESSAGES: Record<string, string> = {
    BAD_JSON: "Malformed JSON body",
    BAD_SCHEMA: "Request failed schema validation",
    UNAUTHORIZED: "Authentication required",
    FORBIDDEN: "Insufficient role for this operation",
    NOT_FOUND: "Resource not found",
    STATE_CONFLICT: "Operation not applicable to current state",
    REVISION_CONFLICT: "Resource revision changed",
    IDEMPOTENCY_CONFLICT: "Idempotency key reused with a different body",
    LEASE_FENCED: "Lease is fenced, stale, or expired",
    TARGET_DRIFT: "Target no longer matches the admitted manifest",
    RELEASE_UNAVAILABLE: "Release is withdrawn or unreadable",
    EVIDENCE_INVALID: "Evidence failed validation",
    HASH_MISMATCH: "Content hash mismatch",
    LIMIT_EXCEEDED: "Limit exceeded",
    RATE_LIMITED: "Rate limited",
    CURSOR_EXPIRED: "Cursor expired",
    BAD_REFERENCE: "Invalid reference",
    UNAVAILABLE: "Dependency unavailable",
  };
  static STATUS: Record<string, number> = {
    BAD_JSON: 400, BAD_SCHEMA: 400, UNAUTHORIZED: 401, FORBIDDEN: 403,
    NOT_FOUND: 404, STATE_CONFLICT: 409, REVISION_CONFLICT: 409,
    IDEMPOTENCY_CONFLICT: 409, LEASE_FENCED: 409, CURSOR_EXPIRED: 409,
    TARGET_DRIFT: 422, RELEASE_UNAVAILABLE: 422, EVIDENCE_INVALID: 422,
    HASH_MISMATCH: 422, BAD_REFERENCE: 422, LIMIT_EXCEEDED: 413,
    RATE_LIMITED: 429, UNAVAILABLE: 503,
  };
  static RETRYABLE = new Set(["RATE_LIMITED", "UNAVAILABLE", "LIMIT_EXCEEDED"]);

  code: string;
  status: number;
  retryable: boolean;
  retryAfter: number | null;

  constructor(code: string, retryAfter: number | null = null) {
    super(code);
    this.code = code;
    this.status = ApiError.STATUS[code] ?? 400;
    this.retryable = ApiError.RETRYABLE.has(code);
    this.retryAfter = retryAfter;
  }

  body() {
    return { error: { code: this.code, message: ApiError.MESSAGES[this.code], retryable: this.retryable } };
  }
}
