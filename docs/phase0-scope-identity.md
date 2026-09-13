# Phase 0 — Scope and identity record

Spec: EVALSEAL_SPEC_EXTREME rev 2 (edition 2026-09-12), §15 Phase 0 gate:
"Five dated checks across source/package/project naming namespaces, one
provisional choice, zero unsupported legal/trademark certainty."

## Naming availability checks (2026-09-13, UTC)

Candidates: **EvalSeal, EvalMark, SuiteSeal, GradeLedger, AdversarySeal**.

| Candidate | npm registry | PyPI | github.com/LatticeAG path | GitHub name search |
|---|---|---|---|---|
| evalseal | 404 (free) | 404 (free) | 404 (free) | 1 unrelated personal repo (`jonathanjasare/evalseal`, similar concept space) |
| evalmark | 404 (free) | 404 (free) | 404 (free) | 0 hits |
| suiteseal | 404 (free) | 404 (free) | 404 (free) | 2 unrelated repos |
| gradeledger | 404 (free) | 404 (free) | 404 (free) | 5 unrelated repos (gradebook tools — crowded) |
| adversaryseal | 404 (free) | 404 (free) | 404 (free) | 0 hits |

Method: `GET https://registry.npmjs.org/<name>`,
`GET https://pypi.org/pypi/<name>/json`,
`GET https://github.com/LatticeAG/<name>`,
`GET https://api.github.com/search/repositories?q=<name>+in:name`.
All checks performed 2026-09-13 against live registries; HTTP 404 is read as
"name currently unclaimed in that namespace", nothing more.

## Provisional choice

**EvalSeal** — matches the A-N6 report naming and the protocol string
`evalseal/1`. npm/PyPI/org-path namespaces are unclaimed. One third-party
GitHub repository shares the name in a similar concept space; this record does
not assert trademark availability, legal clearance, or freedom to register —
it is a namespace-availability snapshot only.

## A-N6 scope cuts preserved (binding, spec §1.3)

1. No LLM risk classifier, reviewer-fatigue model, or standards accreditation.
2. No cross-mesh token chaining or delegation fabric.
3. No amendment ceremonies; no precedents-as-law.
4. Treaty machinery stays killed: registry CRUD + signed claims ≠ treaties.
5. No generic proof-bundle hosting, generic tracer, workflow engine, or hosted
   long-horizon evaluator.
6. Launch suite families: poisoning, injection, approval-bypass only.
7. English text, simulated tools, one gateway, exact tested target only.
8. Grades are deterministic code — never a second model or hidden heuristic.
9. Weather cites EvalSeal as a point-in-time baseline; no automatic
   re-certification here.
10. Build order follows the report sequence; no parallel product launches.

## OSS / hosted split (spec §1.1, §2.1)

MIT core (this repository): suite definitions/importer (locker), runner
adapters, recorder + simulated tool boundary, deterministic grader, schemas,
canonicalization + Ed25519 signing, audit-chain verification, deterministic
PDF/ZIP/HTML/SVG rendering, pack builder + offline verifier, a local reference
authority/service for development and conformance, and the `evalseal` /
`python -m evalseal` CLI.

Hosted paid surface (not this repository; stub interfaces only): Cloudflare
Workers API/site, TenantAuthority/PublicIndex Durable Objects, private R2
evidence buckets, the isolated IssuerSigner binding/DO, hosted certification
runs, and private boards. Public verification stays unauthenticated.
