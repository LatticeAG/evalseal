# EvalSeal

**Protocol `evalseal/1` — bounded, evidence-backed certification records.**

EvalSeal produces a signed certificate for *one pinned suite release* against
*one observed run* of *one measured target*: locked adversarial suites
(poisoning, injection, approval-bypass), a deterministic 360-trial grid
(120 cases × 3 repeats, seeds 11/23/37), closed-code oracles, hash-chained
audit trails, and an offline-verifiable attestation pack.

It is **not** a universal safety claim, not a standards accreditation, not an
evaluator marketplace, and not a general security gateway. Scope limits are
carried on every public artifact as four visible `scope_lines`.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | TypeScript library + `evalseal` CLI (Node ≥ 22.5, zero runtime deps) |
| `python/evalseal/` | Python reference package (library, service, CLI) |
| `tests/conformance/` | Python conformance suite — all vectors TV-E--01..62 |
| `tests/ts/` | TypeScript conformance + live-HTTP integration suites |
| `tests/fixtures/` | Golden byte anchors (pack.zip, PDF, badge, pages, transcript) |
| `examples/evalharness-export/` | Minimal EvalHarness export for `suite lock` |
| `docs/phase0-scope-identity.md` | Naming record + OSS/hosted scope split |

## Quick start (simulation profile)

```bash
# Python (reference) — requires >= 3.11; provision with uv (fetches 3.12 if absent).
# uv venvs ship no pip: always use `uv pip install`, never `.venv/bin/pip`.
uv venv --python 3.12 .venv
uv pip install -e python/
.venv/bin/evalseal --version

# TypeScript
pnpm install && pnpm build        # → dist/ and the evalseal bin
```

Lock and run the bundled simulation suite locally:

```bash
evalseal --json suite lock examples/evalharness-export \
    --version 1.0.0 --out lock.json
evalseal --json run local --lock lock.json --target target.json \
    --out run-out --simulation
```

`run local` executes all 360 trials against the simulation target over the
NDJSON tool channel and prints the graded `evalseal-result/1` body.

### Local reference service

```bash
evalseal serve --provision provision.json --bind 127.0.0.1:8099
evalseal --config client.json product create --label "My Agent" \
    --target-ref target-fixture --idempotency-key p1
evalseal --config client.json run submit --product es_prd_… \
    --release sha256:… --track public --idempotency-key r1
evalseal worker serve --worker-config worker.json --once
evalseal --config client.json run status es_run_…
evalseal --config client.json pack download es_crt_… --out pack.zip
evalseal pack verify pack.zip --trust trust.json \
    --keyring-file keyring.json --status-file status.json
```

#### Configuration files

The JSON files those commands consume are closed-schema documents:

| File | Schema | Shape / generation |
|---|---|---|
| `provision.json` | `evalseal-devservice/1` | Dev-service provisioning (issuer seed, principals, workers, targets, releases). Generate a working one with `python3 tests/ts/provision.py > provision.json`; field-by-field reference in `python/evalseal/devserver.py`. |
| `client.json` | `evalseal-client-config/1` | `{schema, origin, token_env, trust_file, cache_dir, timeout_ms, profile}`. `timeout_ms` ∈ [1, 300000]; `profile: "production"` requires an `https://` non-loopback `origin`. Example: `{"schema":"evalseal-client-config/1","origin":"http://127.0.0.1:8099","token_env":"EVALSEAL_TOKEN","trust_file":"trust.json","cache_dir":"cache/evalseal","timeout_ms":30000,"profile":"simulation"}` |
| `worker.json` | `evalseal-worker-config/1` | `{schema, origin, identity_env, work_dir, poll_seconds, heartbeat_seconds, lease_seconds, parallel_runs, sandbox_profile, network_profile, profile}`. Intervals are **pinned**: `poll_seconds` must be `5`, `heartbeat_seconds` `30`, `lease_seconds` `120` — any other value is rejected (`worker-config.intervals`). `parallel_runs` ∈ [1, 4]; `sandbox_profile` must be `"linux-isolated-v1"` and `network_profile` `"approved-model-only"`; `profile` ∈ `"simulation"` \| `"production"`. |
| `trust.json` | `evalseal-trust/1` | `{schema, profile, roots, minimum_keyring_epoch}`; `roots` is a non-empty list of `{key_id: "key_…", public_key: <base64url Ed25519>, roles: […], not_before, not_after, revoked}`. Under `profile: "production"` root keys may only carry `release`/`release-index`/`keyring` roles. |
| `keyring.json` | `evalseal-keyring/1` | Issuer-issued key rotation file — an `evalseal-signed/1` envelope `{schema, kind:"keyring", key_id, body_hash, body, signature}` whose body is `{schema, epoch, issued_at, valid_until, keys, previous_hash}` (`valid_until` ≤ `issued_at` + 86400). Produced by `evalseal keyring issue`. |
| `status.json` | `evalseal-status/1` | Certificate status body: `{schema, certificate_id: "crt_…", certificate_hash, state: "ACTIVE"\|"EXPIRED"\|"REVOKED", qualifies, reason, as_of, valid_until, head}` — the shape `run status --status` serves. |

`pack verify` works fully offline: it checks the ZIP bounds, every entry hash
against the signed manifest, all signatures against pinned trust roots, the
audit prefix against its checkpoint anchor, and — for `private-full` packs —
replays every oracle verdict. Exit codes: `0` QUALIFIES, `4` NOT_QUALIFIED,
`5` integrity INVALID, `8` UNKNOWN.

## What gets verified

- **Canonicalization**: RFC 8785-intent canonical JSON over a constrained
  scalar domain (safe integers, no fractions, no −0, no duplicate members).
- **Signatures**: Ed25519 envelopes `evalseal-signed/1`, domain-separated
  `evalseal/1/<kind>` body hashes, `evalseal/1/signature` messages.
- **Grading**: closed band thresholds (A/B/C/F), per-family floors, unanimous
  repeat rule, any critical failure → F. Recomputed, never submitted.
- **Audit**: hash-chained per-run entries plus signed checkpoints; packs carry
  the prefix through `evidence_head`.
- **Packs**: deterministic ZIP, manifest-pinned entries, public packs are
  redacted (`summary-only`), private packs carry full evidence for
  `full-replay` verification.

## Hosted surfaces

The paid deployment (Cloudflare Workers + Durable Objects + R2 + isolated
issuer-signer binding) is **not** in this repository. `hosted.ts` /
`hosted.py` expose the interfaces as documented stubs that raise
`NotImplemented`/`HostedUnavailable` — they never pretend to run server-side
infrastructure locally. See `docs/phase0-scope-identity.md`.

## Testing

```bash
pnpm test                  # TS conformance + live-HTTP integration (needs python)
pnpm test:conformance      # TS library vectors, golden byte anchors
pnpm test:integration      # TS client/worker ↔ Python reference service
python -m pytest tests/conformance -q   # Python: all 62 TV-E vectors
```

The conformance meta-test asserts every vector TV-E--01..62 exists; golden
anchors in `tests/fixtures/` pin byte-identical rendering across both
implementations.

## License

MIT — see `LICENSE`.
