# ADR-0017: Recorded fixtures, never live cloud in CI

Status: accepted
Date: 2026-08-05

## Context

A CSPM's correctness is its product. A wrong verdict — especially a false `pass` — is worse than a
crash, because a crash is visible. But the system's inputs come from four cloud providers, and
testing against real cloud accounts in CI would require live credentials, cost money, be
non-deterministic, and be slow.

## Decision

**No live cloud credentials in CI, ever. Provider behaviour is tested against recorded fixtures and
mocks; the full pipeline is tested end-to-end against the demo adapter.** Detail in
[testing-strategy.md](../testing-strategy.md).

| Layer | Tool | Covers |
| --- | --- | --- |
| Unit | pytest 9.x | Fact schemas, normalizers, helpers, fingerprints, URNs |
| **Policy** | pytest + YAML fixtures | Every policy: pass, fail, `insufficient_data`, `not_applicable` |
| **Determinism** | Golden file over a frozen fact corpus | Byte-identical evaluations across runs |
| **Adapter conformance** | One parameterized suite over every adapter | Contract invariants, error mapping, cancellation, read-only allowlist |
| Adapter behaviour | `moto` 5.x (AWS), `vcrpy` 8.x cassettes (all) | Real payload shapes |
| Integration | pytest + PostgreSQL container | Repositories, migrations, reconciliation, crash recovery |
| API | `httpx2.AsyncClient` + `ASGITransport` | Endpoints, auth, RBAC, errors, pagination |
| API property | Schemathesis 4.x against our OpenAPI | Unhandled 500s on malformed input |
| E2E | `@playwright/test` | Demo connection → scan → dashboard |

Choices worth recording:

- **`httpx2.AsyncClient` + `ASGITransport`, not Starlette's `TestClient`.** Our assertions are async
  (database reads alongside API calls), and `TestClient` runs its own event loop that conflicts with
  async fixtures. Note `base_url` must be set for relative URLs to resolve.
- **`httpx2`, not `httpx`.** Stewardship moved to Pydantic Services under the `httpx2` name; Starlette's
  own TestClient documentation now marks plain `httpx` deprecated and ships `httpx2` in
  `starlette[full]`. A consequence for mocking: **`responses` will not work** — it is `requests`-only.
  Use `vcrpy` (transport level) or RESPX.
- **`moto` for AWS, cassettes elsewhere.** moto documents 161 services and covers the CSPM-critical
  ones (`s3`, `iam`, `ec2`, `cloudtrail`, `kms`, `sts`, `config`). But coverage is tracked
  *per operation* and varies, so **each specific call a collector makes must be verified against moto
  before relying on it**, with a scrubbed vcrpy cassette as the fallback. There is no comparable mock
  for Azure, GCP, or IBM — those are cassette-only.
- **Fixtures are scrubbed and checked.** A dedicated CI check scans fixtures for credential patterns
  and real account identifiers, because fixtures are the single most likely place for a real secret to
  enter the repository.

**The demo adapter is a test surface, not just a demo.** It exercises pagination, throttle-and-retry,
permission denied, partial failure, service-disabled skips, and malformed payloads — the paths that
are hardest to provoke against a real cloud and most likely to be wrong
([ADR-0023](0023-demo-mode-as-provider.md)).

### Release gates

Two tests are release blockers because they guard the failure modes that would make the product
actively harmful:

1. **Total-failure regression gate** — a scan in which every target fails must resolve **zero**
   findings ([AC-FIND-5](../../planning/acceptance-criteria.md)). Without this, a permission
   regression turns the dashboard green.
2. **Read-only proof** — no cloud mutation operation is reachable from any adapter, and the operation
   allowlist rejects an unlisted call before any request is sent.

Coverage thresholds are high on `core`, `facts`, `policy`, and `engine` — where a bug produces a wrong
security verdict — and pragmatic elsewhere. 100% coverage is explicitly not a goal.

## Rejected alternatives

- **A nightly job against real sandbox accounts.** Genuinely valuable for catching provider API drift,
  and it requires storing four sets of cloud credentials in CI — the exact anti-pattern this product
  exists to detect. Deferred until the project can offer a maintainer-run, out-of-band verification
  with disposable accounts, documented rather than automated in the public repository.
- **LocalStack / Azurite as the mock layer.** LocalStack is AWS-only, there is no credible IBM
  equivalent, and their fidelity gaps become our bugs. moto plus cassettes is lighter and honest about
  what it covers.
- **Testing policies through the API only.** Slow, and it hides which layer produced a wrong verdict.
  Policies are pure functions and must be tested as such.
- **Snapshot-testing whole API responses.** Brittle; fails on every field addition and trains reviewers
  to accept snapshot updates without reading them.
- **Skipping the E2E test as "too slow."** It runs against demo with no network in seconds, and it is
  the only test that proves the parts fit together.

## Consequences

- Fixtures must be refreshed when provider APIs change, and a provider change will therefore be caught
  late — by a user, not by CI. This is the accepted cost of not putting cloud credentials in CI, and it
  is recorded in [risk-register.md](../../planning/risk-register.md).
- Cassette maintenance is real work; the recording helper scrubs account IDs, ARNs, and tokens
  automatically so it is not left to discipline.
- The demo adapter must stay current with the collector contract — enforced by the shared conformance
  suite, which is the point.
- CI runs entirely offline, so it is fast, deterministic, and safe to run on fork pull requests.
