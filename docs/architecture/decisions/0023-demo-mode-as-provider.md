# ADR-0023: Demo mode as a first-class provider adapter

Status: accepted
Date: 2026-08-05

## Context

The product must be usable, demonstrable, and developable without live cloud credentials. Most
projects meet this with database seed fixtures: insert rows for assets and findings, render them.

That approach satisfies the demo requirement and satisfies nothing else. Seeded rows bypass
collection, normalization, pagination, retry, error classification, evaluation, and finding
reconciliation — which is to say, they bypass the entire system. Worse, seeded data drifts from
reality as the pipeline evolves, so the demo eventually shows a shape the real pipeline can no longer
produce.

Separately, the code paths hardest to test against real clouds are exactly the ones most likely to be
wrong: multi-page pagination, throttling and backoff, permission-denied handling, partial scan
failure, and malformed responses. Provoking those on demand in a real account is difficult and, for
throttling, actively antisocial.

## Decision

**`demo` is a `CloudProvider` with a full `ProviderAdapter` implementation**, registered like AWS,
Azure, GCP, and IBM. A demo scan traverses the identical path: connection → scope resolution →
collectors → `RawObservation` → normalization → evaluation → evidence → persistence.

The adapter generates four synthetic estates (one per real provider's shape) from a **fixed seed**,
so the same estate is produced on every machine, every run.

The generator is scripted to exercise, deterministically:

| Behaviour | Why it must be in the demo |
| --- | --- |
| Findings at every severity | Dashboard rendering, filtering, sorting |
| Compliant resources (`pass`) | Prove passes exist; a UI showing only failures is misleading |
| `not_applicable` results | Distinct from passes and from failures |
| **Permission denied → `insufficient_data`** | The most important correctness path in the product |
| Multi-page pagination (>1 page on at least two collectors) | Pagination bugs are silent data loss |
| Throttling → retry → success | Backoff logic otherwise untested |
| A collector failing entirely → `partially_completed` | Partial-failure UI state |
| Service disabled → target `skipped` | Skip is not an error |
| A malformed payload → `parse_error` | Normalization guardrails |

Two hard constraints, enforced by test:

- **The demo generator performs no network I/O whatsoever.** Asserted by a test that fails on any
  socket use.
- **Demo data is flagged end to end** — `is_demo` on connection, scan, asset, finding, and every
  export; a persistent UI banner and per-row badges. Demo output must never be mistakable for a real
  assessment.

Demo estates are synthetic and generic. They deliberately do not resemble any real organization.

## Rejected alternatives

- **SQL seed fixtures.** Bypasses the entire pipeline, drifts from reality, and tests nothing. This is
  the alternative this ADR exists to reject.
- **Recorded HTTP cassettes replayed through the real adapters.** Genuinely valuable and we use it —
  but for **adapter unit tests**, where fidelity to real payloads is the point
  ([ADR-0017](0017-testing-strategy.md)). As a demo mechanism it is poor: cassettes are large,
  awkward to author for scripted failure sequences, must be scrubbed of real account identifiers, and
  break whenever a fixture is regenerated.
- **A mock cloud server (LocalStack, Azurite, moto in server mode).** Adds infrastructure to the
  demo path, covers providers unevenly (LocalStack is AWS-only; there is no credible IBM equivalent),
  and its own fidelity gaps become our bugs.
- **A `--demo` flag branching inside each real adapter.** Puts demo logic in production code paths and
  invites a bug where real scans take a demo branch. A separate adapter cannot do that.
- **Demo data generated randomly at seed time.** Non-deterministic screenshots, documentation, and
  tests. The fixed seed is essential.

## Consequences

- The demo adapter is real code with real maintenance cost, and it must be updated when the
  `Collector` contract or fact schemas change. This is a **feature**: it means the contract change
  cannot be merged while leaving a consumer broken, and the demo adapter is the cheapest possible
  consumer to keep current.
- CI runs a full end-to-end scan against demo on every pull request, in seconds, with no credentials
  and no network — covering orchestration, pagination, retry, partial failure, evaluation,
  reconciliation, API, and export.
- Screenshots and documentation are reproducible from a command.
- Contributors can develop and test policies, UI, and API without any cloud account, which materially
  lowers the barrier to contribution.
- The demo adapter is the reference implementation contributors read when writing a new provider
  adapter, because it is the only one whose behaviour is fully legible without cloud knowledge.
