# ADR-0025: Database-free local scan mode for CI/CD

Status: accepted
Date: 2026-08-05

## Context

One target user runs posture checks in a CI/CD pipeline and fails the build on new critical exposure.
That user does not want to provision PostgreSQL, run migrations, start a worker, create an
organization, and mint an API token inside an ephemeral build container.

The naive fix is a second, cut-down scanning implementation for the CLI. That produces two engines
that disagree, which in a security tool means the pipeline passes and the dashboard fails, or the
reverse — and nobody can say which is right.

## Decision

**The core engine takes no database dependency.** Persistence is one consumer of its output, not a
step inside it.

```python
# engine/runner.py — no session, no repository, no HTTP
async def run_scan(
    connection: ConnectionDescriptor,
    bundle: PolicyBundle,
    options: ScanOptions,
) -> ScanResult:            # assets, evaluations, findings, evidence, errors, stats
    ...
```

Two consumers of the identical function:

| Consumer | Sink |
| --- | --- |
| Worker | `PersistenceSink` — upserts assets, evaluations, evidence, reconciles findings |
| `mcs scan --local` | `SerializingSink` — writes JSON/CSV to a file or stdout |

`mcs scan --local` therefore needs no server, no database, no migrations, and no authentication:

```bash
mcs scan --local --provider aws --scope 111122223333 \
         --output json --out findings.json --fail-on high
```

Exit codes are the CI contract: `0` clean, `2` findings at or above `--fail-on`, `3` scan failed,
`4` partial results (configurable whether that fails the build).

Because finding **fingerprints** are computed from `(organization_id, connection_id, policy_id,
asset_urn, sub_locator)` and not from database identity, a local scan's findings carry the same
stable identity as a server scan's. Local mode uses a deterministic synthetic organization and
connection ID derived from the provider and scope, so the same estate produces the same fingerprints
in CI and on the server — which means a CI result can be correlated with a dashboard finding.

Local mode has no finding history, so it reports current state only: no `new` vs `existing`, no
resolution, no suppression. That is the honest limitation of a stateless run, and the CLI says so.

## Rejected alternatives

- **Require a server for all scanning.** Rejected on the user requirement. A CSPM that cannot run in
  a pipeline without infrastructure will not run in pipelines.
- **Ephemeral SQLite for local mode.** Would introduce a second SQL dialect, a second JSON story, and
  a second set of migrations to keep working — for a mode that does not need persistence at all
  ([ADR-0005](0005-database-and-orm.md) rejects SQLite outright).
- **A separate lightweight scanner binary.** Two implementations that will diverge. This is the
  outcome the ADR exists to prevent.
- **Local mode posts results to a server.** Useful (and a good post-MVP option, `--report-to`), but it
  reintroduces the server dependency for the base case.
- **Persist locally to a JSON state file for history.** Half a database with none of the guarantees,
  and it invites concurrent-write bugs in matrix builds. History belongs on the server.

## Consequences

- The engine's public function signature is a real contract with two consumers, so a database concern
  cannot quietly creep into orchestration — the compiler and the tests catch it.
- Testing the engine needs no database, which makes engine tests fast and makes the golden-file
  determinism test trivial to run.
- The CLI ships as a Python package installable on its own; the container image is optional for the
  CI use case.
- Local mode's authorization model is "whoever can run the process" — it is bounded by the cloud
  credentials available in that environment, exactly like the AWS CLI. Documented explicitly so that
  nobody expects application-level authorization in a mode that has no application.
- `--local` with `--provider demo` gives a zero-dependency smoke test: no cloud, no database, no
  network. It is the first command in the README and the first check in CI.
