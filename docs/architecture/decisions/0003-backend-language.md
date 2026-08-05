# ADR-0003: Python as the backend language

Status: accepted
Date: 2026-08-05

## Context

The backend collects from four cloud APIs, normalizes results, evaluates policies, and serves an API.
The dominant constraint is **cloud SDK quality**, not raw runtime performance: a scan is
I/O-bound on remote APIs, and a wrong verdict costs far more than a slow one.

Contributors are the second constraint. The people who write CSPM policies are cloud security
engineers, and the language they already write is Python.

## Decision

**Python. Minimum supported 3.12; CI primary 3.13.**

Version rationale, from the official [devguide status page](https://devguide.python.org/versions/)
(2026-08-05): 3.14.7 is current stable; 3.14 and 3.13 are in *bugfix* status; 3.12 is in *security*
status until 2028-10; **3.10 reaches end of life in 2026-10** and 3.11 in 2027-10.

- **Floor 3.12** — supported until 2028-10, ships in current LTS distributions, and every dependency
  we need supports it (FastAPI, SQLAlchemy, Alembic, Typer, structlog, procrastinate, pytest 9, and
  mypy 2 all floor at ≥3.10; boto3 requires ≥3.10).
- **CI primary 3.13** — bugfix status, and a conservative choice against 3.14, which is one month old
  at the time of writing. CI runs the full matrix on 3.12 and 3.13.
- Not flooring at 3.10 or 3.11: both EOL inside this project's expected life, and a security tool
  running on an unsupported interpreter is an embarrassment.

Every cloud SDK we need is first-party and current
([provider-adapters.md](../provider-adapters.md) §4).

## Rejected alternatives

- **Go.** Genuinely attractive: single static binary (excellent for the CI/CD use case), strong
  concurrency, and the language of most cloud infrastructure tooling. Rejected because the
  contributor pool for *policy authoring* is smaller, and because our largest risk is provider
  coverage, where Python's SDK ecosystem is at least as good and its data-shaping ergonomics are
  better. Revisit only if the CLI's distribution weight becomes a real complaint.
- **TypeScript/Node everywhere.** Would unify with the frontend, but cloud SDK maturity for
  security-posture reads is weaker (particularly IBM), and the type system is less useful for the
  fact-schema modelling that carries this design.
- **Rust.** Wrong risk profile: the scarce resource is contributor time, not CPU cycles, and the
  provider SDK story is far thinner.
- **Java/C#.** Excellent Azure and AWS SDKs, poor fit for a small open-source CSPM's contributor pool
  and for a lightweight self-hosted deployment.

## Consequences

- Runtime performance is not a differentiator. Acceptable: scans are I/O-bound, and the concurrency
  design ([data-flows.md](../data-flows.md) §3.2) bounds throughput deliberately to avoid throttling
  customer accounts.
- Distribution is a wheel plus a container image, not a static binary. The `--local` CLI mode
  ([ADR-0025](0025-stateless-local-scan-mode.md)) therefore requires a Python environment or the
  container. Documented, and mitigated by publishing the CLI to PyPI.
- Static typing is opt-in, so it is enforced: mypy in strict mode is a CI gate
  ([ADR-0017](0017-testing-strategy.md)). Given that fact schemas and `TriState` carry the
  correctness of the whole system, this is non-negotiable rather than a nicety.
- We inherit boto3's synchronous model. Concurrency comes from bounded task/thread pools rather than
  a fully async provider layer — see [ADR-0006](0006-background-execution.md).
- 3.14 support is a tracked follow-up, not an MVP requirement.
