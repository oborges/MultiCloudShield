# Project status

Last updated: 2026-08-05

MultiCloudShield v0.1.0 is implemented on `feat/multicloudshield-v0.1.0`. The branch contains the
domain and policy engine, PostgreSQL persistence and job queue, REST API, CLI, worker, four live
provider adapters, deterministic demo provider, React dashboard, exports, migrations, and hardened
container packaging. The implementation baseline through `d45ad6e` has been pushed to `origin`; it
has not been merged, tagged, or published.

## Verified

The following checks passed against commit `d45ad6e` or its direct predecessors on the same branch:

| Area | Evidence |
| --- | --- |
| Python formatting and lint | Ruff format check and Ruff lint passed |
| Static analysis | mypy passed for 60 source files; both import-linter contracts passed |
| Python tests | 77 passed, 1 live-provider test skipped by design |
| Frontend | ESLint passed; 5 tests passed; production Vite build passed |
| Dependency audit | npm reported zero high-level vulnerabilities; Python dependency audit reported no known vulnerabilities in resolved third-party packages |
| Provider packaging | AWS, Azure, GCP, and IBM Cloud SDK extras installed and imported successfully |
| Container image | Multi-stage production image built successfully with Podman 5.8.2 |
| PostgreSQL migration | Alembic upgraded an empty PostgreSQL 18 database to head successfully |
| Runtime | API and worker ran as hardened containers; `/healthz` returned version `0.1.0` |
| Deterministic demo | Persisted 1 partially completed scan, 24 assets, 552 policy evaluations, and 37 findings |
| Failure safety | Regression test prevents all-failed targets from producing passing verdicts or resolving findings |

The temporary verification containers, network, credentials, and PostgreSQL volume were removed
after the run. No test secret was committed.

## Still outstanding before a v0.1.0 release

- Run live least-privilege smoke tests against explicitly authorized non-production AWS, Azure, GCP,
  and IBM Cloud accounts. Current provider verification uses mocked official SDK clients.
- Run browser end-to-end testing of the complete login-to-finding workflow.
- Run the documented fault-injection recovery and 10,000-asset performance gates.
- Scan the final container image for high/critical vulnerabilities and generate the release SBOM and
  provenance attestation.
- Review the threat model against the final implementation, verify the security reporting channel,
  merge the branch, and create the signed `v0.1.0` tag and release notes.

These are release gates, not hidden implementation claims. The detailed checklist remains in the
[Definition of Done](planning/definition-of-done.md), and product limitations are listed in
[Known limitations](known-limitations.md).

## Current runtime notes

- PostgreSQL 18 is required because the schema uses native `uuidv7()`.
- The PostgreSQL 18 image must mount persistent storage at `/var/lib/postgresql`; the older
  `/var/lib/postgresql/data` mount fails intentionally in PostgreSQL 18 images.
- Docker Compose v2 is the primary local topology. Podman 5.8.2 plus `podman-compose` 1.6.0 is
  verified with the reconciliation sequence in the [demo workflow](demo-workflow.md#podman).
- Live cloud adapters are read-only and accept provider credentials only in the worker process.
