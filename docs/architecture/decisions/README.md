# Architecture Decision Records

Each ADR records one decision, the forces behind it, the alternatives that were genuinely
considered, and the consequences we accept. ADRs are immutable once accepted: to change a decision,
write a new ADR that supersedes the old one and update the `Status` line of both.

Format: context → decision → rejected alternatives → consequences. Keep them short; the detail
belongs in the architecture documents they link to.

Statuses: `proposed`, `accepted`, `superseded by ADR-NNNN`, `deprecated`.

## Index

| # | Title | Status | Decides |
| --- | --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | accepted | ADR process |
| [0002](0002-modular-monolith.md) | Modular monolith with two process roles | accepted | System topology |
| [0003](0003-backend-language.md) | Python as the backend language | accepted | Language, minimum version |
| [0004](0004-backend-framework.md) | FastAPI as the backend framework | accepted | Backend framework |
| [0005](0005-database-and-orm.md) | PostgreSQL, SQLAlchemy 2, Alembic | accepted | Database, ORM, migrations |
| [0006](0006-background-execution.md) | PostgreSQL-backed job queue and worker | accepted | Background scan execution |
| [0007](0007-provider-adapter-contract.md) | Provider adapter contract | accepted | Adapter interface, cloud SDKs |
| [0008](0008-normalized-asset-and-fact-model.md) | Normalized asset and fact model | accepted | Asset/finding models |
| [0009](0009-policy-representation.md) | Declarative metadata + Python predicates | accepted | Policy representation and execution |
| [0010](0010-determinism-and-evidence.md) | Determinism contract and recorded evidence | accepted | Reproducibility, evidence capture |
| [0011](0011-authentication-model.md) | Sessions for humans, hashed tokens for machines | accepted | Authentication |
| [0012](0012-authorization-model.md) | Org-scoped RBAC with a tenancy seam | accepted | Authorization, tenancy |
| [0013](0013-credential-handling.md) | Provider-native credential chains, no stored secrets | accepted | Credential handling |
| [0014](0014-frontend-stack.md) | React + TypeScript + Vite, generated API client | accepted | Frontend framework |
| [0015](0015-configuration.md) | Validated environment configuration, fail fast | accepted | Configuration |
| [0016](0016-observability.md) | Structured logs, health/readiness, no APM in MVP | accepted | Observability |
| [0017](0017-testing-strategy.md) | Recorded fixtures, no live cloud in CI | accepted | Testing |
| [0018](0018-packaging-and-deployment.md) | One image, two commands; wheel for the CLI | accepted | Packaging, deployment |
| [0019](0019-ci-cd.md) | GitHub Actions with pinned, least-privilege workflows | accepted | CI/CD |
| [0020](0020-versioning.md) | SemVer product, dated policy bundles, versioned API | accepted | Versioning |
| [0021](0021-extension-mechanism.md) | Registries plus Python entry points | accepted | Extension mechanism |
| [0022](0022-dependency-management.md) | uv lockfiles and automated update PRs | accepted | Dependency strategy |
| [0023](0023-demo-mode-as-provider.md) | Demo mode as a first-class provider adapter | accepted | Demo mode |
| [0024](0024-compliance-mapping-policy.md) | Identifiers only, original prose | accepted | Compliance mappings |
| [0025](0025-stateless-local-scan-mode.md) | Database-free local scan mode | accepted | CI/CD scanning path |
