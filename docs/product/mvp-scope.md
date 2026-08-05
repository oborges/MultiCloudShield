# v0.1.0 MVP Scope

Status: accepted
Last updated: 2026-08-05

This document is the authoritative in/out list for v0.1.0. If something is not listed as **In**, it
is not in the MVP. Detailed behaviour lives in
[acceptance-criteria.md](../planning/acceptance-criteria.md); sequencing lives in
[implementation-plan.md](../planning/implementation-plan.md).

Three categories are used throughout:

- **In (v0.1.0)** — required to ship.
- **Post-MVP** — planned, deliberately not now.
- **Deferred** — decided against for the foreseeable future, with a reason. Not a backlog item.

---

## 1. Cloud connection management

**In**

- Register a connection to an AWS account, Azure subscription, GCP project, or IBM Cloud account.
- Store configuration metadata and a **non-secret** credential reference (env var names, role ARNs,
  service-account emails to impersonate). Raw secrets are rejected at the API boundary.
- Record the `CredentialMechanism` in use without exposing values.
- Connectivity test that reports three outcomes: `ok`, `degraded` (authenticated, missing some
  permissions — lists which collectors will be skipped and the exact permission needed), `failed`.
- Enable/disable a connection. Disabled connections are skipped by scans and visibly marked.
- Region/location allowlist per connection.
- Delete a connection, with an explicit choice to retain or purge its assets and findings.

**Post-MVP**

- Organization-wide scanning (AWS Organizations, Azure management groups, GCP folders/orgs, IBM
  enterprise accounts) — v0.1.0 registers one scope per connection.
- Credential rotation reminders; connection health monitoring between scans.

**Deferred**

- Storing any cloud secret in MultiCloudShield, encrypted or otherwise. This is a permanent
  architectural constraint, not a missing feature.
- Provider-side automated onboarding (CloudFormation/Terraform/ARM one-click deploy of the read-only
  role). We ship the least-privilege policy documents; the operator applies them.

---

## 2. Scanning

**In**

- Start a scan manually from the CLI, REST API, and dashboard.
- Full lifecycle: `queued`, `running`, `completed`, `partially_completed`, `failed`, `cancelled`.
- Cooperative cancellation, checked between scan targets and pagination pages; documented as
  best-effort with a bounded delay.
- Per-scan record of provider, scope, trigger, actor, start/end time, statistics, errors, and the
  pinned policy bundle + engine version.
- Bounded concurrency (global, per-connection, and per-provider caps), retries with exponential
  backoff and jitter, per-call and per-target timeouts, full pagination.
- Idempotent scan steps (asset upsert by URN, evaluation upsert, finding upsert by fingerprint) and
  an `Idempotency-Key` on scan creation.
- At-least-once execution with lease/heartbeat; a worker crash requeues rather than corrupts.
- Evidence captured automatically from fact access; raw provider payloads not persisted by default.
- **Stateless local scan** (`mcs scan --local`) that runs collection + evaluation in-process and
  emits JSON/CSV without a database — the CI/CD path.

**Post-MVP**

- Scheduled/recurring scans; incremental or event-driven rescan; scan diffing UI.
- Distributed workers across hosts (the queue design already supports it; the MVP runs one worker).

**Deferred**

- Continuous/streaming ingestion of provider change events (EventBridge, Azure Event Grid, GCP
  Pub/Sub audit sinks). Substantial new inbound attack surface and infrastructure for no MVP value.

---

## 3. Domain model

**In** — all entities specified in [domain-model.md](../architecture/domain-model.md):
`CloudProvider`, `CloudConnection`, `Scan`, `ScanTarget`, `Asset`, `AssetRelationship`, `Policy`,
`PolicyEvaluation`, `Finding`, `FindingStatus`, `Severity`, `Evidence`, `RemediationGuidance`,
`ComplianceMapping`, `ScanError`, plus `Organization`, `User`, `ApiToken`, `FindingStatusChange`.

`AssetRelationship` is populated where it is cheap and useful (firewall ruleset → attachment,
bucket → KMS key, audit trail → destination). **No v0.1.0 policy depends on relationships**, so
incomplete relationship data degrades explanation, never correctness.

**Post-MVP** — asset graph traversal and reachability queries.

---

## 4. Provider coverage

**In** — AWS, Azure, GCP, IBM Cloud, plus `demo`. Per-provider collectors and policies are
enumerated in [provider-coverage-matrix.md](../planning/provider-coverage-matrix.md), covering:
object storage, network firewall exposure, identity/access configuration, audit logging, and
encryption/key management where technically meaningful.

Coverage is **intentionally asymmetric**. Where a provider has no meaningful equivalent of a check,
the matrix records "not applicable" with the reason rather than inventing a check. Where a provider
has a concept the others lack, we implement it as a provider-specific policy rather than dropping it.

AWS is the reference implementation and ships first (it has the broadest read-only API surface and
the most mature Python SDK); the other three follow the same adapter contract.

**Post-MVP** — additional services per provider; Oracle Cloud, Alibaba Cloud, Kubernetes posture.

---

## 5. Policy engine

**In**

- Hybrid representation: **declarative metadata (YAML) + a pure Python evaluation function**
  ([ADR-0009](../architecture/decisions/0009-policy-representation.md)).
- Policies read only normalized facts, or explicitly declared provider-specific facts, through the
  recording `FactView` interface. No policy touches a cloud SDK.
- Stable IDs, title, description, rationale, severity + rubric cell, provider applicability,
  resource applicability, `requires_facts`, references, remediation guidance, compliance mappings,
  and `origin` (`mcs_best_practice` vs `external_control_derived`).
- Five-valued results: `pass`, `fail`, `not_applicable`, `insufficient_data`, `error`.
- Policies unit-testable against fixture facts with no cloud account; a golden-file determinism test.
- Versioned policy bundle; the version is pinned into every scan.
- All prose original; compliance mappings store identifiers only.

**Post-MVP**

- Custom user policies loaded from a configured directory, with a documented trust model.
- Policy parameters/thresholds configurable per connection (e.g. permitted public CIDRs).
- Policy exception rules as data (suppress by tag/pattern) rather than per-finding suppression.

**Deferred**

- Rego/OPA or a general-purpose expression DSL as the primary representation — rationale and
  rejected alternatives in [policy-engine.md](../architecture/policy-engine.md) §3.
- Executing remediation snippets. Permanently out of the scanner.

---

## 6. Interfaces

### REST API — In

- Versioned under `/api/v1`, generated OpenAPI 3.1 document at `/api/v1/openapi.json` plus
  interactive docs.
- Resources: connections, connection tests, scans, scan errors, assets, findings, finding status
  transitions, policies, exports, summary metrics, health/readiness, auth/session, API tokens.
- Consistent error model (RFC 9457 problem details) with stable machine-readable codes.
- Cursor pagination, filtering, and sorting on all collections.

### CLI — In

- `mcs` covering: `connection` (add/list/test/enable/disable/remove), `scan` (start/status/list/
  cancel/wait), `findings` (list/show/export), `policy` (list/show/validate/test), `demo` (seed),
  `version`, `login`/`token`.
- Two modes: **remote** (talks to an API server with a token — the normal path) and **local**
  (`--local`, in-process, no server, no database — the CI path).
- Machine-readable output (`--output json|csv|table`), non-zero exit on `--fail-on <severity>`,
  no colour/TTY assumptions when piped.

### Dashboard — In

- Responsive React SPA served by the API in production.
- Views: overview, connections, connection detail, scans, scan detail (with errors), assets, asset
  detail, findings, finding detail, policy catalog, policy detail.
- Filtering by provider, connection, severity, resource type, policy, finding status, and scan;
  filters reflected in the URL so views are shareable.
- Explicit empty, loading, **partial-failure**, and error states for every view. Partial failure is
  a designed state, not an afterthought.
- Demo mode banner whenever demo data is in view.
- Finding status transitions with a mandatory reason.

**Post-MVP** — saved views, bulk finding actions, dark mode, i18n, keyboard-first navigation.

**Deferred** — mobile native apps; real-time push (polling is sufficient at MVP scan volumes).

---

## 7. Reporting

**In** — JSON export (full fidelity, schema-versioned), CSV export (flattened findings, spreadsheet
safe — see [threat-model.md](../architecture/threat-model.md) §T13 on formula injection), summary
metrics, findings grouped by provider/severity/policy/resource type/connection, and a scan-level
report including errors and coverage gaps.

Every export embeds provenance: scan IDs, engine version, policy bundle version, generation
timestamp, and whether demo data is included.

**Post-MVP** — scheduled report delivery; SARIF export for code-scanning surfaces; report templates.

**Deferred for v0.1.0** — PDF generation. It requires a headless browser or a heavy templating
stack, both of which add attack surface and image weight disproportionate to MVP value. HTML export
that prints cleanly is the post-MVP path.

---

## 8. Authentication and tenancy

**In**

- Single organization, created at bootstrap.
- Interactive auth: email + password with Argon2id, opaque server-side session cookies
  (HttpOnly, Secure, SameSite), CSRF protection on state-changing requests, lockout on repeated
  failures.
- Programmatic auth: API tokens, high-entropy, shown once, stored hashed, prefixed for secret
  scanning, revocable, optionally expiring.
- RBAC: `owner`, `analyst`, `viewer`. Every tenant-scoped query goes through an org-scoped
  repository from day one.
- Explicit statement of isolation boundaries in
  [security-boundaries.md](../architecture/security-boundaries.md) §4.

**Post-MVP** — OIDC SSO against an existing IdP; per-connection authorization scoping; Postgres RLS;
SCIM.

**Deferred** — building an identity provider; password reset via email in v0.1.0 (no mail
dependency; `owner` resets via CLI); MFA in-product (delegated to the IdP once SSO lands).

---

## 9. Demo mode

**In**

- `demo` is a **real provider adapter** implementing the same contract, not a database fixture. It
  therefore exercises the identical collection → normalization → evaluation → persistence path.
- Deterministic synthetic estates for all four providers, generated from a fixed seed.
- Demo data deliberately exercises: failing findings across all severities, compliant resources
  (passes), partial scan failure, multi-page pagination, permission-denied errors producing
  `insufficient_data`, `not_applicable` results, and a service-disabled skip.
- Clearly marked in the UI (persistent banner + per-row badge) and in the API (`is_demo` on
  connections, scans, assets, findings, and every export).
- Seeded with one documented command.

**Deferred** — synthetic data resembling any real organization; demo mode reaching any network.

---

## 10. Engineering

**In** — database migrations; structured JSON logging with redaction; health and readiness
endpoints; startup configuration validation that fails fast; consistent error model; locked
dependencies; formatting, linting, static typing; unit, integration, API, policy, adapter
conformance, and a minimal E2E test; GitHub Actions CI; Dockerfiles and Docker Compose; seed data
and a documented demo workflow; SBOM generation in CI.

**Post-MVP** — metrics/tracing exporters (OpenTelemetry), published container images with signed
provenance, Helm chart, load testing.

**Deferred** — Kubernetes as a supported MVP deployment target; any message broker, cache, or search
engine.

---

## 11. Non-goals restated as constraints

These are checked in CI, not merely documented:

1. No cloud write/mutation call exists in the codebase (adapter contract + import/call-pattern check).
2. No raw cloud credential is accepted, stored, logged, or exported.
3. No external framework's control text is reproduced.
4. No Redis, Kafka, Elasticsearch, or Kubernetes dependency.
5. The product runs end-to-end with no cloud credentials via demo mode.
