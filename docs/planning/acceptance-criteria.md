# Acceptance Criteria

Status: accepted for v0.1.0
Last updated: 2026-08-05

Testable criteria for v0.1.0 capabilities, written so each can be verified by a person or a test.
Format: `AC-<area>-<n>`. Referenced by phase from [implementation-plan.md](implementation-plan.md).

Convention: **Given / When / Then**. "Must" is a release requirement.

---

## AC-CONN · Cloud connection management

**AC-CONN-1 · Register a connection.**
Given an authenticated `owner`, when they POST a connection with provider, scope ID, credential
mechanism, and a non-secret reference, then the connection is created with status `never_tested` and
`enabled = true`, and the response contains no credential values.

**AC-CONN-2 · Secrets are rejected.**
Given a connection payload whose `credential_reference` contains an unknown key, a value matching a
known credential pattern, or a high-entropy string, when submitted, then the API returns `422` with a
problem-details body that **does not echo the offending value**, and no row is created.
Test data must include at least one realistic-shaped secret per provider.

**AC-CONN-3 · Connectivity test — success.**
Given a connection whose credentials resolve and permit all collectors, when tested, then the result
is `ok`, `last_verified_at` is set, and the response lists the collectors that will run.

**AC-CONN-4 · Connectivity test — degraded.**
Given credentials that authenticate but lack permissions for some collectors, when tested, then the
result is `degraded`, the response names **each** affected collector and the **exact** missing
permission, and the connection remains enabled.

**AC-CONN-5 · Connectivity test — failure.**
Given credentials that do not resolve or are rejected, when tested, then the result is `failed` with a
categorized, redacted reason (`authentication` vs `permission_denied` vs `api_error`), and no raw
provider exception text is stored or returned.

**AC-CONN-6 · Enable/disable.**
Given a disabled connection, when a scan is requested for it, then the request is rejected with a
clear error, and the dashboard shows the connection as disabled.

**AC-CONN-7 · Deletion is a choice.**
Given a connection with assets and findings, when deleted, then the caller must specify retain or
purge; purge removes assets, findings, evaluations, and evidence for that connection and nothing else.

**AC-CONN-8 · Mechanism is visible, values are not.**
Given any connection, when read via API, CLI, or dashboard, then the credential mechanism is shown and
no credential value appears in any field, log line, or export.

---

## AC-SCAN · Scanning

**AC-SCAN-1 · Start from three interfaces.**
Given an enabled connection, when a scan is started from the CLI, the REST API, or the dashboard, then
in all three cases a `Scan` is created with status `queued`, the correct `trigger`, and the requesting
principal recorded.

**AC-SCAN-2 · Lifecycle transitions.**
Given a queued scan, when the worker claims it, then it becomes `running`; on completion it becomes
exactly one of `completed`, `partially_completed`, `failed`, or `cancelled` per the rules in
[data-flows.md](../architecture/data-flows.md) §3.1. No scan remains `running` after the worker exits.

**AC-SCAN-3 · One failure does not fail the scan.**
Given a scan where one collector raises an unhandled exception, then that `ScanTarget` is `failed`
with a `ScanError(category=internal)`, all other targets complete, and the scan ends
`partially_completed`. Verified by fault injection, for an exception raised from *inside* a collector.

**AC-SCAN-4 · Permission errors are actionable, not fatal.**
Given a scan where one collector receives permission denied, then a `ScanError(permission_denied)` is
recorded naming the operation and the missing permission, affected policies evaluate to
`insufficient_data`, no finding is created or resolved for them, and the scan ends
`partially_completed`.

**AC-SCAN-5 · Pagination is complete and bounded.**
Given a collector whose provider returns 5 pages, when it runs, then all items across all pages are
collected. Given a provider that returns pages beyond `max_pages_per_target`, then collection stops at
the cap, a `ScanError` is recorded, and the target is not marked fully succeeded.

**AC-SCAN-6 · Retry and backoff.**
Given a provider returning a throttling error twice then success, then the call succeeds, the retry
count appears in `Scan.stats`, and inter-attempt delays increase. Given a permission-denied error,
then **no** retry is attempted.

**AC-SCAN-7 · Cancellation.**
Given a `running` scan, when cancelled, then the scan reaches `cancelled` within the per-call timeout
plus one page, assets already collected are retained, and **no finding is created, resolved, or
reopened** by that scan.

**AC-SCAN-8 · Idempotent replay.**
Given a completed scan, when the same scan job is replayed, then asset, evaluation, and finding counts
are unchanged; `first_seen_*` values are unchanged; no duplicate rows exist.

**AC-SCAN-9 · Crash recovery.**
Given a worker killed mid-scan, when a worker restarts, then the scan's lease expires, the job is
requeued, and re-execution produces no duplicate assets, evaluations, or findings.

**AC-SCAN-10 · Idempotency key.**
Given two scan-creation requests with the same `Idempotency-Key` for one connection, then exactly one
scan exists and both requests return it.

**AC-SCAN-11 · Provenance recorded.**
Given any completed scan, then it records provider, scope, trigger, actor, start/end time, statistics,
errors, `policy_bundle_version`, and `engine_version`.

---

## AC-POL · Policy engine

**AC-POL-1 · Offline testability.**
Given a policy and its fixtures, when its unit tests run, then they pass with no network access and no
cloud credentials. Enforced by a test that fails on socket use.

**AC-POL-2 · Determinism.**
Given the frozen fact corpus, when evaluated twice, then results, reason codes, severities, and
`observed_facts` are byte-identical, and match the committed golden file.

**AC-POL-3 · Five-valued results.**
Given an asset outside a policy's applicability, then `not_applicable`. Given an applicable asset with
a required fact `unknown`, then `insufficient_data` — never `pass`. Given a policy that raises, then
`error` for that asset only, and evaluation of other assets continues.

**AC-POL-4 · Declared facts are enforced.**
Given a policy that reads a fact not listed in `requires_facts`, when its conformance test runs, then
the test fails.

**AC-POL-5 · Provider-specific facts are constrained.**
Given a policy that reads a `provider_specific` fact while declaring applicability to all providers,
when the bundle loads, then loading fails with a clear error.

**AC-POL-6 · Complete metadata.**
Given any policy in the bundle, then it has a stable ID, version, title, description, rationale,
default severity with a rubric cell, provider and resource applicability, `requires_facts`,
references, remediation guidance, `origin`, and zero or more compliance mappings — validated at load.

**AC-POL-7 · No external control text.**
Given all policy metadata, when the compliance-text check runs, then no verbatim external control text
is present; mappings contain framework, version, control ID, relationship, and our own note only.

**AC-POL-8 · Purity.**
Given the policy bundle package, when the lint rule runs, then no module imports network, filesystem,
clock, environment, or randomness APIs.

---

## AC-FIND · Findings and lifecycle

**AC-FIND-1 · Complete finding.**
Given a policy failure, then a finding is created with severity, affected resource, evidence, risk
explanation, remediation guidance, compliance mappings, timestamps, and scan provenance.

**AC-FIND-2 · Stable identity.**
Given the same misconfiguration observed in two scans, then one finding exists with `first_seen`
from the first scan and `last_seen` from the second — not two findings.

**AC-FIND-3 · Identity survives policy edits.**
Given an open finding, when the policy's title, description, or severity changes and a new scan runs,
then the same finding is updated — not resolved and recreated.

**AC-FIND-4 · Resolution requires positive evidence.**
Given an open finding, when a later scan evaluates that policy as `pass` on a **succeeded** target,
then it is `resolved`. When the target instead fails or returns `insufficient_data`, then it remains
`open` and is shown as stale.

**AC-FIND-5 · Total-failure regression gate.** *(release blocker)*
Given a connection with open findings, when a scan runs in which every target fails, then **zero**
findings are resolved, the scan is `failed`, and all findings are marked stale.

**AC-FIND-6 · Human decisions survive scans.**
Given a finding marked `risk_accepted`, `suppressed`, or `false_positive`, when a later scan still
observes the failure, then the status is unchanged and only `last_seen_at` updates.

**AC-FIND-7 · Status changes are audited.**
Given any status transition, then a `FindingStatusChange` records from, to, actor, reason, and
timestamp. A transition without a reason is rejected.

**AC-FIND-8 · Regression reopens.**
Given a `resolved` finding, when the same fingerprint fails again, then it returns to `open` with a
recorded regression transition and its original `first_seen_at`.

**AC-FIND-9 · Evidence is inspectable and minimal.**
Given any finding, then its evidence shows the exact facts consulted and the API calls that produced
them, and contains no full provider payload.

---

## AC-API · REST API

**AC-API-1 · OpenAPI.** The API serves a valid OpenAPI 3.1 document covering every endpoint, with
schemas, error responses, and examples; the TypeScript client generates from it without hand editing.

**AC-API-2 · Consistent errors.** Every error response is a problem-details document with a stable
machine-readable code, and contains no stack trace, SQL, internal path, or provider exception text.

**AC-API-3 · Authentication required.** Every endpoint except health, readiness, and login rejects
unauthenticated requests with `401`. Verified by a test that enumerates routes from the app and
asserts each has an auth dependency — so a new endpoint cannot be added without one.

**AC-API-4 · Authorization enforced.** A `viewer` receives `403` on scan start, finding status change,
and connection mutation. Verified per role, per route.

**AC-API-5 · No cross-organization access.** A request for an object belonging to another organization
returns `404`, not `403` or the object.

**AC-API-6 · Pagination and filtering.** All collections support cursor pagination and the documented
filters (provider, connection, severity, resource type, policy, status, scan) with a bounded page size.

**AC-API-7 · Health and readiness.** `/healthz` reports process liveness without touching the
database; `/readyz` reports database connectivity and migration state and returns non-200 when the
schema is behind.

**AC-API-8 · Demo is labelled.** Every response and export involving demo data carries an `is_demo`
indicator.

---

## AC-CLI · Command-line interface

**AC-CLI-1 · Remote mode.** With a server URL and API token, the CLI performs connection management,
scan start/status/list/cancel, finding listing, and export.

**AC-CLI-2 · Local mode.** `mcs scan --local --provider demo` completes with no server, no database,
and no network, and writes valid JSON.

**AC-CLI-3 · Exit codes.** `0` clean, `2` findings at or above `--fail-on`, `3` scan failed, `4`
partial results. Documented and tested.

**AC-CLI-4 · Machine-readable output.** `--output json` emits only valid JSON on stdout, with logs on
stderr, and no ANSI codes when not a TTY.

**AC-CLI-5 · No secrets in arguments.** The CLI accepts no cloud credential as an argument or flag;
attempting to pass one produces a clear refusal.

---

## AC-UI · Dashboard

**AC-UI-1 · Views exist.** Overview, connections, connection detail, scans, scan detail, assets, asset
detail, findings, finding detail, policy catalog, policy detail.

**AC-UI-2 · Four states per view.** Each list view renders a designed empty, loading, partial-failure,
and error state. The partial-failure state names what failed and what that means for completeness.
Verified against demo data that produces each state.

**AC-UI-3 · Filtering.** Findings can be filtered by provider, connection, severity, resource type,
policy, status, and scan; filters combine; active filters and the result count are visible.

**AC-UI-4 · Shareable URLs.** Filter state is reflected in the URL, and loading that URL reproduces the
view.

**AC-UI-5 · Finding detail is complete.** Shows severity, resource with native ID, evidence facts, the
API calls that produced them, risk explanation, remediation guidance with required permissions,
compliance mappings with the disclaimer, status with history, and scan provenance.

**AC-UI-6 · Demo is unmistakable.** A persistent banner appears whenever demo data is in view, plus a
per-row badge in mixed lists.

**AC-UI-7 · Provider strings are rendered safely.** Given a resource name, tag, or IAM document
containing HTML, script, or control characters, then it renders as inert text everywhere it appears.
A dedicated demo resource carries hostile strings so this is exercised continuously.

**AC-UI-8 · Responsive.** All views are usable from 360 px to 1920 px with no horizontal page scroll;
wide tables scroll within their own container.

**AC-UI-9 · Status change requires a reason.** The UI does not permit a status transition without one.

---

## AC-RPT · Reporting

**AC-RPT-1 · JSON export.** Full-fidelity, schema-versioned, validates against the published schema,
includes a provenance block (`generated_at`, `engine_version`, `policy_bundle_version`, scan IDs,
`contains_demo_data`).

**AC-RPT-2 · CSV export.** Flattened findings with a stable column order and a documented header.

**AC-RPT-3 · CSV formula injection is neutralized.** Given a finding field beginning with `=`, `+`,
`-`, `@`, tab, or carriage return, then the exported cell is prefixed so a spreadsheet treats it as
text. Tested with a demo resource named `=cmd|'/c calc'!A1`.

**AC-RPT-4 · Grouped summaries.** Findings can be grouped by provider, severity, policy, resource
type, and connection, with counts consistent with the underlying list.

**AC-RPT-5 · Scan report.** A per-scan report includes statistics, errors by category, coverage gaps,
and the resulting findings.

**AC-RPT-6 · Exports are bounded.** A large export streams and respects a row cap without unbounded
server memory growth.

---

## AC-AUTH · Authentication

**AC-AUTH-1 · Bootstrap.** A documented command creates the organization and the first `owner`,
refusing weak passwords and never echoing the password.

**AC-AUTH-2 · Password storage.** Passwords are stored with the agreed KDF and parameters; the hash
is never returned by any endpoint.

**AC-AUTH-3 · Sessions.** Login issues an opaque, server-side session as a `HttpOnly`, `Secure`,
`SameSite` cookie with idle and absolute expiry. Logout invalidates it server-side immediately.

**AC-AUTH-4 · CSRF.** Cookie-authenticated state-changing requests without valid CSRF protection are
rejected.

**AC-AUTH-5 · API tokens.** Tokens are high-entropy, shown once, stored hashed, prefixed for secret
scanning, revocable with immediate effect, and comparison is constant-time.

**AC-AUTH-6 · Lockout.** Repeated failed logins lock the account temporarily, and responses do not
reveal whether the account exists.

---

## AC-DEMO · Demo mode

**AC-DEMO-1 · Zero-dependency start.** On a clean machine, `docker compose up` plus the documented
seed command yields populated demo findings for four providers in the dashboard, in under 10 minutes,
with no cloud credentials.

**AC-DEMO-2 · Determinism.** Seeding twice from a clean database produces identical assets, findings,
and fingerprints.

**AC-DEMO-3 · Exercises the hard paths.** A demo scan produces: findings at every severity, at least
one `pass`, at least one `not_applicable`, at least one `insufficient_data` from a simulated
permission denial, multi-page pagination on at least two collectors, a throttle-then-succeed retry, a
target-level failure yielding `partially_completed`, a `service_disabled` skip, and a `parse_error`.

**AC-DEMO-4 · No network.** The demo adapter makes no network call, asserted by test.

**AC-DEMO-5 · Same path as real providers.** Demo runs through the identical collector →
normalizer → policy → persistence pipeline, asserted by the shared adapter conformance suite.

---

## AC-ENG · Engineering

**AC-ENG-1 · Migrations.** Apply cleanly from empty and from the previous release; `readyz` reports
pending migrations; migrations run as a separate role from the application.

**AC-ENG-2 · Structured logging.** Logs are JSON with a correlation ID, and every record passes
through the redaction filter.

**AC-ENG-3 · Redaction is verified.** Given log input containing realistic credential patterns for all
four providers, then no credential material appears in the output. This is a dedicated test with a
pattern corpus, not an assumption.

**AC-ENG-4 · Configuration validation.** Invalid or missing required configuration prevents startup
with a precise message naming the setting; the message never prints a secret value.

**AC-ENG-5 · API process has no cloud access.** Starting the API with provider credential environment
variables present causes a refusal to start. No module reachable from the API router imports a
provider SDK, asserted by test.

**AC-ENG-6 · CI gates.** Every pull request runs format, lint, type check, import rules, unit,
integration, API, policy, adapter conformance, determinism, and demo end-to-end tests, plus dependency
and secret scans.

**AC-ENG-7 · SBOM.** A release produces an SBOM covering Python and JavaScript dependencies.

**AC-ENG-8 · Container hardening.** Images run as a non-root user, contain no build toolchain in the
runtime layer, and pass an image vulnerability scan at high/critical.

**AC-ENG-9 · Read-only proof.** An automated check confirms no cloud mutation operation is reachable
from any adapter, and the operation allowlist rejects an unlisted operation before any request.
