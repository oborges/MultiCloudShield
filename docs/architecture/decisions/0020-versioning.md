# ADR-0020: SemVer product, dated policy bundles, versioned API

Status: accepted
Date: 2026-08-05

## Context

Four things version independently and are frequently conflated: the product, the REST API, the policy
bundle, and the fact schemas. Conflating them causes real problems — a policy tweak should not force a
product major, and a fact schema change is not visible in a policy version.

## Decision

Four independent version streams.

### 1. Product — Semantic Versioning

`0.1.0` now. Pre-1.0, breaking changes may occur in minor releases, stated plainly in release notes.
At 1.0, SemVer applies strictly. "Breaking" includes: REST API contract changes, CLI flag or exit-code
changes, fact schema semantics, adapter or policy interface changes, and finding fingerprint
composition — because a fingerprint change silently orphans every existing finding.

### 2. REST API — path-versioned

`/api/v1`. Additive changes (new endpoints, new optional fields, new enum values a client can ignore)
ship within v1. Removals, renames, type changes, and semantic changes require `/api/v2`, with v1
supported for at least one minor release and a documented sunset.

The generated OpenAPI document is **committed and diffed in review**, so an unintended contract change
is visible in the pull request rather than in production.

### 3. Policy bundle — calendar-versioned, pinned per scan

`policy_bundle_version` uses `YYYY.MM.N` (e.g. `2026.08.1`). Individual policies additionally carry
their own SemVer.

Every `Scan` **pins** the bundle version at start, alongside `engine_version` and
`collector_set_digest`. This is what makes findings reproducible
([ADR-0010](0010-determinism-and-evidence.md)): given the stored facts and those three values,
evaluation must be byte-identical.

Per-policy SemVer rules:

- **Patch** — wording, references, remediation text. No verdict change.
- **Minor** — new facts consulted, narrowed applicability, added compliance mapping. Verdicts may
  change for some assets.
- **Major** — logic change altering verdicts for existing assets, or a severity re-score.

A policy's **ID never changes**, and the finding fingerprint deliberately excludes `policy_version`
([domain-model.md](../domain-model.md) §6.1) — so a policy rewrite updates existing findings instead
of resolving them and raising new ones. Preserving triage history across policy edits is worth more
than the tidiness of a fresh finding.

### 4. Fact schemas — integer `schema_version` per resource type

Additive optional fields are backward compatible. A semantic change bumps the version, and stored
facts are **re-derived on the next scan** rather than migrated — the cloud is the source of truth, and
re-reading it is cheaper and more correct than transforming stale JSON.

### Compatibility statements

| Pair | Guarantee |
| --- | --- |
| CLI ↔ server | CLI supports the current and previous minor; version mismatch produces a clear warning |
| Database ↔ code | Forward-only migrations; `/readyz` fails when the schema is behind |
| Policy bundle ↔ engine | The bundle declares a minimum engine version; loading fails fast on mismatch |
| Exports | Every export carries `schema_version` and a provenance block |

## Rejected alternatives

- **One version for everything.** A policy wording fix would force a product release, so policy fixes
  would batch up and ship late — the opposite of what a security tool needs.
- **SemVer for the policy bundle.** The bundle is a *collection*; "breaking" is not meaningful for it
  when individual policies already carry SemVer. A date says the useful thing: how current is it.
- **Header or query-parameter API versioning.** Path versioning is visible in logs, in bug reports, and
  in a browser address bar. For a self-hosted tool, discoverability beats elegance.
- **No API version until 1.0.** Adding a version prefix later is a breaking change for every client;
  starting with `/api/v1` costs nothing.
- **Including `policy_version` in the finding fingerprint.** Would make every finding "new" after a
  wording fix, destroying triage history and trust in the finding counts.
- **Migrating stored facts on schema change.** Complex, error-prone, and unnecessary when the authority
  is the live cloud.

## Consequences

- Release notes must state all four streams when they move together.
- The engine must handle multiple fact `schema_version` values during a rollout window — bounded, since
  facts are re-derived on the next scan.
- Pinning three versions per scan makes the `Scan` row slightly wider and makes "why did this finding
  change?" answerable, which is a question operators genuinely ask.
- Policy authors must choose the correct SemVer bump; the review checklist asks explicitly whether
  verdicts can change.
