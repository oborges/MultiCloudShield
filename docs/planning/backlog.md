# Backlog

Status: living document
Last updated: 2026-08-05

Work beyond v0.1.0. Items in the MVP live in [implementation-plan.md](implementation-plan.md); the
in/out boundary is [mvp-scope.md](../product/mvp-scope.md).

Each item states **why it is not in v0.1.0**, because "we ran out of time" and "we decided against it"
need different treatment later.

Sizing: **S** days · **M** 1–2 weeks · **L** 3+ weeks · **XL** a project of its own.

---

## 1. Near term — the first things after v0.1.0

Ordered by expected value per unit of effort.

| # | Item | Size | Why not in v0.1.0 | Notes |
| --- | --- | :-: | --- | --- |
| B-01 | **Scheduled scans** | S | Manual trigger proves the pipeline; scheduling adds an unattended failure mode before we have operational experience | `procrastinate` ships periodic tasks, so this is mostly UI, permissions, and a per-connection cadence |
| B-02 | **Finding trend over time** | M | Needs several scans' history to be meaningful, which does not exist on day one | Data is already there — `first_seen`, `last_seen`, status changes. Mostly aggregation queries and a chart |
| B-03 | **More collectors per provider** | L | Five domains give better coverage per unit of effort than breadth | Compute posture (public IPs, IMDSv1 enabled, disk encryption) is the highest-value next domain |
| B-04 | **IMDS posture policy** | S | Needs a compute collector (B-03) | High value: AWS IMDSv2 defaults to `optional`, so IMDSv1 remains accepted. Check `HttpTokens=required` + `HttpPutResponseHopLimit`. IBM's metadata service is disabled by default — flag it being enabled unnecessarily |
| B-05 | **PostgreSQL row-level security** | M | Application-layer scoping is sufficient for one organization; RLS needs careful pooling interaction and thorough testing to avoid false confidence | The column and scoping discipline already exist, so this is a migration plus a session-variable hook, not a query audit |
| B-06 | **OIDC SSO** | M | Would make the 10-minute quickstart impossible as a hard dependency | The `AuthProvider` seam exists. Document Keycloak and Dex. **Zitadel is AGPL-3.0** — legal review before bundling |
| B-07 | **Suppression rules as data** | M | Per-finding suppression covers the MVP need | Suppress by tag, name pattern, or resource type, with expiry. Must be pinned per scan for reproducibility |
| B-08 | **Published signed container images** | S | Shipping unsigned images for a security tool sets a bad precedent | Blocked on the release attestation work landing in Phase 13 |
| B-09 | **TypeScript 7 migration** | S | TS 7 was one month old at decision time; "boring technology" is a mandatory principle | Revisit when type-aware ESLint rules and bundler plugins have demonstrably caught up |
| B-10 | **Bulk inventory APIs as collectors** | M | Require extra enablement or permissions the operator may not have, and their coverage of security-relevant sub-resources is incomplete | Azure Resource Graph, GCP Cloud Asset Inventory, IBM Global Search. Fits the existing `Collector` contract with no change |

---

## 2. Medium term

| # | Item | Size | Why not in v0.1.0 | Notes |
| --- | --- | :-: | --- | --- |
| B-11 | **Organization / folder / management-group scanning** | L | One scope per connection keeps the credential and authorization model simple | Would also **resolve GCP's audit-config limitation** ([provider-coverage-matrix.md](provider-coverage-matrix.md) §6.2), where parent-scope configuration is invisible at project scope |
| B-12 | **Per-connection authorization** | M | Multiplies the authorization matrix and every filter path | The real requirement for consultancies. Needs a decision on whether it composes with or replaces roles |
| B-13 | **Multi-tenancy with hard isolation** | XL | The seam exists; the feature is unvalidated | Requires B-05 first, plus per-tenant quotas, log routing, and org provisioning |
| B-14 | **User-authored policies via CEL** | L | A policy is executable code in a credential-holding process | `cel-python` is the intended engine. **Supply-chain note: the package is `cel-python`, the import is `celpy`; the PyPI package named `celpy` is an unrelated squat** |
| B-15 | **Policy parameters per connection** | M | Parameters must be pinned per scan for reproducibility — a design task of its own | E.g. permitted public CIDRs, credential age thresholds |
| B-16 | **Asset relationship graph and traversal** | L | No v0.1.0 policy depends on relationships | Relationships are already collected. Enables cross-asset policies and attack-path style reachability |
| B-17 | **SARIF export** | S | JSON and CSV cover the MVP need | Would let findings surface in GitHub code scanning — a natural fit for the CI/CD user |
| B-18 | **HTML report that prints cleanly** | M | PDF was deferred; HTML is the sane path to the same outcome | Explicitly **not** a headless-browser PDF pipeline |
| B-19 | **Notification integrations** | M | Adds an arbitrary-destination outbound egress path | **Requires the full SSRF treatment**: blocklist link-local and RFC 1918 (including IPv6 `fd00:ec2::254`, `fd20:ce::254`), resolve once and connect to the validated IP against DNS rebinding, no redirects, never send findings to an unvalidated host ([threat-model.md](../architecture/threat-model.md) §T4) |
| B-20 | **Kubernetes manifests / Helm chart** | M | Shipping a chart means supporting it, and there is no evidence of demand | Architecture already permits it: stateless API and workers, external PostgreSQL |
| B-21 | **Evidence signing** | M | In v0.1.0 the database is trusted infrastructure; a key stored beside the data it protects is theatre | `content_digest` is already the foundation. Needs a real key-custody story to be worth anything |
| B-22 | **OpenTelemetry traces and metrics** | S | Adds a dependency tree, a collector to run, and an egress path before we have evidence we need it | Clean seam exists at structlog processors and FastAPI middleware. **Must remain opt-in — no telemetry by default, ever** |
| B-23 | **Additional providers** | L each | Four is already the largest work item | Oracle Cloud, Alibaba Cloud, Kubernetes posture. The adapter contract is designed for this |
| B-24 | **Public-domain NIST control text** | S | v0.1.0 applies one uniform identifier-only rule for a consistent authorial voice | NIST publications are public domain (17 U.S.C. §105), so this is legally clear and purely additive — identifiers and versions are already stored ([ADR-0024](../architecture/decisions/0024-compliance-mapping-policy.md)) |

---

## 3. Requires a decision before it can be scheduled

Not sized, because the shape depends on the answer.

| # | Question | Why it matters |
| --- | --- | --- |
| B-25 | **Does automated remediation ever get built?** | Deferred, possibly permanently ([vision.md](../product/vision.md) §8). If it happens it must be a **separate, separately-permissioned, opt-in component with its own credential path — never a flag on the scanner.** The moment it becomes a scanner option, the read-only guarantee is gone |
| B-26 | **CIS SecureSuite Product Vendor Membership?** | The only clean path to shipping real CIS Benchmark content. Paid, and it would change the compliance feature substantially. Requires counsel and a funding answer |
| B-27 | **Does the CLI need a static binary?** | Would make the CI/CD story much better, and is awkward with four cloud SDKs' data files and certificate bundles. Decide on user feedback, not speculation |
| B-28 | **Third-party policy bundles: sandbox or trust?** | Currently trust, opt-in, documented. A subprocess or WASM sandbox is the alternative. The `Collector` and policy contracts are narrow enough to serialize across a process boundary, so this stays open |
| B-29 | **Managed PostgreSQL support** | Should work, but queue polling, transaction behavior, and connection-pooler compatibility are untested. Needs verification before it is claimed |

---

## 4. Known gaps to revisit on external change

Items blocked on someone else, tracked so they are not rediscovered.

| # | Gap | Revisit when |
| --- | --- | --- |
| B-30 | **IBM audit logging and KMS posture** | IBM ships maintained official Python SDKs for Activity Tracker / Cloud Logs and Key Protect. Currently none exists ([provider-coverage-matrix.md](provider-coverage-matrix.md) §6.3) |
| B-31 | **`azure-mgmt-authorization` on a 2023 stable release** | A new stable release ships. Only preview releases have followed 4.0.0 (2023-07-25), and this package provides role assignments — a core IAM posture read |
| B-32 | **Rego as a policy representation** | A maintained pure-Python Rego engine appears, or third-party policy portability becomes a real user requirement. Today the only `pip install`-able option wraps a 47-star C++ project ([ADR-0009](../architecture/decisions/0009-policy-representation.md)) |
| B-33 | **Provider API drift not caught by CI** | A safe pattern emerges for out-of-band verification against disposable sandbox accounts. We will not put cloud credentials in CI ([testing-strategy.md](../architecture/testing-strategy.md) §10) |
| B-34 | **Python 3.14 support** | The dependency set supports it. Floor is 3.12, CI primary 3.13 ([ADR-0003](../architecture/decisions/0003-backend-language.md)) |
| B-35 | **Dependency-confusion standard defence** | A successor to PEP 708 is accepted. PEP 708 was **rejected 2026-04-02**, so only operational controls exist (single index URL, hash pinning, defensive name registration) |

---

## 5. Explicitly not planned

Recorded so they are not proposed repeatedly. Each has a reason, not just a "no".

| Item | Reason |
| --- | --- |
| Compliance score or percentage per framework | Prohibited by CIS terms of use, and misleading regardless ([ADR-0024](../architecture/decisions/0024-compliance-mapping-policy.md)) |
| Reproducing external framework control text | Licensing. Identifier-only mapping is the settled approach |
| Data-plane inspection (object contents, database rows) | Permanently out of scope. No collector may read it |
| A hosted MultiCloudShield SaaS | Not the product ([vision.md](../product/vision.md) §3) |
| Storing cloud credentials, encrypted or otherwise | Permanent architectural constraint ([ADR-0013](../architecture/decisions/0013-credential-handling.md)) |
| Cost or quota checks | Adjacent, tempting, and not security posture |
| Live cloud credentials in CI | The exact anti-pattern this product exists to detect |
| Vulnerability or CVE scanning | A different product category |
| Custom identity provider | A category error |
