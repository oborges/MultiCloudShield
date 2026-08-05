# Risk Register

Status: living document
Last updated: 2026-08-05

Risks to delivering and operating MultiCloudShield v0.1.0. Security *threats* are in
[threat-model.md](../architecture/threat-model.md); this register covers delivery, product,
operational, and legal risk.

Scoring: **Likelihood** and **Impact** on 1–5. **Exposure** = L × I. Reviewed at each phase boundary
in the [implementation plan](implementation-plan.md).

| Band | Exposure | Handling |
| --- | --- | --- |
| Critical | 16–25 | Must be mitigated before the affected phase completes |
| High | 10–15 | Mitigation owned and tracked; reviewed each phase |
| Medium | 5–9 | Mitigation planned; accepted for v0.1.0 if cost exceeds value |
| Low | 1–4 | Monitored |

---

## Delivery risks

### R-01 · Provider API surface is larger than estimated — Exposure 16 (L4 × I4) · Critical

Four providers × five domains is the largest single work item, and per-provider effort estimates for
cloud SDK work are habitually optimistic. Azure and IBM in particular require more calls per logical
check than AWS.

**Mitigation.** The adapter contract is proven end to end against the demo adapter (Phases 3–4) before
any real provider; AWS then ships first among real providers (Phase 8) as the reference
implementation. Each subsequent provider is a separate, independently shippable phase with a fixed
collector budget. If a provider overruns, its *collector count* is cut, not its quality — the
coverage matrix records what was cut and why. A provider with three good collectors is shippable; a
provider with eight half-working ones is not.
**Early warning.** Azure (Phase 9) exceeding 1.5× the AWS collector effort.
**Owner.** Architecture lead. **Review.** Phase 8 exit.

### R-02 · Scope creep from "just one more check" — Exposure 12 (L4 × I3) · High

Adding checks is the most visible and most enjoyable work, and check count is the metric everyone
reaches for. It is also the least correlated with product value at this stage.

**Mitigation.** [mvp-scope.md](../product/mvp-scope.md) is the authoritative in/out list; a policy not
in [provider-coverage-matrix.md](provider-coverage-matrix.md) requires an explicit scope change.
The product bet ([vision.md](../product/vision.md) §6) is normalization + evidence + lifecycle, not
breadth. Depth on few checks beats breadth on many.
**Owner.** Product lead.

### R-03 · Frontend effort underestimated — Exposure 12 (L3 × I4) · High

Eleven views with filtering plus four designed states each (empty, loading, partial failure, error)
is roughly 44 state combinations. "Partial failure" states in particular are usually discovered late,
after the happy path is built and the layout will not accommodate them.

**Mitigation.** Build the four states for the **first** view (findings list) before building the
second view, so the state pattern is established and reusable. Generate the API client from OpenAPI
rather than hand-writing it. Use an unstyled accessible component library rather than authoring
primitives. Demo mode provides partial-failure data from day one, so the state is developed against
real data rather than imagined.
**Owner.** Frontend lead. **Review.** Phase 6 exit.

### R-04 · Solo or very small maintainer team — Exposure 12 (L4 × I3) · High

An ambitious scope with few contributors risks a half-finished repository — the common fate of
open-source CSPM projects.

**Mitigation.** Every phase ends in a working, demonstrable repository state
([definition-of-done.md](definition-of-done.md)), so stopping after any phase leaves something
useful rather than rubble. The vertical slice (Phases 0–6) is the minimum viable product on its own.
Provider phases (8–11) are genuinely parallelizable and are the natural first contribution.
**Owner.** Maintainer.

### R-05 · IBM Cloud coverage is thinner than the other three — Exposure 12 (L4 × I3) · High

IBM Cloud's Python SDK ecosystem and security-posture API surface are smaller and less uniformly
documented than AWS/Azure/GCP. There is a real chance some intended checks have no read-only
equivalent.

**Mitigation.** Treated as expected, not as failure — the architecture requires asymmetry to be
representable ([ADR-0008](../architecture/decisions/0008-normalized-asset-and-fact-model.md)). The
coverage matrix records "no equivalent" with the reason. IBM is scheduled **last** among providers so
its uncertainty cannot block the vertical slice, and a reduced IBM collector set is an acceptable
v0.1.0 outcome, documented rather than hidden.
**Owner.** Provider lead. **Review.** Phase 11 entry.

### R-06 · Fact schema churn invalidates stored facts and policies — Exposure 9 (L3 × I3) · Medium

Fact schemas will be wrong in their first version. Changing them after data exists means either
migrating stored JSON or accepting inconsistent history.

**Mitigation.** `schema_version` on every fact model from the first migration. Additive changes are
free; semantic changes bump the version and stored facts are re-derived on the next scan rather than
migrated. The golden-file corpus surfaces any evaluation change immediately.
**Owner.** Architecture lead.

---

## Product risks

### R-07 · False positives destroy trust faster than missed findings — Exposure 15 (L3 × I5) · High

A security tool that cries wolf gets muted, and a muted tool has negative value — it provides the
appearance of coverage with none of the substance.

**Mitigation.** `TriState`/`insufficient_data` prevents the largest class (guessing on unreadable
facts). Every finding carries inspectable evidence so a user can adjudicate rather than guess.
`false_positive` is a first-class status with a required reason, and those reasons are the primary
input to policy tuning. Policies ship with fixtures covering both pass and fail, including edge cases.
**Early warning.** `false_positive` exceeding 5% of findings on any policy in dogfooding.
**Owner.** Policy lead.

### R-08 · Users grant over-broad cloud permissions because narrow ones are hard — Exposure 12 (L4 × I3) · High

If the least-privilege path is painful, operators will attach a broad managed read-only policy — and
a worker compromise then yields far more access than intended
([security-boundaries.md](../architecture/security-boundaries.md) §9).

**Mitigation.** `required_permissions` is declared per collector in code, so generated least-privilege
policy documents cannot drift from what the code actually calls. The connectivity test reports
`degraded` with the exact missing action, making incremental permission granting practical.
Per-provider setup docs lead with the minimal policy and mention the broad managed policy only as a
fallback, with its trade-off stated.
**Owner.** Documentation lead.

### R-09 · Normalization loses information security engineers need — Exposure 9 (L3 × I3) · Medium

Over-normalizing to a common denominator produces facts too coarse to act on.

**Mitigation.** The `provider_specific` namespace exists precisely to carry what does not normalize,
as a first-class typed path rather than an afterthought. Asset detail views show
`provider_resource_type` and the native ID. Review rule: if a check cannot be expressed on normalized
facts, add a provider-specific fact rather than weakening the normalized one.
**Owner.** Architecture lead.

### R-10 · Demo mode diverges from real provider behaviour — Exposure 8 (L4 × I2) · Medium

If demo drifts, CI passes while real scans break — and demo is a primary test surface.

**Mitigation.** Demo implements the same `ProviderAdapter` contract, so a contract change breaks it at
build time ([ADR-0023](../architecture/decisions/0023-demo-mode-as-provider.md)). Adapter conformance
tests run against demo *and* every real adapter with the same assertions. Real adapters are
additionally tested against recorded fixtures from real API responses, so demo is never the only
evidence an adapter works.
**Owner.** Provider lead.

### R-11 · Compliance mappings mislead users into believing they are compliant — Exposure 8 (L2 × I4) · Medium

A user shows a "CIS 90%" dashboard to an auditor and gets a hard lesson.

**Mitigation.** Vocabulary is `supports` / `partially_supports`, never "compliant"
([ADR-0024](../architecture/decisions/0024-compliance-mapping-policy.md)). Every compliance view
carries a standing disclaimer. No aggregate "compliance score" is shipped in v0.1.0 — a percentage is
the specific artefact that gets screenshotted out of context.
**Owner.** Product lead.

---

## Operational risks

### R-12 · Scanning causes throttling or cost in a customer's cloud — Exposure 12 (L3 × I4) · High

An aggressive scanner can throttle a production account's own tooling. Some read APIs are also
billable at volume.

**Mitigation.** Bounded concurrency at three levels, exponential backoff with jitter, no retry on
authorization failures, and hard page/item caps
([data-flows.md](../architecture/data-flows.md) §3.2). Defaults are conservative and tunable
downward. Documentation states which APIs may incur cost. Manual-trigger-only in v0.1.0 means no
unattended scan storms.
**Owner.** Engine lead.

### R-13 · Large estates exhaust worker memory or exceed the scan deadline — Exposure 9 (L3 × I3) · Medium

**Mitigation.** Collectors stream (`Iterator[RawObservation]`) rather than accumulate; raw payloads
are discarded after normalization; per-target and per-scan deadlines produce `partially_completed`
rather than an OOM kill. A load test against a synthetic large demo estate (10 000+ assets) is part
of the definition of done for the engine phase.
**Owner.** Engine lead.

### R-14 · Worker crash or restart corrupts scan state — Exposure 8 (L2 × I4) · Medium

**Mitigation.** Lease + heartbeat + reaper requeue; every write step idempotent (asset upsert by URN,
evaluation upsert by unique key, finding upsert by fingerprint). A fault-injection test kills the
worker mid-scan and asserts recovery. Findings are reconciled in one transaction per connection, so a
crash cannot leave half-resolved findings.
**Owner.** Engine lead.

### R-15 · A permission regression silently resolves all findings — Exposure 10 (L2 × I5) · High

The single most dangerous failure mode in the product: a credential loses permissions, collectors
return nothing, absence is read as deletion, every finding closes, and the dashboard goes green.

**Mitigation.** Resolution requires **positive** evidence — a `PASS` from a succeeded target, or
absence confirmed by a *successful* full collection. `insufficient_data`, a failed target, and
cancelled scans never resolve anything ([data-flows.md](../architecture/data-flows.md) §6). Findings
not re-observed are marked stale in the UI. A dedicated regression test asserts that a scan in which
all targets fail resolves zero findings.
**Owner.** Engine lead. **Review.** Phase 4 exit — this test is a release gate.

---

## Legal and supply-chain risks

### R-16 · Copyright infringement via reproduced benchmark text — Exposure 10 (L2 × I5) · High

Embedding CIS/PCI/ISO control text in an MIT-licensed repository is redistribution we have no right
to perform, and it is the most common licensing mistake in this product category.

**Mitigation.** Identifier-only mappings with original prose, enforced by
[ADR-0024](../architecture/decisions/0024-compliance-mapping-policy.md), a CI check for verbatim
control-text patterns, and a reviewer confirmation on pull requests that add mappings.
**Owner.** Maintainer.

### R-17 · Dependency compromise reaches users through a release — Exposure 8 (L2 × I4) · Medium

**Mitigation.** Fully pinned, hashed lockfiles; automated update PRs reviewed like code;
vulnerability scanning on every PR; SBOM per release; third-party GitHub Actions pinned to commit
SHAs; least-privilege workflow tokens; no secrets exposed to fork-originated workflows.
**Owner.** Maintainer.

### R-18 · A contributor's policy bundle or adapter introduces malicious code — Exposure 8 (L2 × I4) · Medium

Policy bundles and adapters are executable code running in the process that holds cloud credentials.

**Mitigation.** v0.1.0 ships only first-party bundles and adapters; loading external ones is opt-in
with an explicit trust statement. Policy code is constrained (pure functions, banned imports enforced
by lint) so malicious behaviour is easier to spot in review. Adapters are reviewed by a maintainer
with attention to the read-only operation allowlist.
**Owner.** Maintainer.

### R-19 · A load-bearing dependency stalls or changes stewardship — Exposure 9 (L3 × I3) · Medium

Verified 2026-08-05, three dependencies carry maintenance uncertainty: `azure-mgmt-authorization`'s
stable release is **4.0.0 from 2023-07-25** with only previews since — and it provides role
assignments, a core IAM posture read; `procrastinate` (~1.4k stars) is a load-bearing job queue;
`httpx` stewardship has already moved to Pydantic Services under the `httpx2` name, which is a
precedent for this happening again.

**Mitigation.** Each has a named, costed fallback rather than a hope: the job queue sits behind a
`JobQueue` interface with `pgqueuer` and a hand-rolled `SKIP LOCKED` queue as documented alternatives
([ADR-0006](../architecture/decisions/0006-background-execution.md)); Azure role reads use the 2023
stable rather than a preview dependency, with the limitation recorded in the coverage matrix; new
dependencies require a maintenance-status justification at review
([ADR-0022](../architecture/decisions/0022-dependency-management.md)). Rejecting a dependency for a
thin bus factor is a legitimate review outcome — [ADR-0009](../architecture/decisions/0009-policy-representation.md)
already did exactly that.
**Early warning.** No stable release from a load-bearing dependency for 12 months.
**Owner.** Maintainer. **Review.** Each phase boundary.

---

## Accepted risks (no further mitigation in v0.1.0)

| Risk | Why accepted |
| --- | --- |
| No RLS; tenant isolation is application-layer only | v0.1.0 is single-organization; separate deployments are the documented answer for mutually distrusting parties ([security-boundaries.md](../architecture/security-boundaries.md) §4) |
| No MFA in-product | Delegated to the IdP once OIDC lands; building MFA now duplicates what operators already have |
| Best-effort scan cancellation | Hard cancellation of in-flight SDK calls is not reliably achievable across four SDKs; bounded by the 30 s call timeout and documented |
| At-least-once job execution | Exactly-once across an external cloud API is not achievable; idempotent steps make replay safe |
| Single worker in the default deployment | The queue supports multiple consumers; scaling is a deployment change, not an architectural one |
| No PDF export | Requires a headless browser or heavy templating; disproportionate to MVP value ([mvp-scope.md](../product/mvp-scope.md) §7) |
| Polling instead of push in the dashboard | Scan volumes at MVP scale do not justify WebSockets |
