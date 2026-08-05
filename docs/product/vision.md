# Product Vision

Status: accepted
Last updated: 2026-08-05

## 1. Problem

Organizations running workloads across more than one cloud have no affordable, inspectable way to
answer a simple question: **"where is my cloud configuration currently unsafe, and why?"**

The available options each fail a different group:

- **Commercial CSPM platforms** are priced for enterprises, are opaque about how a finding was
  reached, and require sending cloud inventory to a vendor's SaaS.
- **Provider-native tools** (AWS Security Hub, Microsoft Defender for Cloud, Google Security
  Command Center, IBM Security and Compliance Center) are good inside their own cloud and give no
  cross-cloud picture. An organization on three clouds gets three dashboards, three severity
  scales, three vocabularies, and no way to compare.
- **Existing open-source scanners** are strong at breadth of checks but generally produce a
  point-in-time report rather than a tracked posture: no finding lifecycle, no shared asset model
  across providers, limited UI, and per-tool policy formats.

The gap MultiCloudShield fills: **a self-hosted, auditable, multi-cloud posture product with one
asset model, one severity scale, one finding lifecycle, and evidence you can inspect.**

## 2. What MultiCloudShield is

An open-source, defensive, read-only Cloud Security Posture Management platform for AWS, Microsoft
Azure, Google Cloud Platform, and IBM Cloud.

It connects to cloud scopes their owners have explicitly authorized, discovers supported resources,
normalizes them into a shared asset model, evaluates them against testable policies, and reports
findings with severity, affected resource, evidence, risk explanation, remediation guidance,
compliance mappings, and full scan provenance — through a dashboard, a REST API, a CLI, and
JSON/CSV exports.

## 3. What MultiCloudShield is not

Stating this precisely is a product decision, not a disclaimer.

| Not | Why |
| --- | --- |
| A remediation/automation engine | v0.1.0 has no cloud write path at all. Guidance is text the operator reviews and runs themselves. |
| A CNAPP / workload runtime scanner | No agents, no eBPF, no container image scanning, no runtime threat detection. Configuration posture only. |
| A vulnerability scanner | We do not assess CVEs in VMs, images, or packages. |
| A compliance certification | Compliance mappings are our interpretation and support an audit; they are not one. |
| A cloud cost tool | Adjacent, tempting, and out of scope. |
| A SaaS | We ship software you run. There is no MultiCloudShield-operated service that sees your cloud. |
| An offensive tool | No exploitation, no credential harvesting, no lateral-movement simulation. Read-only assessment of configuration. |

## 4. Principles

These are load-bearing; every architectural decision in `docs/architecture/` traces to one.

1. **Defensive and read-only.** The v0.1.0 codebase contains no cloud mutation call. This is
   enforced structurally (adapter contract, CI check), not by policy.
2. **Least privilege, no stored secrets.** MultiCloudShield uses provider-native credential chains
   and stores only non-secret references to how credentials are obtained.
3. **Explain the verdict.** A finding without inspectable evidence is an opinion. Every finding
   carries the exact facts consulted and the API calls that produced them.
4. **Unknown is not safe.** A fact we could not read is `unknown`, produces `insufficient_data`,
   and is surfaced as a permission gap. Guessing in either direction is worse than admitting it.
5. **Partial results beat no results.** A failed region, subscription, project, or API call
   degrades the scan; it never crashes it.
6. **Determinism.** The same facts and the same policy bundle produce the same findings, on any
   machine, in any order.
7. **Asymmetry is honest.** Clouds are not equivalent. We do not invent checks to make a coverage
   matrix look symmetrical.
8. **Boring technology.** Mature, actively maintained, widely understood components. No
   infrastructure without a demonstrated MVP need.
9. **Usable without cloud credentials.** Demo mode is a first-class provider, not a fixture — so
   the product can be evaluated, developed, and tested by anyone.
10. **Our words.** All policy text is original. External control identifiers are referenced, never
    reproduced.

## 5. Users and the job they hire us for

| User | Job to be done | What success looks like |
| --- | --- | --- |
| Cloud security engineer | Know current exposure across all clouds and prove it changed | One dashboard, findings with evidence, trend across scans |
| Cloud platform engineer | Fix the specific misconfiguration without becoming a security expert | Finding detail with concrete steps and the exact permission needed |
| Security consultant | Assess a client's estate quickly and hand over a defensible report | Read-only role, scan, JSON/CSV export, no data leaves the client |
| SMB without a CSPM budget | Get past "we have no idea" | `docker compose up`, connect one account, useful findings same day |
| Developer in CI/CD | Fail a pipeline on new critical exposure | `mcs scan --local --fail-on high`, no server or DB required |
| Contributor / researcher | Add a provider, collector, or policy | Documented extension points, policies testable against fixtures offline |

## 6. Product bet

The differentiator is not check count. Anyone can add checks; check count is the easiest metric to
inflate and the least correlated with usefulness.

The bet is that **normalization plus evidence plus lifecycle** is what turns a scanner into a
posture product:

- **Normalization** lets an operator ask "which of my buckets are public?" once instead of four
  times in four vocabularies.
- **Evidence** makes a finding arguable — the operator can see the fact and the API call, disagree,
  and mark a false positive with a reason.
- **Lifecycle** turns a report into a workload: new, still open, resolved, accepted, suppressed —
  with history that survives a policy rewrite.

Everything in the MVP scope exists to make those three real for a small number of checks, rather
than to make a large number of checks shallowly.

## 7. Success criteria for v0.1.0

Concrete and falsifiable:

1. A newcomer runs `docker compose up`, opens the dashboard, and sees populated demo findings for
   four providers in under 10 minutes on a clean machine, with no cloud account.
2. A user connects one real AWS account with a documented read-only role and gets accurate findings,
   with any permission gaps reported as `insufficient_data` rather than as false passes.
3. The same scan run twice against unchanged infrastructure produces identical findings and
   identical finding IDs.
4. Killing the worker mid-scan leaves a recoverable scan, not a corrupt one.
5. A contributor adds a new policy with fixtures and no cloud account, and CI validates it.
6. A security reviewer can trace any finding from the dashboard back to the API call that produced
   it, and confirm from the code that no cloud write path exists.

## 8. Direction after v0.1.0

Sequenced by expected value, not by ease. Nothing here may compromise the v0.1.0 principles.

- **Near term:** scheduled scans; finding trend/drift over time; more collectors and policies per
  provider; OIDC SSO; Postgres row-level security; policy suppression rules as data.
- **Medium term:** multi-tenancy with hard isolation; org/folder/management-group hierarchy scanning;
  richer asset graph and attack-path style reachability using relationships already modelled;
  PDF/report templating; notification integrations (as an outbound-egress-controlled feature).
- **Explicitly deferred, possibly forever:** automated remediation. If it is ever built it will be
  a separate, separately-permissioned, opt-in component with its own credential path — never a flag
  on the scanner.

## 9. Licensing and governance

MIT (unchanged from the existing `LICENSE`). Contributions accepted under the same terms.
Security reporting process in [SECURITY.md](../../SECURITY.md); contribution rules in
[CONTRIBUTING.md](../../CONTRIBUTING.md).
