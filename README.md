# MultiCloudShield

An open-source, read-only Cloud Security Posture Management (CSPM) platform for **AWS**, **Microsoft
Azure**, **Google Cloud Platform**, and **IBM Cloud**.

One asset model, one severity scale, one finding lifecycle — across four clouds, with evidence you can
inspect.

> ## Project status: planning and architecture
>
> **There is no application code in this repository yet.** This repository currently contains the
> complete architecture and implementation plan for v0.1.0. Everything described below is *designed*,
> not *built*.
>
> If you are looking for something to run today, there is nothing here yet. If you are looking to help
> build it, [CONTRIBUTING.md](CONTRIBUTING.md) and
> [docs/planning/implementation-plan.md](docs/planning/implementation-plan.md) are the place to start.

---

## The problem

An organization running workloads on more than one cloud gets three or four separate security
dashboards, each with its own vocabulary and severity scale, and no way to compare them. Commercial
CSPM platforms are priced for enterprises and are opaque about how a finding was reached. Existing
open-source scanners are strong on check breadth but generally produce a point-in-time report rather
than a tracked posture.

MultiCloudShield is a self-hosted, auditable, multi-cloud posture product: **normalization, evidence,
and finding lifecycle**, for a deliberately modest number of checks.

## What it will do

- Connect to cloud scopes their owners have explicitly authorized — **read-only, no stored secrets**
- Discover resources across object storage, network firewalls, identity, audit logging, and key
  management
- Normalize them into a shared asset model, so "which of my buckets are public?" is one question
  rather than four
- Evaluate testable, deterministic policies
- Report findings with severity, affected resource, **evidence**, risk explanation, remediation
  guidance, compliance mappings, and full scan provenance
- Present them through a web dashboard, REST API, CLI, and JSON/CSV export
- Run **without any cloud credentials at all**, via a first-class demo mode

## What it will not do

| Not | Why |
| --- | --- |
| Modify your cloud | v0.1.0 has **no cloud write path at all**. Remediation is guidance you review and run yourself |
| Store your cloud credentials | We store *which mechanism* to use and non-secret references. Never a value |
| Send your data anywhere | No telemetry, no update checks, no outbound calls you did not ask for. You run it |
| Scan workloads or CVEs | Configuration posture only. No agents, no image scanning |
| Certify compliance | Mappings are our interpretation and support an audit; they are not one |

---

## Design principles

The ones that shape everything else:

- **Unknown is not safe.** A fact we could not read is reported as `insufficient_data` with the exact
  missing permission — never as a silent pass. This is what makes least-privilege credentials safe to
  grant.
- **Partial results beat no results.** A failed region, project, or API call degrades a scan; it never
  crashes it.
- **Explain the verdict.** Every finding carries the exact facts consulted and the API calls that
  produced them, so you can disagree with it on the evidence.
- **Deterministic.** The same facts and policy bundle produce the same findings, on any machine.
- **Asymmetry is honest.** Clouds are not equivalent. We do not invent checks to make a coverage
  matrix look symmetrical, and we document what we cannot cover.

## Planned architecture

A modular monolith: one codebase, one container image, two process roles, PostgreSQL.

```
Dashboard / CLI  →  API process      →  PostgreSQL  ←  Worker process  →  Cloud APIs
                    (no credentials,                    (credentials,       (read-only)
                     no cloud egress)                    no user traffic)
```

The API process — the one exposed to the internet — holds **no cloud credentials and has no cloud
egress**. The worker, which holds credentials, accepts no user requests.

**Stack:** Python 3.12+ · FastAPI · Pydantic v2 · SQLAlchemy 2 · PostgreSQL 18 · procrastinate ·
React 19 · TypeScript · Vite · Tailwind. No Redis, Kafka, Elasticsearch, or Kubernetes.

---

## Planned quickstart

Not yet functional. This is the target experience, and it is an
[acceptance criterion](docs/planning/acceptance-criteria.md) — a newcomer reaching populated demo
findings for four providers in under 10 minutes on a clean machine.

```bash
git clone https://github.com/oborges/MultiCloudShield.git
cd MultiCloudShield
cp .env.example .env
docker compose up -d
docker compose run --rm mcs-api mcs bootstrap --email you@example.com
docker compose run --rm mcs-api mcs demo seed
# open https://localhost
```

Connecting a real account, once built:

```bash
mcs connection add --provider aws --scope-id 111122223333 \
    --mechanism aws_assume_role \
    --role-arn arn:aws:iam::111122223333:role/MultiCloudShieldAudit
mcs connection test --name prod-aws   # ok | degraded (names the missing permission) | failed
mcs scan start --connection prod-aws --wait
```

In CI, with no server and no database:

```bash
mcs scan --local --provider aws --scope 111122223333 --fail-on high
```

---

## Documentation

**Product** — [vision](docs/product/vision.md) · [MVP scope](docs/product/mvp-scope.md)

**Architecture** — [system design](docs/architecture/system-design.md) ·
[domain model](docs/architecture/domain-model.md) ·
[provider adapters](docs/architecture/provider-adapters.md) ·
[policy engine](docs/architecture/policy-engine.md) ·
[data flows](docs/architecture/data-flows.md) ·
[threat model](docs/architecture/threat-model.md) ·
[security boundaries](docs/architecture/security-boundaries.md) ·
[testing strategy](docs/architecture/testing-strategy.md) ·
[deployment](docs/architecture/deployment.md) ·
[25 ADRs](docs/architecture/decisions/)

**Planning** — [implementation plan](docs/planning/implementation-plan.md) ·
[backlog](docs/planning/backlog.md) ·
[acceptance criteria](docs/planning/acceptance-criteria.md) ·
[definition of done](docs/planning/definition-of-done.md) ·
[risk register](docs/planning/risk-register.md) ·
[provider coverage matrix](docs/planning/provider-coverage-matrix.md)

Start with the [implementation plan](docs/planning/implementation-plan.md) — it is ordered, and each
phase ends in a working repository state.

## Contributing

Contributions are welcome, especially provider adapters, collectors, and policies — the most
parallelizable work and the natural first contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

Security issues: **do not open a public issue.** See [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE). Framework names referenced in compliance mappings are trademarks of their owners;
MultiCloudShield is not endorsed by or affiliated with them, and all policy text is original.
