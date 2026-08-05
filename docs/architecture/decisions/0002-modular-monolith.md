# ADR-0002: Modular monolith with two process roles

Status: accepted
Date: 2026-08-05

## Context

MultiCloudShield needs to serve an API and a dashboard, and separately execute long-running scans
that hold cloud credentials and call customer cloud APIs. Those are different workloads: one is
short-lived and internet-adjacent, the other is long-running and privileged.

Constraints: no Kubernetes requirement, no message broker, no premature microservices, and the whole
system must be runnable by one person with `docker compose up`.

## Decision

**One codebase, one container image, two entrypoint roles: `api` and `worker`.** Modules are
separated by dependency direction, not by network boundaries.

```
src/multicloudshield/
  core/          domain models, enums, errors        — depends on nothing
  facts/         fact schemas, TriState, FactView    — depends on core
  policy/        policy loader, engine, bundle       — depends on core, facts
  providers/     adapter contract + per-provider     — depends on core, facts
    aws/ azure/ gcp/ ibm/ demo/
  engine/        orchestrator, concurrency, retry    — depends on core, facts, policy, providers
  persistence/   SQLAlchemy models, repositories     — depends on core
  api/           FastAPI routers, schemas, auth      — depends on core, persistence, engine (enqueue only)
  worker/        job claiming, scan execution        — depends on everything
  cli/           Typer commands                      — depends on core, api client, engine
  config/        settings, validation                — depends on nothing
```

The dependency rule is enforced by an import-linter check in CI: `core` and `facts` may not import
anything above them; `providers` may not import `persistence` or `api`; `policy` may not import
`providers` or `persistence`; **`api` may not import any provider SDK.**

The two roles differ in capability, which is the security-relevant half of this decision
([security-boundaries.md](../security-boundaries.md) §2): the API process has no cloud credentials
and no cloud egress; the worker accepts no user requests.

## Rejected alternatives

- **Microservices (separate collector, policy, API services).** Every cross-service call would be a
  new serialization boundary, a new failure mode, and a new deployment unit, for a system whose
  entire state fits in one PostgreSQL database and whose load is a handful of scans per hour. It
  would also force us to build service-to-service authentication in v0.1.0. No evidence justifies it.
- **A single process running both API and scans.** Simpler to deploy, but a long scan competes with
  request serving, a worker crash takes down the API, and — decisively — the request-handling
  surface would hold cloud credentials. The security separation is worth one extra process.
- **Serverless functions per collector.** Ties the project to a specific cloud, makes local
  development and the `--local` CLI mode awkward, and complicates the "run it yourself" promise.
- **Plugin processes with IPC per provider.** Real isolation benefit if we ever load untrusted
  third-party adapters, but v0.1.0 ships only first-party adapters and a trusted policy bundle. The
  complexity buys nothing yet; the adapter contract keeps the option open.

## Consequences

- Deployment is two containers plus PostgreSQL. That is the floor, and it is a low one.
- Horizontal scale is available by running more worker containers — the queue already supports
  multiple consumers ([ADR-0006](0006-background-execution.md)) — without any architectural change.
- Module boundaries are enforced by a linter rather than by the network, so violations are caught in
  CI but are *possible* to write. This is an accepted trade: the linter is cheap, the network is not.
- If a future component genuinely needs independent scaling or isolation (for example, executing
  untrusted third-party policy bundles), extracting it is a well-defined refactor because the
  contracts already exist.
- One image means the API container ships worker code it never runs. Acceptable: it keeps the build,
  the version, and the dependency set singular.
