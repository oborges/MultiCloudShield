# ADR-0018: One image, two commands; a wheel for the CLI

Status: accepted
Date: 2026-08-05

## Context

Three consumption modes: a self-hosted server (API + worker + PostgreSQL), a CLI in a CI pipeline that
should need nothing but the CLI, and a development environment that must be reproducible.

## Decision

**One container image with two entrypoint commands, plus a separately installable Python package for
the CLI.**

```
docker compose up          # postgres + api + worker + reverse proxy
docker run … mcs-api       # uvicorn, no cloud credentials
docker run … mcs-worker    # scan executor, cloud credentials here
uv tool install multicloudshield   # or pipx — CLI only, for CI
```

- **One image, two commands.** Same code, same version, same dependency set; the difference is the
  entrypoint and the capabilities granted ([security-boundaries.md](../security-boundaries.md) §2).
  The API image ships worker code it never runs — an acceptable cost for a single build and a single
  version.
- **Multi-stage build**: a Node stage builds the SPA, a Python stage installs locked dependencies, and
  the runtime layer contains neither toolchain.
- Base `python:3.13-slim`. Not distroless: it complicates debugging and shell-based healthchecks, and
  no primary normative source recommends it — slim plus a multi-stage build is the pragmatic default.
- **Container hardening**, per the OWASP Docker Security Cheat Sheet: non-root numeric `USER`,
  `--cap-drop=ALL` (a read-only scanner needs no capabilities), `--security-opt=no-new-privileges`,
  read-only root filesystem with a `tmpfs` for scratch, and explicit memory/CPU limits. Compose sets
  all of these so the shipped defaults are the hardened ones.
- **Migrations run as a separate one-shot command** with a distinct, DDL-capable database role — not
  automatically at API startup. Automatic migration on startup causes concurrent-migration races when
  replicas scale and gives the application process DDL rights it should not have.
- **The CLI wheel is publishable and standalone.** `mcs scan --local` needs no server and no database
  ([ADR-0025](0025-stateless-local-scan-mode.md)), so the CI use case is `uv tool install` plus cloud
  credentials in the environment.
- **`uv` 0.12.x** manages dependencies, the lockfile, and Python versions
  ([ADR-0022](0022-dependency-management.md)).

### Deployment model

Docker Compose is the **only** supported v0.1.0 deployment. Detail in
[deployment.md](../deployment.md).

**Kubernetes is not an MVP requirement** and no manifests or Helm chart ship in v0.1.0. The
architecture does not prevent it — stateless API, stateless workers, external PostgreSQL — but
shipping a chart means supporting it, and there is no evidence of demand yet.

TLS is terminated by a reverse proxy included in the Compose stack. The application sets `Secure`
cookies and HSTS accordingly and does not terminate TLS itself.

## Rejected alternatives

- **Separate API and worker images.** Two builds, two version numbers, two dependency sets to keep in
  sync, and a real chance of a version skew between processes sharing a database schema. The
  capability difference is achieved by entrypoint and environment, which is sufficient.
- **A single process running API and worker.** Rejected in [ADR-0002](0002-modular-monolith.md) — it
  would place cloud credentials in the request-serving process.
- **Kubernetes manifests or a Helm chart in v0.1.0.** Explicitly out of scope. Adding them later is
  straightforward; supporting them badly now is not.
- **Running migrations automatically at API startup.** Convenient, and it causes races on scale-up and
  requires DDL rights in the application role. `/readyz` reports pending migrations instead, so the
  operator learns immediately without the application being able to act.
- **A single static binary (PyInstaller/Nuitka).** Attractive for CI, but fragile with four cloud SDKs'
  data files and certificate bundles. A published wheel plus the container image covers it.
- **Publishing to Docker Hub in v0.1.0.** Deferred until release signing and provenance attestation
  are in place ([ADR-0019](0019-ci-cd.md)); shipping unsigned images for a security tool sets a bad
  precedent.

## Consequences

- Operators need Docker and Compose. Documented as a prerequisite alongside PostgreSQL 18.
- The image carries both roles' dependencies, so it is larger than a split build. Acceptable.
- Migration is an explicit step in the upgrade runbook, which is where it belongs for a product whose
  data is an audit history.
- CI users install a wheel, not a container. The `--local` mode makes that genuinely sufficient.
- Kubernetes users must write their own manifests in v0.1.0. Stated plainly rather than implied.
