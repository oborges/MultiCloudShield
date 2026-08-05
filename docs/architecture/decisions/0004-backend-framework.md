# ADR-0004: FastAPI as the backend framework

Status: accepted
Date: 2026-08-05

## Context

We need a REST API with generated OpenAPI documentation good enough to generate a TypeScript client
from, request/response validation strong enough to be a security boundary, and a model layer we can
share between the API and the scan engine.

## Decision

**FastAPI 0.141.x**, on **Starlette 1.4.x**, **Pydantic 2.13.x**, served by **Uvicorn 0.52.x**.
Versions verified 2026-08-05.

Why it wins here specifically:

- **OpenAPI 3.1 output by default** (since FastAPI 0.99.0), which is what
  [`openapi-typescript`](0014-frontend-stack.md) consumes. The generated client is a build artifact,
  not hand-written code — so the API contract cannot silently drift from the frontend.
- **Pydantic v2 models are shared** between API schemas, configuration, and the fact schemas that
  carry policy correctness ([ADR-0008](0008-normalized-asset-and-fact-model.md)). One validation
  library across the whole system, in Rust, is a genuine simplification.
- Validation at the boundary is declarative and therefore reviewable, which matters for a security
  product.
- Async-native, which suits an API that mostly waits on PostgreSQL.

**Uvicorn** remains FastAPI's own documented default. Granian 2.8.0 is a legitimate performance
alternative and Hypercorn is slower-moving; neither buys anything for a control plane whose load is a
handful of dashboard users.

### Version hazards this project must plan for

Recorded here because they will otherwise be discovered by copying stale examples:

- **Starlette 1.0 (2026-03-22) removed the decorator and event APIs.** `@app.on_event`,
  `on_startup`/`on_shutdown`, `add_event_handler`, `@app.route`, `@app.middleware`,
  `@app.exception_handler` are gone. **Use `lifespan` and explicit `routes=` / `middleware=` /
  `exception_handlers=` lists.** Essentially every FastAPI tutorial published before 2026 is wrong on
  this point.
- **FastAPI 0.132.0 turned on `strict_content_type` by default** — requests posting JSON without a
  proper `Content-Type` now fail. Our CLI and generated client set it correctly; this is called out
  so a third-party integration failure is diagnosed in minutes rather than hours.
- **FastAPI 0.137.0 changed `router.routes`** into a tree of preserved `APIRouter`/`APIRoute`
  instances. Our route-enumeration audit test (which asserts every route has an auth dependency —
  [AC-API-3](../../planning/acceptance-criteria.md)) must walk the tree, not assume a flat list.
- FastAPI is still **0.x**. Pin exact versions in the lockfile and read release notes on upgrade.

## Rejected alternatives

- **Litestar 2.24.0.** Actively maintained and a genuine peer — arguably better DI and DTOs.
  Rejected on ecosystem size, not health: fewer answers, fewer examples, and a smaller contributor
  pool matter more for an open-source project than framework elegance.
- **Django + Django REST Framework 3.17.** Very actively maintained, and the admin plus auth would
  save real work. Rejected because it pulls the whole Django stack (ORM, admin, settings model) into
  a system whose core engine must stay framework-free for `mcs scan --local`
  ([ADR-0025](0025-stateless-local-scan-mode.md)), it is sync-first, and its OpenAPI 3.1 story is
  weaker — which directly costs us the generated frontend client.
- **Flask 3.1.** Maintained but slow-moving, with no built-in OpenAPI generation and no async-native
  story. We would rebuild what FastAPI provides.
- **A GraphQL API.** Wrong shape for this product: findings are filtered lists and detail views, CSV
  export is a first-class output, and REST plus OpenAPI gives us a generated client and
  property-based API testing (Schemathesis) for free.

## Consequences

- We take a dependency on a pre-1.0 framework with an active release cadence. Mitigated by exact
  lockfile pins, a dependency-update review process ([ADR-0022](0022-dependency-management.md)), and
  API tests that would catch behavioural regressions.
- The OpenAPI document is a **contract artefact**: it is committed, diffed in review, and its
  regeneration is a CI check. A silent schema change becomes a visible diff.
- FastAPI's dependency-injection system carries authentication, authorization, and `OrgScope`
  construction ([ADR-0012](0012-authorization-model.md)) — a small amount of framework coupling in
  the `api/` module, which is the module allowed to be coupled to it.
- `core/`, `facts/`, `policy/`, `providers/`, and `engine/` import **nothing** from FastAPI. Enforced
  by import-linter ([ADR-0002](0002-modular-monolith.md)), so the engine remains usable without a web
  framework.
