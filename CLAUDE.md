# CLAUDE.md

Instructions for Claude Code and other AI agents working in this repository. Human contributors should
read [CONTRIBUTING.md](CONTRIBUTING.md) — this file assumes that as context and adds what an agent
specifically needs.

---

## What this project is

MultiCloudShield is an open-source, **defensive, read-only** Cloud Security Posture Management platform
for AWS, Azure, GCP, and IBM Cloud. It discovers cloud resources, normalizes them into a shared asset
model, evaluates security policies, and reports findings with evidence.

**Current state (2026-08-05): planning and architecture only.** The repository contains documentation
and no application code. Everything in `docs/` describes what will be built. Do not describe unbuilt
behaviour in the present tense anywhere outside `docs/`.

## Read before implementing

Do not start coding from this file alone.

| Doing | Read first |
| --- | --- |
| Anything | [implementation-plan.md](docs/planning/implementation-plan.md) — find the current phase |
| Domain, models, database | [domain-model.md](docs/architecture/domain-model.md) |
| A provider or collector | [provider-adapters.md](docs/architecture/provider-adapters.md), [provider-coverage-matrix.md](docs/planning/provider-coverage-matrix.md) |
| A policy | [policy-engine.md](docs/architecture/policy-engine.md) |
| Anything security-relevant | [threat-model.md](docs/architecture/threat-model.md), [security-boundaries.md](docs/architecture/security-boundaries.md) |
| Changing the stack or a contract | [decisions/](docs/architecture/decisions/) — an ADR probably already rejected the idea, with reasons |

---

## Hard constraints

These are not preferences. A change that violates one should not be proposed, and CI will reject it.

1. **No cloud write operations.** v0.1.0 contains no code path that mutates a customer's cloud.
   Enforced by an operation allowlist, a CI mutating-verb check, and adapter conformance tests.
   Remediation guidance is text the user reviews and runs themselves — **never executed by us**.
2. **No cloud credentials stored, logged, exported, or accepted by the API.** We store the credential
   *mechanism* and non-secret references (role ARNs, service account emails, environment variable
   *names*). Never a value.
3. **Never guess an unknown fact.** A fact we could not read is `TriState.UNKNOWN`, produces
   `insufficient_data`, and surfaces as a permission gap. Defaulting to `False` creates silent false
   negatives; defaulting to `True` creates alert fatigue. Both are worse than admitting ignorance.
4. **A finding is never resolved without positive evidence.** A `PASS` on a *succeeded* target, or
   absence confirmed by a *successful* full collection. Never from `insufficient_data`, a failed
   target, or a cancelled scan. This is the failure mode that would turn the dashboard green during a
   permission outage.
5. **Never overwrite a human decision.** `risk_accepted`, `suppressed`, and `false_positive` survive
   scans; only `last_seen_at` updates.
6. **Provider data is untrusted input.** Resource names, tags, and IAM documents are attacker-
   controllable. Parse strictly, cap size and depth, strip control characters, escape at every sink.
7. **No external framework control text.** Compliance mappings store identifiers + our own note only.
   No compliance score or percentage, anywhere.
8. **No new infrastructure.** No Redis, Kafka, Elasticsearch, or Kubernetes. PostgreSQL is the only
   backing service.
9. **Everything in English** — identifiers, filenames, comments, docs, UI copy, commit messages.

## Never do these

- Add a dependency without justifying it in the pull request, including its maintenance status.
- Put a real cloud account ID, ARN, subscription GUID, project ID, or credential in code, tests,
  fixtures, or documentation. **Fixtures are the most likely place for this to slip in**, and CI
  checks them specifically.
- Add an API endpoint without an authentication dependency, a declared role, and an org-scoped
  repository.
- Add a policy without fixtures covering pass, fail, and `insufficient_data`.
- Change a technology decision without a superseding ADR.
- Use `pickle`, `marshal`, `yaml.load` (use `safe_load`), `eval`, or `exec`.
- Import a provider SDK from anything reachable by the API router.
- Perform I/O inside a policy `evaluate()` function.
- Update the determinism golden file as if it were a fixture. A diff there means findings on real
  estates will change — explain why in the pull request.

---

## Architecture in one page

**Modular monolith**, one image, two process roles that differ in capability:

- **API process** — serves HTTP. **No cloud credentials, no cloud egress.** Asserts this at startup.
- **Worker process** — runs scans. **Has cloud credentials.** Accepts no user requests.

That separation is the highest-value security control in the design. Do not weaken it for convenience.

```
config/  core/  facts/  policy/  providers/  engine/  persistence/  queue/  api/  worker/  cli/
```

Dependency rules (enforced by import-linter):

- `core` and `facts` import nothing above them.
- `policy` imports no provider and no persistence code.
- `providers` imports no persistence and no API code.
- **`api` imports no provider SDK.**
- `engine` does **not** depend on persistence — that is what makes `mcs scan --local` a mode rather
  than a second implementation.

### The three planes

`Provider plane` (raw SDK responses, never persisted) → `Fact plane` (typed, validated, `TriState`) →
`Domain plane` (assets, findings, evidence). Normalizers are the validation boundary. **No provider
type crosses into the core domain.**

### Stack

Python 3.12+ (CI 3.13) · FastAPI · Pydantic v2 · SQLAlchemy 2 async + `psycopg` 3 · Alembic ·
**PostgreSQL 18** (required — `uuidv7()`) · `procrastinate` job queue · Typer · **`httpx2`** (not
`httpx`) · structlog · React 19 + TypeScript 6 + Vite + TanStack Query + Tailwind 4 · `uv` · Ruff ·
mypy strict · pytest.

---

## Things that will trip you up

Verified 2026-08-05. Each of these has already cost someone time.

| Trap | Reality |
| --- | --- |
| `@app.on_event`, `@app.middleware`, `@app.route` | **Removed in Starlette 1.0.** Use `lifespan` and explicit `routes=`/`middleware=` lists. Most FastAPI examples online are wrong on this |
| `import httpx` | Stewardship moved to **`httpx2`**. Starlette's TestClient docs deprecate plain `httpx`. Consequence: `responses` will not intercept it — use `vcrpy` or RESPX |
| `router.routes` as a flat list | FastAPI 0.137.0 made it a **tree**. The route-audit test must walk it |
| Lazy relationship loading | **Raises under async SQLAlchemy.** Use `selectinload`/`joinedload`; `lazy="raise"` is set globally |
| `Config(retries={"max_attempts": N})` in boto3 | `max_attempts` on `Config` **excludes** the initial request; the config-file form **includes** it. Always use `total_max_attempts` |
| Trusting `DefaultAzureCredential` | Set `AZURE_TOKEN_CREDENTIALS=prod`, or it silently picks up an operator's `az login` identity |
| Azure blob public access | Read `publicAccess` from the **ARM control plane** (`blob_containers.list()`). Never call `listkeys` — it is a *write* action returning full data-plane keys |
| GCP empty result | Distinguish **`SERVICE_DISABLED`** from "zero resources". Conflating them is a false all-clear |
| GCP audit config | Lives in `auditConfigs` **inside the IAM policy**. Parent-scope config is invisible at project scope → return `insufficient_data`, not a finding |
| `iam:GenerateCredentialReport` | **Starts a job and creates account state.** Not a pure read. Never call it by default |
| CloudTrail multi-region trails | Visible from every region. **Deduplicate by `TrailARN`** or you generate duplicate findings |
| `pip install celpy` | The PyPI package `celpy` is an **unrelated squat**. The real one is `cel-python`, imported as `celpy` |
| SQLite for tests | Not supported. Its JSONB is incompatible with PostgreSQL's and there is no GIN equivalent. Use the PostgreSQL container |

---

## Working style in this repository

- **Match the surrounding code** — naming, comment density, idiom. Do not introduce a new pattern
  where one exists.
- **Small, coherent pull requests.** One change. Unrelated refactors go separately.
- **Tests that fail without the change.** Especially error paths: partial failure, permission denied,
  empty results. The happy path is the easy part and the least valuable to test here.
- **Run it, do not just test it.** For engine changes, run `mcs scan --local --provider demo`. For API
  changes, make a real request. For UI changes, open the view.
- **Report outcomes honestly.** If tests fail, say so with the output. If a step was skipped, say so.
  A security tool built on optimistic status reports is a contradiction.
- **When two interpretations would produce materially different products and no safe default exists,
  ask.** Otherwise decide and record the decision.

## Commands

```bash
uv sync                                    # install
docker compose up -d                       # postgres + api + worker
uv run alembic upgrade head                # migrate
uv run mcs demo seed                       # deterministic demo data
uv run mcs scan --local --provider demo    # end-to-end, no server, no network

uv run pytest                              # all tests
uv run pytest tests/policy                 # policies only, offline
uv run ruff format . && uv run ruff check --fix .
uv run mypy src
uv run lint-imports                        # module dependency rules
```

## Where things live

```
docs/product/         vision, mvp-scope
docs/architecture/    system-design, domain-model, provider-adapters, policy-engine,
                      data-flows, threat-model, security-boundaries, testing-strategy, deployment
docs/architecture/decisions/   25 ADRs — read before proposing a stack change
docs/planning/        implementation-plan, backlog, acceptance-criteria,
                      definition-of-done, risk-register, provider-coverage-matrix
```

Documentation is not decoration here. The architecture documents are the specification the
implementation is checked against, and a change that contradicts them needs the document updated in
the same pull request.
