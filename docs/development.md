# Development

Prerequisites are Python 3.12+, uv, Node.js 24, npm, and either Docker with Compose v2 or Podman 5
with a Compose provider.

```bash
uv sync --extra dev
cd web && npm ci && cd ..
uv run ruff format --check .
uv run ruff check .
uv run mypy src/multicloudshield
uv run lint-imports
uv run pytest --import-mode=importlib
cd web && npm test -- --run && npm run build
```

PostgreSQL 18 is required for persistence tests and migrations; SQLite is intentionally unsupported.

```bash
docker compose up -d db
uv run alembic upgrade head
uv run alembic downgrade base
uv run alembic upgrade head
```

With Podman, replace `docker compose` with `podman compose`. PostgreSQL 18 requires the named volume
to be mounted at `/var/lib/postgresql`, not `/var/lib/postgresql/data`; this is already reflected in
the shipped Compose file. See the [demo workflow](demo-workflow.md#podman) for the current
`podman-compose` one-shot migration workaround.

Live tests are marked `live`, skipped unless their provider-specific environment is explicitly
configured, and must never run with production write-capable credentials.

```bash
MCS_RUN_LIVE_TESTS=1 MCS_LIVE_PROVIDER=aws MCS_LIVE_SCOPE_ID=ACCOUNT_ID \
  uv run pytest -m live tests/live
```
