# Development

Prerequisites are Python 3.12+, uv, Node.js 24, npm, Docker, and Compose v2.

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

Live tests are marked `live`, skipped unless their provider-specific environment is explicitly
configured, and must never run with production write-capable credentials.

```bash
MCS_RUN_LIVE_TESTS=1 MCS_LIVE_PROVIDER=aws MCS_LIVE_SCOPE_ID=ACCOUNT_ID \
  uv run pytest -m live tests/live
```
