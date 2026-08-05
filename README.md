# MultiCloudShield

MultiCloudShield is a self-hosted, read-only Cloud Security Posture Management platform for AWS,
Azure, Google Cloud, and IBM Cloud. It normalizes cloud configuration, evaluates 23 deterministic
policies, and tracks evidence-backed findings through a REST API, CLI, and responsive dashboard.

Version 0.1.0 includes a deterministic four-cloud demo that needs no credentials or network access.
Live adapters use official SDKs and native credential chains; only the worker receives those
credentials, and all provider calls are constrained to reviewed read-operation allowlists.

## Quickstart

Prerequisites: Docker Engine and Compose v2.

```bash
cp .env.example .env
# Replace both placeholder values in .env.
docker compose up --build -d
docker compose run --rm api mcs bootstrap --email you@example.com
docker compose run --rm api mcs demo seed
```

Open <http://localhost:8080> and sign in with the password entered during bootstrap. The seeded scan
is intentionally partial: it retains successful assets/findings while demonstrating access denied,
service-disabled, malformed-data, throttling, and collector-failure states.

The same full engine runs without a database:

```bash
uv sync --extra dev
uv run mcs scan --local --provider demo --output json --out demo.json
```

Exit code `4` is expected for the scripted partial demo. The JSON remains valid and complete.

## Product flow

1. Add or select a connection.
2. Start a scan from the connection view or CLI.
3. A dedicated worker collects read-only facts with bounded concurrency, pagination, retry, and timeout.
4. The policy engine records pass/fail/unknown evaluations, immutable evidence, errors, and statistics.
5. Findings deduplicate by stable fingerprint; positive evidence resolves stale open findings while
   human suppression and risk decisions survive rescans.
6. Inspect, filter, change lifecycle status, and export results as safe JSON or CSV.

Unknown facts are never treated as safe, and one failed collector never discards successful results.

## Architecture

```text
Dashboard / CLI  ->  API process  ->  PostgreSQL  <-  Worker process  ->  Cloud control planes
                     no cloud creds                  provider creds       read-only operations
```

The modular monolith uses Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy async, PostgreSQL 18,
Alembic, Typer, React 19, TanStack Query, TypeScript, and Vite. The same image runs API, worker, and
migration roles. PostgreSQL is the only backing service.

## Commands

```bash
# Development verification
uv run ruff format --check .
uv run ruff check .
uv run mypy src/multicloudshield
uv run lint-imports
uv run pytest --import-mode=importlib
cd web && npm test -- --run && npm run build

# Remote CLI
export MCS_SERVER_URL=http://localhost:8080
export MCS_API_TOKEN=the-one-time-bootstrap-token
uv run mcs connection list
uv run mcs scan start --connection CONNECTION_UUID --wait
uv run mcs findings list --severity high --output json
uv run mcs findings export --format csv --out findings.csv
```

Interactive API documentation is served at <http://localhost:8080/api/v1/docs>. Health endpoints are
`/healthz` and `/readyz`.

## Documentation

- [Demo workflow](docs/demo-workflow.md)
- [Development and testing](docs/development.md)
- [REST API](docs/api.md) and [CLI](docs/cli.md)
- [Extensions](docs/extensions.md)
- [Operations, migrations, backup, and deployment](docs/operations.md)
- [Known limitations](docs/known-limitations.md)
- [AWS](docs/guides/aws.md), [Azure](docs/guides/azure.md),
  [GCP](docs/guides/gcp.md), and [IBM Cloud](docs/guides/ibm.md) setup
- [Architecture](docs/architecture/system-design.md) and [threat model](docs/architecture/threat-model.md)

## Security

MultiCloudShield never remediates cloud resources and never stores raw cloud secrets. Treat provider
metadata as hostile, keep credentials out of the API container, and place production HTTP behind TLS.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Compliance mappings use identifiers and original explanatory notes only; they do not
constitute certification.
