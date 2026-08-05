# Deterministic demo workflow

Demo mode uses no cloud credential and makes no network request. It emits AWS-, Azure-, GCP-, and
IBM-shaped assets, compliant and non-compliant facts, pagination, a one-time throttle, access denied,
a disabled service, malformed metadata, and a failed target. The resulting scan is intentionally
`partially_completed`; successful assets and findings remain usable.

```bash
cp .env.example .env
# Replace both placeholder values in .env.
docker compose up --build -d
docker compose run --rm api mcs bootstrap --email you@example.com
docker compose run --rm api mcs demo seed
```

Open <http://localhost:8080>, sign in, and inspect Connections, Scans, Assets, Findings, and Policies.
The finding detail view shows observed facts, provider-call provenance, original remediation, and an
audited status form. Exports are available from Findings.

The stateless equivalent is:

```bash
uv run mcs scan --local --provider demo --output json --out demo.json
```

Exit `4` is expected because the deterministic fixture includes partial failures.
