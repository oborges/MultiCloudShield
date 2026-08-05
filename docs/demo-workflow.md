# Deterministic demo workflow

Demo mode uses no cloud credential and makes no network request. It emits AWS-, Azure-, GCP-, and
IBM-shaped assets, compliant and non-compliant facts, pagination, a one-time throttle, access denied,
a disabled service, malformed metadata, and a failed target. The resulting scan is intentionally
`partially_completed`; successful assets and findings remain usable.

## Docker Compose

```bash
cp .env.example .env
# Replace both placeholder values in .env.
docker compose up --build -d
docker compose run --rm api mcs bootstrap --email you@example.com
docker compose run --rm api mcs demo seed
```

## Podman

Podman 5.8.2 with `podman-compose` 1.6.0 has been exercised locally. Install a Compose provider if
`podman compose version` reports that neither `podman-compose` nor `docker-compose` can be found.

The `podman-compose` provider currently retains a stale native dependency edge after the one-shot
`migrate` service exits. The following sequence is the verified workaround; it keeps migration
ordering explicit and recreates only the API and worker without that stale edge:

```bash
cp .env.example .env
# Replace both placeholder values in .env.
podman build -t multicloudshield:0.1.0 .
podman compose up -d db
podman compose run --rm migrate
podman-compose up -d --no-build --no-deps --force-recreate api worker
podman compose exec api mcs bootstrap --email you@example.com
podman compose exec api mcs demo seed
```

If `podman-compose` is installed by Homebrew but the wrapper cannot find it, ensure
`/opt/homebrew/bin` is present in `PATH`.

Open <http://localhost:8080>, sign in, and inspect Connections, Scans, Assets, Findings, and Policies.
The finding detail view shows observed facts, provider-call provenance, original remediation, and an
audited status form. Exports are available from Findings.

The stateless equivalent is:

```bash
uv run mcs scan --local --provider demo --output json --out demo.json
```

Exit `4` is expected because the deterministic fixture includes partial failures.

The verified persisted demo baseline is 1 scan, 24 assets, 552 policy evaluations, and 37 findings.
Changes to those counts should be treated as behavior changes and reviewed deliberately.
