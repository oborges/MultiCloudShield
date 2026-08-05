# ADR-0016: Structured logs, health endpoints, no APM in the MVP

Status: accepted
Date: 2026-08-05

## Context

We need to debug scans that partially failed across four providers and many scopes, without ever
logging a cloud credential, a session ID, or unnecessary customer cloud metadata. The tool is
self-hosted, so telemetry must never leave the operator's deployment.

## Decision

**`structlog` 26.x emitting JSON, with a mandatory redaction processor; `/healthz` and `/readyz`; no
metrics or tracing exporters in v0.1.0.**

### Logging

- JSON to stdout, one event per line. The operator's platform handles shipping and retention.
- Every record carries `correlation_id` (request or job), plus `organization_id`, `scan_id`,
  `connection_id`, `collector_id` where applicable — so a partial scan failure can be reconstructed by
  filtering on `scan_id`.
- **The redaction processor is installed on the root handler, not only on our logger.** This is
  deliberate: `botocore` at debug level will happily emit signed request headers, and third-party
  library logs are exactly where credentials escape.
- Redaction patterns cover, at minimum: AWS key ID prefixes (`AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 chars)
  and secret keys when contextually adjacent; GCP service account JSON fields (`private_key`,
  `private_key_id`, and the `"type": "service_account"` marker) and PEM private-key blocks; Azure
  `AccountKey=` and SAS `sig=` parameters (including sovereign suffixes such as
  `core.chinacloudapi.cn`); IBM `apikey`-family field names; `Authorization: Bearer|Basic`; JWTs; and
  database URLs with embedded passwords. The pattern corpus is a tested fixture
  ([AC-ENG-3](../../planning/acceptance-criteria.md)), not a hopeful regex.
- **Never logged**, per the OWASP Logging Cheat Sheet's exclusion list: passwords, access tokens,
  session identifiers (logged as a **salted hash** where correlation is needed), connection strings,
  encryption keys, and data classified above the log store. To that list we add CSPM-specific items:
  provider response payloads, `credential_reference` contents, and — in anything that could leave the
  deployment — cloud account, subscription, tenant, and resource identifiers.
- Structured *fields*, not interpolated strings, so provider-controlled text (a bucket name, a tag)
  cannot forge a log line ([threat-model.md](../threat-model.md) §T5).

### Health and readiness

| Endpoint | Checks | Semantics |
| --- | --- | --- |
| `/healthz` | Process is alive. **No database access.** | Liveness. A database outage must not trigger a restart loop |
| `/readyz` | Database connectivity, **migration state**, queue reachability | Readiness. Returns non-200 when the schema is behind the code |

Both are unauthenticated, return no internal detail, and are rate-limited.

### No metrics, tracing, or telemetry in v0.1.0

- **No outbound telemetry of any kind.** The product makes no network call the operator did not ask
  for ([security-boundaries.md](../security-boundaries.md) §6). For a security tool with read access
  to a customer's cloud, this is a trust property, not a missing feature.
- Scan statistics — the operational numbers that actually matter here (targets, API calls, throttles,
  retries, findings by severity, duration) — are persisted on `Scan.stats` and exposed through the
  API. That is more useful than a metrics endpoint for a tool whose unit of work is a scan.
- OpenTelemetry is a post-MVP addition with a clean seam: structlog processors and FastAPI middleware
  are where it attaches.

## Rejected alternatives

- **Plain `logging` with formatted strings.** Unparseable at scale, and string interpolation is how
  provider-controlled text gets injected into log lines.
- **Prometheus metrics in v0.1.0.** Would add an endpoint to secure and a scrape target to document
  for a single-worker deployment whose interesting numbers are already in the database.
- **OpenTelemetry tracing now.** Real value for debugging fan-out across scopes, but it adds a
  dependency tree, a collector to run, and an egress path to reason about — before we have evidence we
  need it.
- **Sentry or a hosted error tracker by default.** Would send exception data — which can contain
  provider metadata — to a third party. Never on by default; if added, opt-in with an explicit warning.
- **Redaction only on our own logger.** The failure mode is a third-party library at debug level. The
  root handler is the correct place.
- **Relying on redaction as the primary secret control.** Redaction is the last line of defence. The
  primary control is `SecretStr` ([ADR-0015](0015-configuration.md)) and never placing credentials in
  log-bound structures.

## Consequences

- Logs are verbose JSON. Fine for machines; `mcs` and development mode offer a human-readable
  renderer.
- The redaction processor costs CPU per record. Negligible, and non-negotiable.
- Operators wanting dashboards must derive them from the API or the database in v0.1.0. Documented.
- Every new log statement is reviewed for what it puts in the message body versus structured fields —
  part of the definition of done.
