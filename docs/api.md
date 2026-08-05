# REST API

The API is rooted at `/api/v1`; interactive OpenAPI is at `/api/v1/docs` and the machine document at
`/api/v1/openapi.json`. `/healthz` is liveness and `/readyz` verifies PostgreSQL.

Bootstrap prints an API token once. Use it as a bearer token:

```bash
curl -H "Authorization: Bearer $MCS_API_TOKEN" http://localhost:8080/api/v1/connections
curl -X POST -H "Authorization: Bearer $MCS_API_TOKEN" \
  "http://localhost:8080/api/v1/scans?connection_id=CONNECTION_UUID"
```

Collection endpoints accept a bounded `limit` and numeric `cursor`; the response contains `items`,
`next_cursor`, and metadata. Finding filters are `provider`, `severity`, `status`, `policy`,
`resource_type`, `connection`, and `scan`. Errors use `application/problem+json`. Cookie sessions
require `X-CSRF-Token` for state changes; bearer tokens do not.

Cloud credential values are rejected, never returned, and never belong in URLs. Connection payloads
carry only a credential mechanism and reviewed non-secret references.
