# Known limitations in v0.1.0

- Live provider implementations are verified with mocked official SDK clients, not real cloud accounts.
- Scan cancellation is cooperative; an in-flight synchronous SDK call can run until its configured timeout.
- The local Compose topology uses one PostgreSQL role for migrations and application DML. Production
  operators should separate DDL and DML roles.
- The PostgreSQL queue adapter uses `SKIP LOCKED`, leases, retry scheduling, and cooperative cancellation.
  It does not use LISTEN/NOTIFY, so an idle worker polls once per second.
- v0.1.0 is single-organization in operational scope. Organization predicates are still applied to every
  protected object query, but mutually distrusting organizations should use separate deployments.
- Built-in username/password authentication has no MFA. Put production deployments behind an identity-aware
  reverse proxy until planned OIDC support lands.
- The dashboard exposes the core filters and bounded first pages; cursor traversal is currently API/CLI-first.
- No live integration, browser E2E, or large-estate performance test runs without explicit operator setup.
