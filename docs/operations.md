# Operations, migrations, and backup

Run `alembic upgrade head` before starting API or worker processes. Upgrade one application version at
a time and take a database backup before schema changes. Downgrades are for development recovery;
production rollback should restore the matching database backup and application image together.

PostgreSQL contains cloud inventory, evidence, findings, and audit history, but no raw cloud secrets.
Treat backups as sensitive posture data. Use `pg_dump --format=custom`, encrypt and access-control the
artifact, and test `pg_restore` into PostgreSQL 18 periodically.

The shipped Compose deployment binds HTTP to loopback for local use. Production deployments must put
the API behind a TLS reverse proxy, keep provider credentials exclusively in the worker, restrict
worker egress to provider control-plane domains, and restrict API egress. Containers use a numeric
non-root user, read-only filesystem, dropped capabilities, and `no-new-privileges`.

JSON and CSV exports include provenance. CSV cells beginning with spreadsheet formula characters are
prefixed safely. Exports remain sensitive posture data and should inherit database-backup controls.
