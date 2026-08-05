# ADR-0015: Validated environment configuration, fail fast

Status: accepted
Date: 2026-08-05

## Context

Configuration spans database connection, session and token policy, scan bounds, logging, retention,
and per-provider settings. A misconfigured security tool fails quietly — an over-permissive CORS
origin, a disabled TLS check, a retention window of zero — and quiet failure is the outcome to design
against.

## Decision

**`pydantic-settings` models, environment-first, validated at startup, process refuses to start on
invalid configuration.**

- One typed `Settings` tree, grouped by concern (`database`, `auth`, `scan`, `logging`, `providers`).
- Precedence: environment variables → `.env` (development only) → defaults. No configuration is read
  from the database, so a database compromise cannot change behaviour.
- Prefix `MCS_`, nested with `__` (`MCS_SCAN__MAX_CONCURRENT_TARGETS`).
- **Secret-bearing fields are `SecretStr`**, whose `repr` is redacted — so a settings object dumped
  into a log or an exception cannot leak. This is the primary control; the log redaction filter
  ([ADR-0016](0016-observability.md)) is the backstop.
- Validation goes beyond types: ranges on numeric bounds, URL scheme allowlists, mutually exclusive
  combinations, and **hard refusals** for dangerous states —
  - CORS wildcard combined with credentials → refuse to start;
  - production mode with a default or empty secret → refuse to start;
  - **cloud provider credential environment variables present in the API process → refuse to start**
    ([security-boundaries.md](../security-boundaries.md) §2).
- Startup logs the *effective* configuration with secrets redacted, so an operator can see what the
  process actually believes without reading four layers of override.
- There is deliberately **no setting to disable TLS verification** on provider clients. Absent
  settings cannot be turned on by accident.

## Rejected alternatives

- **A YAML/TOML configuration file as the primary source.** Environment variables compose better with
  containers, Compose, systemd, and secret managers — and keeping secrets out of files on disk is the
  point. A file would be a second path to audit.
- **Configuration stored in the database, editable via the UI.** Convenient, and it makes
  configuration a privilege-escalation target: an application compromise becomes a configuration
  compromise. Connection *metadata* is data; runtime security posture is not.
- **`os.environ` with manual parsing.** Untyped, unvalidated, and validation drifts from use. This is
  where "the retention window was the string `'0'`" bugs come from.
- **Lazy validation on first use.** Turns a deployment error into a runtime error hours later, in the
  middle of a scan. Fail at startup, where it is visible.
- **`dynaconf` / `python-decouple`.** Fine, but we already have Pydantic for validation everywhere
  else; a second validation library is a second thing to learn.

## Consequences

- Every configuration option must be declared in the `Settings` tree, documented with default, range,
  and effect, and covered by the definition of done. No undocumented environment variables.
- Startup fails loudly on misconfiguration. That is the intent, and it means the container's restart
  loop surfaces the message.
- Changing configuration requires a restart. Acceptable for a self-hosted tool; hot reload would add
  a consistency problem for no MVP benefit.
- Tests construct `Settings` explicitly rather than relying on ambient environment, so test runs
  cannot be perturbed by a developer's shell.
