# ADR-0026: Use the internal leased PostgreSQL queue for v0.1.0

Status: accepted
Date: 2026-08-05
Supersedes: ADR-0006

## Context

Implementing the vertical slice exposed that Procrastinate's independent schema and transaction
boundary duplicated the scan/job lifecycle already required for organization-scoped API reads,
idempotency, and cooperative cancellation. Keeping both records synchronized created more failure
states than the dependency removed. ADR-0006 explicitly costed an internal `SKIP LOCKED` queue as its
fallback; the v0.1 job model remained small enough to take that fallback.

## Decision

Use the `jobs` table and repository seam already shared by API and worker. Claims use `FOR UPDATE SKIP
LOCKED`; leases are heartbeated and expired leases are reclaimed; failures use bounded retry
scheduling; payloads are idempotent identifiers; cancellation remains scan-record based and is polled
during execution. PostgreSQL remains the only infrastructure.

The queue intentionally polls once per second rather than using LISTEN/NOTIFY. At v0.1 volume this is
measurably simpler and does not affect scan latency materially.

## Consequences

- One durable record represents both API job state and worker execution state.
- Queue correctness is our maintenance responsibility, so lease recovery and concurrent claims need
  PostgreSQL integration coverage.
- Scheduled jobs and notification-driven wakeups remain post-MVP.
- Procrastinate can be reconsidered if the job model expands beyond manual scans and connectivity tests.
