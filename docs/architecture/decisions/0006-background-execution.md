# ADR-0006: PostgreSQL-backed job queue and a dedicated worker

Status: accepted
Date: 2026-08-05

## Context

Scans run for minutes, hold cloud credentials, and must survive an API restart. They need queueing,
at-least-once execution, retry, cancellation, and crash recovery.

Hard constraints: **no Redis, no Kafka, no Kubernetes.** PostgreSQL is already a dependency
([ADR-0005](0005-database-and-orm.md)), so the queue should live there.

## Decision

**A dedicated worker process consuming a PostgreSQL-backed queue, using `procrastinate` 3.9.x**,
behind a thin internal `JobQueue` interface.

`procrastinate` was verified (2026-08-05) to implement precisely the design we would otherwise have
hand-written:

| Requirement | How procrastinate provides it |
| --- | --- |
| Contention-free dequeue | `FOR UPDATE ... SKIP LOCKED` inside `procrastinate_fetch_job_v2()` |
| No hot polling | `pg_notify` on per-queue and any-queue channels (LISTEN/NOTIFY) |
| Crash recovery | `procrastinate_workers` table with `last_heartbeat` and an index supporting stalled-job selection |
| "One scan per connection at a time" | Partial unique indexes on `queueing_lock WHERE status='todo'` and `lock WHERE status='doing'` |
| Scheduling (post-MVP) | Built-in periodic tasks |

PostgreSQL 13+ required; we are on 18.

### Its limitations match our design, which is why it fits

- **Cancellation is cooperative, not forceful.** `cancel_job_by_id(id)` works only before the job
  starts; for a running job, `abort=True` merely *marks* it and "this request has to be handled by
  the task itself." A wedged SDK call is not killed. This is exactly what
  [data-flows.md](../data-flows.md) §3.3 already specifies: the orchestrator polls the abort flag
  between scan targets and pagination pages, bounded by the 30 s per-call timeout.
- **At-least-once.** A job killed mid-flight stays `doing` until heartbeat-based stall detection
  reclaims it, so tasks must be idempotent. Every scan write step already is
  ([domain-model.md](../domain-model.md) §4.3): assets upsert by URN, evaluations by unique key,
  findings by fingerprint.
- **Queue churn shares the database.** Workers get a **separate connection pool** from the API so
  queue polling cannot starve request serving.

### The worker

One `worker` entrypoint of the same image ([ADR-0002](0002-modular-monolith.md)), with cloud
credentials in its environment and no inbound user traffic. Multiple workers are supported by the
queue with no change; the default deployment runs one.

**Concurrency inside a scan uses a bounded thread pool, not async.** boto3 is synchronous, and the
async wrappers are not first-party: `aiobotocore` 3.9.0 still carries a Beta classifier and
`aioboto3` 15.5.0 lagged it by nine months as of 2026-08-05. Both pin narrow botocore ranges. For
I/O-bound reads with deliberately low concurrency caps
([data-flows.md](../data-flows.md) §3.2), a thread pool is the lower-risk choice, and it works
uniformly across all four provider SDKs — three of which are synchronous anyway.

### The `JobQueue` seam

`engine/` and `api/` depend on a small internal interface (`enqueue`, `claim`, `heartbeat`,
`request_cancel`, `complete`), not on procrastinate directly. Swapping the implementation later is a
contained change, and the engine remains testable with an in-memory queue.

## Rejected alternatives

- **Celery 5.6, RQ 2.10, Dramatiq 2.2.** All require RabbitMQ or Redis. Celery has no PostgreSQL
  broker. Directly violates the no-extra-infrastructure constraint.
- **arq.** Redis-based, and its own PyPI description states it is **"in maintenance only mode."**
- **APScheduler.** Stable is **3.11.3**; the v4 line's last artefact is **4.0.0a6 from 2025-04-27** —
  over 15 months with no new alpha, so v4 is effectively stalled and must not be planned around. v3
  is a *scheduler*, not a durable queue: it triggers callables in-process with no worker protocol, no
  at-least-once delivery, and no distributed coordination.
- **FastAPI `BackgroundTasks`.** Not a job system. No persistence across restart, no retry, no
  status, no cancellation, no backpressure; an in-flight task dies silently when Uvicorn recycles.
  FastAPI's own documentation points at a real queue for heavy work.
- **Hand-rolling `SELECT ... FOR UPDATE SKIP LOCKED`.** This was the leading candidate before
  research. It is viable — it is what procrastinate and pgqueuer do internally — but we would be
  reimplementing retries, heartbeats, stall recovery, and NOTIFY plumbing, and then maintaining them.
  Worth it only if the job model is genuinely ~50 lines; ours is not. **We keep the `JobQueue`
  interface precisely so this remains a cheap fallback** if procrastinate's maintenance changes.
- **`pgqueuer` 1.3.2.** Also PostgreSQL-only and lighter, but younger and with fewer of the features
  we need (no queueing locks, no periodic tasks). Named as the fallback alongside a hand-rolled queue.
- **A separate scanner service with an HTTP API.** Premature microservice
  ([ADR-0002](0002-modular-monolith.md)).

## Consequences

- Deployment is API + worker + PostgreSQL. No broker, no cache.
- Scan concurrency is bounded by design ([data-flows.md](../data-flows.md) §3.2) — we deliberately do
  not maximize throughput, because the failure mode is throttling a customer's production account.
- Cancellation latency is bounded by the per-call timeout plus one page, and documented as
  best-effort in the API. Users are told this rather than left to infer it.
- The worker must poll the abort flag inside scan loops. It is easy to forget in a new collector, so
  the orchestrator — not the collector — owns the check, and a conformance test asserts cancellation
  is observed within one page ([provider-adapters.md](../provider-adapters.md) §8).
- We depend on a ~1.4k-star project for a load-bearing component. Mitigated by the `JobQueue`
  interface and by having a concrete, costed fallback. Recorded in
  [risk-register.md](../../planning/risk-register.md).
- A worker heartbeat table means an idle worker still writes periodically. Negligible, and it is what
  makes crash recovery work.
