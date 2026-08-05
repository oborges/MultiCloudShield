from __future__ import annotations

import asyncio
import signal
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update

from multicloudshield.config import Settings
from multicloudshield.core.security import redact_text
from multicloudshield.engine import ScanOptions, run_scan
from multicloudshield.logging import configure_logging, get_logger
from multicloudshield.persistence import Database, OrgScope, Repository
from multicloudshield.persistence.models import JobRow
from multicloudshield.providers import get_adapter
from multicloudshield.providers.base import CancellationToken


async def _claim(database: Database) -> JobRow | None:
    async with database.session() as session:
        async with session.begin():
            await session.execute(
                update(JobRow)
                .where(
                    JobRow.status == "running",
                    JobRow.lease_until < datetime.now(UTC),
                )
                .values(status="queued", lease_until=None)
            )
            job = await session.scalar(
                select(JobRow)
                .where(JobRow.status == "queued", JobRow.available_at <= datetime.now(UTC))
                .order_by(JobRow.created_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if job is None:
                return None
            job.status = "running"
            job.attempts += 1
            job.lease_until = datetime.now(UTC) + timedelta(minutes=10)
            await session.flush()
            session.expunge(job)
            return job


async def _heartbeat(database: Database, job_id: UUID, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=60)
        except TimeoutError:
            async with database.session() as session:
                await session.execute(
                    update(JobRow)
                    .where(JobRow.id == job_id, JobRow.status == "running")
                    .values(lease_until=datetime.now(UTC) + timedelta(minutes=10))
                )
                await session.commit()


async def _finish(database: Database, job_id: UUID, *, error: str | None = None) -> None:
    async with database.session() as session:
        job = await session.get(JobRow, job_id)
        if not job:
            return
        if error and job.attempts < job.max_attempts:
            job.status = "queued"
            job.available_at = datetime.now(UTC) + timedelta(seconds=min(60, 2**job.attempts))
        else:
            job.status = "failed" if error else "completed"
        job.error = redact_text(error or "") or None
        job.lease_until = None
        await session.commit()


async def _process(database: Database, job: JobRow) -> None:
    scope = OrgScope(job.organization_id)
    if job.kind == "scan":
        connection_id = UUID(str(job.payload["connection_id"]))
        scan_id = UUID(str(job.payload["scan_id"]))
        async with database.session() as session:
            repo = Repository(session)
            connection = await repo.connection_descriptor(scope, connection_id)
            scan = await repo.get_scan(scope, scan_id)
            if connection is None or scan is None:
                raise RuntimeError("queued scan references a missing object")
            if scan.cancellation_requested_at:
                scan.status = "cancelled"
                await session.commit()
                return
            scan.status = "running"
            scan.started_at = datetime.now(UTC)
            await session.commit()
        cancel = CancellationToken()

        async def watch_cancellation() -> None:
            while not cancel.cancelled:
                await asyncio.sleep(0.5)
                async with database.session() as watcher_session:
                    watched = await Repository(watcher_session).get_scan(scope, scan_id)
                    if watched is None or watched.cancellation_requested_at is not None:
                        cancel.cancel()
                        return

        watcher = asyncio.create_task(watch_cancellation())
        try:
            result = await run_scan(connection, options=ScanOptions(cancel=cancel), scan_id=scan_id)
        finally:
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await watcher
        async with database.session() as session:
            await Repository(session).persist_scan(scope, result, trigger="manual_api")
            await session.commit()
        return
    if job.kind == "connection_test":
        connection_id = UUID(str(job.payload["connection_id"]))
        async with database.session() as session:
            repo = Repository(session)
            descriptor = await repo.connection_descriptor(scope, connection_id)
            row = await repo.get_connection(scope, connection_id)
            if descriptor is None or row is None:
                raise RuntimeError("connection test references a missing connection")
            report = await asyncio.to_thread(
                get_adapter(descriptor.provider).verify_access, descriptor
            )
            row.last_verified_at = datetime.now(UTC)
            row.last_verification_status = report.status
            row.last_verification_detail = {
                "identity": report.identity,
                "ok": list(report.ok),
                "denied": [item.__dict__ for item in report.denied],
                "disabled": [item.__dict__ for item in report.disabled],
            }
            await session.commit()
        return
    raise RuntimeError(f"unknown job kind: {job.kind}")


async def worker_loop(settings: Settings, stop: asyncio.Event) -> None:
    database = Database(settings.database.url)
    logger = get_logger()
    try:
        while not stop.is_set():
            job = await _claim(database)
            if job is None:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1.0)
                except TimeoutError:
                    pass
                continue
            try:
                heartbeat_stop = asyncio.Event()
                heartbeat = asyncio.create_task(_heartbeat(database, job.id, heartbeat_stop))
                try:
                    await _process(database, job)
                finally:
                    heartbeat_stop.set()
                    await heartbeat
            except Exception as exc:
                logger.error(
                    "job_failed",
                    job_id=str(job.id),
                    kind=job.kind,
                    error_type=type(exc).__name__,
                )
                await _finish(database, job.id, error="job execution failed")
            else:
                await _finish(database, job.id)
    finally:
        await database.dispose()


def run() -> None:
    settings = Settings(process_role="worker")
    configure_logging(json_output=settings.env != "development")

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await worker_loop(settings, stop)

    asyncio.run(main())
