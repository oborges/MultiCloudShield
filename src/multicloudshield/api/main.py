from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from multicloudshield import __version__
from multicloudshield.api.auth import (
    Principal,
    create_api_token,
    create_session,
    current_principal,
    db_session,
    require_roles,
    verify_password,
)
from multicloudshield.api.errors import (
    ApiProblem,
    problem_handler,
    validation_problem_handler,
)
from multicloudshield.api.schemas import (
    ConnectionCreate,
    FindingStatusRequest,
    LoginRequest,
    TokenCreate,
)
from multicloudshield.config import Settings, get_settings
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.core.security import csv_safe
from multicloudshield.logging import configure_logging
from multicloudshield.persistence import Database, Repository
from multicloudshield.persistence.models import (
    ApiTokenRow,
    AssetRow,
    EvidenceRow,
    ScanRow,
    SessionRow,
)
from multicloudshield.policy import load_bundle


class SecurityHeadersMiddleware:
    def __init__(self, app: Any, production: bool = False) -> None:
        self.app = app
        self.production = production

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        correlation_id = str(uuid.uuid4())

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (
                            b"content-security-policy",
                            (
                                b"default-src 'self'; script-src 'self'; style-src 'self'; "
                                b"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
                            ),
                        ),
                        (b"x-correlation-id", correlation_id.encode()),
                    ]
                )
                if self.production:
                    headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestSizeLimitMiddleware:
    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = self.max_bytes + 1
        if declared > self.max_bytes:
            await self._reject(scope, receive, send)
            return
        received = 0

        async def bounded_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > self.max_bytes:
                raise RequestTooLarge
            return cast(dict[str, Any], message)

        try:
            await self.app(scope, bounded_receive, send)
        except RequestTooLarge:
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(scope: dict[str, Any], receive: Any, send: Any) -> None:
        response = JSONResponse(
            status_code=413,
            media_type="application/problem+json",
            content={
                "type": "https://multicloudshield.dev/problems/request_too_large",
                "title": "Request too large",
                "status": 413,
                "detail": "The request body exceeds the configured limit.",
                "instance": str(scope.get("path", "")),
                "code": "request_too_large",
            },
        )
        await response(scope, receive, send)


class RequestTooLarge(Exception):
    pass


def _row(row: Any, *, omit: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        column.name: getattr(row, column.name)
        for column in row.__table__.columns
        if column.name not in omit
    }


def _page(
    items: list[Any], *, is_demo: bool = False, limit: int | None = None, offset: int = 0
) -> dict[str, Any]:
    has_more = limit is not None and len(items) > limit
    visible = items[:limit] if limit is not None else items
    return {
        "items": visible,
        "next_cursor": str(offset + limit) if has_more and limit is not None else None,
        "meta": {"is_demo": is_demo, "generated_at": datetime.now(UTC).isoformat()},
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()
    configure_logging(json_output=config.env != "development")
    middleware: list[Middleware] = [
        Middleware(SecurityHeadersMiddleware, production=config.env == "production"),
        Middleware(RequestSizeLimitMiddleware, max_bytes=config.api.max_request_bytes),
    ]
    if config.api.cors_origins:
        middleware.append(
            Middleware(
                CORSMiddleware,
                allow_origins=config.api.cors_origins,
                allow_credentials=True,
                allow_methods=["GET", "POST", "PATCH", "DELETE"],
                allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "Idempotency-Key"],
            )
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.database = Database(config.database.url)
        yield
        await app.state.database.dispose()

    api = FastAPI(
        title="MultiCloudShield API",
        version=__version__,
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
        middleware=middleware,
        exception_handlers={
            ApiProblem: problem_handler,
            RequestValidationError: validation_problem_handler,
            Exception: problem_handler,
        },
        lifespan=lifespan,
    )
    router = APIRouter(prefix="/api/v1")

    @api.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @api.get("/readyz", include_in_schema=False)
    async def ready(request: Request) -> JSONResponse:
        ok = await request.app.state.database.ready()
        return JSONResponse(
            {"status": "ready" if ok else "not_ready"}, status_code=200 if ok else 503
        )

    @router.post("/auth/login")
    async def login(
        payload: LoginRequest,
        response: Response,
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        user = await Repository(session).user_by_email(payload.email)
        now = datetime.now(UTC)
        valid = (
            user is not None
            and (user.locked_until is None or user.locked_until <= now)
            and verify_password(payload.password, user.password_hash)
        )
        if not valid:
            if user:
                user.failed_login_count += 1
                if user.failed_login_count >= 5:
                    user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
                await session.commit()
            raise ApiProblem(
                401,
                "invalid_credentials",
                "Authentication failed",
                "Email or password is incorrect.",
            )
        assert user is not None
        user.failed_login_count = 0
        user.locked_until = None
        csrf = await create_session(session, user, response, secure=config.env == "production")
        await session.commit()
        return {"user": {"id": user.id, "email": user.email, "role": user.role}, "csrf_token": csrf}

    @router.post("/auth/logout")
    async def logout(
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, bool]:
        raw = request.cookies.get("__Host-mcs_session") or request.cookies.get("mcs_session")
        if raw:
            import hashlib

            await session.execute(
                delete(SessionRow).where(
                    SessionRow.id_hash == hashlib.sha256(raw.encode()).hexdigest(),
                    SessionRow.organization_id == principal.organization_id,
                )
            )
            await session.commit()
        response.delete_cookie("__Host-mcs_session", path="/")
        response.delete_cookie("mcs_session", path="/")
        return {"logged_out": True}

    @router.get("/auth/me")
    async def me(principal: Annotated[Principal, Depends(current_principal)]) -> dict[str, Any]:
        return {
            "id": principal.id,
            "organization_id": principal.organization_id,
            "role": principal.role,
            "kind": principal.kind,
        }

    @router.post("/tokens", status_code=201)
    async def token_create(
        payload: TokenCreate,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        raw, prefix, hashed = create_api_token()
        row = ApiTokenRow(
            organization_id=principal.organization_id,
            name=payload.name,
            token_prefix=prefix,
            token_hash=hashed,
            role=payload.role,
            expires_at=datetime.now(UTC) + timedelta(days=payload.expires_days),
        )
        session.add(row)
        await session.commit()
        return {"id": row.id, "name": row.name, "token": raw, "shown_once": True}

    @router.get("/tokens")
    async def token_list(
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        rows = list(
            (
                await session.scalars(
                    select(ApiTokenRow)
                    .where(ApiTokenRow.organization_id == principal.organization_id)
                    .order_by(ApiTokenRow.created_at.desc())
                    .limit(200)
                )
            ).all()
        )
        return _page(
            [_row(row, omit=("token_hash",)) for row in rows],
            is_demo=False,
        )

    @router.delete("/tokens/{token_id}")
    async def token_revoke(
        token_id: UUID,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> Response:
        row = await session.scalar(
            select(ApiTokenRow).where(
                ApiTokenRow.organization_id == principal.organization_id,
                ApiTokenRow.id == token_id,
            )
        )
        if row is None:
            raise ApiProblem(404, "not_found", "Not found", "API token not found.")
        row.revoked_at = datetime.now(UTC)
        await session.commit()
        return Response(status_code=204)

    @router.get("/connections")
    async def connections(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
        limit: int = Query(100, ge=1, le=200),
        cursor: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await Repository(session).list_connections(
            principal.scope, limit=limit + 1, offset=cursor
        )
        return _page(
            [_row(row, omit=("credential_reference",)) for row in rows],
            is_demo=any(row.is_demo for row in rows),
            limit=limit,
            offset=cursor,
        )

    @router.post("/connections", status_code=201)
    async def connection_create(
        payload: ConnectionCreate,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        descriptor = ConnectionDescriptor(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            name=payload.name,
            provider=payload.provider,
            scope_id=payload.scope_id,
            credential_mechanism=payload.credential_mechanism,
            credential_reference=payload.credential_reference,
            region_allowlist=payload.region_allowlist,
            is_demo=payload.provider.value == "demo",
        )
        row = await Repository(session).create_connection(principal.scope, descriptor)
        await session.commit()
        return _row(row, omit=("credential_reference",))

    @router.get("/connections/{connection_id}")
    async def connection_detail(
        connection_id: UUID,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        row = await Repository(session).get_connection(principal.scope, connection_id)
        if row is None:
            raise ApiProblem(404, "not_found", "Not found", "Connection not found.")
        return _row(row, omit=("credential_reference",))

    @router.patch("/connections/{connection_id}")
    async def connection_toggle(
        connection_id: UUID,
        enabled: bool,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, bool]:
        if not await Repository(session).set_connection_enabled(
            principal.scope, connection_id, enabled
        ):
            raise ApiProblem(404, "not_found", "Not found", "Connection not found.")
        await session.commit()
        return {"enabled": enabled}

    @router.delete("/connections/{connection_id}")
    async def connection_delete(
        connection_id: UUID,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
        purge: bool = False,
    ) -> Response:
        if not await Repository(session).delete_connection(
            principal.scope, connection_id, purge=purge
        ):
            raise ApiProblem(404, "not_found", "Not found", "Connection not found.")
        await session.commit()
        return Response(status_code=204)

    @router.post("/connections/{connection_id}/test", status_code=202)
    async def connection_test(
        connection_id: UUID,
        principal: Annotated[Principal, Depends(require_roles("owner"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        repo = Repository(session)
        if not await repo.get_connection(principal.scope, connection_id):
            raise ApiProblem(404, "not_found", "Not found", "Connection not found.")
        job = await repo.enqueue(
            principal.scope, "connection_test", {"connection_id": str(connection_id)}
        )
        await session.commit()
        return {"job_id": job.id, "status": job.status}

    @router.get("/jobs/{job_id}")
    async def job_detail(
        job_id: UUID,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        job = await Repository(session).job(principal.scope, job_id)
        if not job:
            raise ApiProblem(404, "not_found", "Not found", "Job not found.")
        return _row(job)

    @router.post("/scans", status_code=202)
    async def scan_start(
        connection_id: UUID,
        principal: Annotated[Principal, Depends(require_roles("owner", "analyst"))],
        session: Annotated[AsyncSession, Depends(db_session)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        repo = Repository(session)
        if idempotency_key and len(idempotency_key) > 200:
            raise ApiProblem(
                422,
                "validation_error",
                "Request validation failed",
                "Idempotency-Key must not exceed 200 characters.",
            )
        connection = await repo.get_connection(principal.scope, connection_id)
        if connection is None:
            raise ApiProblem(404, "not_found", "Not found", "Connection not found.")
        if not connection.enabled:
            raise ApiProblem(
                409,
                "connection_disabled",
                "Connection disabled",
                "Enable the connection before scanning.",
            )
        if idempotency_key:
            existing = await session.scalar(
                select(ScanRow).where(
                    ScanRow.connection_id == connection_id,
                    ScanRow.idempotency_key == idempotency_key,
                )
            )
            if existing:
                return {"scan_id": existing.id, "status": existing.status, "replayed": True}
        scan_id = uuid.uuid4()
        session.add(
            ScanRow(
                id=scan_id,
                organization_id=principal.organization_id,
                connection_id=connection_id,
                requested_by_id=principal.id,
                status="queued",
                trigger="manual_api",
                idempotency_key=idempotency_key,
                policy_bundle_version=load_bundle().version,
                engine_version=__version__,
                collector_set_digest="pending",
                stats={},
                result_payload={},
                is_demo=connection.is_demo,
            )
        )
        job = await repo.enqueue(
            principal.scope, "scan", {"scan_id": str(scan_id), "connection_id": str(connection_id)}
        )
        await session.commit()
        return {"scan_id": scan_id, "job_id": job.id, "status": "queued", "replayed": False}

    @router.delete("/scans/{scan_id}")
    async def scan_cancel(
        scan_id: UUID,
        principal: Annotated[Principal, Depends(require_roles("owner", "analyst"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, str]:
        row = await Repository(session).get_scan(principal.scope, scan_id)
        if not row:
            raise ApiProblem(404, "not_found", "Not found", "Scan not found.")
        row.cancellation_requested_at = datetime.now(UTC)
        if row.status == "queued":
            row.status = "cancelled"
        await session.commit()
        return {"status": row.status}

    @router.get("/scans")
    async def scans(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
        limit: int = Query(100, ge=1, le=200),
        cursor: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await Repository(session).list_scans(principal.scope, limit=limit + 1, offset=cursor)
        return _page(
            [_row(row, omit=("result_payload",)) for row in rows],
            is_demo=any(row.is_demo for row in rows),
            limit=limit,
            offset=cursor,
        )

    @router.get("/scans/{scan_id}")
    async def scan_detail(
        scan_id: UUID,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        row = await Repository(session).get_scan(principal.scope, scan_id)
        if not row:
            raise ApiProblem(404, "not_found", "Not found", "Scan not found.")
        return row.result_payload or _row(row, omit=("result_payload",))

    @router.get("/assets")
    async def assets(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
        provider: str | None = None,
        resource_type: str | None = None,
        connection_id: UUID | None = None,
        limit: int = Query(100, ge=1, le=200),
        cursor: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await Repository(session).list_assets(
            principal.scope,
            provider=provider,
            resource_type=resource_type,
            connection_id=connection_id,
            limit=limit + 1,
            offset=cursor,
        )
        return _page(
            [_row(row) for row in rows],
            is_demo=any(row.is_demo for row in rows),
            limit=limit,
            offset=cursor,
        )

    @router.get("/assets/{asset_id}")
    async def asset_detail(
        asset_id: UUID,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        row = await session.scalar(
            select(AssetRow).where(
                AssetRow.organization_id == principal.organization_id, AssetRow.id == asset_id
            )
        )
        if not row:
            raise ApiProblem(404, "not_found", "Not found", "Asset not found.")
        return _row(row)

    @router.get("/findings")
    async def findings(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
        provider: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        policy: str | None = None,
        resource_type: str | None = None,
        scan: UUID | None = None,
        connection: UUID | None = None,
        limit: int = Query(100, ge=1, le=200),
        cursor: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        rows = await Repository(session).list_findings(
            principal.scope,
            provider=provider,
            severity=severity,
            status=status,
            policy_id=policy,
            resource_type=resource_type,
            scan_id=scan,
            connection_id=connection,
            limit=limit + 1,
            offset=cursor,
        )
        return _page(
            [_row(row) for row in rows],
            is_demo=any(row.is_demo for row in rows),
            limit=limit,
            offset=cursor,
        )

    @router.get("/findings/{finding_id}")
    async def finding_detail(
        finding_id: UUID,
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        finding = await Repository(session).get_finding(principal.scope, finding_id)
        if not finding:
            raise ApiProblem(404, "not_found", "Not found", "Finding not found.")
        evidence = await session.scalar(
            select(EvidenceRow).where(
                EvidenceRow.organization_id == principal.organization_id,
                EvidenceRow.id == finding.evidence_id,
            )
        )
        payload = _row(finding)
        payload["evidence"] = _row(evidence) if evidence else None
        return payload

    @router.post("/findings/{finding_id}/status")
    async def finding_status(
        finding_id: UUID,
        payload: FindingStatusRequest,
        principal: Annotated[Principal, Depends(require_roles("owner", "analyst"))],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        if not await Repository(session).change_finding_status(
            principal.scope,
            finding_id,
            status=payload.status,
            actor_id=principal.id,
            reason=payload.reason,
        ):
            raise ApiProblem(404, "not_found", "Not found", "Finding not found.")
        await session.commit()
        return {"id": finding_id, "status": payload.status}

    @router.get("/policies")
    async def policies(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> dict[str, Any]:
        bundle = load_bundle()
        return _page([item.model_dump(mode="json") for item in bundle.policies])

    @router.get("/policies/{policy_id}")
    async def policy_detail(
        policy_id: str, principal: Annotated[Principal, Depends(current_principal)]
    ) -> dict[str, Any]:
        policy = next((item for item in load_bundle().policies if item.id == policy_id), None)
        if not policy:
            raise ApiProblem(404, "not_found", "Not found", "Policy not found.")
        return policy.model_dump(mode="json")

    @router.get("/summary")
    async def summary(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
    ) -> dict[str, Any]:
        return await Repository(session).summary(principal.scope)

    @router.get("/exports/findings")
    async def export_findings(
        principal: Annotated[Principal, Depends(current_principal)],
        session: Annotated[AsyncSession, Depends(db_session)],
        format: str = Query("json", pattern="^(json|csv)$"),
    ) -> Response:
        repo = Repository(session)
        rows: list[Any] = []
        offset = 0
        while len(rows) < 100_000:
            batch = await repo.list_findings(principal.scope, limit=201, offset=offset)
            rows.extend(batch[:200])
            if len(batch) <= 200:
                break
            offset += 200
        provenance = {
            "schema_version": "1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "engine_version": __version__,
            "policy_bundle_version": load_bundle().version,
            "contains_demo_data": any(row.is_demo for row in rows),
        }
        headers = {
            "Content-Disposition": f'attachment; filename="multicloudshield-findings.{format}"',
            "X-Content-Type-Options": "nosniff",
        }
        if format == "json":
            return JSONResponse(
                jsonable_encoder(
                    {"provenance": provenance, "findings": [_row(row) for row in rows]}
                ),
                headers=headers,
            )
        import csv
        import io

        output = io.StringIO(newline="")
        fields = [
            "id",
            "policy_id",
            "severity",
            "status",
            "title",
            "first_seen_at",
            "last_seen_at",
            "is_demo",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_safe(getattr(row, field)) for field in fields})
        return PlainTextResponse(output.getvalue(), media_type="text/csv", headers=headers)

    api.include_router(router)

    @api.get("/api/v1/{unknown_path:path}", include_in_schema=False)
    async def unknown_api_route(unknown_path: str) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            media_type="application/problem+json",
            content={
                "type": "https://multicloudshield.dev/problems/not_found",
                "title": "Not found",
                "status": 404,
                "detail": "API route not found.",
                "instance": f"/api/v1/{unknown_path}",
                "code": "not_found",
            },
        )

    web_dist = Path(__file__).resolve().parents[3] / "web" / "dist"
    if web_dist.exists():
        api.mount("/assets", StaticFiles(directory=web_dist / "assets"), name="web-assets")

        @api.get("/{path:path}", include_in_schema=False)
        async def spa(path: str) -> FileResponse:
            return FileResponse(web_dist / "index.html")
    else:

        @api.get("/", include_in_schema=False)
        async def placeholder() -> HTMLResponse:
            return HTMLResponse(
                "<main><h1>MultiCloudShield</h1><p>Build the dashboard with "
                "<code>npm run build</code> in web/.</p></main>"
            )

    return api


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("multicloudshield.api.main:app", host="0.0.0.0", port=8080, reload=False)
