from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Header, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from multicloudshield.api.errors import ApiProblem
from multicloudshield.persistence.models import ApiTokenRow, SessionRow, UserRow
from multicloudshield.persistence.repository import OrgScope

PASSWORD_HASHER = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)


@dataclass(frozen=True)
class Principal:
    id: UUID
    organization_id: UUID
    role: str
    kind: str

    @property
    def scope(self) -> OrgScope:
        return OrgScope(self.organization_id)


async def db_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.database.session() as session:
        yield session


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def current_principal(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    authorization: Annotated[str | None, Header()] = None,
    session_cookie: Annotated[str | None, Cookie(alias="__Host-mcs_session")] = None,
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Principal:
    now = datetime.now(UTC)
    if session_cookie is None:
        session_cookie = request.cookies.get("mcs_session")
    if authorization and authorization.startswith("Bearer "):
        raw = authorization[7:]
        pieces = raw.split("_")
        if len(pieces) >= 4 and pieces[0:2] == ["mcs", "pat"]:
            prefix = "_".join(pieces[:3])
            row = await session.scalar(
                select(ApiTokenRow).where(ApiTokenRow.token_prefix == prefix)
            )
            if (
                row
                and row.revoked_at is None
                and (row.expires_at is None or row.expires_at > now)
                and hmac.compare_digest(row.token_hash, _hash(raw))
            ):
                row.last_used_at = now
                await session.commit()
                return Principal(row.id, row.organization_id, row.role, "token")
    if session_cookie:
        row = await session.scalar(
            select(SessionRow).where(SessionRow.id_hash == _hash(session_cookie))
        )
        if row and row.idle_expires_at > now and row.absolute_expires_at > now:
            user = await session.get(UserRow, row.user_id)
            if user and user.is_active:
                if request.method not in {"GET", "HEAD", "OPTIONS"} and not (
                    csrf_token and hmac.compare_digest(row.csrf_hash, _hash(csrf_token))
                ):
                    raise ApiProblem(
                        403,
                        "csrf_failed",
                        "CSRF validation failed",
                        "A valid CSRF token is required.",
                    )
                return Principal(user.id, row.organization_id, user.role, "session")
    raise ApiProblem(
        401,
        "authentication_required",
        "Authentication required",
        "Provide a valid session or API token.",
    )


def require_roles(*roles: str) -> Callable[..., object]:
    async def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if principal.role not in roles:
            raise ApiProblem(
                403, "forbidden", "Forbidden", "Your role does not permit this action."
            )
        return principal

    return dependency


async def create_session(
    session: AsyncSession, user: UserRow, response: Response, *, secure: bool = True
) -> str:
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = datetime.now(UTC)
    session.add(
        SessionRow(
            id_hash=_hash(raw),
            user_id=user.id,
            organization_id=user.organization_id,
            csrf_hash=_hash(csrf),
            idle_expires_at=now + timedelta(minutes=30),
            absolute_expires_at=now + timedelta(hours=8),
        )
    )
    cookie_name = "__Host-mcs_session" if secure else "mcs_session"
    response.set_cookie(cookie_name, raw, secure=secure, httponly=True, samesite="strict", path="/")
    response.set_cookie(
        "mcs_csrf", csrf, secure=secure, httponly=False, samesite="strict", path="/"
    )
    return csrf


def verify_password(password: str, encoded: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded, password)
    except VerifyMismatchError:
        return False


def create_api_token() -> tuple[str, str, str]:
    public_id = secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
    secret = secrets.token_urlsafe(32)
    checksum = hashlib.sha256((public_id + secret).encode()).hexdigest()[:6]
    raw = f"mcs_pat_{public_id}_{secret}{checksum}"
    return raw, f"mcs_pat_{public_id}", _hash(raw)
