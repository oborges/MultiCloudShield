from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ApiProblem(Exception):
    def __init__(self, status: int, code: str, title: str, detail: str) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail


async def problem_handler(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, ApiProblem):
        status, code, title, detail = exc.status, exc.code, exc.title, exc.detail
    else:
        status, code, title, detail = (
            500,
            "internal_error",
            "Internal server error",
            "The request could not be completed.",
        )
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={
            "type": f"https://multicloudshield.dev/problems/{code}",
            "title": title,
            "status": status,
            "detail": detail,
            "instance": str(request.url.path),
            "code": code,
        },
    )


async def validation_problem_handler(
    request: Request, _exc: RequestValidationError
) -> JSONResponse:
    """Return a stable validation problem without echoing rejected secret-shaped input."""
    return JSONResponse(
        status_code=422,
        media_type="application/problem+json",
        content={
            "type": "https://multicloudshield.dev/problems/validation_error",
            "title": "Request validation failed",
            "status": 422,
            "detail": "One or more request fields are invalid.",
            "instance": str(request.url.path),
            "code": "validation_error",
        },
    )
