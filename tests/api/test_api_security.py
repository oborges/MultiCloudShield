import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from multicloudshield.api.auth import current_principal
from multicloudshield.api.main import _page, create_app
from multicloudshield.api.schemas import ConnectionCreate
from multicloudshield.config import Settings


@pytest.mark.asyncio
async def test_security_headers_validation_does_not_echo_password_and_size_is_bounded() -> None:
    app = create_app(Settings(env="test", process_role="api", api={"max_request_bytes": 1024}))
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/login", json={"email": "x", "password": "short"}
            )
            assert response.status_code == 422
            assert "short" not in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            oversized = await client.post(
                "/api/v1/auth/login",
                content=b"x" * 1025,
                headers={"content-type": "application/json"},
            )
            assert oversized.status_code == 413


def test_every_protected_api_route_declares_authentication_dependency() -> None:
    app = create_app(Settings(env="test", process_role="api"))
    exempt = {"/api/v1/auth/login"}
    included = next(
        route for route in app.routes if hasattr(route, "original_router")
    ).original_router.routes
    protected = [
        route
        for route in included
        if isinstance(route, APIRoute)
        and route.path.startswith("/api/v1")
        and route.path not in exempt
    ]

    def dependency_calls(route: APIRoute) -> set[object]:
        found: set[object] = set()
        pending = list(route.dependant.dependencies)
        while pending:
            dependency = pending.pop()
            found.add(dependency.call)
            pending.extend(dependency.dependencies)
        return found

    assert protected
    for route in protected:
        calls = dependency_calls(route)
        assert current_principal in calls or any(
            getattr(call, "__name__", "") == "dependency" for call in calls
        ), route.path


def test_connection_schema_rejects_secret_values_and_cross_provider_mechanisms() -> None:
    with pytest.raises(ValidationError):
        ConnectionCreate(
            name="bad",
            provider="aws",
            scope_id="scope",
            credential_mechanism="aws_assume_role",
            credential_reference={"external_id_env": "AKIAABCDEFGHIJKLMNOP"},
        )
    with pytest.raises(ValidationError):
        ConnectionCreate(
            name="bad",
            provider="gcp",
            scope_id="scope",
            credential_mechanism="aws_default_chain",
        )


def test_bounded_page_emits_a_cursor_only_when_more_data_exists() -> None:
    first = _page([{"id": 1}, {"id": 2}, {"id": 3}], limit=2, offset=0)
    last = _page([{"id": 3}], limit=2, offset=2)
    assert first["items"] == [{"id": 1}, {"id": 2}]
    assert first["next_cursor"] == "2"
    assert last["next_cursor"] is None
