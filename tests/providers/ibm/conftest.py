from __future__ import annotations

from time import monotonic
from uuid import UUID

import pytest

from multicloudshield.core.enums import CloudProvider, CredentialMechanism
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.base import (
    CancellationToken,
    CollectionContext,
    PageBudget,
    ScanScope,
)


@pytest.fixture
def ibm_connection() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=UUID("00000000-0000-4000-8000-000000000101"),
        organization_id=UUID("00000000-0000-4000-8000-000000000102"),
        name="IBM test connection",
        provider=CloudProvider.IBM,
        scope_id="account-under-test",
        credential_mechanism=CredentialMechanism.IBM_TRUSTED_PROFILE,
        credential_reference={"profile_name": "audit-profile", "regions": "eu-de,us-south"},
        region_allowlist=["us-south"],
    )


def context(
    connection: ConnectionDescriptor,
    *,
    kind: str = "global",
    scope_id: str | None = None,
    max_pages: int = 100,
    max_items: int = 10_000,
) -> CollectionContext:
    return CollectionContext(
        connection=connection,
        scope=ScanScope(kind, scope_id or connection.scope_id),
        cancel=CancellationToken(),
        budget=PageBudget(max_pages=max_pages, max_items=max_items),
        deadline_at=monotonic() + 60,
    )
