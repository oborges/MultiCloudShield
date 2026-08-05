import asyncio
from uuid import uuid4

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    ScanErrorCategory,
    ScanStatus,
)
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.engine import ScanOptions, run_scan


def connection() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=uuid4(),
        organization_id=uuid4(),
        name="demo",
        provider=CloudProvider.DEMO,
        scope_id="deterministic-v1",
        credential_mechanism=CredentialMechanism.DEMO_NONE,
        is_demo=True,
    )


def canonical(result) -> tuple[object, ...]:
    return (
        [(asset.asset_urn, asset.name, asset.facts_digest) for asset in result.assets],
        [(item.policy_id, item.asset_urn, item.result) for item in result.evaluations],
        [(item.fingerprint, item.severity, item.title) for item in result.findings],
        [(item.category, item.collector_id, item.provider_error_code) for item in result.errors],
    )


def test_demo_scan_is_deterministic_partial_and_four_cloud() -> None:
    conn = connection()
    first = asyncio.run(run_scan(conn, options=ScanOptions(retry_base_seconds=0)))
    second = asyncio.run(run_scan(conn, options=ScanOptions(retry_base_seconds=0)))
    assert first.status is ScanStatus.PARTIALLY_COMPLETED
    assert canonical(first) == canonical(second)
    assert {asset.provider for asset in first.assets} == {
        CloudProvider.AWS,
        CloudProvider.AZURE,
        CloudProvider.GCP,
        CloudProvider.IBM,
    }
    assert first.stats.retries == 1
    assert first.stats.targets_succeeded > 0
    assert first.stats.targets_failed > 0
    assert first.stats.targets_skipped == 1
    assert {error.category for error in first.errors} >= {
        ScanErrorCategory.PERMISSION_DENIED,
        ScanErrorCategory.PARSE_ERROR,
        ScanErrorCategory.SERVICE_DISABLED,
    }


def test_hostile_demo_metadata_is_sanitized() -> None:
    result = asyncio.run(run_scan(connection(), options=ScanOptions(retry_base_seconds=0)))
    hostile = next(asset for asset in result.assets if asset.name.startswith("=cmd"))
    assert "\x00" not in hostile.name
    assert all("\x00" not in value for value in hostile.tags.values())
