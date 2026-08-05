import asyncio
import time
from collections.abc import Iterator
from uuid import uuid4

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    NormalizedResourceType,
    ScanErrorCategory,
    ScanStatus,
)
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.engine import ScanOptions, run_scan
from multicloudshield.providers.base import (
    CapabilityReport,
    CollectionContext,
    ProviderCapabilities,
    RawObservation,
    ScanScope,
)


class DuplicateCollector:
    id = "test.duplicates"
    version = "1.0.0"
    produces = frozenset({NormalizedResourceType.OBJECT_STORAGE_BUCKET})
    scope_kind = "global"
    required_permissions = ("test:Read",)
    optional_permissions: tuple[str, ...] = ()

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        for _ in range(2):
            ctx.budget.add_page(1)
            yield RawObservation(
                provider=CloudProvider.AWS,
                provider_resource_type="test.bucket",
                native_id="duplicate",
                local_id="duplicate",
                name="duplicate",
                resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "object_storage",
                    "public_read_access": "yes",
                    "public_write_access": "no",
                    "encryption_at_rest": "provider_managed",
                    "versioning_enabled": "yes",
                    "access_logging_enabled": "yes",
                    "tls_required": "yes",
                    "provider_specific": {},
                },
                provenance={"collector_id": self.id},
            )


class SlowCollector(DuplicateCollector):
    id = "test.slow"

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        time.sleep(0.02)
        ctx.checkpoint()
        return
        yield  # pragma: no cover


class Adapter:
    provider = CloudProvider.AWS

    def __init__(self, collector: object) -> None:
        self.collector = collector

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(CloudProvider.AWS, (self.collector.id,), ("test",))

    def resolve_scopes(self, _conn: ConnectionDescriptor) -> list[ScanScope]:
        return [ScanScope("global", "scope")]

    def verify_access(self, _conn: ConnectionDescriptor) -> CapabilityReport:
        return CapabilityReport("ok", "test", (self.collector.id,))

    def collectors(self) -> tuple[object, ...]:
        return (self.collector,)


def connection() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=uuid4(),
        organization_id=uuid4(),
        name="test",
        provider=CloudProvider.AWS,
        scope_id="scope",
        credential_mechanism=CredentialMechanism.AWS_DEFAULT_CHAIN,
    )


def test_duplicate_assets_and_findings_are_collapsed(monkeypatch) -> None:
    monkeypatch.setattr(
        "multicloudshield.engine.runner.get_adapter",
        lambda _provider: Adapter(DuplicateCollector()),
    )
    result = asyncio.run(run_scan(connection(), options=ScanOptions(retry_base_seconds=0)))
    assert len(result.assets) == len({asset.asset_urn for asset in result.assets}) == 1
    assert len(result.findings) == len({finding.fingerprint for finding in result.findings})
    assert result.targets[0].items_collected == 2


def test_scan_deadline_is_bounded_and_normalized(monkeypatch) -> None:
    monkeypatch.setattr(
        "multicloudshield.engine.runner.get_adapter", lambda _provider: Adapter(SlowCollector())
    )
    result = asyncio.run(
        run_scan(
            connection(),
            options=ScanOptions(scan_deadline_seconds=0.001, retry_base_seconds=0),
        )
    )
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].category is ScanErrorCategory.TIMEOUT
    assert result.findings == []
    assert result.evaluations == []
