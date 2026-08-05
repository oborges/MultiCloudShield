from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from types import SimpleNamespace
from uuid import uuid4

import pytest

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    NormalizedResourceType,
    ScanErrorCategory,
)
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.facts import TriState
from multicloudshield.providers.base import (
    CancellationToken,
    CollectionContext,
    PageBudget,
    ProviderError,
)
from multicloudshield.providers.gcp.adapter import GCP_READ_OPERATIONS, GcpAdapter
from multicloudshield.providers.normalize import normalize_observation


@dataclass
class Page:
    results: list[object] | None = None
    buckets: list[object] | None = None
    items: list[object] | None = None
    key_rings: list[object] | None = None
    crypto_keys: list[object] | None = None


class Pager:
    def __init__(self, pages: list[Page]) -> None:
        self.pages = pages


class Bucket:
    def __init__(self) -> None:
        self.name = "fixture-bucket"
        self.labels = {"environment": "test"}
        self.versioning_enabled = True
        self.default_kms_key_name = (
            "projects/fixture-project/locations/global/keyRings/r/cryptoKeys/k"
        )
        self.logging = {"logBucket": "fixture-log-bucket"}
        self.iam_configuration = SimpleNamespace(
            public_access_prevention="enforced",
            uniform_bucket_level_access=SimpleNamespace(enabled=True),
        )
        self.reloaded = False

    def reload(self) -> None:
        self.reloaded = True

    def get_iam_policy(self, *, requested_policy_version: int) -> object:
        assert requested_policy_version == 3
        return SimpleNamespace(
            bindings=[SimpleNamespace(role="roles/storage.objectAdmin", members=["allUsers"])]
        )


class AssetClient:
    def __init__(self, pager: object | None = None, error: Exception | None = None) -> None:
        self.pager = pager or Pager(
            [
                Page(
                    results=[
                        SimpleNamespace(
                            name="//compute.googleapis.com/projects/fixture-project/global/networks/default",
                            display_name="default",
                            asset_type="compute.googleapis.com/Network",
                            location="global",
                            labels={"managed-by": "fixture"},
                        )
                    ]
                )
            ]
        )
        self.error = error

    def search_all_resources(self, *, request: dict[str, object]) -> object:
        assert request["scope"] == "projects/fixture-project"
        if self.error:
            raise self.error
        return self.pager


class StorageClient:
    def __init__(self, buckets: list[Bucket] | None = None) -> None:
        self.buckets = [Bucket()] if buckets is None else buckets

    def list_buckets(self, **request: object) -> object:
        assert request["project"] == "fixture-project"
        return Pager([Page(buckets=self.buckets)])


class ComputeClient:
    def list(self, *, request: dict[str, object]) -> object:
        assert request["project"] == "fixture-project"
        rule = SimpleNamespace(
            name="open-admin",
            direction="INGRESS",
            source_ranges=["0.0.0.0/0"],
            allowed=[SimpleNamespace(ip_protocol="tcp", ports=["22", "5432"])],
            priority=1000,
            network="global/networks/default",
            self_link="projects/fixture-project/global/firewalls/open-admin",
        )
        return Pager([Page(items=[rule])])


class ResourceManagerClient:
    def get_iam_policy(self, *, request: dict[str, str]) -> object:
        assert request == {"resource": "projects/fixture-project"}
        return SimpleNamespace(
            bindings=[
                SimpleNamespace(
                    role="roles/viewer",
                    members=["group:security-reviewers.invalid"],
                    condition=None,
                )
            ],
            audit_configs=[SimpleNamespace(service="allServices")],
        )


class KeyRingClient:
    def list_key_rings(self, *, request: dict[str, str]) -> object:
        assert request["parent"] == "projects/fixture-project/locations/-"
        return Pager(
            [
                Page(
                    key_rings=[
                        SimpleNamespace(
                            name="projects/fixture-project/locations/global/keyRings/ring"
                        )
                    ]
                )
            ]
        )


class CryptoKeyClient:
    def list_crypto_keys(self, *, request: dict[str, str]) -> object:
        assert request["parent"].endswith("/keyRings/ring")
        return Pager(
            [
                Page(
                    crypto_keys=[
                        SimpleNamespace(
                            name=f"{request['parent']}/cryptoKeys/asymmetric-key",
                            purpose="ASYMMETRIC_SIGN",
                            rotation_period=None,
                            next_rotation_time=None,
                            labels={},
                        )
                    ]
                )
            ]
        )


def connection() -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=uuid4(),
        organization_id=uuid4(),
        name="fixture connection",
        provider=CloudProvider.GCP,
        scope_id="projects/fixture-project",
        credential_mechanism=CredentialMechanism.GCP_ADC,
    )


def clients(service: str, _conn: ConnectionDescriptor) -> object:
    return {
        "asset": AssetClient(),
        "storage": StorageClient(),
        "compute": ComputeClient(),
        "resource_manager": ResourceManagerClient(),
        "kms_key_rings": KeyRingClient(),
        "kms_crypto_keys": CryptoKeyClient(),
    }[service]


def context(*, pages: int = 20, items: int = 1000) -> CollectionContext:
    conn = connection()
    return CollectionContext(
        connection=conn,
        scope=GcpAdapter(client_factory=clients).resolve_scopes(conn)[0],
        cancel=CancellationToken(),
        budget=PageBudget(max_pages=pages, max_items=items),
        deadline_at=monotonic() + 10,
    )


def test_capabilities_and_project_scope_are_declared() -> None:
    adapter = GcpAdapter(client_factory=clients)

    capabilities = adapter.describe_capabilities()

    assert capabilities.provider is CloudProvider.GCP
    assert capabilities.collectors == (
        "gcp.inventory.assets",
        "gcp.storage.buckets",
        "gcp.compute.firewalls",
        "gcp.iam.project_policy",
        "gcp.logging.audit_config",
        "gcp.kms.keys",
    )
    assert adapter.resolve_scopes(connection())[0].id == "fixture-project"


def test_all_collectors_emit_normalizable_observations() -> None:
    adapter = GcpAdapter(client_factory=clients)
    observations = []
    for collector in adapter.collectors():
        observations.extend(collector.collect(context()))

    assert {observation.resource_type for observation in observations} == {
        NormalizedResourceType.ACCOUNT_SCOPE,
        NormalizedResourceType.OBJECT_STORAGE_BUCKET,
        NormalizedResourceType.NETWORK_FIREWALL_RULE,
        NormalizedResourceType.NETWORK_FIREWALL_RULESET,
        NormalizedResourceType.IDENTITY_POLICY_BINDING,
        NormalizedResourceType.LOGGING_AUDIT_TRAIL,
        NormalizedResourceType.KMS_KEY,
    }
    for observation in observations:
        asset = normalize_observation(
            observation,
            organization_id=uuid4(),
            connection_id=uuid4(),
        )
        assert asset.provider is CloudProvider.GCP


def test_storage_public_access_prevention_overrides_public_iam_binding() -> None:
    collector = GcpAdapter(client_factory=clients).collectors()[1]

    observation = next(collector.collect(context()))

    assert observation.facts["public_read_access"] is TriState.NO
    assert observation.facts["public_write_access"] is TriState.NO
    assert observation.facts["provider_specific"]["gcp"] == {
        "uniform_bucket_level_access": "yes",
        "public_access_prevention": "yes",
    }


def test_storage_policy_mapping_shape_is_understood() -> None:
    bucket = Bucket()
    bucket.iam_configuration.public_access_prevention = "inherited"
    bucket.get_iam_policy = lambda **_kwargs: {
        "roles/storage.objectViewer": {"allAuthenticatedUsers"}
    }

    def mapping_clients(service: str, conn: ConnectionDescriptor) -> object:
        if service == "storage":
            return StorageClient([bucket])
        return clients(service, conn)

    collector = GcpAdapter(client_factory=mapping_clients).collectors()[1]

    observation = next(collector.collect(context()))

    assert observation.facts["public_read_access"] is TriState.YES
    assert observation.facts["public_write_access"] is TriState.NO


def test_storage_detail_denial_reports_the_exact_permission() -> None:
    class DeniedBucket(Bucket):
        def get_iam_policy(self, *, requested_policy_version: int) -> object:
            raise PermissionError("permission denied")

    def denied_clients(service: str, conn: ConnectionDescriptor) -> object:
        if service == "storage":
            return StorageClient([DeniedBucket()])
        return clients(service, conn)

    collector = GcpAdapter(client_factory=denied_clients).collectors()[1]

    with pytest.raises(ProviderError) as caught:
        list(collector.collect(context()))

    assert caught.value.category is ScanErrorCategory.PERMISSION_DENIED
    assert caught.value.permission == "storage.buckets.getIamPolicy"


def test_project_audit_config_remains_unknown_without_parent_visibility() -> None:
    collector = GcpAdapter(client_factory=clients).collectors()[4]

    observation = next(collector.collect(context()))

    assert observation.facts["audit_logging_enabled"] is TriState.UNKNOWN
    assert observation.facts["parent_scope_visibility"] is TriState.NO
    assert observation.facts["provider_specific"]["gcp"]["project_audit_config_present"] is True


def test_asymmetric_kms_key_marks_rotation_not_applicable_via_facts() -> None:
    collector = GcpAdapter(client_factory=clients).collectors()[5]

    observation = next(collector.collect(context()))

    assert observation.facts["supports_rotation"] is TriState.NO
    assert observation.facts["rotation_enabled"] is TriState.UNKNOWN


class ServiceDisabledError(Exception):
    code = "PERMISSION_DENIED"

    def __init__(self) -> None:
        super().__init__("SERVICE_DISABLED: cloudasset.googleapis.com is disabled")
        self.response = SimpleNamespace(status_code=403)


def test_service_disabled_is_not_classified_as_empty_or_permission_denied() -> None:
    def disabled_clients(service: str, conn: ConnectionDescriptor) -> object:
        if service == "asset":
            return AssetClient(error=ServiceDisabledError())
        return clients(service, conn)

    collector = GcpAdapter(client_factory=disabled_clients).collectors()[0]

    with pytest.raises(ProviderError) as caught:
        list(collector.collect(context()))

    assert caught.value.category is ScanErrorCategory.SERVICE_DISABLED
    assert caught.value.permission == "cloudasset.assets.searchAllResources"


def test_verify_access_surfaces_disabled_service_safely() -> None:
    def disabled_clients(service: str, conn: ConnectionDescriptor) -> object:
        if service == "asset":
            return AssetClient(error=ServiceDisabledError())
        return clients(service, conn)

    adapter = GcpAdapter(
        client_factory=disabled_clients,
        identity_loader=lambda _conn: "fixture-principal.invalid",
    )

    report = adapter.verify_access(connection())

    assert report.status == "degraded"
    assert "gcp.inventory.assets" not in report.ok
    assert report.disabled[0].collector == "gcp.inventory.assets"
    assert report.disabled[0].reason.startswith("service_disabled:")


def test_page_budget_is_enforced_between_pages() -> None:
    pager = Pager(
        [
            Page(results=[SimpleNamespace(name="asset-1", display_name="one", asset_type="x")]),
            Page(results=[SimpleNamespace(name="asset-2", display_name="two", asset_type="x")]),
        ]
    )

    def paged_clients(service: str, conn: ConnectionDescriptor) -> object:
        if service == "asset":
            return AssetClient(pager=pager)
        return clients(service, conn)

    collector = GcpAdapter(client_factory=paged_clients).collectors()[0]

    with pytest.raises(ProviderError) as caught:
        list(collector.collect(context(pages=1)))

    assert caught.value.code == "COLLECTION_LIMIT_EXCEEDED"


def test_cancellation_is_checked_before_the_first_request() -> None:
    ctx = context()
    ctx.cancel.cancel()
    collector = GcpAdapter(client_factory=clients).collectors()[0]

    with pytest.raises(ProviderError) as caught:
        list(collector.collect(ctx))

    assert caught.value.code == "CANCELLED"


def test_allowlist_contains_only_reviewed_reads() -> None:
    all_operations = set().union(*GCP_READ_OPERATIONS.values())

    assert "search_all_resources" in all_operations
    assert "get_iam_policy" in all_operations
    assert all("export" not in operation for operation in all_operations)
