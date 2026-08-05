from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    ScanErrorCategory,
)
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.allowlist import ForbiddenOperationError, ReadOnlyClient
from multicloudshield.providers.azure.adapter import AzureAdapter
from multicloudshield.providers.azure.clients import AZURE_READ_OPERATIONS, azure_provider_error
from multicloudshield.providers.azure.collectors import (
    DiagnosticSettingsCollector,
    InventoryCollector,
    KeyVaultsCollector,
    NetworkSecurityGroupsCollector,
    RoleAssignmentsCollector,
    StorageAccountsCollector,
    StorageContainersCollector,
)
from multicloudshield.providers.base import (
    CancellationToken,
    CollectionContext,
    PageBudget,
    ProviderError,
    ScanScope,
)


def connection(*, locations: list[str] | None = None) -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=uuid4(),
        organization_id=uuid4(),
        name="Synthetic Azure",
        provider=CloudProvider.AZURE,
        scope_id=str(uuid4()),
        credential_mechanism=CredentialMechanism.AZURE_DEFAULT_CREDENTIAL,
        region_allowlist=locations or [],
    )


def context(
    conn: ConnectionDescriptor, *, max_pages: int = 20, max_items: int = 100
) -> CollectionContext:
    return CollectionContext(
        connection=conn,
        scope=ScanScope("subscription", conn.scope_id, "azure-public"),
        cancel=CancellationToken(),
        budget=PageBudget(max_pages=max_pages, max_items=max_items),
        deadline_at=monotonic() + 60,
    )


class FakeFactory:
    def __init__(self, groups: dict[str, Any] | None = None) -> None:
        self.groups = groups or {}
        self.probe_errors: dict[str, ProviderError] = {}

    def operation_group(self, group: str, subscription_id: str) -> Any:
        del subscription_id
        return self.groups[group]

    def verify_identity(self, subscription_id: str) -> str:
        return f"azure://subscription/{subscription_id}"

    def probe(self, collector_id: str, subscription_id: str) -> None:
        del subscription_id
        error = self.probe_errors.get(collector_id)
        if error:
            raise error

    def query_resources(self, subscription_id: str, *, skip_token: str | None = None) -> Any:
        del subscription_id, skip_token
        return SimpleNamespace(data=[], skip_token=None)


def test_capabilities_and_scope_are_explicit() -> None:
    conn = connection(locations=["eastus", "brazilsouth"])
    adapter = AzureAdapter(FakeFactory())

    capabilities = adapter.describe_capabilities()

    assert capabilities.provider is CloudProvider.AZURE
    assert capabilities.collectors == (
        "azure.inventory.resources",
        "azure.storage.accounts",
        "azure.storage.containers",
        "azure.network.security_groups",
        "azure.authorization.role_assignments",
        "azure.monitor.diagnostic_settings",
        "azure.keyvault.vaults",
    )
    assert adapter.resolve_scopes(conn) == [
        ScanScope("subscription", conn.scope_id, "azure-public")
    ]


def test_scope_rejects_non_subscription_identifier() -> None:
    conn = connection().model_copy(update={"scope_id": "not-a-subscription"})

    with pytest.raises(ProviderError) as raised:
        AzureAdapter(FakeFactory()).resolve_scopes(conn)

    assert raised.value.code == "INVALID_SUBSCRIPTION_ID"


def test_verify_access_reports_per_collector_gaps() -> None:
    factory = FakeFactory()
    factory.probe_errors["azure.monitor.diagnostic_settings"] = ProviderError(
        ScanErrorCategory.PERMISSION_DENIED,
        "denied",
        permission="Microsoft.Insights/diagnosticSettings/read",
    )
    factory.probe_errors["azure.keyvault.vaults"] = ProviderError(
        ScanErrorCategory.SERVICE_DISABLED,
        "provider not registered",
        permission="Microsoft.KeyVault/vaults/read",
    )

    report = AzureAdapter(factory).verify_access(connection())

    assert report.status == "degraded"
    assert len(report.ok) == 5
    assert report.denied[0].collector == "azure.monitor.diagnostic_settings"
    assert report.disabled[0].collector == "azure.keyvault.vaults"


def test_error_mapping_is_redacted_and_retry_aware() -> None:
    class HttpError(Exception):
        status_code = 429
        error = SimpleNamespace(code="TooManyRequests")

    error = azure_provider_error(
        HttpError("sensitive-exception-value"), operation="Vaults.List", permission="read"
    )

    assert error.category is ScanErrorCategory.THROTTLED
    assert error.retryable is True
    assert "sensitive-exception-value" not in str(error)


def test_storage_account_keys_are_not_allowlisted() -> None:
    assert "list_keys" not in AZURE_READ_OPERATIONS["storage_accounts"]
    target = SimpleNamespace(list_keys=lambda: pytest.fail("must not be called"))

    with pytest.raises(ForbiddenOperationError):
        ReadOnlyClient(target, AZURE_READ_OPERATIONS["storage_accounts"]).list_keys()


@dataclass
class RecordingGroup:
    result: Any
    calls: list[tuple[Any, ...]]

    def list(self, *args: Any) -> Any:
        self.calls.append(args)
        return self.result


def test_container_posture_comes_from_arm_public_access() -> None:
    conn = connection()
    account_id = (
        f"/subscriptions/{conn.scope_id}/resourceGroups/synthetic-rg/"
        "providers/Microsoft.Storage/storageAccounts/syntheticstore"
    )
    account = SimpleNamespace(
        id=account_id,
        name="syntheticstore",
        location="eastus",
        allow_blob_public_access=True,
        allow_shared_key_access=False,
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        encryption=SimpleNamespace(key_source="Microsoft.Keyvault"),
    )
    container = SimpleNamespace(
        id=f"{account_id}/blobServices/default/containers/public-assets",
        name="public-assets",
        public_access="Blob",
        metadata={},
    )
    account_group = RecordingGroup([account], [])
    container_group = RecordingGroup([container], [])
    factory = FakeFactory({"storage_accounts": account_group, "blob_containers": container_group})

    observations = list(StorageContainersCollector(factory).collect(context(conn)))

    assert len(observations) == 1
    assert observations[0].facts["public_read_access"] is TriState.YES
    assert observations[0].facts["public_write_access"] is TriState.NO
    assert observations[0].facts["encryption_at_rest"] is EncryptionPosture.CUSTOMER_MANAGED
    assert container_group.calls == [("synthetic-rg", "syntheticstore")]


def test_storage_account_properties_are_normalized_without_data_plane_reads() -> None:
    conn = connection()
    account = SimpleNamespace(
        id=(
            f"/subscriptions/{conn.scope_id}/resourceGroups/synthetic-rg/"
            "providers/Microsoft.Storage/storageAccounts/private"
        ),
        name="private",
        location="eastus",
        tags={"owner": "security"},
        allow_blob_public_access=False,
        allow_shared_key_access=False,
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        encryption=SimpleNamespace(key_source="Microsoft.Storage"),
    )
    factory = FakeFactory({"storage_accounts": RecordingGroup([account], [])})

    observation = list(StorageAccountsCollector(factory).collect(context(conn)))[0]

    assert observation.facts["tls_required"] is TriState.YES
    assert observation.facts["encryption_at_rest"] is EncryptionPosture.PROVIDER_MANAGED
    assert observation.facts["provider_specific"]["azure"]["allow_shared_key_access"] == "no"


class InventoryFactory(FakeFactory):
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        super().__init__()
        self.rows = rows

    def query_resources(self, subscription_id: str, *, skip_token: str | None = None) -> Any:
        del subscription_id, skip_token
        return SimpleNamespace(data=self.rows, skip_token=None)


def test_inventory_filters_out_locations_outside_connection_boundary() -> None:
    conn = connection(locations=["eastus"])
    rows = [
        {
            "id": f"/subscriptions/{conn.scope_id}/resourceGroups/r/providers/Synthetic/one/a",
            "name": "a",
            "type": "Synthetic/one",
            "location": "eastus",
            "tags": {},
        },
        {
            "id": f"/subscriptions/{conn.scope_id}/resourceGroups/r/providers/Synthetic/two/b",
            "name": "b",
            "type": "Synthetic/two",
            "location": "westus",
            "tags": {},
        },
    ]

    observations = list(InventoryCollector(InventoryFactory(rows)).collect(context(conn)))

    assert [observation.name for observation in observations] == ["a"]


class NetworkGroup:
    def __init__(self, groups: list[Any]) -> None:
        self.groups = groups

    def list_all(self) -> list[Any]:
        return self.groups


def test_nsg_collector_detects_public_admin_and_all_port_rules() -> None:
    conn = connection()
    group_id = (
        f"/subscriptions/{conn.scope_id}/resourceGroups/synthetic-rg/"
        "providers/Microsoft.Network/networkSecurityGroups/web"
    )
    rules = [
        SimpleNamespace(
            id=f"{group_id}/securityRules/ssh",
            name="ssh",
            direction="Inbound",
            access="Allow",
            source_address_prefix="Internet",
            source_address_prefixes=None,
            destination_port_range="22",
            destination_port_ranges=None,
            protocol="Tcp",
            priority=100,
        ),
        SimpleNamespace(
            id=f"{group_id}/securityRules/all",
            name="all",
            direction="Inbound",
            access="Allow",
            source_address_prefix="0.0.0.0/0",
            source_address_prefixes=None,
            destination_port_range="*",
            destination_port_ranges=None,
            protocol="*",
            priority=200,
        ),
    ]
    group = SimpleNamespace(
        id=group_id,
        name="web",
        location="eastus",
        security_rules=rules,
        default_security_rules=[],
        tags={},
    )
    factory = FakeFactory({"network_security_groups": NetworkGroup([group])})

    observations = list(NetworkSecurityGroupsCollector(factory).collect(context(conn)))

    ruleset = observations[0]
    assert ruleset.facts["unrestricted_admin_ingress"] is TriState.YES
    assert ruleset.facts["unrestricted_all_ports"] is TriState.YES
    assert ruleset.facts["unrestricted_datastore_ingress"] is TriState.YES
    assert len(observations) == 3


def test_nsg_malformed_rule_does_not_become_a_false_clear() -> None:
    conn = connection()
    group_id = (
        f"/subscriptions/{conn.scope_id}/resourceGroups/synthetic-rg/"
        "providers/Microsoft.Network/networkSecurityGroups/incomplete"
    )
    incomplete = SimpleNamespace(
        id=f"{group_id}/securityRules/incomplete",
        name="incomplete",
        direction="Inbound",
        access="Allow",
        source_address_prefix=None,
        source_address_prefixes=None,
        destination_port_range=None,
        destination_port_ranges=None,
        protocol=None,
        priority=100,
    )
    group = SimpleNamespace(
        id=group_id,
        name="incomplete",
        location="eastus",
        security_rules=[incomplete],
        default_security_rules=[],
        tags={},
    )
    factory = FakeFactory({"network_security_groups": NetworkGroup([group])})

    ruleset = list(NetworkSecurityGroupsCollector(factory).collect(context(conn)))[0]

    assert ruleset.facts["unrestricted_admin_ingress"] is TriState.UNKNOWN
    assert ruleset.facts["unrestricted_all_ports"] is TriState.UNKNOWN


class ScopeListGroup:
    def __init__(self, result: list[Any]) -> None:
        self.result = result

    def list_for_scope(self, scope: str) -> list[Any]:
        assert scope.startswith("/subscriptions/")
        return self.result


def test_role_assignments_include_definition_name_but_not_entra_secrets() -> None:
    conn = connection()
    scope = f"/subscriptions/{conn.scope_id}"
    role_id = f"{scope}/providers/Microsoft.Authorization/roleDefinitions/synthetic-reader"
    assignment = SimpleNamespace(
        id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/synthetic-assignment",
        name="synthetic-assignment",
        role_definition_id=role_id,
        principal_id="synthetic-principal",
        principal_type="ServicePrincipal",
        scope=scope,
    )
    definition = SimpleNamespace(id=role_id, name="synthetic-reader", role_name="Reader")
    factory = FakeFactory(
        {
            "role_definitions": RecordingGroup([definition], []),
            "role_assignments": ScopeListGroup([assignment]),
        }
    )

    observation = list(RoleAssignmentsCollector(factory).collect(context(conn)))[0]

    azure = observation.facts["provider_specific"]["azure"]
    assert azure["role_name"] == "Reader"
    assert observation.facts["mfa_enabled"] is TriState.UNKNOWN


class DiagnosticGroup:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.resource_ids: list[str] = []

    def list(self, resource_id: str) -> Any:
        self.resource_ids.append(resource_id)
        return self.result


def test_diagnostic_settings_emit_positive_evidence_only_for_enabled_logs() -> None:
    conn = connection()
    resource_id = (
        f"/subscriptions/{conn.scope_id}/resourceGroups/r/"
        "providers/Microsoft.Storage/storageAccounts/private"
    )
    setting = SimpleNamespace(
        id=f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings/audit",
        name="audit",
        logs=[SimpleNamespace(enabled=True)],
        workspace_id="synthetic-workspace",
        storage_account_id=None,
        event_hub_authorization_rule_id=None,
    )
    group = DiagnosticGroup(SimpleNamespace(value=[setting]))
    factory = InventoryFactory(
        [{"id": resource_id, "name": "private", "location": "eastus", "type": "Synthetic"}]
    )
    factory.groups["diagnostic_settings"] = group

    observation = list(DiagnosticSettingsCollector(factory).collect(context(conn)))[0]

    assert observation.facts["audit_logging_enabled"] is TriState.YES
    assert group.resource_ids == [resource_id]


def test_vault_unknown_values_remain_unknown() -> None:
    conn = connection()
    vault = SimpleNamespace(
        id=(
            f"/subscriptions/{conn.scope_id}/resourceGroups/synthetic-rg/"
            "providers/Microsoft.KeyVault/vaults/synthetic"
        ),
        name="synthetic",
        location="eastus",
        tags={},
        properties=SimpleNamespace(
            enable_soft_delete=None,
            enable_purge_protection=False,
            soft_delete_retention_in_days=30,
        ),
    )
    factory = FakeFactory({"vaults": RecordingGroup([vault], [])})

    observation = list(KeyVaultsCollector(factory).collect(context(conn)))[0]

    azure = observation.facts["provider_specific"]["azure"]
    assert azure["soft_delete_enabled"] == TriState.UNKNOWN.value
    assert azure["purge_protection_enabled"] == TriState.NO.value


def test_cancelled_collection_stops_before_sdk_call() -> None:
    conn = connection()
    group = RecordingGroup([], [])
    factory = FakeFactory({"vaults": group})
    ctx = context(conn)
    ctx.cancel.cancel()

    with pytest.raises(ProviderError) as raised:
        list(KeyVaultsCollector(factory).collect(ctx))

    assert raised.value.code == "CANCELLED"
    assert group.calls == []


def test_page_budget_is_hard_cap() -> None:
    conn = connection()
    vault = SimpleNamespace(
        id=f"/subscriptions/{conn.scope_id}/resourceGroups/r/providers/Microsoft.KeyVault/vaults/v",
        name="v",
        location="eastus",
        tags={},
        properties=SimpleNamespace(),
    )
    factory = FakeFactory({"vaults": RecordingGroup([vault, vault], [])})

    with pytest.raises(ProviderError) as raised:
        list(KeyVaultsCollector(factory).collect(context(conn, max_items=1)))

    assert raised.value.code == "COLLECTION_LIMIT_EXCEEDED"
