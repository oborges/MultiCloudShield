from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from hashlib import sha256
from itertools import islice
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.azure.clients import (
    AzureClientFactory,
    azure_provider_error,
    resource_group_from_id,
)
from multicloudshield.providers.base import CollectionContext, RawObservation

_ADMIN_PORTS = frozenset((22, 3389))
_DATASTORE_PORTS = frozenset((1433, 1521, 3306, 5432, 6379, 27017))
_PUBLIC_SOURCES = frozenset(("*", "internet", "0.0.0.0/0", "::/0"))


def _get(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(value, dict) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return default


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _tags(value: Any) -> dict[str, str]:
    tags = _mapping(value)
    return {str(key): str(item) for key, item in list(tags.items())[:200]}


def _paged(items: Iterable[Any], ctx: CollectionContext) -> Iterator[list[Any]]:
    """Iterate SDK pages while enforcing cancellation, deadline, page and item caps."""

    by_page = getattr(items, "by_page", None)
    if callable(by_page):
        for raw_page in by_page():
            ctx.checkpoint()
            page = list(raw_page)
            ctx.budget.add_page(len(page))
            yield page
        return

    iterator = iter(items)
    while True:
        ctx.checkpoint()
        page = list(islice(iterator, 1000))
        if not page:
            return
        ctx.budget.add_page(len(page))
        yield page


def _provenance(collector: str, operation: str, scope: str, native_id: str) -> dict[str, Any]:
    digest = sha256(f"{collector}\0{operation}\0{native_id}".encode()).hexdigest()
    return {
        "collector_id": collector,
        "collector_version": "1.0.0",
        "calls": [
            {
                "service": "azure-arm",
                "operation": operation,
                "scope": scope,
                "request": {},
                "response_digest": f"sha256:{digest}",
                "http_status": 200,
            }
        ],
    }


def _location_allowed(ctx: CollectionContext, location: str) -> bool:
    allowlist = {item.lower() for item in ctx.connection.region_allowlist}
    normalized = location.lower()
    return not allowlist or normalized in {"", "global"} or normalized in allowlist


def _azure_observation(
    *,
    collector: str,
    operation: str,
    ctx: CollectionContext,
    provider_type: str,
    native_id: str,
    name: str,
    resource_type: NormalizedResourceType,
    tags: dict[str, str],
    facts: dict[str, Any],
) -> RawObservation:
    return RawObservation(
        provider=CloudProvider.AZURE,
        provider_resource_type=provider_type,
        native_id=native_id,
        local_id=native_id.lower(),
        name=name,
        resource_type=resource_type,
        scope=ctx.scope,
        tags=tags,
        facts=facts,
        provenance=_provenance(collector, operation, ctx.scope.id, native_id),
    )


@dataclass(frozen=True)
class AzureCollector:
    factory: AzureClientFactory
    id: str
    produces: frozenset[NormalizedResourceType]
    required_permissions: tuple[str, ...]
    optional_permissions: tuple[str, ...] = ()
    version: str = "1.0.0"
    scope_kind: str = "subscription"

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        raise NotImplementedError


class InventoryCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.inventory.resources",
            frozenset((NormalizedResourceType.ACCOUNT_SCOPE,)),
            ("Microsoft.ResourceGraph/resources/read",),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        token: str | None = None
        try:
            while True:
                ctx.checkpoint()
                response = self.factory.query_resources(ctx.scope.id, skip_token=token)
                rows = list(_get(response, "data", default=()) or ())
                ctx.budget.add_page(len(rows))
                for row in rows:
                    native_id = str(_get(row, "id", default=""))
                    if not native_id:
                        continue
                    location = str(_get(row, "location", default="global") or "global")
                    if not _location_allowed(ctx, location):
                        continue
                    provider_type = str(_get(row, "type", default="azure.resource"))
                    yield _azure_observation(
                        collector=self.id,
                        operation="ResourceGraph.Resources",
                        ctx=ctx,
                        provider_type=provider_type,
                        native_id=native_id,
                        name=str(_get(row, "name", default=native_id.rsplit("/", 1)[-1])),
                        resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
                        tags=_tags(_get(row, "tags", default={})),
                        facts={
                            "kind": "account",
                            "audit_logging_enabled": TriState.UNKNOWN,
                            "mfa_enforced": TriState.UNKNOWN,
                            "provider_specific": {
                                "azure": {"location": location, "resource_type": provider_type}
                            },
                        },
                    )
                token = _get(response, "skip_token", "skipToken")
                if not token:
                    return
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="ResourceGraph.Resources",
                permission=self.required_permissions[0],
            ) from exc


def _account_storage_facts(account: Any) -> dict[str, Any]:
    encryption = _get(account, "encryption")
    key_source = str(_get(encryption, "key_source", "keySource", default="")).lower()
    if "keyvault" in key_source:
        posture = EncryptionPosture.CUSTOMER_MANAGED
    elif encryption is not None:
        posture = EncryptionPosture.PROVIDER_MANAGED
    else:
        posture = EncryptionPosture.UNKNOWN

    allow_public = _get(account, "allow_blob_public_access", "allowBlobPublicAccess")
    https_only = _get(account, "enable_https_traffic_only", "supports_https_traffic_only")
    shared_key = _get(account, "allow_shared_key_access", "allowSharedKeyAccess")
    minimum_tls = _get(account, "minimum_tls_version", "minimumTlsVersion")
    return {
        "kind": "object_storage",
        # Account configuration permits public ACLs but does not prove a container is public.
        "public_read_access": TriState.UNKNOWN,
        "public_write_access": TriState.NO,
        "encryption_at_rest": posture,
        "versioning_enabled": TriState.UNKNOWN,
        "access_logging_enabled": TriState.UNKNOWN,
        "tls_required": (
            TriState.YES
            if https_only is True
            else TriState.NO
            if https_only is False
            else TriState.UNKNOWN
        ),
        "provider_specific": {
            "azure": {
                "allow_blob_public_access": (
                    TriState.YES.value
                    if allow_public is True
                    else TriState.NO.value
                    if allow_public is False
                    else TriState.UNKNOWN.value
                ),
                "allow_shared_key_access": (
                    TriState.YES.value
                    if shared_key is True
                    else TriState.NO.value
                    if shared_key is False
                    else TriState.UNKNOWN.value
                ),
                "minimum_tls_version": str(minimum_tls) if minimum_tls is not None else None,
            }
        },
    }


class StorageAccountsCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.storage.accounts",
            frozenset((NormalizedResourceType.OBJECT_STORAGE_ACCOUNT,)),
            ("Microsoft.Storage/storageAccounts/read",),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        try:
            ctx.checkpoint()
            accounts = self.factory.operation_group("storage_accounts", ctx.scope.id).list()
            for page in _paged(accounts, ctx):
                for account in page:
                    native_id = str(_get(account, "id", default=""))
                    location = str(_get(account, "location", default="global") or "global")
                    if not native_id or not _location_allowed(ctx, location):
                        continue
                    yield _azure_observation(
                        collector=self.id,
                        operation="StorageAccounts.List",
                        ctx=ctx,
                        provider_type=str(
                            _get(account, "type", default="Microsoft.Storage/storageAccounts")
                        ),
                        native_id=native_id,
                        name=str(_get(account, "name", default=native_id.rsplit("/", 1)[-1])),
                        resource_type=NormalizedResourceType.OBJECT_STORAGE_ACCOUNT,
                        tags=_tags(_get(account, "tags", default={})),
                        facts=_account_storage_facts(account),
                    )
        except Exception as exc:
            raise azure_provider_error(
                exc, operation="StorageAccounts.List", permission=self.required_permissions[0]
            ) from exc


class StorageContainersCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.storage.containers",
            frozenset((NormalizedResourceType.OBJECT_STORAGE_BUCKET,)),
            (
                "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                "Microsoft.Storage/storageAccounts/read",
            ),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        try:
            ctx.checkpoint()
            accounts = self.factory.operation_group("storage_accounts", ctx.scope.id).list()
            for account_page in _paged(accounts, ctx):
                for account in account_page:
                    location = str(_get(account, "location", default="global") or "global")
                    if not _location_allowed(ctx, location):
                        continue
                    account_id = str(_get(account, "id", default=""))
                    account_name = str(_get(account, "name", default=""))
                    if not account_id or not account_name:
                        continue
                    resource_group = resource_group_from_id(account_id)
                    ctx.checkpoint()
                    containers = self.factory.operation_group("blob_containers", ctx.scope.id).list(
                        resource_group, account_name
                    )
                    account_facts = _account_storage_facts(account)
                    for container_page in _paged(containers, ctx):
                        for container in container_page:
                            name = str(_get(container, "name", default=""))
                            native_id = str(
                                _get(
                                    container,
                                    "id",
                                    default=f"{account_id}/blobServices/default/containers/{name}",
                                )
                            )
                            access = str(
                                _get(container, "public_access", "publicAccess", default="None")
                            ).lower()
                            public = (
                                TriState.YES if access in {"blob", "container"} else TriState.NO
                            )
                            facts = dict(account_facts)
                            facts["public_read_access"] = public
                            facts["provider_specific"] = {
                                "azure": {
                                    **account_facts["provider_specific"]["azure"],
                                    "public_access": access,
                                    "storage_account_id": account_id,
                                }
                            }
                            yield _azure_observation(
                                collector=self.id,
                                operation="BlobContainers.List",
                                ctx=ctx,
                                provider_type="Microsoft.Storage/storageAccounts/blobServices/containers",
                                native_id=native_id,
                                name=name or native_id.rsplit("/", 1)[-1],
                                resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                                tags=_tags(_get(container, "metadata", default={})),
                                facts=facts,
                            )
        except Exception as exc:
            raise azure_provider_error(
                exc, operation="BlobContainers.List", permission=self.required_permissions[0]
            ) from exc


def _rule_sources(rule: Any) -> list[str]:
    values = list(_get(rule, "source_address_prefixes", default=()) or ())
    single = _get(rule, "source_address_prefix")
    if single:
        values.append(single)
    return [str(item).lower() for item in values]


def _rule_port_ranges(rule: Any) -> tuple[bool, set[int], bool]:
    values = list(_get(rule, "destination_port_ranges", default=()) or ())
    single = _get(rule, "destination_port_range")
    if single:
        values.append(single)
    all_ports = False
    ports: set[int] = set()
    understood = bool(values)
    for value in values:
        text = str(value).strip()
        if text in {"*", "0-65535"}:
            all_ports = True
        elif text.isdigit():
            ports.add(int(text))
        elif "-" in text:
            start, _, end = text.partition("-")
            if start.isdigit() and end.isdigit():
                low, high = int(start), int(end)
                ports.update(
                    port for port in _ADMIN_PORTS | _DATASTORE_PORTS if low <= port <= high
                )
            else:
                understood = False
        else:
            understood = False
    return all_ports, ports, understood


def _rule_posture(rule: Any) -> tuple[bool | None, bool | None, bool | None]:
    direction = str(_get(rule, "direction", default="")).lower()
    access = str(_get(rule, "access", default="")).lower()
    if direction and direction != "inbound":
        return False, False, False
    if access and access != "allow":
        return False, False, False
    if not direction or not access:
        return None, None, None
    sources = _rule_sources(rule)
    if not sources:
        return None, None, None
    if not any(source in _PUBLIC_SOURCES for source in sources):
        return False, False, False
    all_ports, ports, understood = _rule_port_ranges(rule)
    if not understood:
        return None, None, None
    return (
        all_ports or bool(ports & _ADMIN_PORTS),
        all_ports,
        all_ports or bool(ports & _DATASTORE_PORTS),
    )


def _tri_state(values: Iterable[bool | None]) -> TriState:
    items = list(values)
    if any(item is True for item in items):
        return TriState.YES
    if any(item is None for item in items):
        return TriState.UNKNOWN
    return TriState.NO


class NetworkSecurityGroupsCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.network.security_groups",
            frozenset(
                (
                    NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                    NormalizedResourceType.NETWORK_FIREWALL_RULE,
                )
            ),
            ("Microsoft.Network/networkSecurityGroups/read",),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        try:
            ctx.checkpoint()
            groups = self.factory.operation_group(
                "network_security_groups", ctx.scope.id
            ).list_all()
            for page in _paged(groups, ctx):
                for group in page:
                    group_id = str(_get(group, "id", default=""))
                    location = str(_get(group, "location", default="global") or "global")
                    if not group_id or not _location_allowed(ctx, location):
                        continue
                    rules = list(_get(group, "security_rules", default=()) or ()) + list(
                        _get(group, "default_security_rules", default=()) or ()
                    )
                    postures = [_rule_posture(rule) for rule in rules]
                    offending = [
                        str(_get(rule, "name", default=f"rule-{index}"))
                        for index, (rule, posture) in enumerate(zip(rules, postures, strict=True))
                        if any(posture)
                    ]
                    common = {
                        "kind": "firewall",
                        "unrestricted_admin_ingress": _tri_state(item[0] for item in postures),
                        "unrestricted_all_ports": _tri_state(item[1] for item in postures),
                        "unrestricted_datastore_ingress": _tri_state(item[2] for item in postures),
                        "offending_rules": offending,
                        "provider_specific": {"azure": {"location": location}},
                    }
                    yield _azure_observation(
                        collector=self.id,
                        operation="NetworkSecurityGroups.ListAll",
                        ctx=ctx,
                        provider_type="Microsoft.Network/networkSecurityGroups",
                        native_id=group_id,
                        name=str(_get(group, "name", default=group_id.rsplit("/", 1)[-1])),
                        resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                        tags=_tags(_get(group, "tags", default={})),
                        facts=common,
                    )
                    for rule, posture in zip(rules, postures, strict=True):
                        rule_id = str(_get(rule, "id", default=f"{group_id}/securityRules/unknown"))
                        rule_name = str(_get(rule, "name", default=rule_id.rsplit("/", 1)[-1]))
                        yield _azure_observation(
                            collector=self.id,
                            operation="NetworkSecurityGroups.ListAll",
                            ctx=ctx,
                            provider_type="Microsoft.Network/networkSecurityGroups/securityRules",
                            native_id=rule_id,
                            name=rule_name,
                            resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULE,
                            tags={},
                            facts={
                                "kind": "firewall",
                                "unrestricted_admin_ingress": _tri_state((posture[0],)),
                                "unrestricted_all_ports": _tri_state((posture[1],)),
                                "unrestricted_datastore_ingress": _tri_state((posture[2],)),
                                "offending_rules": [rule_name] if any(posture) else [],
                                "provider_specific": {
                                    "azure": {
                                        "priority": _get(rule, "priority"),
                                        "protocol": str(_get(rule, "protocol", default="")),
                                    }
                                },
                            },
                        )
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="NetworkSecurityGroups.ListAll",
                permission=self.required_permissions[0],
            ) from exc


class RoleAssignmentsCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.authorization.role_assignments",
            frozenset((NormalizedResourceType.IDENTITY_POLICY_BINDING,)),
            (
                "Microsoft.Authorization/roleAssignments/read",
                "Microsoft.Authorization/roleDefinitions/read",
            ),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        scope = f"/subscriptions/{ctx.scope.id}"
        try:
            ctx.checkpoint()
            definition_names: dict[str, str] = {}
            definitions = self.factory.operation_group("role_definitions", ctx.scope.id).list(scope)
            for page in _paged(definitions, ctx):
                for definition in page:
                    identifier = str(_get(definition, "id", default="")).lower()
                    if identifier:
                        definition_names[identifier] = str(
                            _get(
                                definition,
                                "role_name",
                                default=_get(definition, "name", default=""),
                            )
                        )
            ctx.checkpoint()
            assignments = self.factory.operation_group(
                "role_assignments", ctx.scope.id
            ).list_for_scope(scope)
            for page in _paged(assignments, ctx):
                for assignment in page:
                    native_id = str(_get(assignment, "id", default=""))
                    if not native_id:
                        continue
                    role_id = str(_get(assignment, "role_definition_id", default=""))
                    principal_id = str(_get(assignment, "principal_id", default=""))
                    yield _azure_observation(
                        collector=self.id,
                        operation="RoleAssignments.ListForScope",
                        ctx=ctx,
                        provider_type="Microsoft.Authorization/roleAssignments",
                        native_id=native_id,
                        name=str(_get(assignment, "name", default=native_id.rsplit("/", 1)[-1])),
                        resource_type=NormalizedResourceType.IDENTITY_POLICY_BINDING,
                        tags={},
                        facts={
                            "kind": "identity",
                            "interactive": TriState.UNKNOWN,
                            "mfa_enabled": TriState.UNKNOWN,
                            "long_lived_credential": TriState.UNKNOWN,
                            "credential_age_days": None,
                            "provider_specific": {
                                "azure": {
                                    "principal_id": principal_id,
                                    "principal_type": str(
                                        _get(assignment, "principal_type", default="")
                                    ),
                                    "role_definition_id": role_id,
                                    "role_name": definition_names.get(role_id.lower()),
                                    "scope": str(_get(assignment, "scope", default=scope)),
                                }
                            },
                        },
                    )
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="RoleAssignments.ListForScope",
                permission=self.required_permissions[0],
            ) from exc


def _diagnostic_enabled(setting: Any) -> bool:
    logs = list(_get(setting, "logs", default=()) or ())
    return any(_get(log, "enabled") is True for log in logs)


class DiagnosticSettingsCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.monitor.diagnostic_settings",
            frozenset((NormalizedResourceType.LOGGING_DIAGNOSTIC_SETTING,)),
            (
                "Microsoft.Insights/diagnosticSettings/read",
                "Microsoft.ResourceGraph/resources/read",
            ),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        token: str | None = None
        try:
            while True:
                ctx.checkpoint()
                response = self.factory.query_resources(ctx.scope.id, skip_token=token)
                resources = list(_get(response, "data", default=()) or ())
                ctx.budget.add_page(len(resources))
                for resource in resources:
                    ctx.checkpoint()
                    resource_id = str(_get(resource, "id", default=""))
                    location = str(_get(resource, "location", default="global") or "global")
                    if not resource_id or not _location_allowed(ctx, location):
                        continue
                    ctx.checkpoint()
                    raw_settings = self.factory.operation_group(
                        "diagnostic_settings", ctx.scope.id
                    ).list(resource_id)
                    settings = list(_get(raw_settings, "value", default=raw_settings) or ())
                    ctx.budget.add_page(len(settings))
                    if not settings:
                        settings = [None]
                    for setting in settings:
                        setting_name = str(_get(setting, "name", default="none"))
                        native_id = str(
                            _get(
                                setting,
                                "id",
                                default=f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings/{setting_name}",
                            )
                        )
                        yield _azure_observation(
                            collector=self.id,
                            operation="DiagnosticSettings.List",
                            ctx=ctx,
                            provider_type="Microsoft.Insights/diagnosticSettings",
                            native_id=native_id,
                            name=setting_name,
                            resource_type=NormalizedResourceType.LOGGING_DIAGNOSTIC_SETTING,
                            tags={},
                            facts={
                                "kind": "logging",
                                "audit_logging_enabled": (
                                    TriState.YES
                                    if setting is not None and _diagnostic_enabled(setting)
                                    else TriState.NO
                                ),
                                "destination_public": TriState.UNKNOWN,
                                "parent_scope_visibility": TriState.YES,
                                "provider_specific": {
                                    "azure": {
                                        "resource_id": resource_id,
                                        "workspace_id": _get(setting, "workspace_id"),
                                        "storage_account_id": _get(setting, "storage_account_id"),
                                        "event_hub_authorization_rule_id": _get(
                                            setting, "event_hub_authorization_rule_id"
                                        ),
                                    }
                                },
                            },
                        )
                token = _get(response, "skip_token", "skipToken")
                if not token:
                    return
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="DiagnosticSettings.List",
                permission=self.required_permissions[0],
            ) from exc


class KeyVaultsCollector(AzureCollector):
    def __init__(self, factory: AzureClientFactory) -> None:
        super().__init__(
            factory,
            "azure.keyvault.vaults",
            frozenset((NormalizedResourceType.KMS_VAULT,)),
            ("Microsoft.KeyVault/vaults/read",),
        )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        try:
            ctx.checkpoint()
            vaults = self.factory.operation_group("vaults", ctx.scope.id).list()
            for page in _paged(vaults, ctx):
                for vault in page:
                    native_id = str(_get(vault, "id", default=""))
                    location = str(_get(vault, "location", default="global") or "global")
                    if not native_id or not _location_allowed(ctx, location):
                        continue
                    properties = _get(vault, "properties", default=vault)
                    soft_delete = _get(properties, "enable_soft_delete", "enableSoftDelete")
                    purge = _get(properties, "enable_purge_protection", "enablePurgeProtection")
                    yield _azure_observation(
                        collector=self.id,
                        operation="Vaults.List",
                        ctx=ctx,
                        provider_type="Microsoft.KeyVault/vaults",
                        native_id=native_id,
                        name=str(_get(vault, "name", default=native_id.rsplit("/", 1)[-1])),
                        resource_type=NormalizedResourceType.KMS_VAULT,
                        tags=_tags(_get(vault, "tags", default={})),
                        facts={
                            "kind": "kms",
                            "rotation_enabled": TriState.UNKNOWN,
                            "supports_rotation": TriState.UNKNOWN,
                            "provider_specific": {
                                "azure": {
                                    "soft_delete_enabled": (
                                        TriState.YES.value
                                        if soft_delete is True
                                        else TriState.NO.value
                                        if soft_delete is False
                                        else TriState.UNKNOWN.value
                                    ),
                                    "purge_protection_enabled": (
                                        TriState.YES.value
                                        if purge is True
                                        else TriState.NO.value
                                        if purge is False
                                        else TriState.UNKNOWN.value
                                    ),
                                    "soft_delete_retention_days": _get(
                                        properties,
                                        "soft_delete_retention_in_days",
                                        "softDeleteRetentionInDays",
                                    ),
                                }
                            },
                        },
                    )
        except Exception as exc:
            raise azure_provider_error(
                exc, operation="Vaults.List", permission=self.required_permissions[0]
            ) from exc


def azure_collectors(factory: AzureClientFactory) -> tuple[AzureCollector, ...]:
    return (
        InventoryCollector(factory),
        StorageAccountsCollector(factory),
        StorageContainersCollector(factory),
        NetworkSecurityGroupsCollector(factory),
        RoleAssignmentsCollector(factory),
        DiagnosticSettingsCollector(factory),
        KeyVaultsCollector(factory),
    )
