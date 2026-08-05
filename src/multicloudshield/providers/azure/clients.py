from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from importlib import import_module
from typing import Any

from multicloudshield.core.enums import ScanErrorCategory
from multicloudshield.providers.allowlist import ReadOnlyClient, assert_read_only_allowlist
from multicloudshield.providers.base import ProviderError

# Operation-group allowlists are deliberately local to the Azure adapter. Azure management
# clients expose operations in groups (for example ``client.storage_accounts.list``), so each
# group is wrapped independently. ``list_keys`` is intentionally absent: despite its name it is
# a POST action that returns data-plane credentials.
AZURE_READ_OPERATIONS: dict[str, frozenset[str]] = {
    "resource_graph": frozenset(("resources",)),
    "subscriptions": frozenset(("get",)),
    "storage_accounts": frozenset(("list",)),
    "blob_containers": frozenset(("list",)),
    "network_security_groups": frozenset(("list_all",)),
    "role_assignments": frozenset(("list_for_scope",)),
    "role_definitions": frozenset(("list",)),
    "diagnostic_settings": frozenset(("list",)),
    "vaults": frozenset(("list",)),
}

for _operations in AZURE_READ_OPERATIONS.values():
    assert_read_only_allowlist(_operations)


def _error_code(exc: Exception) -> str | None:
    error = getattr(exc, "error", None)
    code = getattr(error, "code", None) or getattr(exc, "code", None)
    return str(code) if code else None


def _status_code(exc: Exception) -> int | None:
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return status if isinstance(status, int) else None


def azure_provider_error(
    exc: Exception,
    *,
    operation: str,
    permission: str | None = None,
) -> ProviderError:
    """Convert Azure/SDK failures without copying potentially sensitive exception text."""

    if isinstance(exc, ProviderError):
        return exc
    if isinstance(exc, (ImportError, ModuleNotFoundError)):
        return ProviderError(
            ScanErrorCategory.API_ERROR,
            "Azure provider SDK is not installed; install the azure optional dependencies",
            operation=operation,
            code="AZURE_SDK_UNAVAILABLE",
        )

    code = _error_code(exc)
    status = _status_code(exc)
    class_name = type(exc).__name__
    lowered_code = (code or "").lower()
    if (
        class_name
        in {
            "ClientAuthenticationError",
            "CredentialUnavailableError",
            "AuthenticationRequiredError",
        }
        or status == 401
    ):
        return ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "Azure authentication failed",
            operation=operation,
            code=code or class_name,
        )
    if lowered_code == "missingsubscriptionregistration":
        return ProviderError(
            ScanErrorCategory.SERVICE_DISABLED,
            "Required Azure resource provider is not registered",
            operation=operation,
            code=code,
        )
    if lowered_code in {"locationnotavailable", "invalidresourcelocation"}:
        return ProviderError(
            ScanErrorCategory.UNSUPPORTED_REGION,
            "Azure resource is not available in the selected location",
            operation=operation,
            code=code,
        )
    if status == 403 or lowered_code in {"authorizationfailed", "forbidden"}:
        return ProviderError(
            ScanErrorCategory.PERMISSION_DENIED,
            "Azure denied the required read permission",
            operation=operation,
            code=code or "AuthorizationFailed",
            permission=permission,
        )
    if status == 429:
        return ProviderError(
            ScanErrorCategory.THROTTLED,
            "Azure request was throttled",
            operation=operation,
            code=code or "TooManyRequests",
            retryable=True,
        )
    if status == 404:
        return ProviderError(
            ScanErrorCategory.NOT_FOUND,
            "Azure resource was not found",
            operation=operation,
            code=code or "ResourceNotFound",
        )
    if class_name in {"ServiceRequestTimeoutError", "ServiceResponseTimeoutError"}:
        return ProviderError(
            ScanErrorCategory.TIMEOUT,
            "Azure request timed out",
            operation=operation,
            code=class_name,
            retryable=True,
        )
    return ProviderError(
        ScanErrorCategory.API_ERROR,
        "Azure management API request failed",
        operation=operation,
        code=code or class_name,
        retryable=status is not None and status >= 500,
    )


def _first(items: Iterable[Any]) -> Any | None:
    return next(iter(items), None)


class AzureClientFactory:
    """Lazily constructs official Azure SDK clients using deployed-service credentials."""

    def __init__(self) -> None:
        self._credential: Any | None = None
        self._clients: dict[tuple[str, str], Any] = {}

    def credential(self) -> Any:
        if self._credential is None:
            # This excludes az CLI, PowerShell, developer CLI, VS Code and shared-cache identities.
            # It is set immediately before construction so workstation scans cannot silently adopt
            # an operator's broader developer identity.
            os.environ["AZURE_TOKEN_CREDENTIALS"] = "prod"  # noqa: S105 -- chain selector, not a secret
            try:
                DefaultAzureCredential = import_module("azure.identity").DefaultAzureCredential
                self._credential = DefaultAzureCredential()
            except Exception as exc:
                raise azure_provider_error(exc, operation="DefaultAzureCredential") from exc
        return self._credential

    def _client(self, service: str, subscription_id: str) -> Any:
        key = (service, subscription_id)
        if key in self._clients:
            return self._clients[key]
        try:
            credential = self.credential()
            if service == "resource_graph":
                ResourceGraphClient = import_module("azure.mgmt.resourcegraph").ResourceGraphClient
                client = ResourceGraphClient(credential)
            elif service == "subscriptions":
                SubscriptionClient = import_module(
                    "azure.mgmt.resource.subscriptions"
                ).SubscriptionClient
                client = SubscriptionClient(credential)
            elif service == "storage":
                StorageManagementClient = import_module(
                    "azure.mgmt.storage"
                ).StorageManagementClient
                client = StorageManagementClient(credential, subscription_id)
            elif service == "network":
                NetworkManagementClient = import_module(
                    "azure.mgmt.network"
                ).NetworkManagementClient
                client = NetworkManagementClient(credential, subscription_id)
            elif service == "authorization":
                AuthorizationManagementClient = import_module(
                    "azure.mgmt.authorization"
                ).AuthorizationManagementClient
                client = AuthorizationManagementClient(credential, subscription_id)
            elif service == "monitor":
                MonitorManagementClient = import_module(
                    "azure.mgmt.monitor"
                ).MonitorManagementClient
                client = MonitorManagementClient(credential, subscription_id)
            elif service == "keyvault":
                KeyVaultManagementClient = import_module(
                    "azure.mgmt.keyvault"
                ).KeyVaultManagementClient
                client = KeyVaultManagementClient(credential, subscription_id)
            else:  # pragma: no cover - internal programming error
                raise ValueError(f"unknown Azure client service: {service}")
        except Exception as exc:
            raise azure_provider_error(exc, operation=f"construct:{service}") from exc
        self._clients[key] = client
        return client

    def operation_group(self, group: str, subscription_id: str) -> ReadOnlyClient:
        service, attribute = {
            "resource_graph": ("resource_graph", None),
            "subscriptions": ("subscriptions", "subscriptions"),
            "storage_accounts": ("storage", "storage_accounts"),
            "blob_containers": ("storage", "blob_containers"),
            "network_security_groups": ("network", "network_security_groups"),
            "role_assignments": ("authorization", "role_assignments"),
            "role_definitions": ("authorization", "role_definitions"),
            "diagnostic_settings": ("monitor", "diagnostic_settings"),
            "vaults": ("keyvault", "vaults"),
        }[group]
        client = self._client(service, subscription_id)
        target = client if attribute is None else getattr(client, attribute)
        return ReadOnlyClient(target, AZURE_READ_OPERATIONS[group])

    def query_resources(self, subscription_id: str, *, skip_token: str | None = None) -> Any:
        try:
            models = import_module("azure.mgmt.resourcegraph.models")
            QueryRequest = models.QueryRequest
            QueryRequestOptions = models.QueryRequestOptions

            options = QueryRequestOptions(
                result_format="objectArray", top=1000, skip_token=skip_token
            )
            request = QueryRequest(
                subscriptions=[subscription_id],
                query="Resources | project id, name, type, location, tags | order by id asc",
                options=options,
            )
            return self.operation_group("resource_graph", subscription_id).resources(request)
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="ResourceGraph.Resources",
                permission="Microsoft.ResourceGraph/resources/read",
            ) from exc

    def iter_resource_ids(self, subscription_id: str) -> Iterator[str]:
        token: str | None = None
        while True:
            response = self.query_resources(subscription_id, skip_token=token)
            for row in getattr(response, "data", ()) or ():
                resource_id = row.get("id") if isinstance(row, dict) else getattr(row, "id", None)
                if resource_id:
                    yield str(resource_id)
            token = getattr(response, "skip_token", None)
            if not token:
                return

    def verify_identity(self, subscription_id: str) -> str:
        try:
            subscription = self.operation_group("subscriptions", subscription_id).get(
                subscription_id
            )
        except Exception as exc:
            raise azure_provider_error(
                exc,
                operation="Subscriptions.Get",
                permission="Microsoft.Resources/subscriptions/read",
            ) from exc
        native_id = getattr(subscription, "subscription_id", None) or subscription_id
        return f"azure://subscription/{native_id}"

    def probe(self, collector_id: str, subscription_id: str) -> None:
        """Perform the cheapest read that demonstrates each collector's required access."""

        try:
            if collector_id == "azure.inventory.resources":
                self.query_resources(subscription_id)
            elif collector_id in {"azure.storage.accounts", "azure.storage.containers"}:
                account = _first(self.operation_group("storage_accounts", subscription_id).list())
                if collector_id.endswith("containers") and account is not None:
                    resource_group = resource_group_from_id(str(getattr(account, "id", "")))
                    _first(
                        self.operation_group("blob_containers", subscription_id).list(
                            resource_group, str(getattr(account, "name", ""))
                        )
                    )
            elif collector_id == "azure.network.security_groups":
                _first(self.operation_group("network_security_groups", subscription_id).list_all())
            elif collector_id == "azure.authorization.role_assignments":
                scope = f"/subscriptions/{subscription_id}"
                _first(
                    self.operation_group("role_assignments", subscription_id).list_for_scope(scope)
                )
                _first(self.operation_group("role_definitions", subscription_id).list(scope))
            elif collector_id == "azure.monitor.diagnostic_settings":
                resource_id = next(self.iter_resource_ids(subscription_id), None)
                if resource_id:
                    self.operation_group("diagnostic_settings", subscription_id).list(resource_id)
            elif collector_id == "azure.keyvault.vaults":
                _first(self.operation_group("vaults", subscription_id).list())
            else:  # pragma: no cover - adapter owns this closed set
                raise ValueError(f"unknown Azure collector: {collector_id}")
        except Exception as exc:
            raise azure_provider_error(exc, operation=f"probe:{collector_id}") from exc


def resource_group_from_id(resource_id: str) -> str:
    parts = [part for part in resource_id.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "resourcegroups":
            return parts[index + 1]
    raise ProviderError(
        ScanErrorCategory.PARSE_ERROR,
        "Azure resource ID does not contain a resource group",
        operation="ParseResourceId",
        code="INVALID_RESOURCE_ID",
    )
