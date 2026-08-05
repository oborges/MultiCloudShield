from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from multicloudshield.core.enums import CloudProvider, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.azure.clients import AzureClientFactory
from multicloudshield.providers.azure.collectors import AzureCollector, azure_collectors
from multicloudshield.providers.base import (
    CapabilityGap,
    CapabilityReport,
    ProviderCapabilities,
    ProviderError,
    ScanScope,
)

_LOCATION_RE = re.compile(r"^[a-z0-9-]{2,32}$")


class AzureAdapter:
    provider = CloudProvider.AZURE

    def __init__(self, client_factory: AzureClientFactory | Any | None = None) -> None:
        # Constructing this object performs no SDK import, credential lookup, or network call.
        self._factory = client_factory or AzureClientFactory()
        self._collectors = azure_collectors(self._factory)

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider,
            collectors=tuple(collector.id for collector in self._collectors),
            domains=("inventory", "object_storage", "network", "identity", "logging", "kms"),
            unsupported={
                "entra_principal_posture": (
                    "Entra ID principal and credential posture is outside the subscription boundary"
                ),
                "management_group_scanning": "management-group hierarchy scanning is post-MVP",
            },
            credential_mechanisms=(
                "azure_default_credential",
                "azure_workload_identity",
                "azure_managed_identity",
            ),
        )

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]:
        if conn.provider is not CloudProvider.AZURE:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "Azure adapter received a connection for another provider",
                code="PROVIDER_MISMATCH",
            )
        try:
            subscription_id = str(UUID(conn.scope_id))
        except ValueError as exc:
            raise ProviderError(
                ScanErrorCategory.API_ERROR,
                "Azure connection scope must be a subscription UUID",
                code="INVALID_SUBSCRIPTION_ID",
            ) from exc
        invalid_locations = [
            location for location in conn.region_allowlist if not _LOCATION_RE.fullmatch(location)
        ]
        if invalid_locations:
            raise ProviderError(
                ScanErrorCategory.UNSUPPORTED_REGION,
                "Azure connection contains an invalid location allowlist entry",
                code="INVALID_LOCATION",
            )
        # Collection stays inside the registered subscription. Location allowlisting is applied to
        # every observation; it never expands the connection boundary.
        return [ScanScope("subscription", subscription_id, "azure-public")]

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport:
        scope = self.resolve_scopes(conn)[0]
        identity = self._factory.verify_identity(scope.id)
        ok: list[str] = []
        denied: list[CapabilityGap] = []
        disabled: list[CapabilityGap] = []
        for collector in self._collectors:
            try:
                self._factory.probe(collector.id, scope.id)
            except ProviderError as exc:
                permission = exc.permission or collector.required_permissions[0]
                gap = CapabilityGap(collector.id, permission, str(exc))
                if exc.category is ScanErrorCategory.PERMISSION_DENIED:
                    denied.append(gap)
                elif exc.category is ScanErrorCategory.SERVICE_DISABLED:
                    disabled.append(gap)
                else:
                    # Authentication, SDK configuration, timeouts and unexpected API failures must
                    # not masquerade as a partial authorization report.
                    raise
            else:
                ok.append(collector.id)
        return CapabilityReport(
            status="ok" if not denied and not disabled else "degraded",
            identity=identity,
            ok=tuple(ok),
            denied=tuple(denied),
            disabled=tuple(disabled),
        )

    def collectors(self) -> tuple[AzureCollector, ...]:
        return self._collectors
