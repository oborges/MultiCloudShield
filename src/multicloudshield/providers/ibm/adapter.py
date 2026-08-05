from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from multicloudshield.core.enums import CloudProvider, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.base import (
    CapabilityGap,
    CapabilityReport,
    ProviderCapabilities,
    ProviderError,
    ScanScope,
)
from multicloudshield.providers.ibm.clients import (
    IBM_REGIONS,
    DefaultIbmClientFactory,
    IbmClientFactory,
)
from multicloudshield.providers.ibm.common import classify_error, sdk_call
from multicloudshield.providers.ibm.cos import CosBucketsCollector
from multicloudshield.providers.ibm.iam import IamIdentityCollector, IamPoliciesCollector
from multicloudshield.providers.ibm.inventory import InventoryCollector
from multicloudshield.providers.ibm.network import NetworkAclsCollector, SecurityGroupsCollector

_AUDIT_GAP = "No maintained official IBM Activity Tracker or Cloud Logs Python SDK in v0.1.0"
_KMS_GAP = "No maintained official IBM Key Protect or HPCS Python SDK in v0.1.0"


@dataclass(frozen=True)
class IbmAdapter:
    factory: IbmClientFactory = field(default_factory=DefaultIbmClientFactory)
    provider: CloudProvider = CloudProvider.IBM

    def collectors(
        self,
    ) -> tuple[
        InventoryCollector,
        CosBucketsCollector,
        SecurityGroupsCollector,
        NetworkAclsCollector,
        IamPoliciesCollector,
        IamIdentityCollector,
    ]:
        return (
            InventoryCollector(self.factory),
            CosBucketsCollector(self.factory),
            SecurityGroupsCollector(self.factory),
            NetworkAclsCollector(self.factory),
            IamPoliciesCollector(self.factory),
            IamIdentityCollector(self.factory),
        )

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider,
            collectors=tuple(collector.id for collector in self.collectors()),
            domains=("inventory", "object_storage", "network", "identity"),
            unsupported={"logging": _AUDIT_GAP, "kms": _KMS_GAP},
            credential_mechanisms=("ibm_trusted_profile", "ibm_api_key_env", "ibm_service_id"),
        )

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]:
        if conn.provider is not CloudProvider.IBM:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM adapter received a connection for another provider",
                code="PROVIDER_MISMATCH",
            )
        configured = {
            region.strip()
            for region in conn.credential_reference.get("regions", "").split(",")
            if region.strip()
        }
        allowlisted = set(conn.region_allowlist)
        regions = (
            configured & allowlisted if configured and allowlisted else (allowlisted or configured)
        )
        invalid = sorted(region for region in regions if region not in IBM_REGIONS)
        if invalid:
            raise ProviderError(
                ScanErrorCategory.UNSUPPORTED_REGION,
                "IBM connection contains an unsupported region",
                code="INVALID_REGION",
            )
        return [
            ScanScope("global", conn.scope_id),
            *(ScanScope("region", region) for region in sorted(regions)),
        ]

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport:
        collectors = self.collectors()
        identity = f"ibm://account/{conn.scope_id}"
        try:
            identity_client = self.factory.identity(conn)
            sdk_call(
                "get_account_settings",
                identity_client.get_account_settings,
                permission=collectors[-1].required_permissions[2],
                account_id=conn.scope_id,
            )
        except Exception as exc:
            error = classify_error(exc, operation="get_account_settings")
            gaps = tuple(
                CapabilityGap(
                    collector.id,
                    collector.required_permissions[0],
                    f"identity probe failed ({error.category.value})",
                )
                for collector in collectors
            )
            return CapabilityReport(status="failed", identity="unknown", ok=(), denied=gaps)

        regions = [scope.id for scope in self.resolve_scopes(conn) if scope.kind == "region"]
        probes: tuple[tuple[Any, str, str, Any], ...] = (
            (collectors[0], "search", collectors[0].required_permissions[0], self._probe_inventory),
            (collectors[1], "list_buckets", collectors[1].required_permissions[0], self._probe_cos),
            (
                collectors[2],
                "list_security_groups",
                collectors[2].required_permissions[0],
                self._probe_security_groups,
            ),
            (
                collectors[3],
                "list_network_acls",
                collectors[3].required_permissions[0],
                self._probe_network_acls,
            ),
            (
                collectors[4],
                "list_policies",
                collectors[4].required_permissions[0],
                self._probe_policies,
            ),
            (
                collectors[5],
                "list_service_ids",
                collectors[5].required_permissions[0],
                self._probe_identity,
            ),
        )
        ok: list[str] = []
        denied: list[CapabilityGap] = []
        disabled: list[CapabilityGap] = []
        for collector, operation, permission, probe in probes:
            try:
                if collector.scope_kind == "region" and not regions:
                    raise ProviderError(
                        ScanErrorCategory.UNSUPPORTED_REGION,
                        "no IBM Cloud regions are configured",
                        operation=operation,
                        code="NO_REGIONS_CONFIGURED",
                    )
                probe(conn, regions[0] if collector.scope_kind == "region" else None)
                ok.append(collector.id)
            except Exception as exc:
                error = classify_error(exc, operation=operation, permission=permission)
                gap = CapabilityGap(collector.id, permission, error.category.value)
                if error.category in {
                    ScanErrorCategory.SERVICE_DISABLED,
                    ScanErrorCategory.UNSUPPORTED_REGION,
                }:
                    disabled.append(gap)
                else:
                    denied.append(gap)
        status = "ok" if not denied and not disabled else "degraded"
        return CapabilityReport(
            status=status,
            identity=identity,
            ok=tuple(ok),
            denied=tuple(denied),
            disabled=tuple(disabled),
        )

    def _probe_inventory(self, conn: ConnectionDescriptor, region: str | None) -> None:
        client = self.factory.inventory(conn)
        sdk_call(
            "search",
            client.search,
            permission="global-search.tagging.search",
            query=f"account_id:{conn.scope_id}",
            limit=1,
        )

    def _probe_cos(self, conn: ConnectionDescriptor, region: str | None) -> None:
        assert region is not None
        client = self.factory.cos(conn, region)
        sdk_call(
            "list_buckets",
            client.list_buckets,
            permission="cloud-object-storage.bucket.list",
        )

    def _probe_security_groups(self, conn: ConnectionDescriptor, region: str | None) -> None:
        assert region is not None
        client = self.factory.vpc(conn, region)
        sdk_call(
            "list_security_groups",
            client.list_security_groups,
            permission="is.security-group.security-group.read",
            limit=1,
            generation=2,
        )

    def _probe_network_acls(self, conn: ConnectionDescriptor, region: str | None) -> None:
        assert region is not None
        client = self.factory.vpc(conn, region)
        sdk_call(
            "list_network_acls",
            client.list_network_acls,
            permission="is.network-acl.network-acl.read",
            limit=1,
            generation=2,
        )

    def _probe_policies(self, conn: ConnectionDescriptor, region: str | None) -> None:
        client = self.factory.policies(conn)
        sdk_call(
            "list_policies",
            client.list_policies,
            permission="iam.policy.read",
            account_id=conn.scope_id,
            limit=1,
        )

    def _probe_identity(self, conn: ConnectionDescriptor, region: str | None) -> None:
        client = self.factory.identity(conn)
        sdk_call(
            "list_service_ids",
            client.list_service_ids,
            permission="iam.service-id.read",
            account_id=conn.scope_id,
            pagesize=1,
        )
