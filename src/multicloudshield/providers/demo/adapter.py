from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.base import (
    CapabilityGap,
    CapabilityReport,
    CollectionContext,
    ProviderCapabilities,
    ProviderError,
    RawObservation,
    ScanScope,
)


def _prov(collector: str, operation: str, page: int) -> dict[str, Any]:
    return {
        "collector_id": collector,
        "collector_version": "1.0.0",
        "calls": [
            {
                "service": "demo",
                "operation": operation,
                "scope": "synthetic",
                "request": {"page": page},
                "response_digest": f"sha256:demo-{collector}-{page}",
                "http_status": 200,
            }
        ],
    }


@dataclass
class DemoCollector:
    id: str
    resource_type: NormalizedResourceType
    records: tuple[dict[str, Any], ...]
    behavior: str = "ok"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = ("demo:Read",)
    optional_permissions: tuple[str, ...] = ()
    attempts: int = 0

    @property
    def produces(self) -> frozenset[NormalizedResourceType]:
        return frozenset((self.resource_type,))

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        if self.behavior == "throttle_once" and self.attempts == 0:
            self.attempts += 1
            raise ProviderError(
                ScanErrorCategory.THROTTLED,
                "simulated rate limit",
                operation="ListSynthetic",
                code="TooManyRequests",
                retryable=True,
            )
        page_size = 2
        for page_index in range(0, len(self.records), page_size):
            ctx.checkpoint()
            page = self.records[page_index : page_index + page_size]
            ctx.budget.add_page(len(page))
            for record in page:
                provider = CloudProvider(record["provider"])
                local_id = str(record["id"])
                yield RawObservation(
                    provider=provider,
                    provider_resource_type=str(record["provider_type"]),
                    native_id=f"demo://{provider.value}/{local_id}",
                    local_id=local_id,
                    name=str(record["name"]),
                    resource_type=self.resource_type,
                    scope=ScanScope("global", f"demo-{provider.value}"),
                    tags=dict(record.get("tags", {})),
                    facts=dict(record["facts"]),
                    provenance=_prov(self.id, "ListSynthetic", page_index // page_size + 1),
                    is_demo=True,
                )
            if self.behavior == "permission_denied" and page_index == 0:
                raise ProviderError(
                    ScanErrorCategory.PERMISSION_DENIED,
                    "collector lacks a synthetic permission",
                    operation="GetSyntheticDetail",
                    code="AccessDenied",
                    permission="demo:ReadRestricted",
                )
        if self.behavior == "parse_error":
            yield RawObservation(
                provider=CloudProvider.AWS,
                provider_resource_type="demo.malformed",
                native_id="demo://malformed",
                local_id="malformed",
                name="malformed\x00resource",
                resource_type=self.resource_type,
                scope=ctx.scope,
                tags={},
                facts={"kind": "object_storage", "public_read_access": "invalid"},
                provenance=_prov(self.id, "MalformedSynthetic", 1),
                is_demo=True,
            )
        if self.behavior == "failure":
            raise ProviderError(
                ScanErrorCategory.API_ERROR,
                "simulated collector failure",
                operation="ListSynthetic",
                code="SyntheticFailure",
            )
        if self.behavior == "service_disabled":
            raise ProviderError(
                ScanErrorCategory.SERVICE_DISABLED,
                "synthetic service is disabled",
                operation="ListSynthetic",
                code="SERVICE_DISABLED",
            )


def _storage_records() -> tuple[dict[str, Any], ...]:
    providers = (CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP, CloudProvider.IBM)
    records: list[dict[str, Any]] = []
    for index, provider in enumerate(providers):
        records.extend(
            [
                {
                    "provider": provider,
                    "id": f"{provider.value}-public",
                    "name": "=cmd|'/c calc'!A1"
                    if provider is CloudProvider.AWS
                    else f"{provider.value}-public-bucket",
                    "provider_type": f"{provider.value}.storage.bucket",
                    "tags": {"display": "<script>alert('inert')</script>\x00"},
                    "facts": {
                        "kind": "object_storage",
                        "public_read_access": TriState.YES,
                        "public_write_access": TriState.YES if index == 0 else TriState.NO,
                        "encryption_at_rest": EncryptionPosture.NONE
                        if index < 2
                        else EncryptionPosture.PROVIDER_MANAGED,
                        "versioning_enabled": TriState.NO,
                        "access_logging_enabled": TriState.NO,
                        "tls_required": TriState.NO,
                        "provider_specific": _provider_specific(provider, insecure=True),
                    },
                },
                {
                    "provider": provider,
                    "id": f"{provider.value}-private",
                    "name": f"{provider.value}-private-bucket",
                    "provider_type": f"{provider.value}.storage.bucket",
                    "facts": {
                        "kind": "object_storage",
                        "public_read_access": TriState.NO,
                        "public_write_access": TriState.NO,
                        "encryption_at_rest": EncryptionPosture.CUSTOMER_MANAGED,
                        "versioning_enabled": TriState.YES,
                        "access_logging_enabled": TriState.YES,
                        "tls_required": TriState.YES,
                        "provider_specific": _provider_specific(provider, insecure=False),
                    },
                },
            ]
        )
    return tuple(records)


def _provider_specific(provider: CloudProvider, *, insecure: bool) -> dict[str, Any]:
    state = TriState.NO.value if insecure else TriState.YES.value
    if provider is CloudProvider.AWS:
        return {"aws": {"block_public_access_all": state}}
    if provider is CloudProvider.AZURE:
        return {
            "azure": {
                "allow_shared_key_access": TriState.YES.value if insecure else TriState.NO.value
            }
        }
    if provider is CloudProvider.GCP:
        return {"gcp": {"uniform_bucket_level_access": state, "public_access_prevention": state}}
    return {}


def _records(kind: str) -> tuple[dict[str, Any], ...]:
    providers = (CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP, CloudProvider.IBM)
    rows: list[dict[str, Any]] = []
    for index, provider in enumerate(providers):
        facts: dict[str, Any]
        if kind == "firewall":
            facts = {
                "kind": "firewall",
                "unrestricted_admin_ingress": TriState.YES if index < 2 else TriState.NO,
                "unrestricted_all_ports": TriState.YES if index == 0 else TriState.NO,
                "unrestricted_datastore_ingress": TriState.YES if index == 2 else TriState.NO,
                "offending_rules": [f"rule-{index}"],
            }
        elif kind == "identity":
            facts = {
                "kind": "identity",
                "interactive": TriState.YES,
                "mfa_enabled": TriState.NO if index in (0, 3) else TriState.YES,
                "long_lived_credential": TriState.YES if index in (0, 3) else TriState.NO,
                "credential_age_days": 180 if index in (0, 3) else 5,
                "provider_specific": {
                    "aws": {
                        "root_access_keys_active": TriState.YES.value,
                        "password_policy_strong": TriState.NO.value,
                    }
                }
                if provider is CloudProvider.AWS
                else (
                    {"ibm": {"account_mfa_enforced": TriState.NO.value}}
                    if provider is CloudProvider.IBM
                    else {}
                ),
            }
        elif kind == "logging":
            facts = {
                "kind": "logging",
                "audit_logging_enabled": TriState.UNKNOWN
                if provider is CloudProvider.GCP
                else (TriState.NO if index < 2 else TriState.YES),
                "destination_public": TriState.YES if index == 0 else TriState.NO,
                "parent_scope_visibility": TriState.NO
                if provider is CloudProvider.GCP
                else TriState.YES,
                "provider_specific": {
                    "aws": {
                        "multi_region": TriState.NO.value,
                        "validation_enabled": TriState.NO.value,
                    }
                }
                if provider is CloudProvider.AWS
                else {},
            }
        else:
            facts = {
                "kind": "kms",
                "rotation_enabled": TriState.NO if index < 3 else TriState.UNKNOWN,
                "supports_rotation": TriState.NO
                if provider is CloudProvider.GCP and index == 2
                else TriState.YES,
                "provider_specific": {
                    "azure": {
                        "soft_delete_enabled": TriState.NO.value,
                        "purge_protection_enabled": TriState.NO.value,
                    }
                }
                if provider is CloudProvider.AZURE
                else {},
            }
        rows.append(
            {
                "provider": provider,
                "id": f"{provider.value}-{kind}",
                "name": f"{provider.value}-{kind}-resource",
                "provider_type": f"{provider.value}.{kind}",
                "facts": facts,
            }
        )
    return tuple(rows)


def _account_records() -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for provider in (CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP, CloudProvider.IBM):
        specific: dict[str, Any] = {}
        if provider is CloudProvider.AWS:
            specific = {"aws": {"block_public_access_all": TriState.NO.value}}
        elif provider is CloudProvider.IBM:
            specific = {"ibm": {"account_mfa_enforced": TriState.NO.value}}
        rows.append(
            {
                "provider": provider,
                "id": f"{provider.value}-account",
                "name": f"{provider.value}-account-scope",
                "provider_type": f"{provider.value}.account",
                "facts": {
                    "kind": "account",
                    "audit_logging_enabled": TriState.UNKNOWN
                    if provider in (CloudProvider.GCP, CloudProvider.IBM)
                    else TriState.NO,
                    "mfa_enforced": TriState.NO,
                    "provider_specific": specific,
                },
            }
        )
    return tuple(rows)


class DemoAdapter:
    provider = CloudProvider.DEMO

    def describe_capabilities(self) -> ProviderCapabilities:
        collectors = tuple(item.id for item in self.collectors())
        return ProviderCapabilities(
            provider=self.provider,
            collectors=collectors,
            domains=("object_storage", "network", "identity", "logging", "kms"),
            credential_mechanisms=("demo_none",),
        )

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]:
        return [ScanScope("global", conn.scope_id)]

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport:
        collectors = tuple(item.id for item in self.collectors())
        return CapabilityReport(
            status="degraded",
            identity="demo://deterministic-estate",
            ok=collectors[:-1],
            denied=(CapabilityGap(collectors[-1], "demo:ReadRestricted", "scripted demo denial"),),
        )

    def collectors(self) -> tuple[DemoCollector, ...]:
        return (
            DemoCollector(
                "demo.storage.buckets",
                NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                _storage_records(),
            ),
            DemoCollector(
                "demo.network.firewalls",
                NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                _records("firewall"),
            ),
            DemoCollector(
                "demo.identity.principals",
                NormalizedResourceType.IDENTITY_PRINCIPAL,
                _records("identity"),
                "permission_denied",
            ),
            DemoCollector(
                "demo.logging.audit",
                NormalizedResourceType.LOGGING_AUDIT_TRAIL,
                _records("logging"),
                "throttle_once",
            ),
            DemoCollector("demo.kms.keys", NormalizedResourceType.KMS_KEY, _records("kms")),
            DemoCollector(
                "demo.account.scopes", NormalizedResourceType.ACCOUNT_SCOPE, _account_records()
            ),
            DemoCollector(
                "demo.malformed", NormalizedResourceType.OBJECT_STORAGE_BUCKET, (), "parse_error"
            ),
            DemoCollector(
                "demo.partial.failure", NormalizedResourceType.ACCOUNT_SCOPE, (), "failure"
            ),
            DemoCollector(
                "demo.service.disabled",
                NormalizedResourceType.ACCOUNT_SCOPE,
                (),
                "service_disabled",
            ),
        )
