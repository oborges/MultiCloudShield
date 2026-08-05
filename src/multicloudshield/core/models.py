from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    EvaluationResult,
    FindingStatus,
    NormalizedResourceType,
    ScanErrorCategory,
    ScanStatus,
    Severity,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


class ConnectionDescriptor(BaseModel):
    id: UUID
    organization_id: UUID
    name: str = Field(min_length=1, max_length=120)
    provider: CloudProvider
    scope_id: str = Field(min_length=1, max_length=512)
    credential_mechanism: CredentialMechanism
    credential_reference: dict[str, str] = Field(default_factory=dict)
    region_allowlist: list[str] = Field(default_factory=list)
    enabled: bool = True
    is_demo: bool = False


class Asset(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    connection_id: UUID
    provider: CloudProvider
    asset_urn: str
    native_id: str
    resource_type: NormalizedResourceType
    provider_resource_type: str
    name: str
    scope_kind: str = "global"
    scope_id: str
    tags: dict[str, str] = Field(default_factory=dict)
    facts: dict[str, Any]
    facts_digest: str
    is_demo: bool = False


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    collected_at: datetime = Field(default_factory=utcnow)
    observed_facts: dict[str, Any]
    provenance: dict[str, Any]
    content_digest: str
    redaction_applied: bool = True


class PolicyEvaluation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    asset_id: UUID
    asset_urn: str
    policy_id: str
    policy_version: str
    result: EvaluationResult
    reason_code: str
    severity: Severity
    sub_locator: str = ""
    evidence_id: UUID
    duration_ms: int = 0


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    connection_id: UUID
    asset_id: UUID
    asset_urn: str
    provider: CloudProvider
    resource_type: NormalizedResourceType
    resource_name: str
    fingerprint: str
    policy_id: str
    policy_version: str
    title: str
    risk_explanation: str
    remediation: dict[str, Any]
    compliance_mappings: list[dict[str, str]] = Field(default_factory=list)
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    evidence_id: UUID
    first_seen_at: datetime = Field(default_factory=utcnow)
    last_seen_at: datetime = Field(default_factory=utcnow)
    first_seen_scan_id: UUID
    last_seen_scan_id: UUID
    is_demo: bool = False


class ScanError(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    category: ScanErrorCategory
    provider: CloudProvider
    scope_id: str
    collector_id: str
    operation: str = ""
    message: str
    provider_error_code: str | None = None
    retryable: bool = False
    retry_count: int = 0
    remediation_hint: str | None = None
    occurred_at: datetime = Field(default_factory=utcnow)


class ScanStatistics(BaseModel):
    targets_total: int = 0
    targets_succeeded: int = 0
    targets_failed: int = 0
    targets_skipped: int = 0
    assets_discovered: int = 0
    pages_fetched: int = 0
    api_calls: int = 0
    retries: int = 0
    policies_evaluated: int = 0
    pass_count: int = 0
    fail_count: int = 0
    not_applicable_count: int = 0
    insufficient_data_count: int = 0
    error_count: int = 0
    duration_ms: int = 0


class ScanTarget(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    scope_kind: str
    scope_id: str
    collector_id: str
    collector_version: str
    status: str
    items_collected: int = 0
    pages_fetched: int = 0
    error_count: int = 0


class ScanResult(BaseModel):
    schema_version: str = "1.0"
    scan_id: UUID = Field(default_factory=uuid4)
    connection: ConnectionDescriptor
    status: ScanStatus
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime = Field(default_factory=utcnow)
    engine_version: str = "0.1.0"
    policy_bundle_version: str = "2026.08.1"
    collector_set_digest: str
    targets: list[ScanTarget] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    evaluations: list[PolicyEvaluation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    stats: ScanStatistics = Field(default_factory=ScanStatistics)
    is_demo: bool = False
