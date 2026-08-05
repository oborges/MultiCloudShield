from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class OrganizationRow(Base):
    __tablename__ = "organizations"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    slug: Mapped[str] = mapped_column(String(120), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class UserRow(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="owner")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (
        UniqueConstraint("organization_id", "email"),
        Index("ix_users_org", "organization_id", "id"),
    )


class ApiTokenRow(Base):
    __tablename__ = "api_tokens"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(120))
    token_prefix: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (Index("ix_tokens_org", "organization_id", "id"),)


class SessionRow(Base):
    __tablename__ = "sessions"
    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    csrf_hash: Mapped[str] = mapped_column(String(64))
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (Index("ix_sessions_org", "organization_id", "id_hash"),)


class CloudConnectionRow(Base):
    __tablename__ = "cloud_connections"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(120))
    provider: Mapped[str] = mapped_column(String(20))
    scope_id: Mapped[str] = mapped_column(String(512))
    credential_mechanism: Mapped[str] = mapped_column(String(64))
    credential_reference: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    region_allowlist: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verification_status: Mapped[str] = mapped_column(String(32), default="never_tested")
    last_verification_detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        Index("ix_connections_org", "organization_id", "id"),
        CheckConstraint("provider IN ('aws','azure','gcp','ibm','demo')"),
    )


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    requested_by_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String(32))
    trigger: Mapped[str] = mapped_column(String(32), default="manual_api")
    idempotency_key: Mapped[str | None] = mapped_column(String(200))
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    policy_bundle_version: Mapped[str] = mapped_column(String(32))
    engine_version: Mapped[str] = mapped_column(String(32))
    collector_set_digest: Mapped[str] = mapped_column(String(128))
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        UniqueConstraint("connection_id", "idempotency_key"),
        Index("ix_scans_org", "organization_id", "id"),
    )


class JobRow(Base):
    __tablename__ = "jobs"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    __table_args__ = (
        Index("ix_jobs_claim", "status", "available_at", "id"),
        Index("ix_jobs_org", "organization_id", "id"),
    )


class ScanTargetRow(Base):
    __tablename__ = "scan_targets"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    scope_kind: Mapped[str] = mapped_column(String(32))
    scope_id: Mapped[str] = mapped_column(String(512))
    collector_id: Mapped[str] = mapped_column(String(160))
    collector_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    items_collected: Mapped[int] = mapped_column(Integer, default=0)
    pages_fetched: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (
        UniqueConstraint("scan_id", "scope_id", "collector_id"),
        Index("ix_targets_org", "organization_id", "id"),
    )


class AssetRow(Base):
    __tablename__ = "assets"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    asset_urn: Mapped[str] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(String(20))
    native_id: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(String(100))
    provider_resource_type: Mapped[str] = mapped_column(String(256))
    name: Mapped[str] = mapped_column(String(512))
    scope_kind: Mapped[str] = mapped_column(String(32))
    scope_id: Mapped[str] = mapped_column(String(512))
    tags: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    facts: Mapped[dict[str, Any]] = mapped_column(JSONB)
    facts_digest: Mapped[str] = mapped_column(String(128))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    first_seen_scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    last_seen_scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        UniqueConstraint("organization_id", "asset_urn"),
        Index("ix_assets_org_type", "organization_id", "resource_type", "id"),
    )


class AssetRelationshipRow(Base):
    __tablename__ = "asset_relationships"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    source_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    relationship_type: Mapped[str] = mapped_column(String(64))
    discovered_by_scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    confidence: Mapped[str] = mapped_column(String(20))
    __table_args__ = (Index("ix_relationships_org", "organization_id", "id"),)


class PolicyRow(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB)
    bundle_version: Mapped[str] = mapped_column(String(32))


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observed_facts: Mapped[dict[str, Any]] = mapped_column(JSONB)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_digest: Mapped[str] = mapped_column(String(128))
    redaction_applied: Mapped[bool] = mapped_column(Boolean)
    __table_args__ = (Index("ix_evidence_org", "organization_id", "id"),)


class PolicyEvaluationRow(Base):
    __tablename__ = "policy_evaluations"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    policy_id: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(32))
    sub_locator: Mapped[str] = mapped_column(String(512), default="")
    result: Mapped[str] = mapped_column(String(32))
    reason_code: Mapped[str] = mapped_column(String(100))
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"))
    __table_args__ = (
        UniqueConstraint("scan_id", "policy_id", "asset_id", "sub_locator"),
        Index("ix_evaluations_org", "organization_id", "id"),
    )


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    policy_id: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(Text)
    risk_explanation: Mapped[str] = mapped_column(Text)
    remediation_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    compliance_mappings: Mapped[list[dict[str, str]]] = mapped_column(JSONB, default=list)
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(32), default="open")
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="RESTRICT"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_seen_scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    last_seen_scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint"),
        Index("ix_findings_org_status", "organization_id", "status", "id"),
    )


class FindingStatusChangeRow(Base):
    __tablename__ = "finding_status_changes"
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.uuidv7()
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    from_status: Mapped[str] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    reason: Mapped[str] = mapped_column(Text)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (Index("ix_status_changes_org", "organization_id", "id"),)


class ScanErrorRow(Base):
    __tablename__ = "scan_errors"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(20))
    scope_id: Mapped[str] = mapped_column(String(512))
    collector_id: Mapped[str] = mapped_column(String(160))
    operation: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(Text)
    provider_error_code: Mapped[str | None] = mapped_column(String(100))
    retryable: Mapped[bool] = mapped_column(Boolean)
    retry_count: Mapped[int] = mapped_column(Integer)
    remediation_hint: Mapped[str | None] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    __table_args__ = (Index("ix_scan_errors_org", "organization_id", "id"),)
