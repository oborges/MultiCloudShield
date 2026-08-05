from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from sqlalchemy import case, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    EvaluationResult,
    FindingStatus,
    ScanStatus,
)
from multicloudshield.core.models import ConnectionDescriptor, ScanResult
from multicloudshield.persistence.models import (
    AssetRow,
    CloudConnectionRow,
    EvidenceRow,
    FindingRow,
    FindingStatusChangeRow,
    JobRow,
    OrganizationRow,
    PolicyEvaluationRow,
    PolicyRow,
    ScanErrorRow,
    ScanRow,
    ScanTargetRow,
    UserRow,
)
from multicloudshield.policy import load_bundle


@dataclass(frozen=True)
class OrgScope:
    organization_id: UUID


class Repository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def first_organization(self) -> OrganizationRow | None:
        return cast(
            OrganizationRow | None,
            await self.session.scalar(select(OrganizationRow).limit(1)),
        )

    async def create_organization(self, slug: str, name: str) -> OrganizationRow:
        row = OrganizationRow(slug=slug, name=name)
        self.session.add(row)
        await self.session.flush()
        return row

    async def create_user(
        self, scope: OrgScope, email: str, password_hash: str, role: str = "owner"
    ) -> UserRow:
        row = UserRow(
            organization_id=scope.organization_id,
            email=email.lower(),
            password_hash=password_hash,
            role=role,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def user_by_email(self, email: str) -> UserRow | None:
        return cast(
            UserRow | None,
            await self.session.scalar(select(UserRow).where(UserRow.email == email.lower())),
        )

    async def create_connection(
        self, scope: OrgScope, descriptor: ConnectionDescriptor
    ) -> CloudConnectionRow:
        if descriptor.organization_id != scope.organization_id:
            raise ValueError("connection organization does not match scope")
        row = CloudConnectionRow(
            id=descriptor.id,
            organization_id=scope.organization_id,
            name=descriptor.name,
            provider=descriptor.provider.value,
            scope_id=descriptor.scope_id,
            credential_mechanism=descriptor.credential_mechanism.value,
            credential_reference=descriptor.credential_reference,
            region_allowlist=descriptor.region_allowlist,
            enabled=descriptor.enabled,
            is_demo=descriptor.is_demo,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_connections(
        self, scope: OrgScope, *, limit: int = 100, offset: int = 0
    ) -> list[CloudConnectionRow]:
        query = (
            select(CloudConnectionRow)
            .where(CloudConnectionRow.organization_id == scope.organization_id)
            .order_by(CloudConnectionRow.created_at)
            .offset(offset)
            .limit(min(limit, 201))
        )
        return list((await self.session.scalars(query)).all())

    async def get_connection(
        self, scope: OrgScope, connection_id: UUID
    ) -> CloudConnectionRow | None:
        return cast(
            CloudConnectionRow | None,
            await self.session.scalar(
                select(CloudConnectionRow).where(
                    CloudConnectionRow.organization_id == scope.organization_id,
                    CloudConnectionRow.id == connection_id,
                )
            ),
        )

    async def connection_descriptor(
        self, scope: OrgScope, connection_id: UUID
    ) -> ConnectionDescriptor | None:
        row = await self.get_connection(scope, connection_id)
        if row is None:
            return None
        return ConnectionDescriptor(
            id=row.id,
            organization_id=row.organization_id,
            name=row.name,
            provider=CloudProvider(row.provider),
            scope_id=row.scope_id,
            credential_mechanism=CredentialMechanism(row.credential_mechanism),
            credential_reference=row.credential_reference,
            region_allowlist=row.region_allowlist,
            enabled=row.enabled,
            is_demo=row.is_demo,
        )

    async def set_connection_enabled(
        self, scope: OrgScope, connection_id: UUID, enabled: bool
    ) -> bool:
        statement = (
            update(CloudConnectionRow)
            .where(
                CloudConnectionRow.organization_id == scope.organization_id,
                CloudConnectionRow.id == connection_id,
            )
            .values(enabled=enabled)
        )
        result = cast(CursorResult[Any], await self.session.execute(statement))
        return bool(result.rowcount)

    async def delete_connection(self, scope: OrgScope, connection_id: UUID, *, purge: bool) -> bool:
        row = await self.get_connection(scope, connection_id)
        if row is None:
            return False
        if not purge:
            row.enabled = False
            row.name = f"deleted-{row.id}"
            return True
        await self.session.delete(row)
        return True

    async def persist_scan(
        self,
        scope: OrgScope,
        result: ScanResult,
        *,
        trigger: str = "manual_cli",
        idempotency_key: str | None = None,
    ) -> None:
        if result.connection.organization_id != scope.organization_id:
            raise ValueError("scan organization does not match scope")
        scan_values = {
            "id": result.scan_id,
            "organization_id": scope.organization_id,
            "connection_id": result.connection.id,
            "status": result.status.value,
            "trigger": trigger,
            "idempotency_key": idempotency_key,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "policy_bundle_version": result.policy_bundle_version,
            "engine_version": result.engine_version,
            "collector_set_digest": result.collector_set_digest,
            "stats": result.stats.model_dump(mode="json"),
            "result_payload": result.model_dump(mode="json"),
            "is_demo": result.is_demo,
        }
        await self.session.execute(
            insert(ScanRow)
            .values(**scan_values)
            .on_conflict_do_update(index_elements=[ScanRow.id], set_=scan_values)
        )
        for target in result.targets:
            values = {
                "id": target.id,
                "organization_id": scope.organization_id,
                "scan_id": result.scan_id,
                "scope_kind": target.scope_kind,
                "scope_id": target.scope_id,
                "collector_id": target.collector_id,
                "collector_version": target.collector_version,
                "status": target.status,
                "items_collected": target.items_collected,
                "pages_fetched": target.pages_fetched,
                "error_count": target.error_count,
            }
            await self.session.execute(
                insert(ScanTargetRow)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[
                        ScanTargetRow.scan_id,
                        ScanTargetRow.scope_id,
                        ScanTargetRow.collector_id,
                    ],
                    set_=values,
                )
            )
        bundle = load_bundle()
        for policy in bundle.policies:
            metadata = policy.model_dump(mode="json")
            await self.session.execute(
                insert(PolicyRow)
                .values(
                    id=policy.id,
                    version=policy.version,
                    metadata_json=metadata,
                    bundle_version=bundle.version,
                )
                .on_conflict_do_update(
                    index_elements=[PolicyRow.id, PolicyRow.version],
                    set_={"metadata_json": metadata, "bundle_version": bundle.version},
                )
            )
        for asset in result.assets:
            values = {
                "id": asset.id,
                "organization_id": scope.organization_id,
                "connection_id": result.connection.id,
                "asset_urn": asset.asset_urn,
                "provider": asset.provider.value,
                "native_id": asset.native_id,
                "resource_type": asset.resource_type.value,
                "provider_resource_type": asset.provider_resource_type,
                "name": asset.name,
                "scope_kind": asset.scope_kind,
                "scope_id": asset.scope_id,
                "tags": asset.tags,
                "facts": asset.facts,
                "facts_digest": asset.facts_digest,
                "first_seen_scan_id": result.scan_id,
                "last_seen_scan_id": result.scan_id,
                "is_demo": asset.is_demo,
            }
            statement = (
                insert(AssetRow)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[AssetRow.organization_id, AssetRow.asset_urn],
                    set_={
                        "facts": asset.facts,
                        "facts_digest": asset.facts_digest,
                        "last_seen_at": func.now(),
                        "last_seen_scan_id": result.scan_id,
                        "name": asset.name,
                        "tags": asset.tags,
                    },
                )
            )
            await self.session.execute(statement)
        persisted_assets = {
            urn: asset_id
            for asset_id, urn in (
                await self.session.execute(
                    select(AssetRow.id, AssetRow.asset_urn).where(
                        AssetRow.organization_id == scope.organization_id,
                        AssetRow.asset_urn.in_([asset.asset_urn for asset in result.assets]),
                    )
                )
            ).all()
        }
        transient_asset_urns = {asset.id: asset.asset_urn for asset in result.assets}

        def persisted_asset_id(transient_id: UUID) -> UUID:
            return cast(UUID, persisted_assets[transient_asset_urns[transient_id]])

        for evidence in result.evidence:
            await self.session.execute(
                insert(EvidenceRow)
                .values(
                    id=evidence.id,
                    organization_id=scope.organization_id,
                    scan_id=result.scan_id,
                    collected_at=evidence.collected_at,
                    observed_facts=evidence.observed_facts,
                    provenance=evidence.provenance,
                    content_digest=evidence.content_digest,
                    redaction_applied=evidence.redaction_applied,
                )
                .on_conflict_do_nothing()
            )
        for evaluation in result.evaluations:
            values = {
                "id": evaluation.id,
                "organization_id": scope.organization_id,
                "scan_id": result.scan_id,
                "asset_id": persisted_asset_id(evaluation.asset_id),
                "policy_id": evaluation.policy_id,
                "policy_version": evaluation.policy_version,
                "sub_locator": evaluation.sub_locator,
                "result": evaluation.result.value,
                "reason_code": evaluation.reason_code,
                "evidence_id": evaluation.evidence_id,
            }
            await self.session.execute(
                insert(PolicyEvaluationRow)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[
                        PolicyEvaluationRow.scan_id,
                        PolicyEvaluationRow.policy_id,
                        PolicyEvaluationRow.asset_id,
                        PolicyEvaluationRow.sub_locator,
                    ],
                    set_={
                        "result": evaluation.result.value,
                        "reason_code": evaluation.reason_code,
                        "evidence_id": evaluation.evidence_id,
                    },
                )
            )
        for finding in result.findings:
            values = {
                "id": finding.id,
                "organization_id": scope.organization_id,
                "connection_id": result.connection.id,
                "asset_id": persisted_asset_id(finding.asset_id),
                "fingerprint": finding.fingerprint,
                "policy_id": finding.policy_id,
                "policy_version": finding.policy_version,
                "title": finding.title,
                "risk_explanation": finding.risk_explanation,
                "remediation_snapshot": finding.remediation,
                "compliance_mappings": finding.compliance_mappings,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "evidence_id": finding.evidence_id,
                "first_seen_at": finding.first_seen_at,
                "last_seen_at": finding.last_seen_at,
                "first_seen_scan_id": finding.first_seen_scan_id,
                "last_seen_scan_id": finding.last_seen_scan_id,
                "is_demo": finding.is_demo,
            }
            await self.session.execute(
                insert(FindingRow)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[FindingRow.organization_id, FindingRow.fingerprint],
                    set_={
                        "policy_version": finding.policy_version,
                        "severity": finding.severity.value,
                        "evidence_id": finding.evidence_id,
                        "last_seen_at": finding.last_seen_at,
                        "last_seen_scan_id": finding.last_seen_scan_id,
                        "status": case(
                            (
                                FindingRow.status == FindingStatus.RESOLVED.value,
                                FindingStatus.OPEN.value,
                            ),
                            else_=FindingRow.status,
                        ),
                    },
                )
            )
        if result.status in {ScanStatus.COMPLETED, ScanStatus.PARTIALLY_COMPLETED}:
            evidence_by_id = {evidence.id: evidence for evidence in result.evidence}
            succeeded_targets = {
                (target.scope_id, target.collector_id)
                for target in result.targets
                if target.status == "succeeded"
            }
            for evaluation in result.evaluations:
                if evaluation.result is not EvaluationResult.PASS:
                    continue
                provenance = evidence_by_id[evaluation.evidence_id].provenance
                target = provenance.get("scan_target", {})
                if (
                    not isinstance(target, dict)
                    or (str(target.get("scope_id", "")), str(target.get("collector_id", "")))
                    not in succeeded_targets
                ):
                    continue
                await self.session.execute(
                    update(FindingRow)
                    .where(
                        FindingRow.organization_id == scope.organization_id,
                        FindingRow.connection_id == result.connection.id,
                        FindingRow.asset_id == persisted_asset_id(evaluation.asset_id),
                        FindingRow.policy_id == evaluation.policy_id,
                        FindingRow.status == FindingStatus.OPEN.value,
                    )
                    .values(status=FindingStatus.RESOLVED.value)
                )
        for error in result.errors:
            await self.session.execute(
                insert(ScanErrorRow)
                .values(
                    id=error.id,
                    organization_id=scope.organization_id,
                    scan_id=result.scan_id,
                    category=error.category.value,
                    provider=error.provider.value,
                    scope_id=error.scope_id,
                    collector_id=error.collector_id,
                    operation=error.operation,
                    message=error.message,
                    provider_error_code=error.provider_error_code,
                    retryable=error.retryable,
                    retry_count=error.retry_count,
                    remediation_hint=error.remediation_hint,
                    occurred_at=error.occurred_at,
                )
                .on_conflict_do_nothing()
            )

    async def enqueue(self, scope: OrgScope, kind: str, payload: dict[str, object]) -> JobRow:
        row = JobRow(organization_id=scope.organization_id, kind=kind, payload=payload)
        self.session.add(row)
        await self.session.flush()
        return row

    async def job(self, scope: OrgScope, job_id: UUID) -> JobRow | None:
        return cast(
            JobRow | None,
            await self.session.scalar(
                select(JobRow).where(
                    JobRow.organization_id == scope.organization_id, JobRow.id == job_id
                )
            ),
        )

    async def list_scans(
        self, scope: OrgScope, *, limit: int = 100, offset: int = 0
    ) -> list[ScanRow]:
        return list(
            (
                await self.session.scalars(
                    select(ScanRow)
                    .where(ScanRow.organization_id == scope.organization_id)
                    .order_by(ScanRow.started_at.desc())
                    .offset(offset)
                    .limit(min(limit, 201))
                )
            ).all()
        )

    async def get_scan(self, scope: OrgScope, scan_id: UUID) -> ScanRow | None:
        return cast(
            ScanRow | None,
            await self.session.scalar(
                select(ScanRow).where(
                    ScanRow.organization_id == scope.organization_id, ScanRow.id == scan_id
                )
            ),
        )

    async def list_assets(
        self,
        scope: OrgScope,
        *,
        provider: str | None = None,
        resource_type: str | None = None,
        connection_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AssetRow]:
        query = select(AssetRow).where(AssetRow.organization_id == scope.organization_id)
        if provider:
            query = query.where(AssetRow.provider == provider)
        if resource_type:
            query = query.where(AssetRow.resource_type == resource_type)
        if connection_id:
            query = query.where(AssetRow.connection_id == connection_id)
        return list(
            (
                await self.session.scalars(
                    query.order_by(AssetRow.asset_urn).offset(offset).limit(min(limit, 201))
                )
            ).all()
        )

    async def list_findings(
        self,
        scope: OrgScope,
        *,
        provider: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        policy_id: str | None = None,
        resource_type: str | None = None,
        scan_id: UUID | None = None,
        connection_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FindingRow]:
        query = (
            select(FindingRow)
            .where(FindingRow.organization_id == scope.organization_id)
            .join(AssetRow, AssetRow.id == FindingRow.asset_id)
        )
        if provider:
            query = query.where(AssetRow.provider == provider)
        if severity:
            query = query.where(FindingRow.severity == severity)
        if status:
            query = query.where(FindingRow.status == status)
        if policy_id:
            query = query.where(FindingRow.policy_id == policy_id)
        if resource_type:
            query = query.where(AssetRow.resource_type == resource_type)
        if scan_id:
            query = query.where(FindingRow.last_seen_scan_id == scan_id)
        if connection_id:
            query = query.where(FindingRow.connection_id == connection_id)
        return list(
            (
                await self.session.scalars(
                    query.order_by(FindingRow.last_seen_at.desc())
                    .offset(offset)
                    .limit(min(limit, 201))
                )
            ).all()
        )

    async def get_finding(self, scope: OrgScope, finding_id: UUID) -> FindingRow | None:
        return cast(
            FindingRow | None,
            await self.session.scalar(
                select(FindingRow).where(
                    FindingRow.organization_id == scope.organization_id,
                    FindingRow.id == finding_id,
                )
            ),
        )

    async def change_finding_status(
        self,
        scope: OrgScope,
        finding_id: UUID,
        *,
        status: FindingStatus,
        actor_id: UUID,
        reason: str,
    ) -> bool:
        if not reason.strip():
            raise ValueError("a reason is required")
        finding = await self.get_finding(scope, finding_id)
        if finding is None:
            return False
        old = finding.status
        finding.status = status.value
        self.session.add(
            FindingStatusChangeRow(
                organization_id=scope.organization_id,
                finding_id=finding.id,
                from_status=old,
                to_status=status.value,
                actor_id=actor_id,
                reason=reason.strip(),
            )
        )
        return True

    async def summary(self, scope: OrgScope) -> dict[str, object]:
        base = (
            FindingRow.organization_id == scope.organization_id,
            FindingRow.status == FindingStatus.OPEN.value,
        )

        async def counts(column: Any, *, join_assets: bool = False) -> dict[str, int]:
            query = select(column, func.count()).where(*base)
            if join_assets:
                query = query.join(AssetRow, AssetRow.id == FindingRow.asset_id)
            rows = await self.session.execute(query.group_by(column))
            return {str(key): int(count) for key, count in rows.all()}

        return {
            "open_findings": await counts(FindingRow.severity),
            "by_provider": await counts(AssetRow.provider, join_assets=True),
            "by_policy": await counts(FindingRow.policy_id),
            "by_resource_type": await counts(AssetRow.resource_type, join_assets=True),
            "by_connection": await counts(FindingRow.connection_id),
        }
