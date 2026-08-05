from uuid import uuid4

from multicloudshield.core.enums import (
    CloudProvider,
    EvaluationResult,
    FindingStatus,
    NormalizedResourceType,
    Severity,
)
from multicloudshield.core.models import Finding, PolicyEvaluation
from multicloudshield.engine.reconciliation import reconcile_findings


def finding(*, status: FindingStatus = FindingStatus.OPEN) -> Finding:
    scan_id = uuid4()
    return Finding(
        organization_id=uuid4(),
        connection_id=uuid4(),
        asset_id=uuid4(),
        asset_urn="mcs:aws:scope:object_storage.bucket:asset",
        provider=CloudProvider.AWS,
        resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
        resource_name="asset",
        fingerprint="stable",
        policy_id="MCS-STOR-001",
        policy_version="1.0.0",
        title="Public read",
        risk_explanation="risk",
        remediation={"summary": "fix", "steps": ["review"]},
        severity=Severity.HIGH,
        status=status,
        evidence_id=uuid4(),
        first_seen_scan_id=scan_id,
        last_seen_scan_id=scan_id,
    )


def evaluation(item: Finding, result: EvaluationResult) -> PolicyEvaluation:
    return PolicyEvaluation(
        scan_id=uuid4(),
        asset_id=item.asset_id,
        asset_urn=item.asset_urn,
        policy_id=item.policy_id,
        policy_version=item.policy_version,
        result=result,
        reason_code="TEST",
        severity=item.severity,
        evidence_id=uuid4(),
    )


def test_stale_finding_requires_positive_pass_on_successful_scan() -> None:
    old = finding()
    assert (
        reconcile_findings(
            [old], [], [evaluation(old, EvaluationResult.PASS)], scan_succeeded=False
        )[0].status
        is FindingStatus.OPEN
    )
    assert (
        reconcile_findings(
            [old], [], [evaluation(old, EvaluationResult.INSUFFICIENT_DATA)], scan_succeeded=True
        )[0].status
        is FindingStatus.OPEN
    )
    assert (
        reconcile_findings(
            [old], [], [evaluation(old, EvaluationResult.PASS)], scan_succeeded=True
        )[0].status
        is FindingStatus.RESOLVED
    )


def test_human_status_survives_and_auto_resolved_reopens() -> None:
    current = finding()
    suppressed = finding(status=FindingStatus.SUPPRESSED)
    resolved = finding(status=FindingStatus.RESOLVED)
    assert (
        reconcile_findings([suppressed], [current], [], scan_succeeded=True)[0].status
        is FindingStatus.SUPPRESSED
    )
    assert (
        reconcile_findings([resolved], [current], [], scan_succeeded=True)[0].status
        is FindingStatus.OPEN
    )
