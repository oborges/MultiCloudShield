from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from multicloudshield.core.enums import EvaluationResult, FindingStatus
from multicloudshield.core.models import Finding, PolicyEvaluation

_HUMAN_STATUSES = {
    FindingStatus.SUPPRESSED,
    FindingStatus.RISK_ACCEPTED,
    FindingStatus.FALSE_POSITIVE,
}


def reconcile_findings(
    existing: Iterable[Finding],
    current: Iterable[Finding],
    evaluations: Iterable[PolicyEvaluation],
    *,
    scan_succeeded: bool,
) -> list[Finding]:
    """Reconcile without ever resolving from absence, unknown, or a failed scan."""
    by_fingerprint = {item.fingerprint: item.model_copy(deep=True) for item in existing}
    current_by_fingerprint = {item.fingerprint: item for item in current}
    now = datetime.now(UTC)
    for fingerprint, finding in current_by_fingerprint.items():
        old = by_fingerprint.get(fingerprint)
        if old is None:
            by_fingerprint[fingerprint] = finding
            continue
        old.last_seen_at = finding.last_seen_at
        old.last_seen_scan_id = finding.last_seen_scan_id
        old.evidence_id = finding.evidence_id
        old.severity = finding.severity
        if old.status is FindingStatus.RESOLVED:
            old.status = FindingStatus.OPEN
        by_fingerprint[fingerprint] = old
    if scan_succeeded:
        passed_keys = {
            (item.asset_urn, item.policy_id, item.sub_locator)
            for item in evaluations
            if item.result is EvaluationResult.PASS
        }
        for fingerprint, old in by_fingerprint.items():
            key = (old.asset_urn, old.policy_id, "")
            if (
                fingerprint not in current_by_fingerprint
                and key in passed_keys
                and old.status not in _HUMAN_STATUSES
            ):
                old.status = FindingStatus.RESOLVED
                old.last_seen_at = now
    return sorted(by_fingerprint.values(), key=lambda item: item.fingerprint)
