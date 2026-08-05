from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from multicloudshield.core.models import ScanResult
from multicloudshield.core.security import csv_safe, redact


def export_json(result: ScanResult) -> str:
    payload = result.model_dump(mode="json")
    payload["provenance"] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "engine_version": result.engine_version,
        "policy_bundle_version": result.policy_bundle_version,
        "scan_ids": [str(result.scan_id)],
        "contains_demo_data": result.is_demo,
    }
    return json.dumps(redact(payload), sort_keys=True, indent=2)


def export_csv(result: ScanResult) -> str:
    output = io.StringIO(newline="")
    fields = [
        "scan_id",
        "provider",
        "severity",
        "status",
        "policy_id",
        "resource_type",
        "resource_name",
        "asset_urn",
        "title",
        "first_seen_at",
        "last_seen_at",
        "is_demo",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for finding in result.findings[:100_000]:
        row = {
            "scan_id": result.scan_id,
            "provider": finding.provider,
            "severity": finding.severity,
            "status": finding.status,
            "policy_id": finding.policy_id,
            "resource_type": finding.resource_type,
            "resource_name": finding.resource_name,
            "asset_urn": finding.asset_urn,
            "title": finding.title,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
            "is_demo": finding.is_demo,
        }
        writer.writerow({key: csv_safe(value) for key, value in row.items()})
    return output.getvalue()
