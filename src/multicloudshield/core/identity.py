from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import UUID, uuid5

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType

_URN_PART = re.compile(r"[^a-zA-Z0-9._~:/@+-]+")
LOCAL_NAMESPACE = UUID("5bb4497f-5528-4b8f-b2bc-dd33dd4c8574")


def sanitize_identifier(value: str, *, max_length: int = 512) -> str:
    cleaned = "".join(ch for ch in value if ch >= " " and ch != "\x7f")[:max_length].strip()
    return _URN_PART.sub("_", cleaned)


def asset_urn(
    provider: CloudProvider, scope_id: str, resource_type: NormalizedResourceType, local_id: str
) -> str:
    return ":".join(
        (
            "mcs",
            provider.value,
            sanitize_identifier(scope_id),
            resource_type.value,
            sanitize_identifier(local_id),
        )
    )


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def finding_fingerprint(
    organization_id: UUID,
    connection_id: UUID,
    policy_id: str,
    urn: str,
    sub_locator: str = "",
) -> str:
    raw = "\x1f".join((str(organization_id), str(connection_id), policy_id, urn, sub_locator))
    return hashlib.sha256(raw.encode()).hexdigest()


def local_uuid(kind: str, value: str) -> UUID:
    return uuid5(LOCAL_NAMESPACE, f"{kind}:{value}")
