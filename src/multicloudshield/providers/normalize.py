from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter, ValidationError

from multicloudshield.core.identity import asset_urn, digest
from multicloudshield.core.models import Asset
from multicloudshield.core.security import sanitize_text
from multicloudshield.facts import AssetFacts
from multicloudshield.providers.base import RawObservation

_FACT_ADAPTER: TypeAdapter[AssetFacts] = TypeAdapter(AssetFacts)


def _depth(value: Any, current: int = 0) -> int:
    if current > 32:
        return current
    if isinstance(value, dict):
        return max((_depth(item, current + 1) for item in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(item, current + 1) for item in value), default=current)
    return current


def normalize_observation(
    observation: RawObservation, *, organization_id: Any, connection_id: Any
) -> Asset:
    if len(repr(observation.facts).encode()) > 5 * 1024 * 1024:
        raise ValueError("provider observation exceeds 5 MiB")
    if _depth(observation.facts) > 32:
        raise ValueError("provider observation exceeds nesting limit")
    try:
        parsed = _FACT_ADAPTER.validate_python(observation.facts)
    except ValidationError as exc:
        raise ValueError("provider observation failed fact validation") from exc
    safe_name = sanitize_text(observation.name, max_length=512)
    safe_native = sanitize_text(observation.native_id, max_length=2048)
    safe_tags = {
        sanitize_text(str(key).lower(), max_length=128): sanitize_text(str(value), max_length=512)
        for key, value in list(observation.tags.items())[:200]
    }
    facts = parsed.model_dump(mode="json")
    return Asset(
        organization_id=organization_id,
        connection_id=connection_id,
        provider=observation.provider,
        asset_urn=asset_urn(
            observation.provider,
            observation.scope.id,
            observation.resource_type,
            observation.local_id,
        ),
        native_id=safe_native,
        resource_type=observation.resource_type,
        provider_resource_type=sanitize_text(observation.provider_resource_type, max_length=256),
        name=safe_name,
        scope_kind=observation.scope.kind,
        scope_id=sanitize_text(observation.scope.id, max_length=512),
        tags=safe_tags,
        facts=facts,
        facts_digest=digest(facts),
        is_demo=observation.is_demo,
    )
