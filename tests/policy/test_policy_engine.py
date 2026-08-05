import pytest
from pydantic import ValidationError

from multicloudshield.core.enums import CloudProvider, EvaluationResult, NormalizedResourceType
from multicloudshield.policy import evaluate_policy, load_bundle


def policy(policy_id: str):
    return next(item for item in load_bundle().policies if item.id == policy_id)


def storage(public_read_access: str = "no") -> dict[str, object]:
    return {
        "kind": "object_storage",
        "public_read_access": public_read_access,
        "public_write_access": "no",
        "encryption_at_rest": "customer_managed",
        "versioning_enabled": "yes",
        "access_logging_enabled": "yes",
        "tls_required": "yes",
        "provider_specific": {},
    }


def test_policy_pass_fail_unknown_and_not_applicable() -> None:
    item = policy("MCS-STOR-001")
    passed = evaluate_policy(
        item,
        provider=CloudProvider.AWS,
        resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
        facts=storage("no"),
    )
    failed = evaluate_policy(
        item,
        provider=CloudProvider.AWS,
        resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
        facts=storage("yes"),
    )
    unknown = evaluate_policy(
        item,
        provider=CloudProvider.AWS,
        resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
        facts=storage("unknown"),
    )
    outside = evaluate_policy(
        item,
        provider=CloudProvider.AWS,
        resource_type=NormalizedResourceType.KMS_KEY,
        facts={"kind": "kms", "rotation_enabled": "yes", "supports_rotation": "yes"},
    )
    assert passed.verdict.result is EvaluationResult.PASS
    assert failed.verdict.result is EvaluationResult.FAIL
    assert unknown.verdict.result is EvaluationResult.INSUFFICIENT_DATA
    assert outside.verdict.result is EvaluationResult.NOT_APPLICABLE


def test_catalog_has_stable_complete_metadata() -> None:
    bundle = load_bundle()
    assert len(bundle.policies) == 23
    assert len({item.id for item in bundle.policies}) == 23
    for item in bundle.policies:
        assert item.rationale
        assert item.remediation.steps
        assert item.references
        assert item.version.count(".") == 2


def test_malformed_policy_input_is_rejected() -> None:
    with pytest.raises(ValidationError):
        evaluate_policy(
            policy("MCS-STOR-001"),
            provider=CloudProvider.AWS,
            resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
            facts={"kind": "object_storage", "public_read_access": "definitely"},
        )
