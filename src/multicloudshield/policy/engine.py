from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter

from multicloudshield.core.enums import CloudProvider, EvaluationResult, NormalizedResourceType
from multicloudshield.facts import AssetFacts, EncryptionPosture, FactView, TriState
from multicloudshield.policy.loader import PolicyDefinition
from multicloudshield.policy.verdict import Verdict

_FACT_ADAPTER: TypeAdapter[AssetFacts] = TypeAdapter(AssetFacts)


@dataclass(frozen=True)
class EvaluationOutcome:
    verdict: Verdict
    observed_facts: dict[str, Any]


def _read(view: FactView[Any], path: str) -> Any:
    parts = path.split(".")
    value = getattr(view, parts[0])
    for part in parts[1:]:
        if not isinstance(value, dict) or part not in value:
            return TriState.UNKNOWN
        value = value[part]
    return value


def evaluate_policy(
    policy: PolicyDefinition,
    *,
    provider: CloudProvider,
    resource_type: NormalizedResourceType,
    facts: dict[str, Any],
) -> EvaluationOutcome:
    if (
        provider not in policy.provider_applicability
        or resource_type not in policy.resource_type_applicability
    ):
        return EvaluationOutcome(Verdict.not_applicable("OUTSIDE_APPLICABILITY"), {})
    parsed = _FACT_ADAPTER.validate_python(facts)
    view: FactView[Any] = FactView(parsed)
    value = _read(view, policy.requires_facts[0])
    if value in (TriState.UNKNOWN, EncryptionPosture.UNKNOWN, "unknown", None):
        return EvaluationOutcome(Verdict.insufficient_data("REQUIRED_FACT_UNKNOWN"), view.observed)
    if policy.predicate in ("yes_is_fail", "provider_yes_is_fail"):
        failed = value in (TriState.YES, "yes", True)
    elif policy.predicate in ("no_is_fail", "provider_no_is_fail"):
        failed = value in (TriState.NO, "no", False)
    elif policy.predicate == "not_customer_managed":
        failed = value not in (EncryptionPosture.CUSTOMER_MANAGED, "customer_managed")
    elif policy.predicate == "age_over_90":
        failed = isinstance(value, int) and not isinstance(value, bool) and value > 90
    else:
        raise ValueError(f"unsupported predicate: {policy.predicate}")
    verdict = Verdict.fail(policy.reason_code) if failed else Verdict.pass_()
    return EvaluationOutcome(verdict, view.observed)


def result_counter_name(result: EvaluationResult) -> str:
    return {
        EvaluationResult.PASS: "pass_count",
        EvaluationResult.FAIL: "fail_count",
        EvaluationResult.NOT_APPLICABLE: "not_applicable_count",
        EvaluationResult.INSUFFICIENT_DATA: "insufficient_data_count",
        EvaluationResult.ERROR: "error_count",
    }[result]
