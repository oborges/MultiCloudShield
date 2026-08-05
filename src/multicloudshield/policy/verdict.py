from __future__ import annotations

from dataclasses import dataclass

from multicloudshield.core.enums import EvaluationResult


@dataclass(frozen=True)
class Verdict:
    result: EvaluationResult
    reason_code: str
    sub_locators: tuple[str, ...] = ()

    @classmethod
    def pass_(cls, reason_code: str = "CONTROL_SATISFIED") -> Verdict:
        return cls(EvaluationResult.PASS, reason_code)

    @classmethod
    def fail(cls, reason_code: str, sub_locators: tuple[str, ...] = ()) -> Verdict:
        return cls(EvaluationResult.FAIL, reason_code, sub_locators)

    @classmethod
    def not_applicable(cls, reason_code: str) -> Verdict:
        return cls(EvaluationResult.NOT_APPLICABLE, reason_code)

    @classmethod
    def insufficient_data(cls, reason_code: str) -> Verdict:
        return cls(EvaluationResult.INSUFFICIENT_DATA, reason_code)
