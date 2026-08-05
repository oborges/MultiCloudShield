from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, Severity


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str
    url: HttpUrl
    accessed_on: str


class ComplianceMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: str
    framework_version: str
    control_id: str
    relationship: Literal["supports", "partially_supports"]
    note: str


class Remediation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str
    steps: list[str] = Field(min_length=1)
    required_permissions: dict[str, list[str]] = Field(default_factory=dict)
    verification: str
    change_risk: Literal["low", "medium", "high"] = "medium"
    change_risk_note: str


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^MCS-[A-Z0-9-]+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    title: str
    description: str
    rationale: str
    severity: Severity
    severity_rubric_cell: str
    provider_applicability: tuple[CloudProvider, ...]
    resource_type_applicability: tuple[NormalizedResourceType, ...]
    requires_facts: tuple[str, ...]
    origin: Literal["mcs_best_practice", "external_control_derived"]
    predicate: Literal[
        "yes_is_fail",
        "no_is_fail",
        "not_customer_managed",
        "age_over_90",
        "provider_no_is_fail",
        "provider_yes_is_fail",
    ]
    reason_code: str
    references: tuple[Reference, ...]
    remediation: Remediation
    compliance_mappings: tuple[ComplianceMapping, ...] = ()
    enabled_by_default: bool = True

    @field_validator("requires_facts")
    @classmethod
    def one_fact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != 1:
            raise ValueError("v0.1.0 catalog predicates require exactly one fact")
        return value

    @model_validator(mode="after")
    def provider_fact_is_narrowed(self) -> PolicyDefinition:
        path = self.requires_facts[0]
        if path.startswith("provider_specific."):
            expected = CloudProvider(path.split(".")[1])
            if tuple(self.provider_applicability) != (expected,):
                raise ValueError("provider-specific policy must have exactly one provider")
        return self


class PolicyBundle(BaseModel):
    version: str
    policies: tuple[PolicyDefinition, ...]

    @model_validator(mode="after")
    def unique_ids(self) -> PolicyBundle:
        ids = [policy.id for policy in self.policies]
        if len(ids) != len(set(ids)):
            raise ValueError("policy IDs must be unique")
        return self


@lru_cache(maxsize=1)
def load_bundle() -> PolicyBundle:
    path = files("multicloudshield.policy.bundle").joinpath("catalog.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return PolicyBundle.model_validate(raw)
