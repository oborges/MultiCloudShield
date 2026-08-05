from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TriState(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("TriState must be compared explicitly")


class EncryptionPosture(StrEnum):
    NONE = "none"
    PROVIDER_MANAGED = "provider_managed"
    CUSTOMER_MANAGED = "customer_managed"
    UNKNOWN = "unknown"


class StrictFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    kind: str
    provider_specific: dict[str, Any] = Field(default_factory=dict)


class ObjectStorageFacts(StrictFacts):
    kind: Literal["object_storage"] = "object_storage"
    public_read_access: TriState
    public_write_access: TriState
    encryption_at_rest: EncryptionPosture
    versioning_enabled: TriState
    access_logging_enabled: TriState
    tls_required: TriState


class FirewallFacts(StrictFacts):
    kind: Literal["firewall"] = "firewall"
    unrestricted_admin_ingress: TriState
    unrestricted_all_ports: TriState
    unrestricted_datastore_ingress: TriState
    offending_rules: list[str] = Field(default_factory=list, max_length=1000)


class IdentityFacts(StrictFacts):
    kind: Literal["identity"] = "identity"
    interactive: TriState
    mfa_enabled: TriState
    long_lived_credential: TriState
    credential_age_days: int | None = Field(default=None, ge=0, le=100_000)


class LoggingFacts(StrictFacts):
    kind: Literal["logging"] = "logging"
    audit_logging_enabled: TriState
    destination_public: TriState
    parent_scope_visibility: TriState = TriState.YES


class KmsFacts(StrictFacts):
    kind: Literal["kms"] = "kms"
    rotation_enabled: TriState
    supports_rotation: TriState = TriState.YES


class AccountFacts(StrictFacts):
    kind: Literal["account"] = "account"
    audit_logging_enabled: TriState
    mfa_enforced: TriState


AssetFacts = Annotated[
    ObjectStorageFacts | FirewallFacts | IdentityFacts | LoggingFacts | KmsFacts | AccountFacts,
    Field(discriminator="kind"),
]
