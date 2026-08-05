from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from multicloudshield.core.enums import CloudProvider, CredentialMechanism, FindingStatus
from multicloudshield.core.security import looks_secret

_ALLOWED_REFERENCE_KEYS: dict[CredentialMechanism, set[str]] = {
    CredentialMechanism.AWS_DEFAULT_CHAIN: {"profile"},
    CredentialMechanism.AWS_ASSUME_ROLE: {"role_arn", "external_id_env", "session_name"},
    CredentialMechanism.AWS_SSO_PROFILE: {"profile"},
    CredentialMechanism.AZURE_DEFAULT_CREDENTIAL: {"tenant_id"},
    CredentialMechanism.AZURE_WORKLOAD_IDENTITY: {"tenant_id", "client_id", "token_file_env"},
    CredentialMechanism.AZURE_MANAGED_IDENTITY: {"client_id"},
    CredentialMechanism.GCP_ADC: {"quota_project"},
    CredentialMechanism.GCP_IMPERSONATION: {"service_account_email"},
    CredentialMechanism.GCP_WORKLOAD_IDENTITY: {"audience", "credential_file_env"},
    CredentialMechanism.IBM_API_KEY_ENV: {
        "api_key_env",
        "cos_service_instance_id",
        "regions",
    },
    CredentialMechanism.IBM_TRUSTED_PROFILE: {
        "profile_id",
        "profile_name",
        "cr_token_filename_env",
        "cos_service_instance_id",
        "regions",
    },
    CredentialMechanism.DEMO_NONE: set(),
}


class ConnectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    provider: CloudProvider
    scope_id: str = Field(min_length=1, max_length=512)
    credential_mechanism: CredentialMechanism
    credential_reference: dict[str, str] = Field(default_factory=dict)
    region_allowlist: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def screen_credentials(self) -> ConnectionCreate:
        provider_for_mechanism = {
            CredentialMechanism.AWS_DEFAULT_CHAIN: CloudProvider.AWS,
            CredentialMechanism.AWS_ASSUME_ROLE: CloudProvider.AWS,
            CredentialMechanism.AWS_SSO_PROFILE: CloudProvider.AWS,
            CredentialMechanism.AZURE_DEFAULT_CREDENTIAL: CloudProvider.AZURE,
            CredentialMechanism.AZURE_WORKLOAD_IDENTITY: CloudProvider.AZURE,
            CredentialMechanism.AZURE_MANAGED_IDENTITY: CloudProvider.AZURE,
            CredentialMechanism.GCP_ADC: CloudProvider.GCP,
            CredentialMechanism.GCP_IMPERSONATION: CloudProvider.GCP,
            CredentialMechanism.GCP_WORKLOAD_IDENTITY: CloudProvider.GCP,
            CredentialMechanism.IBM_API_KEY_ENV: CloudProvider.IBM,
            CredentialMechanism.IBM_TRUSTED_PROFILE: CloudProvider.IBM,
            CredentialMechanism.DEMO_NONE: CloudProvider.DEMO,
        }
        if provider_for_mechanism[self.credential_mechanism] is not self.provider:
            raise ValueError("credential mechanism does not match provider")
        allowed = _ALLOWED_REFERENCE_KEYS[self.credential_mechanism]
        if set(self.credential_reference) - allowed:
            raise ValueError("credential_reference contains an unsupported key")
        if any(looks_secret(value) for value in self.credential_reference.values()):
            raise ValueError("credential_reference contains a secret-shaped value")
        return self


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=1024)


class FindingStatusRequest(BaseModel):
    status: FindingStatus
    reason: str = Field(min_length=3, max_length=2000)


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern="^(owner|analyst|viewer)$")
    expires_days: int = Field(default=90, ge=1, le=365)


class Page(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
