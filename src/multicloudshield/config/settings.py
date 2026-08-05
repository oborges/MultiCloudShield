from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseModel):
    url: str = "postgresql+psycopg://localhost:5432/multicloudshield"

    @field_validator("url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        if not value.startswith(("postgresql+psycopg://", "postgresql://")):
            raise ValueError("MCS_DATABASE__URL must be a PostgreSQL URL")
        return value


class ApiSettings(BaseModel):
    public_url: str = "http://localhost:8080"
    cors_origins: list[str] = Field(default_factory=list)
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)


class ScanSettings(BaseModel):
    max_concurrent_targets: int = Field(default=16, ge=1, le=64)
    max_per_connection: int = Field(default=8, ge=1, le=32)
    max_per_provider: int = Field(default=4, ge=1, le=16)
    call_timeout_seconds: float = Field(default=30, ge=1, le=120)
    target_deadline_seconds: float = Field(default=300, ge=5, le=3600)
    scan_deadline_seconds: float = Field(default=3600, ge=30, le=14400)
    max_pages_per_target: int = Field(default=200, ge=1, le=1000)
    max_items_per_target: int = Field(default=50_000, ge=1, le=250_000)
    max_retries: int = Field(default=5, ge=0, le=10)


class AuthSettings(BaseModel):
    session_idle_minutes: int = Field(default=30, ge=5, le=1440)
    session_absolute_hours: int = Field(default=8, ge=1, le=168)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MCS_", env_nested_delimiter="__", env_file=".env", extra="ignore"
    )

    env: Literal["development", "test", "production"] = "development"
    process_role: Literal["api", "worker", "cli"] = "api"
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    secret_key: SecretStr = SecretStr("")
    bootstrap_token: SecretStr | None = None

    @model_validator(mode="after")
    def secure_combinations(self) -> Settings:
        if self.env == "production" and len(self.secret_key.get_secret_value()) < 32:
            raise ValueError("MCS_SECRET_KEY must contain at least 32 characters in production")
        if "*" in self.api.cors_origins:
            raise ValueError("MCS_API__CORS_ORIGINS cannot contain a wildcard")
        return self

    def assert_process_boundary(self, environ: dict[str, str] | None = None) -> None:
        if self.process_role != "api":
            return
        env = environ if environ is not None else dict(os.environ)
        credential_names = (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "IBM_CLOUD_API_KEY",
            "IBMCLOUD_API_KEY",
        )
        present = [name for name in credential_names if env.get(name)]
        if present:
            raise RuntimeError(
                "API process refuses cloud credential environment variables: "
                + ", ".join(sorted(present))
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.assert_process_boundary()
    return settings
