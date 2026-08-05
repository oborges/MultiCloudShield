import pytest
from pydantic import ValidationError

from multicloudshield.config import Settings


def test_api_refuses_cloud_credentials() -> None:
    settings = Settings(process_role="api")
    with pytest.raises(RuntimeError, match="AWS_ACCESS_KEY_ID"):
        settings.assert_process_boundary({"AWS_ACCESS_KEY_ID": "present"})


def test_configuration_rejects_non_postgresql_and_wildcard_cors() -> None:
    with pytest.raises(ValidationError):
        Settings(database={"url": "sqlite:///unsafe.db"})
    with pytest.raises(ValidationError):
        Settings(api={"cors_origins": ["*"]})


def test_production_requires_strong_secret_key() -> None:
    with pytest.raises(ValidationError):
        Settings(env="production", secret_key="short")  # noqa: S106 - intentional rejection case
