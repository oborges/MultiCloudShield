from __future__ import annotations

from importlib import import_module
from typing import Any, cast

from multicloudshield.core.enums import CredentialMechanism, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.base import ProviderError


def build_cos_client(conn: ConnectionDescriptor, region: str) -> object:
    """Create the COS boto-compatible client in a module isolated from other SDK imports."""
    try:
        boto = import_module("ibm_boto3")
        config_class = import_module("ibm_botocore.client").Config
    except ImportError as exc:
        raise ProviderError(
            ScanErrorCategory.INTERNAL,
            "IBM COS SDK is not installed",
            code="SDK_NOT_INSTALLED",
        ) from exc

    from multicloudshield.providers.ibm.clients import validate_region

    region = validate_region(region)
    endpoint = f"https://s3.{region}.cloud-object-storage.appdomain.cloud"
    instance_id = conn.credential_reference.get("cos_service_instance_id")
    if not instance_id:
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "IBM COS service instance reference is missing",
            code="MISSING_SERVICE_INSTANCE_REFERENCE",
        )
    arguments: dict[str, object] = {
        "service_name": "s3",
        "ibm_service_instance_id": instance_id,
        "endpoint_url": endpoint,
        "config": config_class(
            signature_version="oauth",
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    }
    if conn.credential_mechanism is CredentialMechanism.IBM_API_KEY_ENV:
        from multicloudshield.providers.ibm.clients import api_key_from_environment

        arguments["ibm_api_key_id"] = api_key_from_environment(conn)
        arguments["ibm_auth_endpoint"] = "https://iam.cloud.ibm.com/identity/token"
    elif conn.credential_mechanism is CredentialMechanism.IBM_TRUSTED_PROFILE:
        from multicloudshield.providers.ibm.clients import _authenticator

        authenticator = cast(Any, _authenticator(conn))
        token_manager = authenticator.token_manager
        if token_manager is None or not callable(token_manager.get_token):
            raise ProviderError(
                ScanErrorCategory.AUTHENTICATION,
                "IBM trusted profile did not provide a compatible COS token manager",
                code="COS_TOKEN_MANAGER_UNAVAILABLE",
            )
        # The IBM COS SDK documents token_manager as its native custom-IAM integration point.
        arguments["token_manager"] = token_manager
    else:
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "unsupported IBM COS credential mechanism",
            code="UNSUPPORTED_CREDENTIAL_MECHANISM",
        )
    return boto.client(**arguments)
