from __future__ import annotations

import os
import re
from importlib import import_module
from typing import Any, Protocol

from multicloudshield.core.enums import CredentialMechanism, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.allowlist import ReadOnlyClient, assert_read_only_allowlist
from multicloudshield.providers.base import ProviderError

VPC_API_VERSION = "2026-08-05"
IBM_REGIONS = frozenset(
    (
        "au-syd",
        "br-sao",
        "ca-tor",
        "eu-de",
        "eu-es",
        "eu-gb",
        "jp-osa",
        "jp-tok",
        "us-east",
        "us-south",
    )
)

INVENTORY_OPERATIONS = frozenset(("search", "list_resource_instances"))
COS_OPERATIONS = frozenset(
    ("list_buckets", "get_bucket_acl", "get_bucket_policy", "get_bucket_policy_status")
)
VPC_OPERATIONS = frozenset(
    (
        "list_security_groups",
        "list_security_group_rules",
        "list_security_group_targets",
        "list_network_acls",
        "list_network_acl_rules",
    )
)
POLICY_OPERATIONS = frozenset(("list_policies", "list_roles"))
IDENTITY_OPERATIONS = frozenset(
    (
        "list_service_ids",
        "list_api_keys",
        "get_account_settings",
        "get_mfa_status",
        "get_mfa_report",
    )
)

for _operations in (
    INVENTORY_OPERATIONS,
    COS_OPERATIONS,
    VPC_OPERATIONS,
    POLICY_OPERATIONS,
    IDENTITY_OPERATIONS,
):
    assert_read_only_allowlist(_operations)


class IbmClientFactory(Protocol):
    def inventory(self, conn: ConnectionDescriptor) -> Any: ...

    def resource_controller(self, conn: ConnectionDescriptor) -> Any: ...

    def cos(self, conn: ConnectionDescriptor, region: str) -> Any: ...

    def vpc(self, conn: ConnectionDescriptor, region: str) -> Any: ...

    def policies(self, conn: ConnectionDescriptor) -> Any: ...

    def identity(self, conn: ConnectionDescriptor) -> Any: ...


def _credential_value(conn: ConnectionDescriptor, key: str) -> str:
    value = conn.credential_reference.get(key, "")
    if not value:
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            f"IBM Cloud credential reference is missing {key}",
            code="MISSING_CREDENTIAL_REFERENCE",
        )
    return value


def api_key_from_environment(conn: ConnectionDescriptor) -> str:
    env_name = _credential_value(conn, "api_key_env")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", env_name):
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "IBM Cloud API key environment variable name is invalid",
            code="INVALID_ENVIRONMENT_REFERENCE",
        )
    api_key = os.environ.get(env_name)
    if not api_key:
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "IBM Cloud API key environment variable is not available",
            code="CREDENTIAL_NOT_AVAILABLE",
        )
    return api_key


def validate_region(region: str) -> str:
    if region not in IBM_REGIONS:
        raise ProviderError(
            ScanErrorCategory.UNSUPPORTED_REGION,
            "invalid IBM Cloud region identifier",
            code="INVALID_REGION",
        )
    return region


def _authenticator(conn: ConnectionDescriptor) -> object:
    """Construct an official SDK authenticator only when a live client is requested."""
    try:
        authenticators = import_module("ibm_cloud_sdk_core.authenticators")
        if conn.credential_mechanism is CredentialMechanism.IBM_API_KEY_ENV:
            authenticator_class = authenticators.IamAuthenticator
            return authenticator_class(api_key_from_environment(conn))
        if conn.credential_mechanism is CredentialMechanism.IBM_TRUSTED_PROFILE:
            profile_name = conn.credential_reference.get("profile_name")
            profile_id = conn.credential_reference.get("profile_id")
            if not profile_name and not profile_id:
                raise ProviderError(
                    ScanErrorCategory.AUTHENTICATION,
                    "IBM Cloud trusted profile reference is missing profile_name or profile_id",
                    code="MISSING_PROFILE_REFERENCE",
                )
            authenticator_class = authenticators.ContainerAuthenticator
            return authenticator_class(iam_profile_name=profile_name, iam_profile_id=profile_id)
    except ImportError as exc:
        raise ProviderError(
            ScanErrorCategory.INTERNAL,
            "IBM Cloud SDK is not installed; install the ibm provider extra",
            code="SDK_NOT_INSTALLED",
        ) from exc
    raise ProviderError(
        ScanErrorCategory.AUTHENTICATION,
        "unsupported IBM Cloud credential mechanism",
        code="UNSUPPORTED_CREDENTIAL_MECHANISM",
    )


def _service_url(service: str, region: str | None = None) -> str | None:
    if region is None:
        return None
    region = validate_region(region)
    if service == "vpc":
        return f"https://{region}.iaas.cloud.ibm.com/v1"
    if service == "cos":
        return f"https://s3.{region}.cloud-object-storage.appdomain.cloud"
    return None


def _set_url(service: object, url: str | None) -> None:
    if url is not None:
        setter = getattr(service, "set_service_url", None)
        if callable(setter):
            setter(url)


class DefaultIbmClientFactory:
    """Lazy official-SDK factory wrapped by reviewed read-operation allowlists."""

    def inventory(self, conn: ConnectionDescriptor) -> object:
        try:
            service_class = import_module("ibm_platform_services").GlobalSearchV2
        except ImportError as exc:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM Platform Services SDK is not installed",
                code="SDK_NOT_INSTALLED",
            ) from exc
        service = service_class(authenticator=_authenticator(conn))
        _set_url(service, _service_url("search"))
        return ReadOnlyClient(service, INVENTORY_OPERATIONS)

    def resource_controller(self, conn: ConnectionDescriptor) -> object:
        try:
            service_class = import_module("ibm_platform_services").ResourceControllerV2
        except ImportError as exc:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM Platform Services SDK is not installed",
                code="SDK_NOT_INSTALLED",
            ) from exc
        service = service_class(authenticator=_authenticator(conn))
        _set_url(service, _service_url("resource_controller"))
        return ReadOnlyClient(service, INVENTORY_OPERATIONS)

    def cos(self, conn: ConnectionDescriptor, region: str) -> object:
        # This import boundary is deliberate: ibm-cos-sdk vendors a botocore fork.
        from multicloudshield.providers.ibm.cos_client import build_cos_client

        return ReadOnlyClient(build_cos_client(conn, region), COS_OPERATIONS)

    def vpc(self, conn: ConnectionDescriptor, region: str) -> object:
        try:
            service_class = import_module("ibm_vpc").VpcV1
        except ImportError as exc:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM VPC SDK is not installed",
                code="SDK_NOT_INSTALLED",
            ) from exc
        service = service_class(version=VPC_API_VERSION, authenticator=_authenticator(conn))
        _set_url(service, _service_url("vpc", region))
        return ReadOnlyClient(service, VPC_OPERATIONS)

    def policies(self, conn: ConnectionDescriptor) -> object:
        try:
            service_class = import_module("ibm_platform_services").IamPolicyManagementV1
        except ImportError as exc:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM Platform Services SDK is not installed",
                code="SDK_NOT_INSTALLED",
            ) from exc
        service = service_class(authenticator=_authenticator(conn))
        _set_url(service, _service_url("iam_policy"))
        return ReadOnlyClient(service, POLICY_OPERATIONS)

    def identity(self, conn: ConnectionDescriptor) -> object:
        try:
            service_class = import_module("ibm_platform_services").IamIdentityV1
        except ImportError as exc:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "IBM Platform Services SDK is not installed",
                code="SDK_NOT_INSTALLED",
            ) from exc
        service = service_class(authenticator=_authenticator(conn))
        _set_url(service, _service_url("iam_identity"))
        return ReadOnlyClient(service, IDENTITY_OPERATIONS)
