from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from multicloudshield.core.enums import CredentialMechanism, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers.allowlist import (
    ForbiddenOperationError,
    ReadOnlyClient,
    assert_read_only_allowlist,
)
from multicloudshield.providers.base import ProviderError

AWS_OPERATION_ALLOWLIST: dict[str, frozenset[str]] = {
    "sts": frozenset(("get_caller_identity", "assume_role")),
    "ec2": frozenset(
        ("describe_regions", "describe_security_groups", "describe_security_group_rules")
    ),
    "s3": frozenset(
        (
            "list_buckets",
            "get_bucket_location",
            "get_bucket_policy_status",
            "get_public_access_block",
            "get_bucket_encryption",
            "get_bucket_versioning",
            "get_bucket_logging",
            "get_bucket_policy",
        )
    ),
    "s3control": frozenset(("get_public_access_block",)),
    "iam": frozenset(
        (
            "list_users",
            "list_access_keys",
            "list_mfa_devices",
            "get_account_password_policy",
            "get_account_summary",
            "get_credential_report",
        )
    ),
    "cloudtrail": frozenset(("describe_trails", "get_trail_status", "get_event_selectors")),
    "kms": frozenset(("list_keys", "describe_key", "get_key_rotation_status")),
}

for _operations in AWS_OPERATION_ALLOWLIST.values():
    assert_read_only_allowlist(_operations)


_AUTH_CODES = frozenset(
    (
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
    )
)
_DENIED_CODES = frozenset(
    ("AccessDenied", "AccessDeniedException", "AuthorizationError", "UnauthorizedOperation")
)
_THROTTLED_CODES = frozenset(
    (
        "LimitExceededException",
        "RequestLimitExceeded",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    )
)
_NOT_FOUND_CODES = frozenset(
    (
        "NoSuchBucket",
        "NoSuchBucketPolicy",
        "NoSuchEntity",
        "NoSuchPublicAccessBlockConfiguration",
        "ReportExpired",
        "ReportInProgress",
        "ReportNotPresent",
        "ResourceNotFoundException",
        "ServerSideEncryptionConfigurationNotFoundError",
    )
)


def _error_details(exc: Exception) -> tuple[str, int | None]:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return type(exc).__name__, None
    error = response.get("Error")
    metadata = response.get("ResponseMetadata")
    code = (
        str(error.get("Code", type(exc).__name__))
        if isinstance(error, Mapping)
        else type(exc).__name__
    )
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return code, status if isinstance(status, int) else None


def normalize_aws_error(exc: Exception, *, operation: str, permission: str) -> ProviderError:
    """Map an SDK exception without copying its potentially sensitive message."""

    if isinstance(exc, ProviderError):
        return exc
    if isinstance(exc, ForbiddenOperationError):
        return ProviderError(
            ScanErrorCategory.INTERNAL,
            "AWS operation blocked by the read-only allowlist",
            operation=operation,
            code="FORBIDDEN_OPERATION",
            permission=permission,
        )
    code, status = _error_details(exc)
    class_name = type(exc).__name__
    if code in _AUTH_CODES or class_name in {
        "CredentialRetrievalError",
        "NoCredentialsError",
        "PartialCredentialsError",
        "ProfileNotFound",
        "SSOTokenLoadError",
        "UnauthorizedSSOTokenError",
    }:
        category = ScanErrorCategory.AUTHENTICATION
        retryable = False
    elif code in _DENIED_CODES or status == 403:
        category = ScanErrorCategory.PERMISSION_DENIED
        retryable = False
    elif code in _THROTTLED_CODES or status == 429:
        category = ScanErrorCategory.THROTTLED
        retryable = True
    elif code in _NOT_FOUND_CODES or status == 404:
        category = ScanErrorCategory.NOT_FOUND
        retryable = False
    elif class_name in {"ConnectTimeoutError", "ReadTimeoutError"}:
        category = ScanErrorCategory.TIMEOUT
        retryable = True
    elif class_name in {"EndpointConnectionError", "UnknownEndpointError"}:
        category = ScanErrorCategory.UNSUPPORTED_REGION
        retryable = False
    else:
        category = ScanErrorCategory.API_ERROR
        retryable = status is not None and status >= 500
    return ProviderError(
        category,
        f"AWS {operation} failed ({code})",
        operation=operation,
        code=code,
        permission=permission,
        retryable=retryable,
    )


def aws_call(client: object, operation: str, permission: str, **params: Any) -> dict[str, Any]:
    try:
        result = getattr(client, operation)(**params)
    except Exception as exc:
        raise normalize_aws_error(exc, operation=operation, permission=permission) from None
    if not isinstance(result, dict):
        raise ProviderError(
            ScanErrorCategory.PARSE_ERROR,
            f"AWS {operation} returned an invalid response",
            operation=operation,
            code="INVALID_RESPONSE",
            permission=permission,
        )
    return result


class AwsClientFactory:
    """Lazily creates allowlisted boto3 clients using the native credential chain."""

    def __init__(self, connection: ConnectionDescriptor) -> None:
        self._connection = connection
        self._session: Any | None = None

    @staticmethod
    def _reject_endpoint_overrides() -> None:
        if any(
            name == "AWS_ENDPOINT_URL" or name.startswith("AWS_ENDPOINT_URL_")
            for name in os.environ
        ):
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "AWS endpoint overrides are not permitted",
                code="AWS_ENDPOINT_OVERRIDE_FORBIDDEN",
            )

    @staticmethod
    def _config() -> Any:
        try:
            from botocore.config import Config
        except ModuleNotFoundError:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "AWS support is unavailable; install the aws provider extra",
                code="AWS_SDK_MISSING",
            ) from None
        return Config(
            retries={"mode": "adaptive", "total_max_attempts": 5},
            connect_timeout=5,
            read_timeout=20,
        )

    def _new_session(self) -> Any:
        self._reject_endpoint_overrides()
        try:
            import boto3
        except ModuleNotFoundError:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "AWS support is unavailable; install the aws provider extra",
                code="AWS_SDK_MISSING",
            ) from None

        mechanism = self._connection.credential_mechanism
        reference = self._connection.credential_reference
        if mechanism not in {
            CredentialMechanism.AWS_DEFAULT_CHAIN,
            CredentialMechanism.AWS_ASSUME_ROLE,
            CredentialMechanism.AWS_SSO_PROFILE,
        }:
            raise ProviderError(
                ScanErrorCategory.AUTHENTICATION,
                "AWS credential mechanism is invalid",
                code="AWS_CREDENTIAL_MECHANISM_INVALID",
            )
        if mechanism is CredentialMechanism.AWS_SSO_PROFILE:
            profile_name = reference.get("profile")
            if not profile_name:
                raise ProviderError(
                    ScanErrorCategory.AUTHENTICATION,
                    "AWS SSO profile name is not configured",
                    code="AWS_PROFILE_MISSING",
                )
            try:
                return boto3.Session(profile_name=profile_name)
            except Exception as exc:
                raise normalize_aws_error(
                    exc,
                    operation="resolve_credentials",
                    permission="sts:GetCallerIdentity",
                ) from None

        try:
            base = boto3.Session()
        except Exception as exc:
            raise normalize_aws_error(
                exc,
                operation="resolve_credentials",
                permission="sts:GetCallerIdentity",
            ) from None
        if mechanism is not CredentialMechanism.AWS_ASSUME_ROLE:
            return base

        role_arn = reference.get("role_arn")
        if not role_arn:
            raise ProviderError(
                ScanErrorCategory.AUTHENTICATION,
                "AWS role ARN is not configured",
                code="AWS_ROLE_ARN_MISSING",
            )
        session_name = reference.get("session_name", "multicloudshield")
        params: dict[str, str] = {"RoleArn": role_arn, "RoleSessionName": session_name}
        external_id_env = reference.get("external_id_env")
        if external_id_env:
            external_id = os.environ.get(external_id_env)
            if not external_id:
                raise ProviderError(
                    ScanErrorCategory.AUTHENTICATION,
                    "AWS external ID environment variable is not set",
                    code="AWS_EXTERNAL_ID_MISSING",
                )
            params["ExternalId"] = external_id
        try:
            sts = ReadOnlyClient(
                base.client("sts", config=self._config()), AWS_OPERATION_ALLOWLIST["sts"]
            )
        except Exception as exc:
            raise normalize_aws_error(
                exc, operation="assume_role", permission="sts:AssumeRole"
            ) from None
        assumed = aws_call(sts, "assume_role", "sts:AssumeRole", **params)
        credentials = assumed.get("Credentials")
        if not isinstance(credentials, Mapping):
            raise ProviderError(
                ScanErrorCategory.AUTHENTICATION,
                "AWS AssumeRole did not return credentials",
                operation="assume_role",
                code="AWS_ASSUME_ROLE_INVALID_RESPONSE",
            )
        try:
            return boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
        except Exception as exc:
            if isinstance(exc, (KeyError, TypeError)):
                raise ProviderError(
                    ScanErrorCategory.AUTHENTICATION,
                    "AWS AssumeRole returned incomplete credentials",
                    operation="assume_role",
                    code="AWS_ASSUME_ROLE_INVALID_RESPONSE",
                ) from None
            raise normalize_aws_error(
                exc, operation="resolve_credentials", permission="sts:AssumeRole"
            ) from None

    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = self._new_session()
        return self._session

    @property
    def default_region(self) -> str:
        return self.session.region_name or "us-east-1"

    def client(self, service: str, *, region: str | None = None) -> ReadOnlyClient:
        operations = AWS_OPERATION_ALLOWLIST.get(service)
        if operations is None:
            raise ProviderError(
                ScanErrorCategory.INTERNAL,
                "AWS service is not allowlisted",
                code="AWS_SERVICE_FORBIDDEN",
            )
        try:
            sdk_client = self.session.client(
                service,
                region_name=region or self.default_region,
                config=self._config(),
            )
        except Exception as exc:
            raise normalize_aws_error(
                exc, operation="create_client", permission=f"{service}:Connect"
            ) from None
        return ReadOnlyClient(sdk_client, operations)


__all__ = [
    "AWS_OPERATION_ALLOWLIST",
    "AwsClientFactory",
    "aws_call",
    "normalize_aws_error",
]
