from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from time import monotonic
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest

from multicloudshield.core.enums import (
    CloudProvider,
    CredentialMechanism,
    ScanErrorCategory,
)
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.aws.adapter import (
    AwsAdapter,
    CloudTrailCollector,
    Ec2SecurityGroupsCollector,
    IamPrincipalsCollector,
    KmsKeysCollector,
    S3AccountCollector,
    S3BucketsCollector,
)
from multicloudshield.providers.aws.clients import (
    AWS_OPERATION_ALLOWLIST,
    AwsClientFactory,
    normalize_aws_error,
)
from multicloudshield.providers.base import (
    CancellationToken,
    CollectionContext,
    PageBudget,
    ProviderError,
    ScanScope,
)
from multicloudshield.providers.normalize import normalize_observation


class SdkError(Exception):
    def __init__(self, code: str, status: int) -> None:
        self.response = {
            "Error": {"Code": code, "Message": "sensitive provider text is discarded"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class StubBackend:
    def __init__(self) -> None:
        self.handlers: dict[tuple[str, str], list[Any] | Callable[..., Any]] = {}
        self.calls: list[tuple[str, str, str | None, dict[str, Any]]] = []

    def add(self, service: str, operation: str, *responses: Any) -> None:
        self.handlers[(service, operation)] = list(responses)

    def invoke(
        self, service: str, operation: str, region: str | None, params: dict[str, Any]
    ) -> Any:
        self.calls.append((service, operation, region, params))
        handler = self.handlers[(service, operation)]
        if callable(handler):
            value = handler(**params)
        else:
            value = handler.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class StubClient:
    def __init__(self, backend: StubBackend, service: str, region: str | None) -> None:
        self.backend = backend
        self.service = service
        self.region = region

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        def call(**params: Any) -> dict[str, Any]:
            value = self.backend.invoke(self.service, operation, self.region, params)
            assert isinstance(value, dict)
            return value

        return call


class StubFactory:
    def __init__(self, _connection: ConnectionDescriptor, backend: StubBackend) -> None:
        self.backend = backend
        self.default_region = "us-east-1"

    def client(self, service: str, *, region: str | None = None) -> StubClient:
        return StubClient(self.backend, service, region)


def connection(*, regions: list[str] | None = None) -> ConnectionDescriptor:
    return ConnectionDescriptor(
        id=UUID(int=1),
        organization_id=UUID(int=2),
        name="AWS test connection",
        provider=CloudProvider.AWS,
        scope_id="example-account",
        credential_mechanism=CredentialMechanism.AWS_DEFAULT_CHAIN,
        region_allowlist=regions or [],
    )


def context(
    *,
    kind: str = "global",
    scope_id: str = "example-account",
    budget: PageBudget | None = None,
    cancel: CancellationToken | None = None,
) -> CollectionContext:
    return CollectionContext(
        connection=connection(),
        scope=ScanScope(kind, scope_id, "aws"),
        cancel=cancel or CancellationToken(),
        budget=budget or PageBudget(max_pages=100, max_items=10_000),
        deadline_at=monotonic() + 60,
    )


def builder(backend: StubBackend) -> Callable[[ConnectionDescriptor], Any]:
    return lambda conn: StubFactory(conn, backend)


def assert_normalizable(observation: Any) -> None:
    asset = normalize_observation(
        observation, organization_id=UUID(int=2), connection_id=UUID(int=1)
    )
    assert asset.provider is CloudProvider.AWS


def test_allowlist_excludes_state_creating_and_mutating_operations() -> None:
    operations = set().union(*AWS_OPERATION_ALLOWLIST.values())
    assert "generate_credential_report" not in operations
    assert "generate_service_last_accessed_details" not in operations
    assert "get_object" not in operations
    assert not any(operation.startswith(("create_", "put_", "delete_")) for operation in operations)


def test_missing_sdk_is_a_normalized_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = __import__

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "boto3":
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", guarded_import)
    with pytest.raises(ProviderError) as raised:
        _ = AwsClientFactory(connection()).session
    assert raised.value.category is ScanErrorCategory.INTERNAL
    assert raised.value.code == "AWS_SDK_MISSING"


def test_sso_uses_the_non_secret_profile_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def session(**kwargs: Any) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setitem(__import__("sys").modules, "boto3", SimpleNamespace(Session=session))
    conn = connection().model_copy(
        update={
            "credential_mechanism": CredentialMechanism.AWS_SSO_PROFILE,
            "credential_reference": {"profile": "audit-profile"},
        }
    )
    _ = AwsClientFactory(conn).session
    assert captured == {"profile_name": "audit-profile"}


def test_access_denied_is_normalized_without_provider_message() -> None:
    error = normalize_aws_error(
        SdkError("AccessDenied", 403),
        operation="get_trail_status",
        permission="cloudtrail:GetTrailStatus",
    )
    assert error.category is ScanErrorCategory.PERMISSION_DENIED
    assert error.permission == "cloudtrail:GetTrailStatus"
    assert "sensitive provider text" not in str(error)


def test_resolve_scopes_uses_enabled_regions_and_allowlist() -> None:
    backend = StubBackend()
    backend.add(
        "sts",
        "get_caller_identity",
        {"Account": "example-account", "Arn": "arn:aws:sts::example-account:role/audit"},
    )
    backend.add(
        "ec2",
        "describe_regions",
        {"Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "us-east-2"}]},
    )
    conn = connection(regions=["eu-west-1"])
    scopes = AwsAdapter(builder(backend)).resolve_scopes(conn)
    assert scopes == [
        ScanScope("global", "example-account", "aws"),
        ScanScope("region", "eu-west-1", "aws"),
    ]


def test_verify_access_returns_degraded_report_for_a_denied_collector() -> None:
    backend = StubBackend()
    backend.add(
        "sts",
        "get_caller_identity",
        {"Account": "example-account", "Arn": "arn:aws:sts::example-account:role/audit"},
    )
    backend.add("s3", "list_buckets", {"Buckets": []})
    backend.add(
        "s3control",
        "get_public_access_block",
        SdkError("NoSuchPublicAccessBlockConfiguration", 404),
    )
    backend.add("ec2", "describe_regions", {"Regions": []})
    backend.add("iam", "get_account_summary", {"SummaryMap": {}})
    backend.add("cloudtrail", "describe_trails", SdkError("AccessDenied", 403))
    backend.add("kms", "list_keys", {"Keys": [], "Truncated": False})
    report = AwsAdapter(builder(backend)).verify_access(connection())
    assert report.status == "degraded"
    assert {gap.collector for gap in report.denied} == {"aws.cloudtrail.trails"}
    assert "aws.s3.account" in report.ok


def test_s3_collector_routes_bucket_calls_and_normalizes_posture() -> None:
    backend = StubBackend()
    backend.add("s3", "list_buckets", {"Buckets": [{"Name": "example-bucket"}]})
    backend.add("s3", "get_bucket_location", {"LocationConstraint": "eu-west-1"})
    backend.add("s3", "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}})
    backend.add(
        "s3",
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        },
    )
    backend.add(
        "s3",
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "alias/customer-key",
                        }
                    }
                ]
            }
        },
    )
    backend.add("s3", "get_bucket_versioning", {"Status": "Enabled"})
    backend.add("s3", "get_bucket_logging", {})
    backend.add(
        "s3",
        "get_bucket_policy",
        {
            "Policy": (
                '{"Statement":['
                '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"},'
                '{"Effect":"Deny","Principal":"*","Action":"s3:*",'
                '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
            )
        },
    )
    observation = next(iter(S3BucketsCollector(builder(backend)).collect(context())))
    assert_normalizable(observation)
    assert observation.scope.id == "eu-west-1"
    assert observation.facts["public_read_access"] is TriState.YES
    assert observation.facts["public_write_access"] is TriState.UNKNOWN
    assert observation.facts["tls_required"] is TriState.YES
    assert observation.facts["encryption_at_rest"] is EncryptionPosture.CUSTOMER_MANAGED
    detail_regions = {
        region
        for service, operation, region, _params in backend.calls
        if service == "s3" and operation not in {"list_buckets", "get_bucket_location"}
    }
    assert detail_regions == {"eu-west-1"}


def test_s3_account_collector_reports_all_four_controls() -> None:
    backend = StubBackend()
    backend.add(
        "s3control",
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
    )
    observation = next(iter(S3AccountCollector(builder(backend)).collect(context())))
    assert_normalizable(observation)
    assert observation.facts["provider_specific"]["aws"]["block_public_access_all"] == "yes"


def test_ec2_collector_paginates_and_observes_cancellation() -> None:
    backend = StubBackend()
    backend.add(
        "ec2",
        "describe_security_groups",
        {"SecurityGroups": [{"GroupId": "sg-example", "GroupName": "example"}], "NextToken": "p2"},
        {"SecurityGroups": []},
    )
    backend.add(
        "ec2",
        "describe_security_group_rules",
        {
            "SecurityGroupRules": [
                {
                    "GroupId": "sg-example",
                    "SecurityGroupRuleId": "sgr-example",
                    "IsEgress": False,
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIpv4": "0.0.0.0/0",
                }
            ]
        },
    )
    observations = list(
        Ec2SecurityGroupsCollector(builder(backend)).collect(
            context(kind="region", scope_id="eu-west-1")
        )
    )
    for observation in observations:
        assert_normalizable(observation)
    assert len(observations) == 2
    assert observations[0].facts["unrestricted_admin_ingress"] is TriState.YES
    assert backend.calls[1][3]["NextToken"] == "p2"

    token = CancellationToken()
    token.cancel()
    with pytest.raises(ProviderError, match="scan cancelled"):
        list(
            Ec2SecurityGroupsCollector(builder(backend)).collect(
                context(kind="region", scope_id="eu-west-1", cancel=token)
            )
        )


def test_iam_fallback_never_generates_report_and_keeps_interactive_unknown() -> None:
    backend = StubBackend()
    backend.add(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}},
    )
    backend.add("iam", "get_account_password_policy", SdkError("NoSuchEntity", 404))
    backend.add("iam", "get_credential_report", SdkError("ReportNotPresent", 404))
    backend.add(
        "iam",
        "list_users",
        {"Users": [{"UserName": "audit-user", "UserId": "user-example"}]},
    )
    backend.add(
        "iam",
        "list_access_keys",
        {
            "AccessKeyMetadata": [
                {
                    "Status": "Active",
                    "CreateDate": datetime.now(UTC) - timedelta(days=120),
                }
            ]
        },
    )
    backend.add("iam", "list_mfa_devices", {"MFADevices": []})
    observations = list(IamPrincipalsCollector(builder(backend)).collect(context()))
    for observation in observations:
        assert_normalizable(observation)
    user = observations[1]
    assert user.facts["interactive"] is TriState.UNKNOWN
    assert user.facts["mfa_enabled"] is TriState.NO
    assert user.facts["credential_age_days"] >= 120
    assert "generate_credential_report" not in {operation for _, operation, _, _ in backend.calls}


def test_cloudtrail_deduplicates_shadow_and_duplicate_trails_by_arn() -> None:
    backend = StubBackend()
    home = {
        "TrailARN": "arn:aws:cloudtrail:eu-west-1:example-account:trail/main",
        "Name": "main",
        "HomeRegion": "eu-west-1",
        "IsMultiRegionTrail": True,
        "LogFileValidationEnabled": True,
    }
    shadow = {**home, "HomeRegion": "us-east-2"}
    backend.add("cloudtrail", "describe_trails", {"trailList": [home, home, shadow]})
    backend.add("cloudtrail", "get_trail_status", {"IsLogging": True})
    backend.add("cloudtrail", "get_event_selectors", {"EventSelectors": []})
    observations = list(
        CloudTrailCollector(builder(backend)).collect(context(kind="region", scope_id="eu-west-1"))
    )
    assert_normalizable(observations[0])
    assert len(observations) == 1
    assert observations[0].facts["audit_logging_enabled"] is TriState.YES


def test_kms_skips_rotation_api_for_unsupported_key() -> None:
    backend = StubBackend()
    backend.add("kms", "list_keys", {"Keys": [{"KeyId": "key-example"}], "Truncated": False})
    backend.add(
        "kms",
        "describe_key",
        {
            "KeyMetadata": {
                "KeyId": "key-example",
                "Arn": "arn:aws:kms:eu-west-1:example-account:key/key-example",
                "KeyManager": "CUSTOMER",
                "Origin": "AWS_KMS",
                "KeySpec": "RSA_2048",
                "KeyUsage": "SIGN_VERIFY",
            }
        },
    )
    observation = next(
        iter(
            KmsKeysCollector(builder(backend)).collect(context(kind="region", scope_id="eu-west-1"))
        )
    )
    assert_normalizable(observation)
    assert observation.facts["supports_rotation"] is TriState.NO
    assert observation.facts["rotation_enabled"] is TriState.UNKNOWN
    assert "get_key_rotation_status" not in {operation for _, operation, _, _ in backend.calls}


def test_page_budget_is_enforced_between_pages() -> None:
    backend = StubBackend()
    backend.add(
        "ec2",
        "describe_security_groups",
        {"SecurityGroups": [], "NextToken": "p2"},
        {"SecurityGroups": []},
    )
    with pytest.raises(ProviderError) as raised:
        list(
            Ec2SecurityGroupsCollector(builder(backend)).collect(
                context(
                    kind="region",
                    scope_id="eu-west-1",
                    budget=PageBudget(max_pages=1, max_items=10),
                )
            )
        )
    assert raised.value.code == "COLLECTION_LIMIT_EXCEEDED"
