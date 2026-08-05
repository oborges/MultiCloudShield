from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.aws.clients import AwsClientFactory, aws_call
from multicloudshield.providers.base import (
    CapabilityGap,
    CapabilityReport,
    CollectionContext,
    ProviderCapabilities,
    ProviderError,
    RawObservation,
    ScanScope,
)

FactoryBuilder = Callable[[ConnectionDescriptor], AwsClientFactory]
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_CREDENTIAL_REPORT_BYTES = 5 * 1024 * 1024
_ADMIN_PORTS = frozenset((22, 3389))
_DATASTORE_PORTS = frozenset((1433, 1521, 27017, 3306, 5432, 6379, 9200, 11211))


def _partition_from_arn(arn: str) -> str:
    parts = arn.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else "aws"


def _bootstrap_region(partition: str, fallback: str) -> str:
    if partition == "aws-us-gov":
        return "us-gov-west-1"
    if partition == "aws-cn":
        return "cn-north-1"
    return fallback


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _provenance(
    collector_id: str,
    calls: list[dict[str, Any]],
) -> dict[str, Any]:
    return {"collector_id": collector_id, "collector_version": "1.0.0", "calls": calls}


def _call(
    ctx: CollectionContext,
    client: object,
    service: str,
    operation: str,
    permission: str,
    *,
    item_key: str | None = None,
    **params: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ctx.checkpoint()
    response = aws_call(client, operation, permission, **params)
    count = 1
    if item_key is not None:
        items = response.get(item_key, ())
        if not isinstance(items, list):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                f"AWS {operation} response field is invalid",
                operation=operation,
                code="INVALID_RESPONSE",
                permission=permission,
            )
        count = len(items)
    ctx.budget.add_page(count)
    return response, {
        "service": service,
        "operation": operation,
        "scope": ctx.scope.id,
        "request": {"parameter_names": sorted(params)},
        "response_digest": _digest(response),
        "http_status": 200,
    }


def _optional_call(
    ctx: CollectionContext,
    client: object,
    service: str,
    operation: str,
    permission: str,
    *,
    missing_codes: frozenset[str],
    **params: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        return _call(ctx, client, service, operation, permission, **params)
    except ProviderError as exc:
        if exc.category is ScanErrorCategory.NOT_FOUND and exc.code in missing_codes:
            ctx.budget.add_page(0)
            return None, {
                "service": service,
                "operation": operation,
                "scope": ctx.scope.id,
                "request": {"parameter_names": sorted(params)},
                "response_digest": _digest({"code": exc.code}),
                "http_status": 404,
            }
        raise


def _paginate(
    ctx: CollectionContext,
    client: object,
    service: str,
    operation: str,
    permission: str,
    item_key: str,
    *,
    request_cursor_field: str = "NextToken",
    response_cursor_field: str = "NextToken",
    truncated_key: str | None = None,
    base_params: Mapping[str, Any] | None = None,
) -> Iterator[tuple[list[dict[str, Any]], dict[str, Any]]]:
    token: str | None = None
    while True:
        params = dict(base_params or {})
        if token:
            params[request_cursor_field] = token
        response, call = _call(
            ctx,
            client,
            service,
            operation,
            permission,
            item_key=item_key,
            **params,
        )
        items = response[item_key]
        if not all(isinstance(item, dict) for item in items):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                f"AWS {operation} returned an invalid item",
                operation=operation,
                code="INVALID_RESPONSE",
                permission=permission,
            )
        yield items, call
        if truncated_key and not response.get(truncated_key):
            return
        raw_token = response.get(response_cursor_field)
        if not raw_token:
            return
        next_token = str(raw_token)
        if next_token == token:
            raise ProviderError(
                ScanErrorCategory.API_ERROR,
                f"AWS {operation} repeated a pagination token",
                operation=operation,
                code="REPEATED_PAGE_TOKEN",
                permission=permission,
            )
        token = next_token


def _tristate(value: object) -> TriState:
    if not isinstance(value, bool):
        return TriState.UNKNOWN
    return TriState.YES if value else TriState.NO


def _all_public_blocks(config: Mapping[str, Any] | None) -> bool | None:
    if config is None:
        return False
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if not all(key in config for key in keys):
        return None
    if not all(isinstance(config.get(key), bool) for key in keys):
        return None
    return all(config.get(key) is True for key in keys)


def _policy_document(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, str) or len(raw.encode()) > _MAX_POLICY_BYTES:
        return None
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _public_principal(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, dict):
        return any(item == "*" for values in value.values() for item in _as_list(values))
    return False


def _bucket_policy_facts(document: Mapping[str, Any] | None) -> tuple[bool, bool, bool]:
    public_read = False
    public_write = False
    tls_required = False
    if document is None:
        return public_read, public_write, tls_required
    statements = document.get("Statement", ())
    for statement in _as_list(statements)[:1000]:
        if not isinstance(statement, Mapping):
            continue
        actions = {str(action).lower() for action in _as_list(statement.get("Action", ()))[:1000]}
        effect = str(statement.get("Effect", "")).lower()
        principal = statement.get("Principal")
        condition = statement.get("Condition")
        if effect == "deny" and _public_principal(principal) and isinstance(condition, Mapping):
            bool_condition = condition.get("Bool")
            if (
                isinstance(bool_condition, Mapping)
                and str(bool_condition.get("aws:SecureTransport", "")).lower() == "false"
            ):
                tls_required = True
        if effect != "allow" or not _public_principal(principal):
            continue
        if condition:
            # Conditions may constrain access to an organization, VPC, or source range. The AWS
            # policy-status API remains authoritative for whether the statement is public.
            continue
        if "s3:*" in actions or any(action.startswith("s3:getobject") for action in actions):
            public_read = True
        if "s3:*" in actions or any(
            action.startswith(("s3:putobject", "s3:deleteobject")) for action in actions
        ):
            public_write = True
    return public_read, public_write, tls_required


def _encryption_posture(response: Mapping[str, Any] | None) -> EncryptionPosture:
    if response is None:
        return EncryptionPosture.NONE
    configuration = response.get("ServerSideEncryptionConfiguration")
    if not isinstance(configuration, Mapping):
        return EncryptionPosture.UNKNOWN
    rules = configuration.get("Rules", ())
    postures: list[EncryptionPosture] = []
    for rule in rules if isinstance(rules, list) else ():
        default = (
            rule.get("ApplyServerSideEncryptionByDefault", {}) if isinstance(rule, Mapping) else {}
        )
        algorithm = str(default.get("SSEAlgorithm", "")) if isinstance(default, Mapping) else ""
        key_id = default.get("KMSMasterKeyID") if isinstance(default, Mapping) else None
        if (
            algorithm in {"aws:kms", "aws:kms:dsse"}
            and key_id
            and "alias/aws/s3" not in str(key_id)
        ):
            postures.append(EncryptionPosture.CUSTOMER_MANAGED)
        elif algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}:
            postures.append(EncryptionPosture.PROVIDER_MANAGED)
    if EncryptionPosture.CUSTOMER_MANAGED in postures:
        return EncryptionPosture.CUSTOMER_MANAGED
    if EncryptionPosture.PROVIDER_MANAGED in postures:
        return EncryptionPosture.PROVIDER_MANAGED
    return EncryptionPosture.UNKNOWN


@dataclass(frozen=True)
class S3BucketsCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.s3.buckets"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.OBJECT_STORAGE_BUCKET,)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        global_client = factory.client("s3")
        pages = _paginate(
            ctx,
            global_client,
            "s3",
            "list_buckets",
            "s3:ListAllMyBuckets",
            "Buckets",
            request_cursor_field="ContinuationToken",
            response_cursor_field="ContinuationToken",
        )
        for buckets, list_call in pages:
            for bucket in buckets:
                ctx.checkpoint()
                name = str(bucket.get("Name", ""))
                if not name:
                    continue
                calls = [list_call]
                location, call = _call(
                    ctx,
                    global_client,
                    "s3",
                    "get_bucket_location",
                    "s3:GetBucketLocation",
                    Bucket=name,
                )
                calls.append(call)
                region = str(location.get("LocationConstraint") or "us-east-1")
                if region == "EU":
                    region = "eu-west-1"
                client = factory.client("s3", region=region)

                policy_status, policy_status_call = _optional_call(
                    ctx,
                    client,
                    "s3",
                    "get_bucket_policy_status",
                    "s3:GetBucketPolicyStatus",
                    missing_codes=frozenset(("NoSuchBucketPolicy",)),
                    Bucket=name,
                )
                if policy_status_call:
                    calls.append(policy_status_call)
                public_block, public_block_call = _optional_call(
                    ctx,
                    client,
                    "s3",
                    "get_public_access_block",
                    "s3:GetPublicAccessBlock",
                    missing_codes=frozenset(("NoSuchPublicAccessBlockConfiguration",)),
                    Bucket=name,
                )
                if public_block_call:
                    calls.append(public_block_call)
                encryption, encryption_call = _optional_call(
                    ctx,
                    client,
                    "s3",
                    "get_bucket_encryption",
                    "s3:GetBucketEncryption",
                    missing_codes=frozenset(("ServerSideEncryptionConfigurationNotFoundError",)),
                    Bucket=name,
                )
                if encryption_call:
                    calls.append(encryption_call)
                versioning, call = _call(
                    ctx,
                    client,
                    "s3",
                    "get_bucket_versioning",
                    "s3:GetBucketVersioning",
                    Bucket=name,
                )
                calls.append(call)
                logging, call = _call(
                    ctx,
                    client,
                    "s3",
                    "get_bucket_logging",
                    "s3:GetBucketLogging",
                    Bucket=name,
                )
                calls.append(call)
                policy, policy_call = _optional_call(
                    ctx,
                    client,
                    "s3",
                    "get_bucket_policy",
                    "s3:GetBucketPolicy",
                    missing_codes=frozenset(("NoSuchBucketPolicy",)),
                    Bucket=name,
                )
                if policy_call:
                    calls.append(policy_call)

                config = (
                    public_block.get("PublicAccessBlockConfiguration") if public_block else None
                )
                all_blocks = _all_public_blocks(config if isinstance(config, Mapping) else None)
                raw_policy_status = policy_status.get("PolicyStatus") if policy_status else None
                status_public = (
                    raw_policy_status.get("IsPublic")
                    if isinstance(raw_policy_status, Mapping)
                    else False
                    if policy_status is None
                    else None
                )
                document = _policy_document(policy.get("Policy")) if policy else None
                public_read, public_write, tls_required = _bucket_policy_facts(document)
                policy_parse_failed = policy is not None and document is None
                if all_blocks is True:
                    read_state = write_state = TriState.NO
                else:
                    read_state = (
                        TriState.YES if status_public is True and public_read else TriState.UNKNOWN
                    )
                    write_state = (
                        TriState.YES if status_public is True and public_write else TriState.UNKNOWN
                    )

                yield RawObservation(
                    provider=CloudProvider.AWS,
                    provider_resource_type="AWS::S3::Bucket",
                    native_id=f"arn:{ctx.scope.partition}:s3:::{name}",
                    local_id=name,
                    name=name,
                    resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                    scope=ScanScope("region", region, ctx.scope.partition),
                    tags={},
                    facts={
                        "kind": "object_storage",
                        "public_read_access": read_state,
                        "public_write_access": write_state,
                        "encryption_at_rest": _encryption_posture(encryption),
                        "versioning_enabled": _tristate(versioning.get("Status") == "Enabled"),
                        "access_logging_enabled": _tristate("LoggingEnabled" in logging),
                        "tls_required": (
                            TriState.UNKNOWN if policy_parse_failed else _tristate(tls_required)
                        ),
                        "provider_specific": {
                            "aws": {"block_public_access_all": _tristate(all_blocks).value}
                        },
                    },
                    provenance=_provenance(self.id, calls),
                )


@dataclass(frozen=True)
class S3AccountCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.s3.account"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = ("s3:GetAccountPublicAccessBlock",)
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset((NormalizedResourceType.ACCOUNT_SCOPE,))

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        client = factory.client("s3control")
        response, call = _optional_call(
            ctx,
            client,
            "s3control",
            "get_public_access_block",
            "s3:GetAccountPublicAccessBlock",
            missing_codes=frozenset(("NoSuchPublicAccessBlockConfiguration",)),
            AccountId=ctx.connection.scope_id,
        )
        config = response.get("PublicAccessBlockConfiguration") if response else None
        all_blocks = _all_public_blocks(config if isinstance(config, Mapping) else None)
        yield RawObservation(
            provider=CloudProvider.AWS,
            provider_resource_type="AWS::Account::S3PublicAccessBlock",
            native_id=f"arn:{ctx.scope.partition}:s3control::{ctx.connection.scope_id}:public-access-block",
            local_id="s3-public-access-block",
            name="S3 account public access block",
            resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
            scope=ctx.scope,
            tags={},
            facts={
                "kind": "account",
                "audit_logging_enabled": TriState.UNKNOWN,
                "mfa_enforced": TriState.UNKNOWN,
                "provider_specific": {
                    "aws": {"block_public_access_all": _tristate(all_blocks).value}
                },
            },
            provenance=_provenance(self.id, [call] if call else []),
        )


def _port_overlaps(from_port: Any, to_port: Any, candidates: frozenset[int]) -> bool:
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return False
    return any(from_port <= port <= to_port for port in candidates)


def _rule_posture(rule: Mapping[str, Any]) -> tuple[bool, bool, bool]:
    if rule.get("IsEgress") is True:
        return False, False, False
    public = rule.get("CidrIpv4") == "0.0.0.0/0" or rule.get("CidrIpv6") == "::/0"
    if not public:
        return False, False, False
    protocol = str(rule.get("IpProtocol", ""))
    all_ports = protocol == "-1"
    return (
        all_ports or _port_overlaps(rule.get("FromPort"), rule.get("ToPort"), _ADMIN_PORTS),
        all_ports,
        all_ports or _port_overlaps(rule.get("FromPort"), rule.get("ToPort"), _DATASTORE_PORTS),
    )


def _firewall_facts(rules: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    admin = all_ports = datastore = False
    offending: list[str] = []
    for rule in rules:
        rule_admin, rule_all, rule_datastore = _rule_posture(rule)
        if rule_admin or rule_all or rule_datastore:
            offending.append(str(rule.get("SecurityGroupRuleId", "unknown-rule")))
        admin = admin or rule_admin
        all_ports = all_ports or rule_all
        datastore = datastore or rule_datastore
    return {
        "kind": "firewall",
        "unrestricted_admin_ingress": _tristate(admin),
        "unrestricted_all_ports": _tristate(all_ports),
        "unrestricted_datastore_ingress": _tristate(datastore),
        "offending_rules": offending[:1000],
        "provider_specific": {},
    }


@dataclass(frozen=True)
class Ec2SecurityGroupsCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.ec2.security_groups"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (
            NormalizedResourceType.NETWORK_FIREWALL_RULESET,
            NormalizedResourceType.NETWORK_FIREWALL_RULE,
        )
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        client = factory.client("ec2", region=ctx.scope.id)
        groups: dict[str, dict[str, Any]] = {}
        group_calls: list[dict[str, Any]] = []
        for page, call in _paginate(
            ctx,
            client,
            "ec2",
            "describe_security_groups",
            "ec2:DescribeSecurityGroups",
            "SecurityGroups",
            base_params={"MaxResults": 1000},
        ):
            group_calls.append(call)
            for group in page:
                group_id = str(group.get("GroupId", ""))
                if group_id:
                    groups[group_id] = group

        rules_by_group: dict[str, list[dict[str, Any]]] = {group_id: [] for group_id in groups}
        rule_calls: list[dict[str, Any]] = []
        for page, call in _paginate(
            ctx,
            client,
            "ec2",
            "describe_security_group_rules",
            "ec2:DescribeSecurityGroupRules",
            "SecurityGroupRules",
            base_params={"MaxResults": 1000},
        ):
            rule_calls.append(call)
            for rule in page:
                group_id = str(rule.get("GroupId", ""))
                if group_id in rules_by_group:
                    rules_by_group[group_id].append(rule)

        for group_id, group in groups.items():
            ctx.checkpoint()
            rules = rules_by_group[group_id]
            yield RawObservation(
                provider=CloudProvider.AWS,
                provider_resource_type="AWS::EC2::SecurityGroup",
                native_id=str(
                    group.get("GroupArn")
                    or (
                        f"arn:{ctx.scope.partition}:ec2:{ctx.scope.id}:"
                        f"{ctx.connection.scope_id}:security-group/{group_id}"
                    )
                ),
                local_id=group_id,
                name=str(group.get("GroupName") or group_id),
                resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                scope=ctx.scope,
                tags={
                    str(tag.get("Key")): str(tag.get("Value", ""))
                    for tag in group.get("Tags", ())[:200]
                    if isinstance(tag, Mapping) and tag.get("Key") is not None
                },
                facts=_firewall_facts(rules),
                provenance=_provenance(self.id, group_calls + rule_calls),
            )
            for rule in rules:
                rule_id = str(rule.get("SecurityGroupRuleId", ""))
                if not rule_id:
                    continue
                yield RawObservation(
                    provider=CloudProvider.AWS,
                    provider_resource_type="AWS::EC2::SecurityGroupIngress",
                    native_id=f"arn:{ctx.scope.partition}:ec2:{ctx.scope.id}:{ctx.connection.scope_id}:security-group-rule/{rule_id}",
                    local_id=rule_id,
                    name=rule_id,
                    resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULE,
                    scope=ctx.scope,
                    tags={},
                    facts=_firewall_facts([rule]),
                    provenance=_provenance(self.id, rule_calls),
                )


def _parse_credential_report(response: Mapping[str, Any] | None) -> dict[str, dict[str, str]]:
    if response is None:
        return {}
    generated = response.get("GeneratedTime")
    if not isinstance(generated, datetime):
        return {}
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=UTC)
    if datetime.now(UTC) - generated.astimezone(UTC) > timedelta(hours=4):
        return {}
    content = response.get("Content")
    if not isinstance(content, (bytes, bytearray)) or len(content) > _MAX_CREDENTIAL_REPORT_BYTES:
        return {}
    try:
        text = bytes(content).decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
    except (UnicodeError, csv.Error):
        return {}
    if len(rows) > 50_000:
        return {}
    return {str(row.get("user", "")): dict(row) for row in rows if row.get("user")}


def _report_bool(row: Mapping[str, str] | None, key: str) -> bool | None:
    if not row:
        return None
    value = row.get(key, "").lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _credential_age(keys: Sequence[Mapping[str, Any]]) -> tuple[TriState, int | None]:
    active = [key for key in keys if key.get("Status") == "Active"]
    if not active:
        return TriState.NO, 0
    active_dates = [
        value for key in active for value in (key.get("CreateDate"),) if isinstance(value, datetime)
    ]
    if len(active_dates) != len(active):
        return TriState.UNKNOWN, None
    now = datetime.now(UTC)
    ages = [max(0, (now - value.astimezone(UTC)).days) for value in active_dates]
    oldest = max(ages)
    return _tristate(oldest > 90), oldest


def _password_policy_strong(policy: Mapping[str, Any] | None) -> bool | None:
    if policy is None:
        return False
    minimum_length = policy.get("MinimumPasswordLength")
    reuse = policy.get("PasswordReusePrevention")
    max_age = policy.get("MaxPasswordAge")
    if (
        not isinstance(minimum_length, int)
        or isinstance(minimum_length, bool)
        or not isinstance(reuse, int)
        or isinstance(reuse, bool)
        or not isinstance(max_age, int)
        or isinstance(max_age, bool)
    ):
        return None
    required = (
        minimum_length >= 14,
        policy.get("RequireSymbols") is True,
        policy.get("RequireNumbers") is True,
        policy.get("RequireUppercaseCharacters") is True,
        policy.get("RequireLowercaseCharacters") is True,
        reuse >= 24,
        0 < max_age <= 90,
    )
    return all(required)


@dataclass(frozen=True)
class IamPrincipalsCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.iam.principals"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = (
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.IDENTITY_PRINCIPAL, NormalizedResourceType.ACCOUNT_SCOPE)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        client = factory.client(
            "iam", region=_bootstrap_region(ctx.scope.partition, factory.default_region)
        )
        summary, summary_call = _call(
            ctx,
            client,
            "iam",
            "get_account_summary",
            "iam:GetAccountSummary",
        )
        password_response, password_call = _optional_call(
            ctx,
            client,
            "iam",
            "get_account_password_policy",
            "iam:GetAccountPasswordPolicy",
            missing_codes=frozenset(("NoSuchEntity",)),
        )
        report_response, report_call = _optional_call(
            ctx,
            client,
            "iam",
            "get_credential_report",
            "iam:GetCredentialReport",
            missing_codes=frozenset(("ReportExpired", "ReportInProgress", "ReportNotPresent")),
        )
        report = _parse_credential_report(report_response)
        calls = [summary_call]
        if password_call:
            calls.append(password_call)
        if report_call:
            calls.append(report_call)

        raw_summary_map = summary.get("SummaryMap")
        if not isinstance(raw_summary_map, Mapping):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "AWS account summary is invalid",
                operation="get_account_summary",
                code="INVALID_RESPONSE",
                permission="iam:GetAccountSummary",
            )
        summary_map = raw_summary_map
        root_row = report.get("<root_account>")
        root_keys = summary_map.get("AccountAccessKeysPresent")
        root_mfa = summary_map.get("AccountMFAEnabled")
        password_policy = password_response.get("PasswordPolicy") if password_response else None
        password_strong = _password_policy_strong(
            password_policy if isinstance(password_policy, Mapping) else None
        )
        yield RawObservation(
            provider=CloudProvider.AWS,
            provider_resource_type="AWS::IAM::Root",
            native_id=f"arn:{ctx.scope.partition}:iam::{ctx.connection.scope_id}:root",
            local_id="root",
            name="root",
            resource_type=NormalizedResourceType.IDENTITY_PRINCIPAL,
            scope=ctx.scope,
            tags={},
            facts={
                "kind": "identity",
                "interactive": _tristate(_report_bool(root_row, "password_enabled")),
                "mfa_enabled": (
                    _tristate(bool(root_mfa)) if isinstance(root_mfa, int) else TriState.UNKNOWN
                ),
                "long_lived_credential": _tristate(bool(root_keys))
                if isinstance(root_keys, int)
                else TriState.UNKNOWN,
                "credential_age_days": None,
                "provider_specific": {
                    "aws": {
                        "root_access_keys_active": _tristate(bool(root_keys)).value
                        if isinstance(root_keys, int)
                        else TriState.UNKNOWN.value,
                        "password_policy_strong": _tristate(password_strong).value,
                    }
                },
            },
            provenance=_provenance(self.id, calls),
        )

        for users, list_call in _paginate(
            ctx,
            client,
            "iam",
            "list_users",
            "iam:ListUsers",
            "Users",
            request_cursor_field="Marker",
            response_cursor_field="Marker",
            truncated_key="IsTruncated",
            base_params={"MaxItems": 1000},
        ):
            for user in users:
                user_name = str(user.get("UserName", ""))
                user_id = str(user.get("UserId", ""))
                if not user_name or not user_id:
                    continue
                keys: list[dict[str, Any]] = []
                key_calls: list[dict[str, Any]] = []
                for page, call in _paginate(
                    ctx,
                    client,
                    "iam",
                    "list_access_keys",
                    "iam:ListAccessKeys",
                    "AccessKeyMetadata",
                    request_cursor_field="Marker",
                    response_cursor_field="Marker",
                    truncated_key="IsTruncated",
                    base_params={"UserName": user_name, "MaxItems": 1000},
                ):
                    keys.extend(page)
                    key_calls.append(call)
                devices: list[dict[str, Any]] = []
                mfa_calls: list[dict[str, Any]] = []
                for page, call in _paginate(
                    ctx,
                    client,
                    "iam",
                    "list_mfa_devices",
                    "iam:ListMFADevices",
                    "MFADevices",
                    request_cursor_field="Marker",
                    response_cursor_field="Marker",
                    truncated_key="IsTruncated",
                    base_params={"UserName": user_name, "MaxItems": 1000},
                ):
                    devices.extend(page)
                    mfa_calls.append(call)
                long_lived, age = _credential_age(keys)
                row = report.get(user_name)
                yield RawObservation(
                    provider=CloudProvider.AWS,
                    provider_resource_type="AWS::IAM::User",
                    native_id=str(
                        user.get("Arn")
                        or (
                            f"arn:{ctx.scope.partition}:iam::{ctx.connection.scope_id}:"
                            f"user/{user_name}"
                        )
                    ),
                    local_id=user_id,
                    name=user_name,
                    resource_type=NormalizedResourceType.IDENTITY_PRINCIPAL,
                    scope=ctx.scope,
                    tags={},
                    facts={
                        "kind": "identity",
                        "interactive": _tristate(_report_bool(row, "password_enabled")),
                        "mfa_enabled": _tristate(bool(devices)),
                        "long_lived_credential": long_lived,
                        "credential_age_days": age,
                        "provider_specific": {},
                    },
                    provenance=_provenance(self.id, [list_call] + key_calls + mfa_calls),
                )

        yield RawObservation(
            provider=CloudProvider.AWS,
            provider_resource_type="AWS::IAM::AccountSummary",
            native_id=f"arn:{ctx.scope.partition}:iam::{ctx.connection.scope_id}:account-summary",
            local_id="iam-account-summary",
            name="IAM account summary",
            resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
            scope=ctx.scope,
            tags={},
            facts={
                "kind": "account",
                "audit_logging_enabled": TriState.UNKNOWN,
                "mfa_enforced": TriState.UNKNOWN,
                "provider_specific": {
                    "aws": {
                        "root_mfa_enabled": (
                            _tristate(bool(root_mfa)).value
                            if isinstance(root_mfa, int)
                            else TriState.UNKNOWN.value
                        ),
                        "password_policy_strong": _tristate(password_strong).value,
                    }
                },
            },
            provenance=_provenance(self.id, calls),
        )


@dataclass(frozen=True)
class CloudTrailCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.cloudtrail.trails"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.LOGGING_AUDIT_TRAIL,)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        client = factory.client("cloudtrail", region=ctx.scope.id)
        response, describe_call = _call(
            ctx,
            client,
            "cloudtrail",
            "describe_trails",
            "cloudtrail:DescribeTrails",
            item_key="trailList",
            includeShadowTrails=True,
        )
        seen: set[str] = set()
        for trail in response["trailList"]:
            arn = str(trail.get("TrailARN", ""))
            # Multi-region shadow trails are visible from every region. Only the home-region
            # observation is canonical; the ARN set also protects against duplicate SDK entries.
            if not arn or arn in seen or trail.get("HomeRegion") != ctx.scope.id:
                continue
            seen.add(arn)
            name = str(trail.get("Name") or arn.rsplit("/", 1)[-1])
            status, status_call = _call(
                ctx,
                client,
                "cloudtrail",
                "get_trail_status",
                "cloudtrail:GetTrailStatus",
                Name=arn,
            )
            _selectors, selectors_call = _call(
                ctx,
                client,
                "cloudtrail",
                "get_event_selectors",
                "cloudtrail:GetEventSelectors",
                TrailName=arn,
            )
            yield RawObservation(
                provider=CloudProvider.AWS,
                provider_resource_type="AWS::CloudTrail::Trail",
                native_id=arn,
                local_id=arn,
                name=name,
                resource_type=NormalizedResourceType.LOGGING_AUDIT_TRAIL,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "logging",
                    "audit_logging_enabled": _tristate(status.get("IsLogging")),
                    "destination_public": TriState.UNKNOWN,
                    "parent_scope_visibility": TriState.YES,
                    "provider_specific": {
                        "aws": {
                            "multi_region": _tristate(trail.get("IsMultiRegionTrail")).value,
                            "validation_enabled": _tristate(
                                trail.get("LogFileValidationEnabled")
                            ).value,
                        }
                    },
                },
                provenance=_provenance(self.id, [describe_call, status_call, selectors_call]),
            )


def _kms_supports_rotation(metadata: Mapping[str, Any]) -> bool | None:
    required = ("KeyManager", "Origin", "KeySpec", "KeyUsage")
    if not all(isinstance(metadata.get(key), str) for key in required):
        return None
    return (
        metadata.get("KeyManager") == "CUSTOMER"
        and metadata.get("Origin") == "AWS_KMS"
        and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
        and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
    )


@dataclass(frozen=True)
class KmsKeysCollector:
    factory_builder: FactoryBuilder = AwsClientFactory
    id: str = "aws.kms.keys"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset((NormalizedResourceType.KMS_KEY,))

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        factory = self.factory_builder(ctx.connection)
        client = factory.client("kms", region=ctx.scope.id)
        for keys, list_call in _paginate(
            ctx,
            client,
            "kms",
            "list_keys",
            "kms:ListKeys",
            "Keys",
            request_cursor_field="Marker",
            response_cursor_field="NextMarker",
            truncated_key="Truncated",
            base_params={"Limit": 1000},
        ):
            for key in keys:
                key_id = str(key.get("KeyId", ""))
                if not key_id:
                    continue
                described, describe_call = _call(
                    ctx,
                    client,
                    "kms",
                    "describe_key",
                    "kms:DescribeKey",
                    KeyId=key_id,
                )
                metadata = described.get("KeyMetadata", {})
                if not isinstance(metadata, Mapping):
                    raise ProviderError(
                        ScanErrorCategory.PARSE_ERROR,
                        "AWS DescribeKey returned invalid metadata",
                        operation="describe_key",
                        code="INVALID_RESPONSE",
                        permission="kms:DescribeKey",
                    )
                supports = _kms_supports_rotation(metadata)
                calls = [list_call, describe_call]
                rotation: bool | None = None
                if supports is True:
                    rotation_response, rotation_call = _call(
                        ctx,
                        client,
                        "kms",
                        "get_key_rotation_status",
                        "kms:GetKeyRotationStatus",
                        KeyId=key_id,
                    )
                    calls.append(rotation_call)
                    raw_rotation = rotation_response.get("KeyRotationEnabled")
                    rotation = raw_rotation if isinstance(raw_rotation, bool) else None
                arn = str(metadata.get("Arn") or key.get("KeyArn") or key_id)
                yield RawObservation(
                    provider=CloudProvider.AWS,
                    provider_resource_type="AWS::KMS::Key",
                    native_id=arn,
                    local_id=key_id,
                    name=key_id,
                    resource_type=NormalizedResourceType.KMS_KEY,
                    scope=ctx.scope,
                    tags={},
                    facts={
                        "kind": "kms",
                        "rotation_enabled": _tristate(rotation),
                        "supports_rotation": _tristate(supports),
                        "provider_specific": {
                            "aws": {"key_state": str(metadata.get("KeyState", "unknown"))}
                        },
                    },
                    provenance=_provenance(self.id, calls),
                )


class AwsAdapter:
    provider = CloudProvider.AWS

    def __init__(self, factory_builder: FactoryBuilder = AwsClientFactory) -> None:
        self._factory_builder = factory_builder

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider,
            collectors=tuple(collector.id for collector in self.collectors()),
            domains=("object_storage", "network", "identity", "logging", "kms"),
            credential_mechanisms=("aws_default_chain", "aws_assume_role", "aws_sso_profile"),
        )

    def _identity(
        self, factory: AwsClientFactory, connection: ConnectionDescriptor
    ) -> tuple[str, str, str]:
        client = factory.client("sts")
        response = aws_call(client, "get_caller_identity", "sts:GetCallerIdentity")
        account = response.get("Account")
        arn = response.get("Arn")
        if not isinstance(account, str) or not isinstance(arn, str):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "AWS identity response is invalid",
                operation="get_caller_identity",
                code="INVALID_RESPONSE",
                permission="sts:GetCallerIdentity",
            )
        if account != connection.scope_id:
            raise ProviderError(
                ScanErrorCategory.AUTHENTICATION,
                "AWS credentials resolve to a different account",
                operation="get_caller_identity",
                code="AWS_ACCOUNT_MISMATCH",
            )
        return arn, account, _partition_from_arn(arn)

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]:
        factory = self._factory_builder(conn)
        _arn, account, partition = self._identity(factory, conn)
        region = _bootstrap_region(partition, factory.default_region)
        client = factory.client("ec2", region=region)
        response = aws_call(client, "describe_regions", "ec2:DescribeRegions", AllRegions=False)
        raw_regions = response.get("Regions")
        if not isinstance(raw_regions, list):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "AWS region response is invalid",
                operation="describe_regions",
                code="INVALID_RESPONSE",
                permission="ec2:DescribeRegions",
            )
        enabled = sorted(
            str(item["RegionName"])
            for item in raw_regions
            if isinstance(item, Mapping) and item.get("RegionName")
        )
        if conn.region_allowlist:
            allowed = set(conn.region_allowlist)
            enabled = [item for item in enabled if item in allowed]
        return [ScanScope("global", account, partition)] + [
            ScanScope("region", item, partition) for item in enabled
        ]

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport:
        factory = self._factory_builder(conn)
        identity, account, partition = self._identity(factory, conn)
        region = _bootstrap_region(partition, factory.default_region)
        probes: tuple[tuple[str, str, str, str, dict[str, Any]], ...] = (
            ("aws.s3.buckets", "s3", "list_buckets", "s3:ListAllMyBuckets", {}),
            (
                "aws.s3.account",
                "s3control",
                "get_public_access_block",
                "s3:GetAccountPublicAccessBlock",
                {"AccountId": account},
            ),
            (
                "aws.ec2.security_groups",
                "ec2",
                "describe_regions",
                "ec2:DescribeRegions",
                {"AllRegions": False},
            ),
            (
                "aws.iam.principals",
                "iam",
                "get_account_summary",
                "iam:GetAccountSummary",
                {},
            ),
            (
                "aws.cloudtrail.trails",
                "cloudtrail",
                "describe_trails",
                "cloudtrail:DescribeTrails",
                {"includeShadowTrails": False},
            ),
            ("aws.kms.keys", "kms", "list_keys", "kms:ListKeys", {"Limit": 1}),
        )
        ok: list[str] = []
        denied: list[CapabilityGap] = []
        disabled: list[CapabilityGap] = []
        for collector, service, operation, permission, params in probes:
            try:
                client = factory.client(service, region=region)
                aws_call(client, operation, permission, **params)
            except ProviderError as exc:
                if (
                    collector == "aws.s3.account"
                    and exc.category is ScanErrorCategory.NOT_FOUND
                    and exc.code == "NoSuchPublicAccessBlockConfiguration"
                ):
                    ok.append(collector)
                    continue
                gap = CapabilityGap(collector, exc.permission or permission, str(exc))
                if exc.category is ScanErrorCategory.PERMISSION_DENIED:
                    denied.append(gap)
                elif exc.category in {
                    ScanErrorCategory.SERVICE_DISABLED,
                    ScanErrorCategory.UNSUPPORTED_REGION,
                    ScanErrorCategory.NOT_FOUND,
                }:
                    disabled.append(gap)
                else:
                    raise
            else:
                ok.append(collector)
        return CapabilityReport(
            status="connected" if not denied and not disabled else "degraded",
            identity=identity,
            ok=tuple(ok),
            denied=tuple(denied),
            disabled=tuple(disabled),
        )

    def collectors(
        self,
    ) -> tuple[
        S3BucketsCollector,
        S3AccountCollector,
        Ec2SecurityGroupsCollector,
        IamPrincipalsCollector,
        CloudTrailCollector,
        KmsKeysCollector,
    ]:
        builder = self._factory_builder
        return (
            S3BucketsCollector(builder),
            S3AccountCollector(builder),
            Ec2SecurityGroupsCollector(builder),
            IamPrincipalsCollector(builder),
            CloudTrailCollector(builder),
            KmsKeysCollector(builder),
        )


__all__ = [
    "AwsAdapter",
    "CloudTrailCollector",
    "Ec2SecurityGroupsCollector",
    "IamPrincipalsCollector",
    "KmsKeysCollector",
    "S3AccountCollector",
    "S3BucketsCollector",
]
