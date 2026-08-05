from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.base import CollectionContext, ProviderError, RawObservation
from multicloudshield.providers.ibm.clients import IbmClientFactory
from multicloudshield.providers.ibm.common import client_call, provenance, sdk_call, text

_PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _acl_access(result: Mapping[str, Any]) -> tuple[TriState, TriState]:
    read = TriState.NO
    write = TriState.NO
    grants = result.get("Grants", [])
    if not isinstance(grants, list):
        return TriState.UNKNOWN, TriState.UNKNOWN
    for grant in grants[:10_000]:
        if not isinstance(grant, Mapping):
            return TriState.UNKNOWN, TriState.UNKNOWN
        grantee = grant.get("Grantee")
        uri = grantee.get("URI") if isinstance(grantee, Mapping) else None
        if uri not in _PUBLIC_URIS:
            continue
        permission = str(grant.get("Permission", "")).upper()
        if permission in {"READ", "FULL_CONTROL"}:
            read = TriState.YES
        if permission in {"WRITE", "WRITE_ACP", "FULL_CONTROL"}:
            write = TriState.YES
    return read, write


def _policy_access(policy: Any) -> tuple[TriState, TriState]:
    if policy in (None, ""):
        return TriState.NO, TriState.NO
    if isinstance(policy, str):
        if len(policy.encode("utf-8", errors="replace")) > 1024 * 1024:
            return TriState.UNKNOWN, TriState.UNKNOWN
        try:
            policy = json.loads(policy)
        except (json.JSONDecodeError, RecursionError):
            return TriState.UNKNOWN, TriState.UNKNOWN
    if not isinstance(policy, Mapping):
        return TriState.UNKNOWN, TriState.UNKNOWN
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return TriState.UNKNOWN, TriState.UNKNOWN
    read = TriState.NO
    write = TriState.NO
    for statement in statements[:10_000]:
        if not isinstance(statement, Mapping):
            return TriState.UNKNOWN, TriState.UNKNOWN
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        principal = statement.get("Principal")
        public = principal == "*" or (
            isinstance(principal, Mapping) and principal.get("AWS") == "*"
        )
        if not public:
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            return TriState.UNKNOWN, TriState.UNKNOWN
        lowered = {str(action).lower() for action in actions[:1000]}
        if lowered & {"s3:*", "s3:getobject", "s3:listbucket"}:
            read = TriState.YES
        if lowered & {"s3:*", "s3:putobject", "s3:deleteobject"}:
            write = TriState.YES
    return read, write


def _merge(left: TriState, right: TriState) -> TriState:
    if TriState.YES in (left, right):
        return TriState.YES
    if TriState.UNKNOWN in (left, right):
        return TriState.UNKNOWN
    return TriState.NO


@dataclass(frozen=True)
class CosBucketsCollector:
    factory: IbmClientFactory
    id: str = "ibm.cos.buckets"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "cloud-object-storage.bucket.list",
        "cloud-object-storage.bucket.get_acl",
        "cloud-object-storage.bucket.get_policy",
        "cloud-object-storage.bucket.get_policy_status",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.OBJECT_STORAGE_BUCKET,)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        if ctx.scope.kind != "region":
            raise ProviderError(
                ScanErrorCategory.UNSUPPORTED_REGION,
                "IBM COS collection requires a regional scope",
                code="REGION_REQUIRED",
            )
        client = client_call("create_cos_client", self.factory.cos, ctx.connection, ctx.scope.id)
        ctx.checkpoint()
        listed = sdk_call(
            "list_buckets",
            client.list_buckets,
            permission=self.required_permissions[0],
        )
        buckets = listed.get("Buckets", [])
        if not isinstance(buckets, list):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "IBM COS returned an invalid bucket list",
                code="INVALID_BUCKET_LIST",
            )
        ctx.budget.add_page(len(buckets))
        for bucket in buckets:
            ctx.checkpoint()
            if not isinstance(bucket, Mapping):
                raise ProviderError(
                    ScanErrorCategory.PARSE_ERROR,
                    "IBM COS returned an invalid bucket item",
                    operation="list_buckets",
                    code="INVALID_BUCKET",
                )
            name = text(bucket.get("Name"))
            calls = provenance(self.id, "list_buckets", ctx.scope.id, 1, listed)["calls"]
            acl = sdk_call(
                "get_bucket_acl",
                client.get_bucket_acl,
                permission=self.required_permissions[1],
                Bucket=name,
            )
            ctx.budget.add_page(1)
            calls.extend(provenance(self.id, "get_bucket_acl", ctx.scope.id, 1, acl)["calls"])
            try:
                policy_result = sdk_call(
                    "get_bucket_policy",
                    client.get_bucket_policy,
                    permission=self.required_permissions[2],
                    Bucket=name,
                )
            except ProviderError as exc:
                if exc.category is not ScanErrorCategory.NOT_FOUND:
                    raise
                policy_result = {}
            ctx.budget.add_page(1)
            calls.extend(
                provenance(self.id, "get_bucket_policy", ctx.scope.id, 1, policy_result)["calls"]
            )
            status = sdk_call(
                "get_bucket_policy_status",
                client.get_bucket_policy_status,
                permission=self.required_permissions[3],
                Bucket=name,
            )
            ctx.budget.add_page(1)
            calls.extend(
                provenance(self.id, "get_bucket_policy_status", ctx.scope.id, 1, status)["calls"]
            )
            acl_read, acl_write = _acl_access(acl)
            policy_read, policy_write = _policy_access(policy_result.get("Policy"))
            status_value = status.get("PolicyStatus")
            is_public = status_value.get("IsPublic") if isinstance(status_value, Mapping) else None
            if is_public is False:
                policy_read = TriState.NO
                policy_write = TriState.NO
            elif is_public is True:
                if policy_read is TriState.NO:
                    policy_read = TriState.UNKNOWN
                if policy_write is TriState.NO:
                    policy_write = TriState.UNKNOWN
            else:
                policy_read = TriState.UNKNOWN
                policy_write = TriState.UNKNOWN
            yield RawObservation(
                provider=CloudProvider.IBM,
                provider_resource_type="ibm.cos.bucket",
                native_id=f"crn:v1:bluemix:public:cloud-object-storage:{ctx.scope.id}:a/{ctx.connection.scope_id}::{name}",
                local_id=name,
                name=name,
                resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "object_storage",
                    "public_read_access": _merge(acl_read, policy_read),
                    "public_write_access": _merge(acl_write, policy_write),
                    "encryption_at_rest": EncryptionPosture.PROVIDER_MANAGED,
                    "versioning_enabled": TriState.UNKNOWN,
                    "access_logging_enabled": TriState.UNKNOWN,
                    "tls_required": TriState.UNKNOWN,
                    "provider_specific": {"ibm": {"encryption_coverage": "partial"}},
                },
                provenance={
                    "collector_id": self.id,
                    "collector_version": self.version,
                    "calls": calls,
                },
            )
