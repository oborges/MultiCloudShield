from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.facts import TriState
from multicloudshield.providers.base import CollectionContext, ProviderError, RawObservation
from multicloudshield.providers.ibm.clients import IbmClientFactory
from multicloudshield.providers.ibm.common import (
    client_call,
    paginated,
    provenance,
    sdk_call,
    string_tags,
    text,
)


def _tri_state(value: Any) -> TriState:
    if value is True:
        return TriState.YES
    if value is False:
        return TriState.NO
    normalized = str(value).strip().lower()
    if normalized in {
        "yes",
        "enabled",
        "enable",
        "true",
        "on",
        "required",
        "enforced",
        "totp",
        "totp4all",
    }:
        return TriState.YES
    if normalized in {
        "no",
        "disabled",
        "disable",
        "false",
        "off",
        "optional",
        "not_enforced",
        "none",
    }:
        return TriState.NO
    return TriState.UNKNOWN


def _subjects(policy: Mapping[str, Any]) -> list[str]:
    subjects: list[str] = []
    raw_subjects = policy.get("subjects", [])
    if not isinstance(raw_subjects, list):
        raise ProviderError(
            ScanErrorCategory.PARSE_ERROR,
            "IBM IAM policy contains an invalid subject list",
            operation="list_policies",
            code="INVALID_SUBJECTS",
        )
    for subject in raw_subjects[:1000]:
        if not isinstance(subject, Mapping):
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "IBM IAM policy contains an invalid subject",
                operation="list_policies",
                code="INVALID_SUBJECT",
            )
        attributes = subject.get("attributes")
        if isinstance(attributes, Mapping):
            identifier = attributes.get("iam_id") or attributes.get("access_group_id")
            if identifier:
                subjects.append(text(identifier))
    return subjects


@dataclass(frozen=True)
class IamPoliciesCollector:
    factory: IbmClientFactory
    id: str = "ibm.iam.policies"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = (
        "iam.policy.read",
        "iam.role.read",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.IDENTITY_POLICY_BINDING,)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        client = client_call("create_iam_policy_client", self.factory.policies, ctx.connection)
        roles = sdk_call(
            "list_roles",
            client.list_roles,
            permission=self.required_permissions[1],
        )
        role_count = sum(
            len(values)
            for key in ("custom_roles", "service_roles", "system_defined_roles")
            if isinstance((values := roles.get(key)), list)
        )
        ctx.budget.add_page(role_count)
        role_calls = provenance(self.id, "list_roles", ctx.scope.id, 1, roles)["calls"]
        role_names: dict[str, str] = {}
        for key in ("custom_roles", "service_roles", "system_defined_roles"):
            values = roles.get(key, [])
            if not isinstance(values, list):
                raise ProviderError(
                    ScanErrorCategory.PARSE_ERROR,
                    "IBM IAM returned an invalid role list",
                    operation="list_roles",
                    code="INVALID_ROLES",
                )
            for role in values[:10_000]:
                if not isinstance(role, Mapping):
                    raise ProviderError(
                        ScanErrorCategory.PARSE_ERROR,
                        "IBM IAM returned an invalid role",
                        operation="list_roles",
                        code="INVALID_ROLE",
                    )
                role_id = text(role.get("id") or role.get("crn"))
                role_names[role_id] = text(
                    role.get("display_name") or role.get("name"), fallback=role_id
                )

        for policies, page_result, page in paginated(
            ctx,
            operation="list_policies",
            fetch=client.list_policies,
            item_keys=("policies",),
            permission=self.required_permissions[0],
            base_parameters={"account_id": ctx.connection.scope_id},
        ):
            for policy in policies:
                ctx.checkpoint()
                policy_id = text(policy.get("id"))
                raw_roles = policy.get("roles", [])
                resolved_roles: list[str] = []
                if isinstance(raw_roles, list):
                    for role in raw_roles[:1000]:
                        if isinstance(role, Mapping):
                            role_id = text(role.get("role_id") or role.get("id"))
                            resolved_roles.append(role_names.get(role_id, role_id))
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type="ibm.iam.policy",
                    native_id=policy_id,
                    local_id=policy_id,
                    name=text(policy.get("description"), fallback=policy_id),
                    resource_type=NormalizedResourceType.IDENTITY_POLICY_BINDING,
                    scope=ctx.scope,
                    tags={},
                    facts={
                        "kind": "identity",
                        "interactive": TriState.UNKNOWN,
                        "mfa_enabled": TriState.UNKNOWN,
                        "long_lived_credential": TriState.UNKNOWN,
                        "credential_age_days": None,
                        "provider_specific": {
                            "ibm": {
                                "policy_type": text(policy.get("type"), fallback="unknown"),
                                "subjects": _subjects(policy),
                                "roles": resolved_roles,
                            }
                        },
                    },
                    provenance={
                        "collector_id": self.id,
                        "collector_version": self.version,
                        "calls": [
                            *role_calls,
                            *provenance(self.id, "list_policies", ctx.scope.id, page, page_result)[
                                "calls"
                            ],
                        ],
                    },
                )


def _credential_age_days(created_at: Any) -> int | None:
    if not isinstance(created_at, str):
        return None
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return max(0, min(100_000, (datetime.now(UTC) - created.astimezone(UTC)).days))


@dataclass(frozen=True)
class IamIdentityCollector:
    factory: IbmClientFactory
    id: str = "ibm.iam.identity"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = (
        "iam.service-id.read",
        "iam.api-key.read",
        "iam.account-settings.read",
        "iam.mfa-status.read",
        "iam.mfa-report.read",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (NormalizedResourceType.IDENTITY_PRINCIPAL, NormalizedResourceType.ACCOUNT_SCOPE)
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        client = client_call("create_iam_identity_client", self.factory.identity, ctx.connection)
        settings = sdk_call(
            "get_account_settings",
            client.get_account_settings,
            permission=self.required_permissions[2],
            account_id=ctx.connection.scope_id,
        )
        ctx.budget.add_page(1)
        mfa_value = settings.get("mfa") or settings.get("mfa_status")
        yield RawObservation(
            provider=CloudProvider.IBM,
            provider_resource_type="ibm.iam.account_settings",
            native_id=f"ibm://account/{ctx.connection.scope_id}",
            local_id=ctx.connection.scope_id,
            name="IBM Cloud account",
            resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
            scope=ctx.scope,
            tags={},
            facts={
                "kind": "account",
                "audit_logging_enabled": TriState.UNKNOWN,
                "mfa_enforced": _tri_state(mfa_value),
                "provider_specific": {"ibm": {"account_mfa_enforced": _tri_state(mfa_value)}},
            },
            provenance=provenance(self.id, "get_account_settings", ctx.scope.id, 1, settings),
        )

        keys_by_identity: dict[str, list[dict[str, Any]]] = {}
        key_calls: list[dict[str, Any]] = []
        for keys, key_result, key_page in paginated(
            ctx,
            operation="list_api_keys",
            fetch=client.list_api_keys,
            item_keys=("apikeys",),
            permission=self.required_permissions[1],
            page_size_parameter="pagesize",
            cursor_parameter="pagetoken",
            base_parameters={"account_id": ctx.connection.scope_id},
        ):
            key_calls.extend(
                provenance(self.id, "list_api_keys", ctx.scope.id, key_page, key_result)["calls"]
            )
            for key in keys:
                identity = text(key.get("iam_id"), fallback="")
                if identity:
                    keys_by_identity.setdefault(identity, []).append(key)

        for service_ids, page_result, page in paginated(
            ctx,
            operation="list_service_ids",
            fetch=client.list_service_ids,
            item_keys=("serviceids",),
            permission=self.required_permissions[0],
            page_size_parameter="pagesize",
            cursor_parameter="pagetoken",
            base_parameters={"account_id": ctx.connection.scope_id},
        ):
            for service_id in service_ids:
                ctx.checkpoint()
                iam_id = text(service_id.get("iam_id") or service_id.get("id"))
                keys = keys_by_identity.get(iam_id, [])
                ages = [
                    age
                    for key in keys
                    if (age := _credential_age_days(key.get("created_at"))) is not None
                ]
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type="ibm.iam.service_id",
                    native_id=iam_id,
                    local_id=iam_id,
                    name=text(service_id.get("name"), fallback=iam_id),
                    resource_type=NormalizedResourceType.IDENTITY_PRINCIPAL,
                    scope=ctx.scope,
                    tags=string_tags(service_id.get("tags")),
                    facts={
                        "kind": "identity",
                        "interactive": TriState.NO,
                        "mfa_enabled": TriState.UNKNOWN,
                        "long_lived_credential": TriState.YES if keys else TriState.NO,
                        "credential_age_days": max(ages) if ages else None,
                        "provider_specific": {
                            "ibm": {"service_id": True, "api_key_count": len(keys)}
                        },
                    },
                    provenance={
                        "collector_id": self.id,
                        "collector_version": self.version,
                        "calls": [
                            *key_calls,
                            *provenance(
                                self.id, "list_service_ids", ctx.scope.id, page, page_result
                            )["calls"],
                        ],
                    },
                )

        report = sdk_call(
            "get_mfa_report",
            client.get_mfa_report,
            permission=self.required_permissions[4],
            account_id=ctx.connection.scope_id,
        )
        users = report.get("users", report.get("items", []))
        if not isinstance(users, list):
            users = []
        ctx.budget.add_page(len(users))
        for user in users[:10_000]:
            ctx.checkpoint()
            if not isinstance(user, Mapping):
                raise ProviderError(
                    ScanErrorCategory.PARSE_ERROR,
                    "IBM IAM returned an invalid MFA report entry",
                    operation="get_mfa_report",
                    code="INVALID_MFA_REPORT",
                )
            iam_id = text(user.get("iam_id") or user.get("id"))
            user_mfa = user.get("mfa") or user.get("mfa_status")
            user_calls = provenance(self.id, "get_mfa_report", ctx.scope.id, 1, report)["calls"]
            if _tri_state(user_mfa) is TriState.UNKNOWN:
                status = sdk_call(
                    "get_mfa_status",
                    client.get_mfa_status,
                    permission=self.required_permissions[3],
                    iam_id=iam_id,
                )
                ctx.budget.add_page(1)
                user_mfa = status.get("status") or status.get("mfa")
                user_calls.extend(
                    provenance(self.id, "get_mfa_status", ctx.scope.id, 1, status)["calls"]
                )
            yield RawObservation(
                provider=CloudProvider.IBM,
                provider_resource_type="ibm.iam.user_mfa",
                native_id=iam_id,
                local_id=iam_id,
                name=text(user.get("name") or user.get("email"), fallback=iam_id),
                resource_type=NormalizedResourceType.IDENTITY_PRINCIPAL,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "identity",
                    "interactive": TriState.YES,
                    "mfa_enabled": _tri_state(user_mfa),
                    "long_lived_credential": TriState.UNKNOWN,
                    "credential_age_days": None,
                    "provider_specific": {"ibm": {"mfa_report": True}},
                },
                provenance={
                    "collector_id": self.id,
                    "collector_version": self.version,
                    "calls": user_calls,
                },
            )
