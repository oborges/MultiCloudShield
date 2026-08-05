from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.facts import TriState
from multicloudshield.providers.base import CollectionContext, ProviderError, RawObservation
from multicloudshield.providers.ibm.clients import IbmClientFactory
from multicloudshield.providers.ibm.common import client_call, paginated, provenance, text

_ADMIN_PORTS = frozenset((22, 3389))
_DATASTORE_PORTS = frozenset((1433, 1521, 2049, 2379, 2380, 27017, 3306, 5432, 6379, 9200, 9300))


def _reference_id(value: Any) -> str:
    if isinstance(value, Mapping):
        return text(value.get("id") or value.get("crn") or value.get("address"))
    return text(value)


def _is_world(value: Any) -> bool:
    if isinstance(value, Mapping):
        value = value.get("cidr_block") or value.get("address")
    return value in {"0.0.0.0/0", "::/0"}


def _ports(rule: Mapping[str, Any]) -> tuple[int, int]:
    protocol = str(rule.get("protocol", "all")).lower()
    if protocol in {"all", "icmp", "icmpv6"}:
        return 1, 65_535
    minimum = rule.get("port_min", rule.get("destination_port_min", 1))
    maximum = rule.get("port_max", rule.get("destination_port_max", 65_535))
    try:
        return max(1, int(minimum)), min(65_535, int(maximum))
    except (TypeError, ValueError):
        return 1, 65_535


def _rule_posture(
    rule: Mapping[str, Any], *, network_acl: bool
) -> tuple[TriState, TriState, TriState]:
    direction = str(rule.get("direction", "inbound")).lower()
    source = rule.get("source") or rule.get("remote") or rule.get("source_address")
    if network_acl and str(rule.get("action", "allow")).lower() != "allow":
        return TriState.NO, TriState.NO, TriState.NO
    if direction not in {"inbound", "ingress"} or not _is_world(source):
        return TriState.NO, TriState.NO, TriState.NO
    minimum, maximum = _ports(rule)
    all_ports = minimum <= 1 and maximum >= 65_535
    admin = all_ports or any(minimum <= port <= maximum for port in _ADMIN_PORTS)
    datastore = all_ports or any(minimum <= port <= maximum for port in _DATASTORE_PORTS)
    return (
        TriState.YES if admin else TriState.NO,
        TriState.YES if all_ports else TriState.NO,
        TriState.YES if datastore else TriState.NO,
    )


def _combine(
    rows: list[tuple[TriState, TriState, TriState]],
) -> tuple[TriState, TriState, TriState]:
    return tuple(
        TriState.YES if any(row[index] is TriState.YES for row in rows) else TriState.NO
        for index in range(3)
    )  # type: ignore[return-value]


def _firewall_facts(
    rules: list[dict[str, Any]], *, network_acl: bool, extra: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    postures = [_rule_posture(rule, network_acl=network_acl) for rule in rules]
    admin, all_ports, datastore = _combine(postures)
    offending = [
        text(rule.get("id") or rule.get("name"))
        for rule, posture in zip(rules, postures, strict=True)
        if TriState.YES in posture
    ][:1000]
    return {
        "kind": "firewall",
        "unrestricted_admin_ingress": admin,
        "unrestricted_all_ports": all_ports,
        "unrestricted_datastore_ingress": datastore,
        "offending_rules": offending,
        "provider_specific": {"ibm": dict(extra or {})},
    }


@dataclass(frozen=True)
class SecurityGroupsCollector:
    factory: IbmClientFactory
    id: str = "ibm.vpc.security_groups"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "is.security-group.security-group.read",
        "is.security-group.security-group-rule.read",
        "is.security-group.security-group-target.read",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (
            NormalizedResourceType.NETWORK_FIREWALL_RULESET,
            NormalizedResourceType.NETWORK_FIREWALL_RULE,
        )
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        if ctx.scope.kind != "region":
            raise ProviderError(
                ScanErrorCategory.UNSUPPORTED_REGION,
                "IBM VPC collection requires a regional scope",
                code="REGION_REQUIRED",
            )
        client = client_call("create_vpc_client", self.factory.vpc, ctx.connection, ctx.scope.id)
        for groups, page_result, page in paginated(
            ctx,
            operation="list_security_groups",
            fetch=client.list_security_groups,
            item_keys=("security_groups",),
            permission=self.required_permissions[0],
            base_parameters={"generation": 2},
        ):
            for group in groups:
                ctx.checkpoint()
                group_id = text(group.get("id"))
                rules: list[dict[str, Any]] = []
                calls = provenance(
                    self.id, "list_security_groups", ctx.scope.id, page, page_result
                )["calls"]
                for rule_page, rule_result, rule_page_number in paginated(
                    ctx,
                    operation="list_security_group_rules",
                    fetch=client.list_security_group_rules,
                    item_keys=("rules",),
                    permission=self.required_permissions[1],
                    base_parameters={"security_group_id": group_id},
                ):
                    rules.extend(rule_page)
                    calls.extend(
                        provenance(
                            self.id,
                            "list_security_group_rules",
                            ctx.scope.id,
                            rule_page_number,
                            rule_result,
                        )["calls"]
                    )
                targets: list[str] = []
                for target_page, target_result, target_page_number in paginated(
                    ctx,
                    operation="list_security_group_targets",
                    fetch=client.list_security_group_targets,
                    item_keys=("targets",),
                    permission=self.required_permissions[2],
                    base_parameters={"security_group_id": group_id},
                ):
                    targets.extend(_reference_id(target) for target in target_page)
                    calls.extend(
                        provenance(
                            self.id,
                            "list_security_group_targets",
                            ctx.scope.id,
                            target_page_number,
                            target_result,
                        )["calls"]
                    )
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type="ibm.vpc.security_group",
                    native_id=text(group.get("crn"), fallback=group_id),
                    local_id=group_id,
                    name=text(group.get("name"), fallback=group_id),
                    resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                    scope=ctx.scope,
                    tags={},
                    facts=_firewall_facts(
                        rules, network_acl=False, extra={"targets": targets[:1000]}
                    ),
                    provenance={
                        "collector_id": self.id,
                        "collector_version": self.version,
                        "calls": calls,
                    },
                )
                for rule in rules:
                    rule_id = text(rule.get("id"))
                    yield RawObservation(
                        provider=CloudProvider.IBM,
                        provider_resource_type="ibm.vpc.security_group_rule",
                        native_id=f"{group_id}/rule/{rule_id}",
                        local_id=f"{group_id}:{rule_id}",
                        name=rule_id,
                        resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULE,
                        scope=ctx.scope,
                        tags={},
                        facts=_firewall_facts([rule], network_acl=False),
                        provenance=provenance(
                            self.id, "list_security_group_rules", ctx.scope.id, 1, {"rules": [rule]}
                        ),
                    )


@dataclass(frozen=True)
class NetworkAclsCollector:
    factory: IbmClientFactory
    id: str = "ibm.vpc.network_acls"
    version: str = "1.0.0"
    scope_kind: str = "region"
    required_permissions: tuple[str, ...] = (
        "is.network-acl.network-acl.read",
        "is.network-acl.network-acl-rule.read",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset(
        (
            NormalizedResourceType.NETWORK_FIREWALL_RULESET,
            NormalizedResourceType.NETWORK_FIREWALL_RULE,
        )
    )

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        if ctx.scope.kind != "region":
            raise ProviderError(
                ScanErrorCategory.UNSUPPORTED_REGION,
                "IBM VPC collection requires a regional scope",
                code="REGION_REQUIRED",
            )
        client = client_call("create_vpc_client", self.factory.vpc, ctx.connection, ctx.scope.id)
        for acls, page_result, page in paginated(
            ctx,
            operation="list_network_acls",
            fetch=client.list_network_acls,
            item_keys=("network_acls",),
            permission=self.required_permissions[0],
            base_parameters={"generation": 2},
        ):
            for acl in acls:
                ctx.checkpoint()
                acl_id = text(acl.get("id"))
                rules: list[dict[str, Any]] = []
                calls = provenance(self.id, "list_network_acls", ctx.scope.id, page, page_result)[
                    "calls"
                ]
                for rule_page, rule_result, rule_page_number in paginated(
                    ctx,
                    operation="list_network_acl_rules",
                    fetch=client.list_network_acl_rules,
                    item_keys=("rules",),
                    permission=self.required_permissions[1],
                    base_parameters={"network_acl_id": acl_id},
                ):
                    rules.extend(rule_page)
                    calls.extend(
                        provenance(
                            self.id,
                            "list_network_acl_rules",
                            ctx.scope.id,
                            rule_page_number,
                            rule_result,
                        )["calls"]
                    )
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type="ibm.vpc.network_acl",
                    native_id=text(acl.get("crn"), fallback=acl_id),
                    local_id=acl_id,
                    name=text(acl.get("name"), fallback=acl_id),
                    resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                    scope=ctx.scope,
                    tags={},
                    facts=_firewall_facts(rules, network_acl=True),
                    provenance={
                        "collector_id": self.id,
                        "collector_version": self.version,
                        "calls": calls,
                    },
                )
                for rule in rules:
                    rule_id = text(rule.get("id") or rule.get("name"))
                    yield RawObservation(
                        provider=CloudProvider.IBM,
                        provider_resource_type="ibm.vpc.network_acl_rule",
                        native_id=f"{acl_id}/rule/{rule_id}",
                        local_id=f"{acl_id}:{rule_id}",
                        name=rule_id,
                        resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULE,
                        scope=ctx.scope,
                        tags={},
                        facts=_firewall_facts([rule], network_acl=True),
                        provenance=provenance(
                            self.id, "list_network_acl_rules", ctx.scope.id, 1, {"rules": [rule]}
                        ),
                    )
