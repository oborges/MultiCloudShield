from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType
from multicloudshield.facts import TriState
from multicloudshield.providers.base import CollectionContext, RawObservation
from multicloudshield.providers.ibm.clients import IbmClientFactory
from multicloudshield.providers.ibm.common import (
    client_call,
    paginated,
    provenance,
    string_tags,
    text,
)


@dataclass(frozen=True)
class InventoryCollector:
    factory: IbmClientFactory
    id: str = "ibm.inventory.resources"
    version: str = "1.0.0"
    scope_kind: str = "global"
    required_permissions: tuple[str, ...] = (
        "global-search.tagging.search",
        "resource-controller.resource-instance.read",
    )
    optional_permissions: tuple[str, ...] = ()
    produces: frozenset[NormalizedResourceType] = frozenset((NormalizedResourceType.ACCOUNT_SCOPE,))

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        search = client_call("create_global_search_client", self.factory.inventory, ctx.connection)
        operation = "search"
        for items, page_result, page in paginated(
            ctx,
            operation=operation,
            fetch=search.search,
            item_keys=("items",),
            permission=self.required_permissions[0],
            cursor_parameter="search_cursor",
            base_parameters={"query": f"account_id:{ctx.connection.scope_id}", "fields": "*"},
        ):
            for item in items:
                ctx.checkpoint()
                native_id = text(item.get("crn") or item.get("id"))
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type=text(item.get("type"), fallback="ibm.resource"),
                    native_id=native_id,
                    local_id=native_id,
                    name=text(item.get("name"), fallback=native_id),
                    resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
                    scope=ctx.scope,
                    tags=string_tags(item.get("tags")),
                    facts={
                        "kind": "account",
                        "audit_logging_enabled": TriState.UNKNOWN,
                        "mfa_enforced": TriState.UNKNOWN,
                        "provider_specific": {
                            "ibm": {
                                "service": text(item.get("service_name"), fallback="unknown"),
                                "region": text(item.get("region"), fallback="global"),
                            }
                        },
                    },
                    provenance=provenance(self.id, operation, ctx.scope.id, page, page_result),
                )

        controller_factory = getattr(self.factory, "resource_controller", None)
        if not callable(controller_factory):
            return
        controller = client_call(
            "create_resource_controller_client", controller_factory, ctx.connection
        )
        operation = "list_resource_instances"
        for items, page_result, page in paginated(
            ctx,
            operation=operation,
            fetch=controller.list_resource_instances,
            item_keys=("resources",),
            permission=self.required_permissions[1],
        ):
            for item in items:
                ctx.checkpoint()
                native_id = text(item.get("crn") or item.get("guid"))
                yield RawObservation(
                    provider=CloudProvider.IBM,
                    provider_resource_type="ibm.resource_instance",
                    native_id=native_id,
                    local_id=native_id,
                    name=text(item.get("name"), fallback=native_id),
                    resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
                    scope=ctx.scope,
                    tags=string_tags(item.get("tags")),
                    facts={
                        "kind": "account",
                        "audit_logging_enabled": TriState.UNKNOWN,
                        "mfa_enforced": TriState.UNKNOWN,
                        "provider_specific": {
                            "ibm": {
                                "resource_instance": True,
                                "state": text(item.get("state"), fallback="unknown"),
                            }
                        },
                    },
                    provenance=provenance(self.id, operation, ctx.scope.id, page, page_result),
                )
