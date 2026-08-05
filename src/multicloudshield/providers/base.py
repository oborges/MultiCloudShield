from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from threading import Event
from time import monotonic
from typing import Any, Protocol

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor


@dataclass(frozen=True)
class ProviderCapabilities:
    provider: CloudProvider
    collectors: tuple[str, ...]
    domains: tuple[str, ...]
    unsupported: dict[str, str] = field(default_factory=dict)
    credential_mechanisms: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityGap:
    collector: str
    permission: str
    reason: str


@dataclass(frozen=True)
class CapabilityReport:
    status: str
    identity: str
    ok: tuple[str, ...]
    denied: tuple[CapabilityGap, ...] = ()
    disabled: tuple[CapabilityGap, ...] = ()


@dataclass(frozen=True)
class ScanScope:
    kind: str
    id: str
    partition: str = "public"


@dataclass(frozen=True)
class RawObservation:
    provider: CloudProvider
    provider_resource_type: str
    native_id: str
    local_id: str
    name: str
    resource_type: NormalizedResourceType
    scope: ScanScope
    tags: dict[str, str]
    facts: dict[str, Any]
    provenance: dict[str, Any]
    is_demo: bool = False


class ProviderError(RuntimeError):
    def __init__(
        self,
        category: ScanErrorCategory,
        message: str,
        *,
        operation: str = "",
        code: str | None = None,
        permission: str | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.operation = operation
        self.code = code
        self.permission = permission
        self.retryable = retryable


class CancellationToken:
    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def checkpoint(self) -> None:
        if self.cancelled:
            raise ProviderError(ScanErrorCategory.INTERNAL, "scan cancelled", code="CANCELLED")


@dataclass
class PageBudget:
    max_pages: int
    max_items: int
    pages: int = 0
    items: int = 0

    def add_page(self, item_count: int) -> None:
        self.pages += 1
        self.items += item_count
        if self.pages > self.max_pages or self.items > self.max_items:
            raise ProviderError(
                ScanErrorCategory.API_ERROR,
                "collection budget exceeded",
                code="COLLECTION_LIMIT_EXCEEDED",
            )


@dataclass(frozen=True)
class CollectionContext:
    connection: ConnectionDescriptor
    scope: ScanScope
    cancel: CancellationToken
    budget: PageBudget
    deadline_at: float

    def checkpoint(self) -> None:
        self.cancel.checkpoint()
        if monotonic() > self.deadline_at:
            raise ProviderError(ScanErrorCategory.TIMEOUT, "target deadline exceeded")


class Collector(Protocol):
    id: str
    version: str
    produces: frozenset[NormalizedResourceType]
    scope_kind: str
    required_permissions: tuple[str, ...]
    optional_permissions: tuple[str, ...]

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]: ...


class ProviderAdapter(Protocol):
    provider: CloudProvider

    def describe_capabilities(self) -> ProviderCapabilities: ...

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]: ...

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport: ...

    def collectors(self) -> Iterable[Collector]: ...
