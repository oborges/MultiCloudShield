from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


class ForbiddenOperationError(RuntimeError):
    pass


MUTATING_PREFIXES = (
    "create_",
    "put_",
    "update_",
    "delete_",
    "set_",
    "attach_",
    "modify_",
    "begin_",
    "generate_",
    "export_",
)


class ReadOnlyClient:
    """Checks a reviewed operation allowlist before forwarding to an SDK client."""

    def __init__(self, client: object, operations: frozenset[str]) -> None:
        self._client = client
        self._operations = operations

    def __getattr__(self, operation: str) -> Callable[..., Any]:
        if operation not in self._operations:
            raise ForbiddenOperationError(f"operation is not allowlisted: {operation}")
        method = getattr(self._client, operation)
        if not callable(method):
            raise ForbiddenOperationError(f"allowlisted SDK attribute is not callable: {operation}")
        return cast(Callable[..., Any], method)


def assert_read_only_allowlist(operations: frozenset[str]) -> None:
    prohibited = [
        op for op in operations if op.startswith(MUTATING_PREFIXES) or op.endswith("_action")
    ]
    if prohibited:
        raise ForbiddenOperationError("mutating operation in allowlist: " + ", ".join(prohibited))
