from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class FactView(Generic[T]):
    """Read-only fact proxy which records evidence access."""

    __slots__ = ("_facts", "_observed")

    def __init__(self, facts: T) -> None:
        object.__setattr__(self, "_facts", facts)
        object.__setattr__(self, "_observed", {})

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        value = getattr(self._facts, name)
        serial = value.value if hasattr(value, "value") else value
        if isinstance(serial, BaseModel):
            serial = serial.model_dump(mode="json")
        self._observed[name] = serial
        return value

    @property
    def observed(self) -> dict[str, Any]:
        return dict(self._observed)
