from __future__ import annotations

import pytest

from multicloudshield.core.enums import ScanErrorCategory
from multicloudshield.providers.base import ProviderError
from multicloudshield.providers.ibm.common import paginated

from .conftest import context


def test_pagination_is_bounded_and_follows_tokens(ibm_connection: object) -> None:
    calls: list[dict[str, object]] = []

    def fetch(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        if "start" not in kwargs:
            return {"items": [{"id": "first"}], "next": {"start": "page-two"}}
        return {"items": [{"id": "second"}]}

    ctx = context(ibm_connection)  # type: ignore[arg-type]
    pages = list(
        paginated(
            ctx,
            operation="list_items",
            fetch=fetch,
            item_keys=("items",),
            permission="service.item.read",
        )
    )

    assert [[item["id"] for item in page[0]] for page in pages] == [["first"], ["second"]]
    assert calls[1]["start"] == "page-two"
    assert ctx.budget.pages == 2
    assert ctx.budget.items == 2


def test_pagination_extracts_cursor_from_next_href(ibm_connection: object) -> None:
    calls: list[dict[str, object]] = []

    def fetch(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        if len(calls) == 1:
            return {
                "items": [],
                "next": {
                    "href": "https://api.global-search-tagging.cloud.ibm.com/v3/resources?start=next-page"
                },
            }
        return {"items": []}

    list(
        paginated(
            context(ibm_connection),  # type: ignore[arg-type]
            operation="list_items",
            fetch=fetch,
            item_keys=("items",),
            permission="service.item.read",
        )
    )

    assert calls[1]["start"] == "next-page"


def test_pagination_observes_cancellation_between_pages(ibm_connection: object) -> None:
    ctx = context(ibm_connection)  # type: ignore[arg-type]

    def fetch(**kwargs: object) -> dict[str, object]:
        ctx.cancel.cancel()
        return {"items": [], "next": {"start": "another"}}

    iterator = paginated(
        ctx,
        operation="list_items",
        fetch=fetch,
        item_keys=("items",),
        permission="service.item.read",
    )
    next(iterator)
    with pytest.raises(ProviderError) as raised:
        next(iterator)
    assert raised.value.code == "CANCELLED"


def test_pagination_enforces_page_budget(ibm_connection: object) -> None:
    ctx = context(ibm_connection, max_pages=1)  # type: ignore[arg-type]

    def fetch(**kwargs: object) -> dict[str, object]:
        return {"items": [], "next": {"start": "same" if kwargs.get("start") else "second"}}

    iterator = paginated(
        ctx,
        operation="list_items",
        fetch=fetch,
        item_keys=("items",),
        permission="service.item.read",
    )
    next(iterator)
    with pytest.raises(ProviderError) as raised:
        next(iterator)
    assert raised.value.category is ScanErrorCategory.API_ERROR
    assert raised.value.code == "COLLECTION_LIMIT_EXCEEDED"
