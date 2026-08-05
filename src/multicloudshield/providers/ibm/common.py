from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qs, urlparse

from multicloudshield.core.enums import ScanErrorCategory
from multicloudshield.core.security import sanitize_text
from multicloudshield.providers.base import CollectionContext, ProviderError


def response_result(response: object) -> dict[str, Any]:
    """Return a plain SDK result without allowing an SDK response type to escape."""
    get_result = getattr(response, "get_result", None)
    result = get_result() if callable(get_result) else response
    if not isinstance(result, Mapping):
        raise ProviderError(
            ScanErrorCategory.PARSE_ERROR,
            "IBM Cloud returned an unexpected response shape",
            code="INVALID_RESPONSE",
        )
    return dict(result)


def error_code(exc: Exception) -> str:
    for attribute in ("code", "error_code", "status_code", "http_status_code"):
        value = getattr(exc, attribute, None)
        if value is not None:
            return sanitize_text(str(value), max_length=128)
    return type(exc).__name__


def classify_error(
    exc: Exception,
    *,
    operation: str,
    permission: str | None = None,
) -> ProviderError:
    if isinstance(exc, ProviderError):
        return exc
    code = error_code(exc)
    lowered = f"{code} {exc}".lower()
    status = getattr(exc, "status_code", getattr(exc, "http_status_code", None))
    if any(
        word in lowered
        for word in ("service_disabled", "service disabled", "service is not enabled")
    ):
        category = ScanErrorCategory.SERVICE_DISABLED
    elif status == 401 or any(
        word in lowered for word in ("unauthorized", "invalid token", "authentication")
    ):
        category = ScanErrorCategory.AUTHENTICATION
    elif status == 403 or any(
        word in lowered for word in ("forbidden", "permission", "access denied")
    ):
        category = ScanErrorCategory.PERMISSION_DENIED
    elif status == 404 or "not found" in lowered:
        category = ScanErrorCategory.NOT_FOUND
    elif status == 429 or any(
        word in lowered for word in ("too many requests", "rate limit", "throttl")
    ):
        category = ScanErrorCategory.THROTTLED
    elif status in (408, 504) or "timeout" in lowered or "timed out" in lowered:
        category = ScanErrorCategory.TIMEOUT
    else:
        category = ScanErrorCategory.API_ERROR
    retryable = category in {
        ScanErrorCategory.THROTTLED,
        ScanErrorCategory.TIMEOUT,
        ScanErrorCategory.API_ERROR,
    }
    # Provider messages may echo request material. Keep the adapter error intentionally generic.
    return ProviderError(
        category,
        f"IBM Cloud operation {operation} failed",
        operation=operation,
        code=code,
        permission=permission,
        retryable=retryable,
    )


def sdk_call(
    operation: str,
    call: Callable[..., object],
    /,
    *,
    permission: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        return response_result(call(**kwargs))
    except Exception as exc:
        raise classify_error(exc, operation=operation, permission=permission) from exc


def client_call(operation: str, call: Callable[..., Any], /, *args: Any) -> Any:
    try:
        return call(*args)
    except Exception as exc:
        raise classify_error(exc, operation=operation) from exc


def items_from(result: Mapping[str, Any], keys: Sequence[str]) -> list[dict[str, Any]]:
    value: Any = result
    for key in keys:
        if not isinstance(value, Mapping):
            return []
        value = value.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProviderError(
            ScanErrorCategory.PARSE_ERROR,
            "IBM Cloud collection page has an invalid item list",
            code="INVALID_ITEM_LIST",
        )
    if not all(isinstance(item, Mapping) for item in value):
        raise ProviderError(
            ScanErrorCategory.PARSE_ERROR,
            "IBM Cloud collection page contains an invalid item",
            code="INVALID_ITEM",
        )
    return [dict(item) for item in value]


def next_token(result: Mapping[str, Any]) -> str | None:
    next_page = result.get("next")
    if isinstance(next_page, Mapping):
        for key in ("start", "page_token", "pagetoken"):
            token = next_page.get(key)
            if token:
                return str(token)
        href = next_page.get("href")
        if href:
            query = parse_qs(urlparse(str(href)).query)
            for key in ("start", "page_token", "pagetoken", "search_cursor"):
                values = query.get(key)
                if values:
                    return values[0]
    for key in ("next_start", "next_page_token", "next_pagetoken"):
        token = result.get(key)
        if token:
            return str(token)
    return None


def paginated(
    ctx: CollectionContext,
    *,
    operation: str,
    fetch: Callable[..., object],
    item_keys: Sequence[str],
    permission: str,
    page_size: int = 100,
    page_size_parameter: str = "limit",
    cursor_parameter: str = "start",
    base_parameters: Mapping[str, Any] | None = None,
) -> Iterator[tuple[list[dict[str, Any]], dict[str, Any], int]]:
    token: str | None = None
    seen: set[str] = set()
    page_number = 0
    while True:
        ctx.checkpoint()
        parameters = dict(base_parameters or {})
        parameters[page_size_parameter] = min(max(page_size, 1), 100)
        if token is not None:
            parameters[cursor_parameter] = token
        result = sdk_call(operation, fetch, permission=permission, **parameters)
        items = items_from(result, item_keys)
        ctx.budget.add_page(len(items))
        page_number += 1
        yield items, result, page_number
        token = next_token(result)
        if token is None:
            return
        if token in seen:
            raise ProviderError(
                ScanErrorCategory.PARSE_ERROR,
                "IBM Cloud returned a repeated pagination token",
                operation=operation,
                code="REPEATED_PAGE_TOKEN",
            )
        seen.add(token)


def _bounded_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 8:
        return "<depth-limit>"
    if isinstance(value, Mapping):
        return {
            sanitize_text(str(key), max_length=128): _bounded_value(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_value(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return sanitize_text(value, max_length=2048)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_text(type(value).__name__, max_length=128)


def response_digest(result: Mapping[str, Any]) -> str:
    # Digests are provenance only. Bound attacker-controlled input before materializing text.
    payload = repr(_bounded_value(result)).encode("utf-8", errors="replace")
    return "sha256:" + sha256(payload).hexdigest()


def provenance(
    collector_id: str,
    operation: str,
    scope: str,
    page: int,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "collector_id": collector_id,
        "collector_version": "1.0.0",
        "calls": [
            {
                "service": "ibm-cloud",
                "operation": operation,
                "scope": scope,
                "request": {"page": page},
                "response_digest": response_digest(result),
            }
        ],
    }


def text(value: Any, *, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    return sanitize_text(str(value), max_length=2048)


def string_tags(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in list(value.items())[:200]}
    if isinstance(value, list):
        return {str(item): "" for item in value[:200] if isinstance(item, (str, int, float, bool))}
    return {}
