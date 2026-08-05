import pytest

from multicloudshield.providers.allowlist import ForbiddenOperationError, assert_read_only_allowlist
from multicloudshield.providers.registry import list_adapters


def test_every_adapter_declares_capabilities_and_collectors() -> None:
    for adapter in list_adapters():
        capabilities = adapter.describe_capabilities()
        assert capabilities.provider == adapter.provider
        assert capabilities.collectors
        for collector in adapter.collectors():
            assert collector.id in capabilities.collectors
            assert collector.produces
            assert collector.required_permissions


def test_mutating_operations_cannot_enter_an_allowlist() -> None:
    with pytest.raises(ForbiddenOperationError):
        assert_read_only_allowlist(frozenset({"list_buckets", "delete_bucket"}))
