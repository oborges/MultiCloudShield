from __future__ import annotations

from functools import lru_cache
from typing import cast

from multicloudshield.core.enums import CloudProvider
from multicloudshield.providers.base import ProviderAdapter


@lru_cache(maxsize=1)
def _registry() -> dict[CloudProvider, ProviderAdapter]:
    from multicloudshield.providers.aws.adapter import AwsAdapter
    from multicloudshield.providers.azure.adapter import AzureAdapter
    from multicloudshield.providers.demo.adapter import DemoAdapter
    from multicloudshield.providers.gcp.adapter import GcpAdapter
    from multicloudshield.providers.ibm.adapter import IbmAdapter

    adapters: list[ProviderAdapter] = [
        cast(ProviderAdapter, DemoAdapter()),
        cast(ProviderAdapter, AwsAdapter()),
        cast(ProviderAdapter, AzureAdapter()),
        cast(ProviderAdapter, GcpAdapter()),
        cast(ProviderAdapter, IbmAdapter()),
    ]
    return {adapter.provider: adapter for adapter in adapters}


def get_adapter(provider: CloudProvider) -> ProviderAdapter:
    return _registry()[provider]


def list_adapters() -> tuple[ProviderAdapter, ...]:
    return tuple(_registry().values())
