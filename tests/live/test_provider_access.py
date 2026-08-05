import os
from uuid import uuid4

import pytest

from multicloudshield.core.enums import CloudProvider, CredentialMechanism
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.providers import get_adapter


@pytest.mark.live
def test_explicit_live_provider_access() -> None:
    if os.getenv("MCS_RUN_LIVE_TESTS") != "1":
        pytest.skip("set MCS_RUN_LIVE_TESTS=1 with a dedicated read-only test account")
    provider_name = os.environ["MCS_LIVE_PROVIDER"]
    scope_id = os.environ["MCS_LIVE_SCOPE_ID"]
    provider = CloudProvider(provider_name)
    mechanism = {
        CloudProvider.AWS: CredentialMechanism.AWS_DEFAULT_CHAIN,
        CloudProvider.AZURE: CredentialMechanism.AZURE_DEFAULT_CREDENTIAL,
        CloudProvider.GCP: CredentialMechanism.GCP_ADC,
        CloudProvider.IBM: CredentialMechanism.IBM_TRUSTED_PROFILE,
    }[provider]
    connection = ConnectionDescriptor(
        id=uuid4(),
        organization_id=uuid4(),
        name="explicit-live-test",
        provider=provider,
        scope_id=scope_id,
        credential_mechanism=mechanism,
        region_allowlist=[
            item for item in os.getenv("MCS_LIVE_REGION_ALLOWLIST", "").split(",") if item
        ],
    )
    report = get_adapter(provider).verify_access(connection)
    assert report.status in {"ok", "degraded"}
    assert report.identity
