from __future__ import annotations

import sys
from types import SimpleNamespace

from multicloudshield.core.enums import CloudProvider
from multicloudshield.providers.ibm import clients
from multicloudshield.providers.ibm.adapter import IbmAdapter
from multicloudshield.providers.ibm.clients import VPC_API_VERSION, DefaultIbmClientFactory


class SuccessfulClient:
    def get_account_settings(self, **kwargs: object) -> dict[str, object]:
        return {"mfa": "enforced"}

    def search(self, **kwargs: object) -> dict[str, object]:
        return {"items": []}

    def list_buckets(self, **kwargs: object) -> dict[str, object]:
        return {"Buckets": []}

    def list_security_groups(self, **kwargs: object) -> dict[str, object]:
        return {"security_groups": []}

    def list_network_acls(self, **kwargs: object) -> dict[str, object]:
        return {"network_acls": []}

    def list_policies(self, **kwargs: object) -> dict[str, object]:
        return {"policies": []}

    def list_service_ids(self, **kwargs: object) -> dict[str, object]:
        return {"serviceids": []}


class SuccessfulFactory:
    client = SuccessfulClient()

    def inventory(self, conn: object) -> SuccessfulClient:
        return self.client

    def resource_controller(self, conn: object) -> SuccessfulClient:
        return self.client

    def cos(self, conn: object, region: str) -> SuccessfulClient:
        return self.client

    def vpc(self, conn: object, region: str) -> SuccessfulClient:
        return self.client

    def policies(self, conn: object) -> SuccessfulClient:
        return self.client

    def identity(self, conn: object) -> SuccessfulClient:
        return self.client


class FailedFactory(SuccessfulFactory):
    def identity(self, conn: object) -> SuccessfulClient:
        raise RuntimeError("401 response containing secret-looking provider text")


def test_capabilities_declare_supported_and_unsupported_domains() -> None:
    capabilities = IbmAdapter(factory=SuccessfulFactory()).describe_capabilities()  # type: ignore[arg-type]

    assert capabilities.provider is CloudProvider.IBM
    assert capabilities.domains == ("inventory", "object_storage", "network", "identity")
    assert set(capabilities.unsupported) == {"logging", "kms"}
    assert "ibm.cos.buckets" in capabilities.collectors


def test_scopes_are_bounded_by_region_allowlist(ibm_connection: object) -> None:
    scopes = IbmAdapter(factory=SuccessfulFactory()).resolve_scopes(ibm_connection)  # type: ignore[arg-type]

    assert [(scope.kind, scope.id) for scope in scopes] == [
        ("global", "account-under-test"),
        ("region", "us-south"),
    ]


def test_verify_access_probes_each_collector(ibm_connection: object) -> None:
    report = IbmAdapter(factory=SuccessfulFactory()).verify_access(ibm_connection)  # type: ignore[arg-type]

    assert report.status == "ok"
    assert len(report.ok) == 6
    assert report.denied == ()


def test_verify_access_never_leaks_provider_failure(ibm_connection: object) -> None:
    report = IbmAdapter(factory=FailedFactory()).verify_access(ibm_connection)  # type: ignore[arg-type]

    assert report.status == "failed"
    assert report.identity == "unknown"
    assert len(report.denied) == 6
    assert all("secret-looking" not in gap.reason for gap in report.denied)


def test_ibm_sdks_are_lazy_and_vpc_date_is_pinned() -> None:
    assert "ibm_boto3" not in sys.modules
    assert "ibm_vpc" not in sys.modules
    assert VPC_API_VERSION == "2026-08-05"


def test_default_factory_uses_native_auth_and_pinned_vpc_version(
    ibm_connection: object, monkeypatch: object
) -> None:
    captured: dict[str, object] = {}

    class Authenticator:
        def __init__(self, **kwargs: object) -> None:
            captured["authenticator"] = kwargs

    class Vpc:
        def __init__(self, **kwargs: object) -> None:
            captured["vpc"] = kwargs

        def set_service_url(self, url: str) -> None:
            captured["url"] = url

    def fake_import(name: str) -> object:
        if name == "ibm_cloud_sdk_core.authenticators":
            return SimpleNamespace(ContainerAuthenticator=Authenticator)
        if name == "ibm_vpc":
            return SimpleNamespace(VpcV1=Vpc)
        raise AssertionError(name)

    monkeypatch.setattr(clients, "import_module", fake_import)  # type: ignore[attr-defined]
    DefaultIbmClientFactory().vpc(ibm_connection, "us-south")  # type: ignore[arg-type]

    assert captured["authenticator"] == {
        "iam_profile_name": "audit-profile",
        "iam_profile_id": None,
    }
    assert captured["vpc"]["version"] == VPC_API_VERSION  # type: ignore[index]
    assert captured["url"] == "https://us-south.iaas.cloud.ibm.com/v1"
