from __future__ import annotations

from pydantic import TypeAdapter

from multicloudshield.core.enums import NormalizedResourceType
from multicloudshield.facts import AssetFacts, TriState
from multicloudshield.providers.ibm.cos import CosBucketsCollector
from multicloudshield.providers.ibm.iam import IamIdentityCollector, IamPoliciesCollector
from multicloudshield.providers.ibm.network import NetworkAclsCollector, SecurityGroupsCollector

from .conftest import context

_FACTS = TypeAdapter(AssetFacts)


class CosClient:
    def list_buckets(self, **kwargs: object) -> dict[str, object]:
        return {"Buckets": [{"Name": "bucket-under-test"}]}

    def get_bucket_acl(self, **kwargs: object) -> dict[str, object]:
        return {
            "Grants": [
                {
                    "Grantee": {
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ]
        }

    def get_bucket_policy(self, **kwargs: object) -> dict[str, object]:
        return {"Policy": '{"Statement": []}'}

    def get_bucket_policy_status(self, **kwargs: object) -> dict[str, object]:
        return {"PolicyStatus": {"IsPublic": True}}


class VpcClient:
    def list_security_groups(self, **kwargs: object) -> dict[str, object]:
        return {"security_groups": [{"id": "sg-under-test", "name": "audit-sg"}]}

    def list_security_group_rules(self, **kwargs: object) -> dict[str, object]:
        return {
            "rules": [
                {
                    "id": "rule-under-test",
                    "direction": "inbound",
                    "remote": {"cidr_block": "0.0.0.0/0"},
                    "protocol": "tcp",
                    "port_min": 22,
                    "port_max": 22,
                }
            ]
        }

    def list_security_group_targets(self, **kwargs: object) -> dict[str, object]:
        return {"targets": [{"id": "target-under-test"}]}

    def list_network_acls(self, **kwargs: object) -> dict[str, object]:
        return {"network_acls": [{"id": "acl-under-test", "name": "audit-acl"}]}

    def list_network_acl_rules(self, **kwargs: object) -> dict[str, object]:
        return {
            "rules": [
                {
                    "id": "acl-rule-under-test",
                    "direction": "inbound",
                    "action": "allow",
                    "source": "::/0",
                    "protocol": "all",
                }
            ]
        }


class PolicyClient:
    def list_roles(self, **kwargs: object) -> dict[str, object]:
        return {
            "custom_roles": [],
            "service_roles": [{"id": "role-reader", "display_name": "Reader"}],
        }

    def list_policies(self, **kwargs: object) -> dict[str, object]:
        return {
            "policies": [
                {
                    "id": "policy-under-test",
                    "type": "access",
                    "subjects": [{"attributes": {"iam_id": "subject-under-test"}}],
                    "roles": [{"role_id": "role-reader"}],
                }
            ]
        }


class IdentityClient:
    def get_account_settings(self, **kwargs: object) -> dict[str, object]:
        return {"mfa": "enforced"}

    def get_mfa_status(self, **kwargs: object) -> dict[str, object]:
        return {"status": "enabled"}

    def list_api_keys(self, **kwargs: object) -> dict[str, object]:
        return {
            "apikeys": [
                {
                    "id": "key-under-test",
                    "iam_id": "iam-service-under-test",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        }

    def list_service_ids(self, **kwargs: object) -> dict[str, object]:
        return {"serviceids": [{"iam_id": "iam-service-under-test", "name": "scanner"}]}

    def get_mfa_report(self, **kwargs: object) -> dict[str, object]:
        return {"users": [{"iam_id": "iam-user-under-test", "name": "auditor", "mfa": "enabled"}]}


class Factory:
    def cos(self, conn: object, region: str) -> CosClient:
        return CosClient()

    def vpc(self, conn: object, region: str) -> VpcClient:
        return VpcClient()

    def policies(self, conn: object) -> PolicyClient:
        return PolicyClient()

    def identity(self, conn: object) -> IdentityClient:
        return IdentityClient()


def test_cos_public_access_is_normalized(ibm_connection: object) -> None:
    collector = CosBucketsCollector(Factory())  # type: ignore[arg-type]
    observations = list(
        collector.collect(context(ibm_connection, kind="region", scope_id="us-south"))  # type: ignore[arg-type]
    )

    assert len(observations) == 1
    assert observations[0].facts["public_read_access"] is TriState.YES
    assert observations[0].facts["access_logging_enabled"] is TriState.UNKNOWN
    _FACTS.validate_python(observations[0].facts)


def test_security_group_and_rule_are_normalized(ibm_connection: object) -> None:
    collector = SecurityGroupsCollector(Factory())  # type: ignore[arg-type]
    observations = list(
        collector.collect(context(ibm_connection, kind="region", scope_id="us-south"))  # type: ignore[arg-type]
    )

    assert {item.resource_type for item in observations} == {
        NormalizedResourceType.NETWORK_FIREWALL_RULESET,
        NormalizedResourceType.NETWORK_FIREWALL_RULE,
    }
    assert all(item.facts["unrestricted_admin_ingress"] is TriState.YES for item in observations)
    for observation in observations:
        _FACTS.validate_python(observation.facts)


def test_network_acl_detects_world_all_ports(ibm_connection: object) -> None:
    collector = NetworkAclsCollector(Factory())  # type: ignore[arg-type]
    observations = list(
        collector.collect(context(ibm_connection, kind="region", scope_id="us-south"))  # type: ignore[arg-type]
    )

    assert all(item.facts["unrestricted_all_ports"] is TriState.YES for item in observations)


def test_iam_policy_and_identity_outputs_validate(ibm_connection: object) -> None:
    policy = list(IamPoliciesCollector(Factory()).collect(context(ibm_connection)))  # type: ignore[arg-type]
    identity = list(IamIdentityCollector(Factory()).collect(context(ibm_connection)))  # type: ignore[arg-type]

    assert policy[0].resource_type is NormalizedResourceType.IDENTITY_POLICY_BINDING
    assert {item.resource_type for item in identity} == {
        NormalizedResourceType.ACCOUNT_SCOPE,
        NormalizedResourceType.IDENTITY_PRINCIPAL,
    }
    assert identity[0].facts["mfa_enforced"] is TriState.YES
    for observation in [*policy, *identity]:
        _FACTS.validate_python(observation.facts)
