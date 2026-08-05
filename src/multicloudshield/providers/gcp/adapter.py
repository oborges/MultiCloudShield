from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from hashlib import sha256
from importlib import import_module
from json import dumps
from time import monotonic
from typing import Any, cast

from multicloudshield.core.enums import CloudProvider, NormalizedResourceType, ScanErrorCategory
from multicloudshield.core.models import ConnectionDescriptor
from multicloudshield.core.security import sanitize_text
from multicloudshield.facts import EncryptionPosture, TriState
from multicloudshield.providers.allowlist import ReadOnlyClient, assert_read_only_allowlist
from multicloudshield.providers.base import (
    CancellationToken,
    CapabilityGap,
    CapabilityReport,
    CollectionContext,
    PageBudget,
    ProviderCapabilities,
    ProviderError,
    RawObservation,
    ScanScope,
)

ClientFactory = Callable[[str, ConnectionDescriptor], object]
IdentityLoader = Callable[[ConnectionDescriptor], str]

GCP_READ_OPERATIONS: dict[str, frozenset[str]] = {
    "asset": frozenset({"search_all_resources"}),
    "storage": frozenset({"list_buckets"}),
    "storage_bucket": frozenset({"reload", "get_iam_policy"}),
    "compute": frozenset({"list"}),
    "resource_manager": frozenset({"get_iam_policy"}),
    "kms_key_rings": frozenset({"list_key_rings"}),
    "kms_crypto_keys": frozenset({"list_crypto_keys"}),
}

for _operations in GCP_READ_OPERATIONS.values():
    assert_read_only_allowlist(_operations)


def _get(value: object, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _as_list(value: object | None) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        return []
    try:
        return list(cast(Iterable[Any], value))
    except TypeError:
        return []


def _page_items(page: object, attribute: str) -> list[Any]:
    explicit = _get(page, attribute)
    if explicit is not None:
        return _as_list(explicit)
    return _as_list(page)


def _iter_pages(response: object, attribute: str) -> Iterator[list[Any]]:
    pages = _get(response, "pages")
    if pages is not None:
        for page in pages:
            yield _page_items(page, attribute)
        return
    yield _page_items(response, attribute)


def _project_id(scope_id: str) -> str:
    return scope_id.removeprefix("projects/").strip("/")


def _digest(value: object) -> str:
    encoded = dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    return f"sha256:{sha256(encoded).hexdigest()}"


def _provenance(
    collector: str,
    calls: list[tuple[str, str, dict[str, Any], object]],
) -> dict[str, Any]:
    return {
        "collector_id": collector,
        "collector_version": "1.0.0",
        "calls": [
            {
                "service": service,
                "operation": operation,
                "request": request,
                "response_digest": _digest(response_identity),
                "http_status": 200,
            }
            for service, operation, request, response_identity in calls
        ],
    }


def _exception_code(exc: Exception) -> tuple[str, int | None]:
    raw_code: object | None = getattr(exc, "code", None)
    if callable(raw_code):
        try:
            raw_code = raw_code()
        except TypeError:
            raw_code = None
    code = str(getattr(raw_code, "name", raw_code or exc.__class__.__name__))
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if status is None and isinstance(raw_code, int):
        status = raw_code
    return code, status


def _provider_error(exc: Exception, operation: str, permission: str) -> ProviderError:
    code, status = _exception_code(exc)
    message = sanitize_text(str(exc), max_length=1000)
    searchable = f"{code} {message}".lower()
    disabled_markers = (
        "service_disabled",
        "servicedisabled",
        "accessnotconfigured",
        "access not configured",
        "api has not been used",
        "has not been used in project",
        "service is disabled",
        "serviceusage.services.use",
    )
    if any(marker in searchable for marker in disabled_markers):
        category = ScanErrorCategory.SERVICE_DISABLED
    elif status in (401,) or any(
        marker in searchable
        for marker in ("defaultcredentialserror", "refresherror", "unauthenticated")
    ):
        category = ScanErrorCategory.AUTHENTICATION
    elif status in (403,) or any(
        marker in searchable for marker in ("permissiondenied", "permission denied", "forbidden")
    ):
        category = ScanErrorCategory.PERMISSION_DENIED
    elif status in (429,) or any(
        marker in searchable for marker in ("resource_exhausted", "too many requests", "ratelimit")
    ):
        category = ScanErrorCategory.THROTTLED
    elif status in (404,) or "notfound" in searchable or "not found" in searchable:
        category = ScanErrorCategory.NOT_FOUND
    elif status in (408, 504) or "deadlineexceeded" in searchable or "timeout" in searchable:
        category = ScanErrorCategory.TIMEOUT
    else:
        category = ScanErrorCategory.API_ERROR
    return ProviderError(
        category,
        message or "GCP API request failed",
        operation=operation,
        code=code,
        permission=permission,
        retryable=category in (ScanErrorCategory.THROTTLED, ScanErrorCategory.TIMEOUT),
    )


def _invoke(
    operation: str,
    permission: str,
    method: Callable[..., Any],
    *args: object,
    **kwargs: object,
) -> Any:
    try:
        return method(*args, **kwargs)
    except ProviderError:
        raise
    except Exception as exc:
        raise _provider_error(exc, operation, permission) from exc


def _default_credentials() -> tuple[object, str | None]:
    try:
        google_auth = import_module("google.auth")
    except ImportError as exc:  # pragma: no cover - exercised without the optional extra
        raise ProviderError(
            ScanErrorCategory.AUTHENTICATION,
            "GCP dependencies are not installed; install the gcp optional dependency",
            operation="google.auth.default",
            code="SDK_NOT_INSTALLED",
        ) from exc
    try:
        credentials, adc_project = cast(
            tuple[object, str | None],
            google_auth.default(
                scopes=("https://www.googleapis.com/auth/cloud-platform.read-only",)
            ),
        )
    except Exception as exc:
        raise _provider_error(
            exc, "google.auth.default", "application-default-credentials"
        ) from exc
    return credentials, adc_project


def _default_identity(conn: ConnectionDescriptor) -> str:
    credentials, _ = _default_credentials()
    principal = getattr(credentials, "service_account_email", None) or getattr(
        credentials, "signer_email", None
    )
    credential_type = f"{credentials.__class__.__module__}.{credentials.__class__.__name__}"
    return str(principal or f"adc:{credential_type}")


def _default_client_factory(service: str, conn: ConnectionDescriptor) -> object:
    credentials, _ = _default_credentials()
    try:
        if service == "asset":
            module = import_module("google.cloud.asset_v1")
            client = module.AssetServiceClient(credentials=credentials)
        elif service == "storage":
            module = import_module("google.cloud.storage")
            client = module.Client(project=_project_id(conn.scope_id), credentials=credentials)
        elif service == "compute":
            module = import_module("google.cloud.compute_v1")
            client = module.FirewallsClient(credentials=credentials)
        elif service == "resource_manager":
            module = import_module("google.cloud.resourcemanager_v3")
            client = module.ProjectsClient(credentials=credentials)
        elif service == "kms_key_rings":
            module = import_module("google.cloud.kms_v1")
            client = module.KeyManagementServiceClient(credentials=credentials)
        elif service == "kms_crypto_keys":
            module = import_module("google.cloud.kms_v1")
            client = module.KeyManagementServiceClient(credentials=credentials)
        else:  # pragma: no cover - internal invariant
            raise ValueError(f"unknown GCP client service: {service}")
    except ImportError as exc:
        raise ProviderError(
            ScanErrorCategory.API_ERROR,
            "GCP dependencies are not installed; install the gcp optional dependency",
            operation=f"load:{service}",
            code="SDK_NOT_INSTALLED",
        ) from exc
    return ReadOnlyClient(client, GCP_READ_OPERATIONS[service])


@dataclass(frozen=True)
class _CollectorBase:
    client_factory: ClientFactory
    id: str
    produces: frozenset[NormalizedResourceType]
    required_permissions: tuple[str, ...]
    optional_permissions: tuple[str, ...] = ()
    version: str = "1.0.0"
    scope_kind: str = "project"

    def _client(self, ctx: CollectionContext, service: str) -> object:
        return self.client_factory(service, ctx.connection)

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        raise NotImplementedError


class InventoryAssetsCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        operation = "SearchAllResources"
        permission = self.required_permissions[0]
        project = _project_id(ctx.scope.id)
        request = {"scope": f"projects/{project}", "page_size": 500}
        try:
            ctx.checkpoint()
            client = self._client(ctx, "asset")
            response = client.search_all_resources(request=request)  # type: ignore[attr-defined]
            for page_number, items in enumerate(_iter_pages(response, "results"), 1):
                ctx.checkpoint()
                ctx.budget.add_page(len(items))
                for item in items:
                    name = str(_get(item, "name", ""))
                    display_name = str(_get(item, "display_name", "") or name)
                    asset_type = str(_get(item, "asset_type", "unknown"))
                    yield RawObservation(
                        provider=CloudProvider.GCP,
                        provider_resource_type=asset_type,
                        native_id=name,
                        local_id=name or f"asset-page-{page_number}",
                        name=display_name,
                        resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
                        scope=ctx.scope,
                        tags=dict(_get(item, "labels", {}) or {}),
                        facts={
                            "kind": "account",
                            "audit_logging_enabled": TriState.UNKNOWN,
                            "mfa_enforced": TriState.UNKNOWN,
                            "provider_specific": {
                                "gcp": {
                                    "asset_type": asset_type,
                                    "location": str(_get(item, "location", "")),
                                }
                            },
                        },
                        provenance=_provenance(
                            self.id,
                            [
                                (
                                    "cloudasset",
                                    operation,
                                    request,
                                    {"page": page_number, "name": name},
                                )
                            ],
                        ),
                    )
        except ProviderError:
            raise
        except Exception as exc:
            raise _provider_error(exc, operation, permission) from exc


_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
_PUBLIC_READ_ROLES = frozenset(
    {
        "roles/storage.objectViewer",
        "roles/storage.legacyBucketReader",
        "roles/storage.legacyObjectReader",
    }
)
_PUBLIC_WRITE_ROLES = frozenset(
    {"roles/storage.objectAdmin", "roles/storage.objectCreator", "roles/storage.legacyBucketOwner"}
)


def _public_access(policy: object) -> tuple[TriState, TriState]:
    read = False
    write = False
    raw_bindings = _get(policy, "bindings", None)
    if raw_bindings is None and isinstance(policy, Mapping):
        raw_bindings = policy
    if isinstance(raw_bindings, Mapping):
        bindings = [
            {"role": str(role), "members": members} for role, members in raw_bindings.items()
        ]
    else:
        bindings = _as_list(raw_bindings)
    for binding in bindings:
        members = {str(member) for member in _as_list(_get(binding, "members", []))}
        if not members.intersection(_PUBLIC_MEMBERS):
            continue
        role = str(_get(binding, "role", ""))
        read = read or role in _PUBLIC_READ_ROLES or role in _PUBLIC_WRITE_ROLES
        write = write or role in _PUBLIC_WRITE_ROLES
    return (TriState.YES if read else TriState.NO, TriState.YES if write else TriState.NO)


class StorageBucketsCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        project = _project_id(ctx.scope.id)
        operation = "ListBuckets"
        permission = self.required_permissions[0]
        request = {"project": project, "page_size": 100}
        try:
            ctx.checkpoint()
            client = self._client(ctx, "storage")
            response = _invoke(
                operation,
                self.required_permissions[0],
                client.list_buckets,  # type: ignore[attr-defined]
                **request,
            )
            for page_number, buckets in enumerate(_iter_pages(response, "buckets"), 1):
                ctx.checkpoint()
                ctx.budget.add_page(len(buckets))
                for raw_bucket in buckets:
                    ctx.checkpoint()
                    bucket = ReadOnlyClient(raw_bucket, GCP_READ_OPERATIONS["storage_bucket"])
                    _invoke("GetBucket", self.required_permissions[1], bucket.reload)
                    policy = _invoke(
                        "GetBucketIamPolicy",
                        self.required_permissions[2],
                        bucket.get_iam_policy,
                        requested_policy_version=3,
                    )
                    bucket_name = str(_get(raw_bucket, "name", ""))
                    iam_config = _get(raw_bucket, "iam_configuration", {}) or {}
                    pap = str(_get(iam_config, "public_access_prevention", "inherited")).lower()
                    uniform = _get(iam_config, "uniform_bucket_level_access", {}) or {}
                    uniform_enabled = _get(iam_config, "uniform_bucket_level_access_enabled", None)
                    if uniform_enabled is None:
                        uniform_enabled = _get(uniform, "enabled", None)
                    public_read, public_write = _public_access(policy)
                    if pap.endswith("enforced"):
                        public_read = TriState.NO
                        public_write = TriState.NO
                    versioning = _get(raw_bucket, "versioning_enabled", None)
                    default_key = _get(raw_bucket, "default_kms_key_name", None)
                    logging = _get(raw_bucket, "logging", None)
                    facts = {
                        "kind": "object_storage",
                        "public_read_access": public_read,
                        "public_write_access": public_write,
                        "encryption_at_rest": (
                            EncryptionPosture.CUSTOMER_MANAGED
                            if default_key
                            else EncryptionPosture.PROVIDER_MANAGED
                        ),
                        "versioning_enabled": (
                            TriState.UNKNOWN
                            if versioning is None
                            else (TriState.YES if versioning else TriState.NO)
                        ),
                        "access_logging_enabled": TriState.YES if logging else TriState.NO,
                        "tls_required": TriState.UNKNOWN,
                        "provider_specific": {
                            "gcp": {
                                "uniform_bucket_level_access": (
                                    TriState.UNKNOWN.value
                                    if uniform_enabled is None
                                    else (
                                        TriState.YES.value if uniform_enabled else TriState.NO.value
                                    )
                                ),
                                "public_access_prevention": (
                                    TriState.YES.value
                                    if pap.endswith("enforced")
                                    else TriState.NO.value
                                ),
                            }
                        },
                    }
                    calls: list[tuple[str, str, dict[str, Any], object]] = [
                        ("storage", operation, request, {"page": page_number}),
                        ("storage", "GetBucket", {"bucket": bucket_name}, bucket_name),
                        ("storage", "GetBucketIamPolicy", {"bucket": bucket_name}, bucket_name),
                    ]
                    yield RawObservation(
                        provider=CloudProvider.GCP,
                        provider_resource_type="storage.googleapis.com/Bucket",
                        native_id=f"//storage.googleapis.com/{bucket_name}",
                        local_id=bucket_name,
                        name=bucket_name,
                        resource_type=NormalizedResourceType.OBJECT_STORAGE_BUCKET,
                        scope=ctx.scope,
                        tags=dict(_get(raw_bucket, "labels", {}) or {}),
                        facts=facts,
                        provenance=_provenance(self.id, calls),
                    )
        except ProviderError:
            raise
        except Exception as exc:
            raise _provider_error(exc, operation, permission) from exc


_ADMIN_PORTS = frozenset({22, 3389})
_DATASTORE_PORTS = frozenset({1433, 1521, 27017, 3306, 5432, 6379, 9200})


def _port_range_contains(port_range: str, ports: frozenset[int]) -> bool:
    if not port_range:
        return True
    start_text, separator, end_text = port_range.partition("-")
    try:
        start = int(start_text)
        end = int(end_text) if separator else start
    except ValueError:
        return False
    return any(start <= port <= end for port in ports)


def _allowed_exposure(rule: object) -> tuple[bool, bool, bool]:
    direction = str(_get(rule, "direction", "INGRESS")).upper()
    sources = set(str(item) for item in _as_list(_get(rule, "source_ranges", [])))
    if direction != "INGRESS" or not sources.intersection({"0.0.0.0/0", "::/0"}):
        return False, False, False
    admin = False
    all_ports = False
    datastore = False
    for allowed in _as_list(_get(rule, "allowed", [])):
        protocol = str(_get(allowed, "I_p_protocol", _get(allowed, "ip_protocol", ""))).lower()
        ports = [str(item) for item in _as_list(_get(allowed, "ports", []))]
        if protocol == "all" or not protocol:
            return True, True, True
        if protocol not in ("tcp", "udp"):
            continue
        if not ports:
            all_ports = True
            admin = admin or protocol == "tcp"
            datastore = datastore or protocol == "tcp"
        for port_range in ports:
            admin = admin or (protocol == "tcp" and _port_range_contains(port_range, _ADMIN_PORTS))
            datastore = datastore or (
                protocol == "tcp" and _port_range_contains(port_range, _DATASTORE_PORTS)
            )
    return admin, all_ports, datastore


class ComputeFirewallsCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        project = _project_id(ctx.scope.id)
        operation = "ListFirewalls"
        permission = self.required_permissions[0]
        request = {"project": project, "max_results": 500}
        offending: list[str] = []
        aggregate_admin = False
        aggregate_all = False
        aggregate_datastore = False
        try:
            ctx.checkpoint()
            client = self._client(ctx, "compute")
            response = client.list(request=request)  # type: ignore[attr-defined]
            for page_number, rules in enumerate(_iter_pages(response, "items"), 1):
                ctx.checkpoint()
                ctx.budget.add_page(len(rules))
                for rule in rules:
                    name = str(_get(rule, "name", ""))
                    admin, all_ports, datastore = _allowed_exposure(rule)
                    aggregate_admin |= admin
                    aggregate_all |= all_ports
                    aggregate_datastore |= datastore
                    if admin or all_ports or datastore:
                        offending.append(name)
                    facts = {
                        "kind": "firewall",
                        "unrestricted_admin_ingress": TriState.YES if admin else TriState.NO,
                        "unrestricted_all_ports": TriState.YES if all_ports else TriState.NO,
                        "unrestricted_datastore_ingress": TriState.YES
                        if datastore
                        else TriState.NO,
                        "offending_rules": [name] if admin or all_ports or datastore else [],
                        "provider_specific": {
                            "gcp": {
                                "direction": str(_get(rule, "direction", "")),
                                "priority": _get(rule, "priority", None),
                                "network": str(_get(rule, "network", "")),
                            }
                        },
                    }
                    yield RawObservation(
                        provider=CloudProvider.GCP,
                        provider_resource_type="compute.googleapis.com/Firewall",
                        native_id=str(
                            _get(rule, "self_link", "")
                            or f"projects/{project}/global/firewalls/{name}"
                        ),
                        local_id=name,
                        name=name,
                        resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULE,
                        scope=ctx.scope,
                        tags={},
                        facts=facts,
                        provenance=_provenance(
                            self.id,
                            [("compute", operation, request, {"page": page_number, "name": name})],
                        ),
                    )
            yield RawObservation(
                provider=CloudProvider.GCP,
                provider_resource_type="compute.googleapis.com/FirewallCollection",
                native_id=f"//compute.googleapis.com/projects/{project}/global/firewalls",
                local_id=f"{project}-firewalls",
                name=f"{project} firewall rules",
                resource_type=NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "firewall",
                    "unrestricted_admin_ingress": TriState.YES if aggregate_admin else TriState.NO,
                    "unrestricted_all_ports": TriState.YES if aggregate_all else TriState.NO,
                    "unrestricted_datastore_ingress": (
                        TriState.YES if aggregate_datastore else TriState.NO
                    ),
                    "offending_rules": offending[:1000],
                    "provider_specific": {"gcp": {"project": project}},
                },
                provenance=_provenance(
                    self.id,
                    [("compute", operation, request, {"rules": len(offending)})],
                ),
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise _provider_error(exc, operation, permission) from exc


def _policy_bindings(policy: object) -> list[Any]:
    return _as_list(_get(policy, "bindings", []))


class ProjectIamPolicyCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        project = _project_id(ctx.scope.id)
        operation = "GetIamPolicy"
        permission = self.required_permissions[0]
        request = {"resource": f"projects/{project}"}
        try:
            ctx.checkpoint()
            client = self._client(ctx, "resource_manager")
            policy = client.get_iam_policy(request=request)  # type: ignore[attr-defined]
            bindings = _policy_bindings(policy)
            ctx.budget.add_page(len(bindings))
            yield RawObservation(
                provider=CloudProvider.GCP,
                provider_resource_type="cloudresourcemanager.googleapis.com/Project",
                native_id=f"//cloudresourcemanager.googleapis.com/projects/{project}",
                local_id=project,
                name=project,
                resource_type=NormalizedResourceType.ACCOUNT_SCOPE,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "account",
                    "audit_logging_enabled": TriState.UNKNOWN,
                    "mfa_enforced": TriState.UNKNOWN,
                    "provider_specific": {"gcp": {"iam_policy_read": True}},
                },
                provenance=_provenance(
                    self.id, [("resource-manager", operation, request, {"bindings": len(bindings)})]
                ),
            )
            for index, binding in enumerate(bindings):
                ctx.checkpoint()
                role = str(_get(binding, "role", ""))
                members = [str(member) for member in _as_list(_get(binding, "members", []))]
                local_id = f"{project}:{role}:{index}"
                yield RawObservation(
                    provider=CloudProvider.GCP,
                    provider_resource_type="iam.googleapis.com/PolicyBinding",
                    native_id=f"//cloudresourcemanager.googleapis.com/projects/{local_id}",
                    local_id=local_id,
                    name=role,
                    resource_type=NormalizedResourceType.IDENTITY_POLICY_BINDING,
                    scope=ctx.scope,
                    tags={},
                    facts={
                        "kind": "identity",
                        "interactive": TriState.UNKNOWN,
                        "mfa_enabled": TriState.UNKNOWN,
                        "long_lived_credential": TriState.UNKNOWN,
                        "credential_age_days": None,
                        "provider_specific": {
                            "gcp": {
                                "role": role,
                                "members": members[:1000],
                                "conditional": bool(_get(binding, "condition", None)),
                            }
                        },
                    },
                    provenance=_provenance(
                        self.id,
                        [("resource-manager", operation, request, {"role": role, "index": index})],
                    ),
                )
        except ProviderError:
            raise
        except Exception as exc:
            raise _provider_error(exc, operation, permission) from exc


class AuditConfigCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        project = _project_id(ctx.scope.id)
        operation = "GetIamPolicy"
        permission = self.required_permissions[0]
        request = {"resource": f"projects/{project}"}
        try:
            ctx.checkpoint()
            client = self._client(ctx, "resource_manager")
            policy = client.get_iam_policy(request=request)  # type: ignore[attr-defined]
            configs = _as_list(_get(policy, "audit_configs", _get(policy, "auditConfigs", [])))
            ctx.budget.add_page(len(configs))
            yield RawObservation(
                provider=CloudProvider.GCP,
                provider_resource_type="iam.googleapis.com/AuditConfig",
                native_id=f"//cloudresourcemanager.googleapis.com/projects/{project}/auditConfig",
                local_id=f"{project}-audit-config",
                name=f"{project} audit configuration",
                resource_type=NormalizedResourceType.LOGGING_AUDIT_TRAIL,
                scope=ctx.scope,
                tags={},
                facts={
                    "kind": "logging",
                    "audit_logging_enabled": TriState.UNKNOWN,
                    "destination_public": TriState.UNKNOWN,
                    "parent_scope_visibility": TriState.NO,
                    "provider_specific": {
                        "gcp": {
                            "project_audit_config_present": bool(configs),
                            "parent_scope_audit_config_visible": False,
                        }
                    },
                },
                provenance=_provenance(
                    self.id, [("resource-manager", operation, request, {"configs": len(configs)})]
                ),
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise _provider_error(exc, operation, permission) from exc


def _rotation_support(key: object) -> tuple[TriState, TriState]:
    purpose_value = _get(key, "purpose", "")
    purpose = str(getattr(purpose_value, "name", purpose_value)).upper()
    asymmetric = "ASYMMETRIC_SIGN" in purpose or "ASYMMETRIC_DECRYPT" in purpose
    if asymmetric:
        return TriState.NO, TriState.UNKNOWN
    rotation = _get(key, "rotation_period", None) or _get(key, "next_rotation_time", None)
    return TriState.YES, TriState.YES if rotation else TriState.NO


class KmsKeysCollector(_CollectorBase):
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]:
        project = _project_id(ctx.scope.id)
        ring_operation = "ListKeyRings"
        key_operation = "ListCryptoKeys"
        permission = self.required_permissions[0]
        ring_request = {"parent": f"projects/{project}/locations/-"}
        try:
            ctx.checkpoint()
            ring_client = self._client(ctx, "kms_key_rings")
            ring_response = ring_client.list_key_rings(request=ring_request)  # type: ignore[attr-defined]
            for ring_page, key_rings in enumerate(_iter_pages(ring_response, "key_rings"), 1):
                ctx.checkpoint()
                ctx.budget.add_page(len(key_rings))
                for key_ring in key_rings:
                    ring_name = str(_get(key_ring, "name", ""))
                    key_request = {"parent": ring_name}
                    key_client = self._client(ctx, "kms_crypto_keys")
                    key_response = key_client.list_crypto_keys(request=key_request)  # type: ignore[attr-defined]
                    for key_page, keys in enumerate(_iter_pages(key_response, "crypto_keys"), 1):
                        ctx.checkpoint()
                        ctx.budget.add_page(len(keys))
                        for key in keys:
                            key_name = str(_get(key, "name", ""))
                            supports_rotation, rotation_enabled = _rotation_support(key)
                            yield RawObservation(
                                provider=CloudProvider.GCP,
                                provider_resource_type="cloudkms.googleapis.com/CryptoKey",
                                native_id=f"//cloudkms.googleapis.com/{key_name}",
                                local_id=key_name,
                                name=key_name.rsplit("/", 1)[-1],
                                resource_type=NormalizedResourceType.KMS_KEY,
                                scope=ctx.scope,
                                tags=dict(_get(key, "labels", {}) or {}),
                                facts={
                                    "kind": "kms",
                                    "rotation_enabled": rotation_enabled,
                                    "supports_rotation": supports_rotation,
                                    "provider_specific": {
                                        "gcp": {"purpose": str(_get(key, "purpose", ""))}
                                    },
                                },
                                provenance=_provenance(
                                    self.id,
                                    [
                                        (
                                            "cloudkms",
                                            ring_operation,
                                            ring_request,
                                            {"page": ring_page},
                                        ),
                                        (
                                            "cloudkms",
                                            key_operation,
                                            key_request,
                                            {"page": key_page, "key": key_name},
                                        ),
                                    ],
                                ),
                            )
        except ProviderError:
            raise
        except Exception as exc:
            active_operation = key_operation if "key_request" in locals() else ring_operation
            active_permission = (
                self.required_permissions[-1] if "key_request" in locals() else permission
            )
            raise _provider_error(exc, active_operation, active_permission) from exc


class GcpAdapter:
    provider = CloudProvider.GCP

    def __init__(
        self,
        *,
        client_factory: ClientFactory | None = None,
        identity_loader: IdentityLoader | None = None,
    ) -> None:
        self._client_factory = client_factory or _default_client_factory
        if identity_loader is not None:
            self._identity_loader = identity_loader
        elif client_factory is None:
            self._identity_loader = _default_identity
        else:
            self._identity_loader = lambda conn: f"adc@projects/{_project_id(conn.scope_id)}"

    def describe_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider,
            collectors=tuple(collector.id for collector in self.collectors()),
            domains=("inventory", "object_storage", "network", "identity", "logging", "kms"),
            credential_mechanisms=("gcp_adc", "gcp_workload_identity", "gcp_impersonation"),
        )

    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]:
        project = _project_id(conn.scope_id)
        if not project or "/" in project:
            raise ProviderError(
                ScanErrorCategory.API_ERROR,
                "v0.1.0 GCP connections require exactly one project scope",
                code="INVALID_PROJECT_SCOPE",
            )
        return [ScanScope("project", project)]

    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport:
        collectors = self.collectors()
        try:
            identity = self._identity_loader(conn)
            scope = self.resolve_scopes(conn)[0]
        except ProviderError as exc:
            gaps = tuple(
                CapabilityGap(
                    collector.id,
                    collector.required_permissions[0],
                    f"{exc.category.value}: {exc}",
                )
                for collector in collectors
            )
            return CapabilityReport(status="failed", identity="unknown", ok=(), denied=gaps)
        except Exception as exc:
            error = _provider_error(exc, "google.auth.default", "application-default-credentials")
            gaps = tuple(
                CapabilityGap(
                    collector.id,
                    collector.required_permissions[0],
                    f"{error.category.value}: {error}",
                )
                for collector in collectors
            )
            return CapabilityReport(status="failed", identity="unknown", ok=(), denied=gaps)

        ok: list[str] = []
        denied: list[CapabilityGap] = []
        disabled: list[CapabilityGap] = []
        for collector in collectors:
            ctx = CollectionContext(
                connection=conn,
                scope=scope,
                cancel=CancellationToken(),
                budget=PageBudget(max_pages=25, max_items=10_000),
                deadline_at=monotonic() + 30,
            )
            iterator = collector.collect(ctx)
            try:
                next(iterator, None)
                ok.append(collector.id)
            except ProviderError as exc:
                gap = CapabilityGap(
                    collector.id,
                    exc.permission or collector.required_permissions[0],
                    f"{exc.category.value}: {exc}",
                )
                if exc.category is ScanErrorCategory.SERVICE_DISABLED:
                    disabled.append(gap)
                else:
                    denied.append(gap)
            finally:
                close = getattr(iterator, "close", None)
                if close is not None:
                    close()
        status = "ok" if not denied and not disabled else ("degraded" if ok else "failed")
        return CapabilityReport(
            status=status,
            identity=identity,
            ok=tuple(ok),
            denied=tuple(denied),
            disabled=tuple(disabled),
        )

    def collectors(self) -> tuple[_CollectorBase, ...]:
        make = self._client_factory
        return (
            InventoryAssetsCollector(
                make,
                "gcp.inventory.assets",
                frozenset({NormalizedResourceType.ACCOUNT_SCOPE}),
                ("cloudasset.assets.searchAllResources",),
            ),
            StorageBucketsCollector(
                make,
                "gcp.storage.buckets",
                frozenset({NormalizedResourceType.OBJECT_STORAGE_BUCKET}),
                ("storage.buckets.list", "storage.buckets.get", "storage.buckets.getIamPolicy"),
            ),
            ComputeFirewallsCollector(
                make,
                "gcp.compute.firewalls",
                frozenset(
                    {
                        NormalizedResourceType.NETWORK_FIREWALL_RULESET,
                        NormalizedResourceType.NETWORK_FIREWALL_RULE,
                    }
                ),
                ("compute.firewalls.list",),
            ),
            ProjectIamPolicyCollector(
                make,
                "gcp.iam.project_policy",
                frozenset(
                    {
                        NormalizedResourceType.IDENTITY_POLICY_BINDING,
                        NormalizedResourceType.ACCOUNT_SCOPE,
                    }
                ),
                ("resourcemanager.projects.getIamPolicy",),
            ),
            AuditConfigCollector(
                make,
                "gcp.logging.audit_config",
                frozenset({NormalizedResourceType.LOGGING_AUDIT_TRAIL}),
                ("resourcemanager.projects.getIamPolicy",),
            ),
            KmsKeysCollector(
                make,
                "gcp.kms.keys",
                frozenset({NormalizedResourceType.KMS_KEY}),
                ("cloudkms.keyRings.list", "cloudkms.cryptoKeys.list"),
            ),
        )
