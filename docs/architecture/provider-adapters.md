# Provider Adapters

Status: accepted for v0.1.0
Last updated: 2026-08-05

How MultiCloudShield talks to AWS, Azure, GCP, IBM Cloud, and the demo provider. The decision itself
is [ADR-0007](decisions/0007-provider-adapter-contract.md); this document is the contract, the
per-provider realities, and the rules a new adapter must satisfy.

**All version and API facts below were verified against official sources on 2026-08-05.** Sources are
listed in §9. Facts we could not verify are marked *(unverified — implementation must confirm)*.

---

## 1. The contract

```python
class ProviderAdapter(Protocol):
    provider: CloudProvider

    def describe_capabilities(self) -> ProviderCapabilities: ...
    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]: ...
    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport: ...
    def collectors(self) -> list[Collector]: ...


class Collector(Protocol):
    id: str                                  # "aws.s3.buckets" — stable, namespaced
    version: str                             # semver; bumped when output shape changes
    produces: frozenset[NormalizedResourceType]
    scope_kind: ScopeKind                    # global | region | location | subscription | project
    required_permissions: tuple[str, ...]    # exact provider action strings
    optional_permissions: tuple[str, ...]    # absence degrades facts to `unknown`, never fails

    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]: ...


class Normalizer(Protocol):
    accepts: str                             # provider_resource_type
    produces: NormalizedResourceType
    def normalize(self, obs: RawObservation) -> NormalizedAsset: ...
```

### CollectionContext

Everything a collector is allowed to touch. Note what is absent: no database session, no policy
access, no logger of its own, no ability to construct an arbitrary client.

```python
@dataclass(frozen=True)
class CollectionContext:
    scope: ScanScope                 # region/location/project/subscription + partition
    clients: ClientFactory           # read-allowlisted SDK clients only
    deadline: Deadline               # per-target, enforced by the orchestrator
    cancel: CancellationToken        # checked between pages
    recorder: CallRecorder           # provenance: operation, allowlisted params, response digest
    budget: PageBudget               # max_pages, max_items — hard caps
```

### Division of responsibility

| Concern | Owner |
| --- | --- |
| Pagination loop | Collector (using shared `paginate()` helpers) |
| Page/item caps, deadline, cancellation | Orchestrator, via `budget`/`deadline`/`cancel` |
| Retry, backoff, jitter | Orchestrator (`clients` returns pre-configured, instrumented clients) |
| Error classification into `ScanErrorCategory` | Adapter — provider exception types never escape `providers/` |
| Concurrency | Orchestrator |
| Persistence, evaluation, finding logic | Never the adapter |

A collector is a paginated read plus a `yield`. That is why they are easy to contribute and easy to
review, and it is the property that keeps four adapters from drifting into four architectures.

---

## 2. Read-only enforcement

Read-only is structural, enforced by three independent controls. One would not survive contributors.

1. **Operation allowlist.** `ClientFactory` returns SDK clients wrapped so that every invoked
   operation name is checked against a per-service registry of permitted read operations. An unlisted
   operation raises `ForbiddenOperationError` **before any request is sent**. The registry is data,
   reviewed as data.
2. **Static check in CI.** A check scans `providers/` for mutating verb prefixes (`create_`, `put_`,
   `update_`, `delete_`, `set_`, `attach_`, `modify_`, `begin_`, `generate_`, `export_`, `*_action`)
   and fails on any call not explicitly annotated and reviewed.
3. **Adapter conformance test.** Every registered adapter runs against a client stub that raises on
   any non-allowlisted operation, over the full collector set.

### Reads that are not reads

Several APIs look like queries and behave like mutations. These are named explicitly because the
"read-only" claim is only as good as this list.

| Operation | Why it is not a pure read | Our handling |
| --- | --- | --- |
| AWS `iam:GenerateCredentialReport` | Starts a server-side job and creates account-level state; can fail with `LimitExceeded` (HTTP 409); reports regenerate only every ~4 hours | **Never called by default.** We call `GetCredentialReport`; if the report is absent or expired we return `insufficient_data` and fall back to `ListUsers` + `ListAccessKeys` + `ListMFADevices` (pure reads) for degraded coverage. Generation is available only behind an explicit opt-in flag, off by default. Note AWS itself includes this action in `SecurityAudit`. |
| AWS `iam:GenerateServiceLastAccessedDetails` | Same job-starting pattern | Not used in v0.1.0 |
| AWS Trusted Advisor refresh operations | Refresh is a mutation | Not used |
| Azure `Microsoft.Storage/storageAccounts/listkeys/action` | Classified as a **write/POST action**, and returns keys granting full data-plane access | **Never called.** Everything we need is reachable with `Reader` via the ARM control plane |
| GCP `cloudasset.ExportAssets` | Writes output to Cloud Storage or BigQuery | **Never called.** We use `SearchAllResources` / `SearchAllIamPolicies` / `ListAssets` |

This table is a test fixture as well as documentation: the allowlist registry asserts each of these
operations is absent.

---

## 3. Credentials and scopes

Adapters resolve credentials through each vendor's native chain
([ADR-0013](decisions/0013-credential-handling.md)). Nothing is read from our database except
non-secret configuration.

| Provider | Mechanisms | Notes verified 2026-08-05 |
| --- | --- | --- |
| AWS | Default provider chain, `sts:AssumeRole` (+ `ExternalId` from an env var name), IAM Identity Center/SSO, IRSA | botocore's resolver handles all of these |
| Azure | `DefaultAzureCredential`, workload identity federation, managed identity | Chain order in §4.2. We set **`AZURE_TOKEN_CREDENTIALS=prod`** in the container image so the chain is limited to deployed-service credentials |
| GCP | Application Default Credentials, workload identity federation, service account impersonation | Google's own documentation states service account **keys are not recommended**; our docs lead with impersonation/WIF and treat key files as a legacy fallback |
| IBM | IAM API key (from an env var), trusted profiles, service IDs | `ibm-cloud-sdk-core` authenticators. Trusted profiles are the closest analogue to AssumeRole/WIF and are our documented default |

`resolve_scopes()` expands a connection into concrete scan scopes — AWS enabled regions, Azure
locations, GCP the project, IBM regions — intersected with the connection's `region_allowlist`. It
never discovers scopes outside the registered connection's boundary.

### verify_access → CapabilityReport

`verify_access` performs an identity probe followed by the cheapest possible permission probe per
collector (one page, minimal scope), producing:

```python
CapabilityReport(
    identity="arn:aws:sts::111122223333:assumed-role/MultiCloudShieldAudit/mcs",
    ok=["aws.s3.buckets", "aws.ec2.security_groups"],
    denied=[Denied(collector="aws.cloudtrail.trails", permission="cloudtrail:GetTrailStatus")],
    disabled=[Disabled(collector="gcp.kms.keys", reason="cloudkms.googleapis.com not enabled")],
)
```

This is what turns "connection failed" into "grant `cloudtrail:GetTrailStatus` to complete this
check", and it is what makes least-privilege credentials practical to grant incrementally.

---

## 4. Per-provider realities

Where the four clouds genuinely differ. Every quirk here is a place a naive shared abstraction would
have produced wrong results.

### 4.1 AWS

**SDK:** `boto3` / `botocore` **1.43.64** (2026-08-04), requires Python ≥ 3.10. They release in
lockstep, near-daily; we pin a floor and let the lockfile pin exact versions.

**Sync, not async.** `aiobotocore` (3.9.0) is actively maintained but still carries a Beta
classifier; `aioboto3` (15.5.0, 2025-10-30) lags it by months. Neither is AWS-official and both pin
narrow `botocore` ranges. For read-only collection, `boto3` in a bounded thread pool is the
lower-risk concurrency route ([ADR-0006](decisions/0006-background-execution.md)).

**Least-privilege baseline: `arn:aws:iam::aws:policy/SecurityAudit`.** This matters, and the
alternatives are both wrong:

| Managed policy | Verdict |
| --- | --- |
| `job-function/ViewOnlyAccess` | **Insufficient — will silently under-report.** Grants `s3:ListAllMyBuckets`, `iam:List*`, `cloudtrail:DescribeTrails`, but **no** `s3:GetBucket*`, **no** `kms:GetKeyRotationStatus`, **no** `cloudtrail:GetTrailStatus`, **no** `iam:GetAccountPasswordPolicy`. It grants metadata, not configuration |
| **`SecurityAudit`** ✅ | Carries `s3:GetBucket*`, `s3:GetEncryptionConfiguration`, `s3:GetAccountPublicAccessBlock`, `kms:Get*`/`Describe*`/`List*`, `cloudtrail:GetTrailStatus`/`GetEventSelectors`, `ec2:Describe*`, `iam:Get*`/`List*`. Critically it grants `s3:GetObjectAcl` but **not** `s3:GetObject` — object ACLs without object contents, which is exactly the posture boundary we want |
| `ReadOnlyAccess` | **Over-privileged for this tool.** Wildcards `s3:Get*`/`s3:List*` **include `s3:GetObject`** (customer data), plus `dynamodb:Scan`/`Query` and `logs:FilterLogEvents`. Recommending it means asking customers to grant us their object data |

We ship a **generated minimal policy** from the collectors' declared `required_permissions` as the
primary recommendation, and name `SecurityAudit` as the convenient fallback with its trade-off stated.

**Collection quirks:**

- **Per-region clients are mandatory** — a client is bound to one region at construction. Enabled
  regions come from `ec2:DescribeRegions`, never a hardcoded list; `account:GetRegionOptStatus`
  (present in `SecurityAudit`) reports opt-in state.
- **S3 is not uniformly global.** `ListBuckets` is global, but per-bucket configuration calls must go
  to the bucket's own region or return `301 PermanentRedirect`. The S3 collector resolves
  `GetBucketLocation` first and routes accordingly.
- **CloudTrail shadow trails.** Multi-region trails are visible from every region;
  `DescribeTrails` with `IncludeShadowTrails` controls replication visibility. We **deduplicate by
  `TrailARN`** — without this, a multi-region trail is counted once per region and generates
  duplicate findings.
- **IAM is global** and pinned to `us-east-1`.
- **Retries:** botocore's default mode is `legacy` (5 attempts). We configure **`adaptive`**
  (`standard` behaviour plus a client-side token bucket), which is the right default for a scanner
  fanning out across many regions. We always use **`total_max_attempts`**, never `max_attempts` —
  the `Config` object's `max_attempts` *excludes* the initial request while the config-file and
  `AWS_MAX_ATTEMPTS` forms *include* it, and that inconsistency is a live foot-gun.
- **Paginators:** `client.can_paginate(op)` is checked; operations without a paginator use explicit
  token loops through the same bounded helper.
- KMS is eventually consistent; a just-created key may not appear. Not a correctness problem for
  posture assessment, but it is why absence never resolves a finding on its own.

### 4.2 Azure

**SDKs (all verified 2026-08-05):** `azure-identity` 1.25.3, `azure-mgmt-resource` 26.0.0,
`azure-mgmt-storage` 25.1.0, `azure-mgmt-network` 31.0.1, `azure-mgmt-monitor` 7.0.0,
`azure-mgmt-keyvault` 14.0.1, `azure-mgmt-resourcegraph` 8.0.1.

**Two packages are effectively frozen** and this is a real risk to plan around:

- `azure-mgmt-authorization` — stable is **4.0.0 (2023-07-25)**; only `5.0.0b2` (2026-05-07) moves.
  This package provides role assignments, a core IAM posture read. We use the 2023 stable and do not
  take a preview dependency; the risk is recorded in [risk-register.md](../planning/risk-register.md).
- `azure-mgmt-subscription` — stable **3.1.1 (2022-09-06)**, Beta classifier. **We do not use it.**
  Subscription and tenant enumeration comes from
  `azure.mgmt.resource.subscriptions.SubscriptionClient` in `azure-mgmt-resource` 26.0.0.
  *(Unverified: we confirmed the class exists and the versions, but not an explicit Microsoft
  deprecation notice. Implementation must confirm.)*

**`DefaultAzureCredential` chain**, read from the shipping source at tag `azure-identity_1.25.3`:
`EnvironmentCredential` → `WorkloadIdentityCredential` → `ManagedIdentityCredential` →
`SharedTokenCacheCredential` → `VisualStudioCodeCredential` → `AzureCliCredential` →
`AzurePowerShellCredential` → `AzureDeveloperCliCredential`. `InteractiveBrowserCredential` is
excluded by default. Since 1.14.0, developer-tool credentials no longer halt the chain on failure.

We set **`AZURE_TOKEN_CREDENTIALS=prod`** in the container image, collapsing the chain to
deployed-service credentials. Without it, a scanner running on an operator's workstation can silently
pick up their `az login` identity — which is both a surprising privilege escalation and a source of
findings attributed to the wrong principal.

**RBAC:** `Reader` (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) + `Security Reader`
(`39bc4728-0917-49c7-9d2c-d95423bc2eb4`) at subscription or management-group scope. `Key Vault Reader`
(`21090545-7ca7-4776-b22c-e363652d74d2`) where vault properties are needed.

**Resource Graph for inventory, management SDK for verdicts.** Azure Resource Graph
(`azure-mgmt-resourcegraph` 8.0.1) queries across subscriptions with KQL and returns provider-level
properties without per-resource calls; it needs only `read` on the targets, so `Reader` suffices, and
returns `403` if the principal has rights to none of the supplied subscriptions. But it is an
**eventually-consistent replica** fed by ARM change notifications, and it snapshots each provider's
latest non-preview API version, so a property may be missing or differently shaped. Therefore:
**Resource Graph for discovery, the per-service management SDK for any property that gates a
finding.** This is the most consequential Azure design decision in the adapter.

**Public blob access — the correction that matters.** Microsoft's guidance notes that the *data-plane*
`Set Container ACL` operation does not support Entra ID authentication, which reads as though a CSPM
needs storage account keys. It does not. The **ARM control plane** `blob_containers.list()`
(`StorageManagementClient`) returns `properties.publicAccess` ∈ {`Container`, `Blob`, `None`} per
container and is OAuth-authorized. Account level is `StorageAccounts.get_properties()` →
`allowBlobPublicAccess`. **`Reader` is sufficient; we never request storage account keys.** That
endpoint returns no continuation token; anonymous access is off by default at both levels.

**Throttling:** ARM moved to a **per-region token-bucket** model; the older flat "12,000 reads/hour"
figure is obsolete and must not be designed to. We read
`x-ms-ratelimit-remaining-subscription-reads` and back off on it. Resource Graph is throttled
separately at the **user** level (`x-ms-user-quota-remaining`, `x-ms-user-quota-resets-after`).

**Diagnostic settings are per-resource** — `diagnostic_settings.list(resource_uri)` costs O(number of
resources), not one call. This is where an Azure scan gets slow, and it is budgeted for explicitly in
the collector's page/item caps.

**Key Vault posture:** `vaults.get` → `properties.enableSoftDelete`, `enablePurgeProtection`,
`softDeleteRetentionInDays` (7–90, default 90). Both flags are one-way latches once enabled.

### 4.3 GCP

**SDKs — all GA (Production/Stable), the most consistent surface of the four:**
`google-cloud-storage` 3.13.0, `google-cloud-asset` 4.4.0, `google-cloud-resource-manager` 1.18.0,
`google-cloud-compute` 1.50.0, `google-cloud-logging` 3.16.1, `google-cloud-kms` 3.16.0,
`google-api-python-client` 2.198.0, `google-auth` 2.56.2.

**Roles:** `roles/cloudasset.viewer` ("read only access to cloud assets metadata") +
`roles/iam.securityReviewer` ("permissions to list all resources and allow policies on them").
Note that `securityReviewer` is **list + `getIamPolicy`, not `get`** — it does not return full
per-resource configuration. Where per-service detail beyond Cloud Asset Inventory is needed,
`roles/viewer` is required, and our documentation says so rather than letting checks silently return
`unknown`.

**Cloud Asset Inventory** scopes to `projects/…`, `folders/…`, or `organizations/…`. We use
`SearchAllResources`, `SearchAllIamPolicies`, and `ListAssets`. Change history is retained 35 days;
data is eventually consistent; not all resource types are searchable. **`ExportAssets` is never
called** — it writes to Cloud Storage or BigQuery (§2).

**Two GCP-specific traps, both handled explicitly:**

1. **`SERVICE_DISABLED` is not "zero resources".** Per-service APIs must each be enabled or calls
   fail rather than returning empty. Conflating the two produces a false all-clear — the single most
   dangerous GCP-specific bug available to us. Disabled APIs mark the `ScanTarget` `skipped` with
   `skip_reason=service_disabled`, and dependent policies return `insufficient_data`, never `pass`.
2. **Audit logging config is not a separate API.** It is the `auditConfigs` block inside the IAM
   policy, retrieved via `getIamPolicy` (requires `resourcemanager.<TYPE>.getIamPolicy`). Data Access
   logs (`ADMIN_READ`/`DATA_READ`/`DATA_WRITE`) are **disabled by default**, and configuration set at
   a **parent** folder or organization is invisible to a project-scoped read. A project-scoped scan
   therefore reports `insufficient_data` — "cannot determine; parent-scope configuration not
   visible" — rather than a failure. Reporting a finding here would be a false positive by design.

**KMS:** `CryptoKey.rotationPeriod` / `nextRotationTime`. Automatic rotation is **not supported for
asymmetric signing/encryption keys**, so absent rotation on an asymmetric key is `not_applicable`,
not a finding.

**Storage:** `buckets.get` → `iamConfiguration.publicAccessPrevention` (`enforced`/`inherited`) and
`iamConfiguration.uniformBucketLevelAccess.{enabled, lockedTime}`.

### 4.4 IBM Cloud — the honest asymmetry

**SDKs:** `ibm-cloud-sdk-core` 3.26.0, `ibm-platform-services` **0.77.0**, `ibm-vpc` **0.34.0**,
`ibm-cos-sdk` 2.16.2.

Two of these carry a **Beta classifier and remain on 0.x** after years (`ibm-platform-services`,
`ibm-vpc`). They are functional and actively released — we use them, and we record the maturity gap
rather than papering over it.

**What works well:**

- `ibm-cos-sdk` is a **fork of boto3**, so `get_bucket_acl`, `get_bucket_policy`,
  `get_bucket_policy_status`, paginators, and `Config` behave like boto3. It vendors its own
  `ibm-cos-sdk-core` fork, which **can conflict with real botocore in one environment** — the IBM
  adapter isolates its imports and this is verified by a dependency-resolution test.
- `ibm-vpc` 0.34.0 provides `list_security_groups`, `get_security_group`,
  `list_security_group_rules`, `list_security_group_targets`, `list_network_acls`,
  `list_network_acl_rules`, `get_vpc_default_security_group`. It requires an API **version date**
  parameter — we pin it explicitly, because IBM's default drifts.
- `ibm-platform-services` 0.77.0 covers Global Search, Global Tagging, IAM Policy Management, IAM
  Identity, IAM Access Groups, Resource Controller, Resource Manager, Enterprise Management. Global
  Search gives breadth; Resource Controller (`list_resource_instances`) gives instance detail.
  `iam_identity_v1` provides `get_mfa_status` / `get_mfa_report` / `get_account_settings`.

**What does not exist — and this determines v0.1.0 IBM scope:**

| Gap | Evidence (2026-08-05) |
| --- | --- |
| **No Activity Tracker / Cloud Logs Python SDK** | `IBM/atracker-python-sdk`, `IBM/activity-tracker-python-sdk`, `IBM/logs-python-sdk`, `IBM/logs-router-python-sdk` all 404; `ibm-atracker*`, `ibm-cloud-logs-sdk`, `ibm-logs-sdk` all absent from PyPI. The `atracker` REST API exists but a client would be hand-rolled |
| **No official Key Protect Python SDK** | `IBM/keyprotect-python-sdk` 404. Only `keyprotect` 2.3.1, last released 2024-06-12 — hand-written, not part of IBM's SDK family, over two years stale |
| **No Hyper Protect Crypto Services SDK** | `IBM/hpcs-python-sdk` 404; HPCS exposes KMIP/PKCS#11 instead |
| **Security and Compliance Center SDK archived** | `ibm-scc` 5.0.0 (2025-06-11); `IBM/scc-python-sdk` is archived |

**Decision:** v0.1.0 IBM coverage is scoped to the four areas with maintained official SDK support —
object storage, network, identity, and inventory. **Audit logging and KMS posture are recorded as
"no maintained Python SDK" in the coverage matrix**, not implemented against a stale third-party
client or a hand-rolled REST client. That is exactly the asymmetry the architecture requires us to
represent honestly ([ADR-0008](decisions/0008-normalized-asset-and-fact-model.md)).

**Roles:** IBM separates **platform access roles** (Viewer, Operator, Editor, Administrator) from
**service access roles** (Reader, Writer, Manager). A CSPM needs **both**, per service instance —
materially more granular and more tedious than attaching one AWS managed policy, and our setup
documentation must not pretend otherwise. *(Unverified: `cloud.ibm.com/docs` is a JavaScript SPA that
could not be rendered; the role taxonomy is corroborated by IBM-hosted search snippets but exact
per-service role-to-action mappings must be confirmed against a live account during implementation.)*

**Endpoints:** IAM, Global Search, and Resource Controller are global; VPC and COS are regional and
take an explicit `service_url`.

### 4.5 Demo

Implements the identical contract with a seeded generator and no network
([ADR-0023](decisions/0023-demo-mode-as-provider.md)). It is the reference implementation a
contributor reads first, because its behaviour is fully legible without cloud knowledge.

---

## 5. Error classification

Each adapter maps provider errors into the shared taxonomy. Provider exception types never leave
`providers/`.

| Category | AWS | Azure | GCP | IBM |
| --- | --- | --- | --- | --- |
| `authentication` | `UnrecognizedClientException`, `ExpiredToken`, no credentials in chain | `ClientAuthenticationError` | `DefaultCredentialsError`, `RefreshError` | `ApiException` 401 |
| `permission_denied` | `AccessDenied`, `UnauthorizedOperation`, `AccessDeniedException` | `AuthorizationFailed` (403) | `PermissionDenied` (403) | `ApiException` 403 |
| `throttled` | `Throttling`, `RequestLimitExceeded`, `TooManyRequestsException` | 429 + `Retry-After` | `ResourceExhausted` (429) | 429 |
| `service_disabled` | Service not available in region | `MissingSubscriptionRegistration` | **`SERVICE_DISABLED`** (403 with reason) | Service not provisioned |
| `unsupported_region` | Region not opted in / endpoint unreachable | Location unavailable | Location unavailable | Region unavailable |
| `not_found` | `NoSuchBucket`, `ResourceNotFoundException` | 404 | `NotFound` | 404 |
| `api_error` | Other `ClientError` / 5xx | Other `HttpResponseError` | Other `GoogleAPICallError` | Other `ApiException` |

`permission_denied`, `service_disabled`, and `not_found` are **never retried** — retrying an
authorization failure only multiplies audit-log noise in the customer's account.

`permission_denied` carries the specific action, which flows to the UI as "grant X to complete this
check". This is only possible because `required_permissions` is declared per collector.

---

## 6. Adding a provider

1. **ADR** covering credential mechanisms, scope model, SDK maturity, and what will *not* be
   supported. Asymmetry is declared up front, not discovered late.
2. `providers/<name>/adapter.py` implementing `ProviderAdapter`.
3. `providers/<name>/clients.py` with the read-operation allowlist. This file is reviewed as a
   security control.
4. Collectors — one file per resource area, each declaring `required_permissions`.
5. Normalizers mapping to existing `NormalizedResourceType` values, populating `unknown` explicitly
   where a fact is unreadable. Extending a fact schema is a separate, reviewed change.
6. Fixtures: recorded (scrubbed) API responses covering success, empty, multi-page, permission
   denied, and malformed input.
7. Register in the adapter registry and add the entry point.
8. Update [provider-coverage-matrix.md](../planning/provider-coverage-matrix.md), including
   unsupported areas **with the reason**.
9. Generate and document the least-privilege role from the declared permissions.

The conformance suite runs automatically once registered.

## 7. Adding a collector

The common contribution. Three files change and nothing in the engine does:

1. The collector — paginated read, `yield RawObservation`, declared permissions.
2. The normalizer — or an extension to an existing one.
3. The registry entry.

Plus fixtures for success, empty, multi-page, permission denied, and malformed input; and a coverage
matrix row.

---

## 8. Adapter conformance suite

One parameterized suite runs against **every** registered adapter, including demo:

- `collect()` returns an iterator and yields only `RawObservation`.
- Every declared `produces` type has a registered normalizer.
- `asset_urn` values are well-formed, stable across two runs, and unique within a scope.
- Every fact declared in the schema is either populated or explicitly `unknown` — silence is a bug.
- Cancellation is observed within one page.
- Page and item budgets are respected.
- Provider errors map to the correct `ScanErrorCategory`, exhaustively per the §5 table.
- No non-allowlisted operation is attempted (client stub raises).
- `required_permissions` is non-empty and syntactically valid for the provider.
- No network access occurs when driven by fixtures.

A new adapter that passes this suite is structurally correct. Fact *accuracy* is covered by
fixture-based unit tests, because conformance cannot tell whether a bucket really is public.

---

## 9. Sources

All accessed **2026-08-05**. Versions from the PyPI JSON API, which is the authoritative live index.

**AWS** — [boto3 paginators](https://docs.aws.amazon.com/boto3/latest/guide/paginators.html);
[boto3 retries](https://docs.aws.amazon.com/boto3/latest/guide/retries.html);
[GenerateCredentialReport API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html);
managed policy documents for `SecurityAudit` (v91), `ViewOnlyAccess` (v45), `ReadOnlyAccess` (v188),
compared as JSON rather than by their prose descriptions.

**Azure** — [azure-identity 1.25.3 `_credentials/default.py`](https://github.com/Azure/azure-sdk-for-python/blob/azure-identity_1.25.3/sdk/identity/azure-identity/azure/identity/_credentials/default.py);
[built-in roles: security](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security);
[built-in roles: general](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general);
[ARM request limits and throttling](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling);
[Resource Graph overview](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview);
[Blob Containers – List (SRP)](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/list);
[Key Vault – Vaults Get](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/get);
[configure anonymous read access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure).

**GCP** — [Application Default Credentials](https://docs.cloud.google.com/docs/authentication/application-default-credentials);
[configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access);
Cloud Asset Inventory overview; IAM predefined role reference.

**IBM** — [platform-services-python-sdk README](https://github.com/IBM/platform-services-python-sdk);
[keyprotect-python-client](https://github.com/IBM/keyprotect-python-client); PyPI and GitHub API
probes confirming the absent SDKs listed in §4.4;
[cloud.ibm.com/docs/account?topic=account-userroles](https://cloud.ibm.com/docs/account?topic=account-userroles)
(SPA — snippets only, see §4.4 caveat).

### Confirmed facts vs design assumptions

**Confirmed:** all package versions and release dates; AWS managed policy contents (diffed as JSON);
the `DefaultAzureCredential` chain order (read from the tagged source); Azure role GUIDs; Azure ARM
control-plane blob container `publicAccess`; Key Vault soft-delete/purge-protection properties; GCP
package GA status and audit-config location; GCP asymmetric-key rotation limitation; the absence of
IBM Activity Tracker, Cloud Logs, Key Protect, and HPCS Python SDKs; `ibm-cos-sdk` being a boto3 fork;
AWS `GenerateCredentialReport` job semantics.

**Assumptions implementation must validate:** that `azure-mgmt-subscription` is formally superseded by
`SubscriptionClient` in `azure-mgmt-resource` (behaviour confirmed, deprecation notice not found);
IBM's exact per-service role-to-action mappings (documentation site not renderable); the Cloud Asset
Inventory API hostname (follows Google's convention, not stated literally); AWS's formal access-level
classification of `GenerateCredentialReport` (our "write-ish" judgement rests on the API's own
documented job-starting semantics, not on AWS's access-level table, which is JavaScript-rendered).
