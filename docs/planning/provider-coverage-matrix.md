# Provider Coverage Matrix

Status: planned for v0.1.0
Last updated: 2026-08-05

What each provider adapter collects, which policies apply, and — equally important — what is **not**
covered and why. Provider capabilities are genuinely asymmetric; this document records that honestly
rather than inventing checks to fill cells
([ADR-0008](../architecture/decisions/0008-normalized-asset-and-fact-model.md)).

At implementation time this document is **generated** from each collector's declared
`required_permissions` and each adapter's `ProviderCapabilities`, so it cannot drift from the code.
Until then it is the specification.

API and SDK facts verified 2026-08-05; sources and caveats in
[provider-adapters.md](../architecture/provider-adapters.md) §9.

---

## 1. Coverage at a glance

| Domain | AWS | Azure | GCP | IBM Cloud |
| --- | :---: | :---: | :---: | :---: |
| Object storage exposure | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Object storage encryption | ✅ Full | ✅ Full | ✅ Full | ⚠️ Partial |
| Network firewall exposure | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Identity / access configuration | ✅ Full | ⚠️ Partial | ⚠️ Partial | ✅ Full |
| Audit logging | ✅ Full | ✅ Full | ⚠️ Partial | ❌ **Not covered** |
| Encryption / key management | ✅ Full | ✅ Full | ✅ Full | ❌ **Not covered** |

✅ Full · ⚠️ Partial (documented limitation) · ❌ Not covered in v0.1.0, with reason

The three non-full cells are explained in §6. None is an oversight.

---

## 2. AWS — reference implementation

SDK: `boto3` / `botocore` 1.43.64. Least-privilege: generated minimal policy (primary), or
`arn:aws:iam::aws:policy/SecurityAudit` (documented fallback). **Not `ViewOnlyAccess`** — it lacks
`s3:GetBucket*`, `kms:GetKeyRotationStatus`, and `cloudtrail:GetTrailStatus`, so checks would silently
under-report. **Not `ReadOnlyAccess`** — its `s3:Get*` wildcard includes `s3:GetObject`, i.e. customer
data.

| Collector | Produces | Required permissions | Notes |
| --- | --- | --- | --- |
| `aws.s3.buckets` | `object_storage.bucket` | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `s3:GetBucketPolicy` | `ListBuckets` is global; per-bucket calls are routed to the bucket's own region after `GetBucketLocation`, else `301 PermanentRedirect` |
| `aws.s3.account` | `account.scope` | `s3:GetAccountPublicAccessBlock` | Account-level Block Public Access |
| `aws.ec2.security_groups` | `network.firewall_ruleset`, `network.firewall_rule` | `ec2:DescribeRegions`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules` | Regions enumerated, never hardcoded |
| `aws.iam.principals` | `identity.principal`, `account.scope` | `iam:ListUsers`, `iam:ListAccessKeys`, `iam:ListMFADevices`, `iam:GetAccountPasswordPolicy`, `iam:GetAccountSummary`, `iam:GetCredentialReport` | Global, pinned to `us-east-1`. **`iam:GenerateCredentialReport` is not called** — see §7 |
| `aws.cloudtrail.trails` | `logging.audit_trail` | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | **Deduplicated by `TrailARN`** — multi-region shadow trails otherwise appear once per region |
| `aws.kms.keys` | `kms.key` | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` | KMS is eventually consistent |

---

## 3. Azure

SDKs: `azure-identity` 1.25.3, `azure-mgmt-resource` 26.0.0, `azure-mgmt-storage` 25.1.0,
`azure-mgmt-network` 31.0.1, `azure-mgmt-monitor` 7.0.0, `azure-mgmt-keyvault` 14.0.1,
`azure-mgmt-resourcegraph` 8.0.1, `azure-mgmt-authorization` 4.0.0.

Least-privilege: **Reader** (`acdd72a7-…`) + **Security Reader** (`39bc4728-…`) at subscription scope.
`AZURE_TOKEN_CREDENTIALS=prod` is set so the credential chain cannot silently pick up an operator's
`az login` identity.

| Collector | Produces | Required permissions | Notes |
| --- | --- | --- | --- |
| `azure.inventory.resources` | `account.scope` | `Microsoft.ResourceGraph/resources/read` | Resource Graph for **discovery only**; it is an eventually-consistent replica, so any property gating a finding is re-read from the management SDK |
| `azure.storage.accounts` | `object_storage.account` | `Microsoft.Storage/storageAccounts/read` | `allowBlobPublicAccess`, `minimumTlsVersion`, `supportsHttpsTrafficOnly`, `allowSharedKeyAccess`, encryption |
| `azure.storage.containers` | `object_storage.bucket` | `Microsoft.Storage/storageAccounts/blobServices/containers/read` | **ARM control plane**, `blob_containers.list()` → `properties.publicAccess`. Reader suffices; **storage account keys are never requested** (`listkeys` is a write action) |
| `azure.network.security_groups` | `network.firewall_ruleset`, `network.firewall_rule` | `Microsoft.Network/networkSecurityGroups/read` | |
| `azure.authorization.role_assignments` | `identity.policy_binding` | `Microsoft.Authorization/roleAssignments/read`, `Microsoft.Authorization/roleDefinitions/read` | `azure-mgmt-authorization` stable is from 2023 — see risk R-19 |
| `azure.monitor.diagnostic_settings` | `logging.diagnostic_setting` | `Microsoft.Insights/diagnosticSettings/read` | **Per-resource**, O(n) calls. The dominant cost of an Azure scan; page/item budgets are tuned for it |
| `azure.keyvault.vaults` | `kms.vault` | `Microsoft.KeyVault/vaults/read` | `enableSoftDelete`, `enablePurgeProtection`, `softDeleteRetentionInDays` |

---

## 4. GCP

SDKs (all GA): `google-cloud-storage` 3.13.0, `google-cloud-asset` 4.4.0,
`google-cloud-resource-manager` 1.18.0, `google-cloud-compute` 1.50.0, `google-cloud-kms` 3.16.0.

Least-privilege: `roles/cloudasset.viewer` + `roles/iam.securityReviewer`, **plus `roles/viewer`**
where per-resource configuration is needed — `securityReviewer` grants list and `getIamPolicy`, not
`get`, so without `viewer` several facts would be `unknown`. Documentation states this explicitly
rather than letting checks quietly degrade.

Credentials: service account **keys are discouraged by Google's own documentation**; our setup guide
leads with workload identity federation and impersonation.

| Collector | Produces | Required permissions | Notes |
| --- | --- | --- | --- |
| `gcp.inventory.assets` | `account.scope` | `cloudasset.assets.searchAllResources` | Cloud Asset Inventory. **`ExportAssets` is never called** — it writes to GCS/BigQuery |
| `gcp.storage.buckets` | `object_storage.bucket` | `storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy` | `publicAccessPrevention`, `uniformBucketLevelAccess`, default encryption |
| `gcp.compute.firewalls` | `network.firewall_ruleset`, `network.firewall_rule` | `compute.firewalls.list` | Returns `sourceRanges`, `allowed[]`, `denied[]`, `priority`, `direction` |
| `gcp.iam.project_policy` | `identity.policy_binding`, `account.scope` | `resourcemanager.projects.getIamPolicy` | |
| `gcp.logging.audit_config` | `logging.audit_trail` | `resourcemanager.projects.getIamPolicy` | Audit config is the `auditConfigs` block **inside the IAM policy**, not a separate API. See §6.2 |
| `gcp.kms.keys` | `kms.key` | `cloudkms.keyRings.list`, `cloudkms.cryptoKeys.list` | Asymmetric signing/encryption keys **cannot** auto-rotate → `not_applicable`, not a finding |

**`SERVICE_DISABLED` is never treated as "zero resources".** A disabled per-service API marks the
`ScanTarget` `skipped` with `skip_reason=service_disabled`; dependent policies return
`insufficient_data`. Conflating the two would produce a false all-clear.

---

## 5. IBM Cloud

SDKs: `ibm-cloud-sdk-core` 3.26.0, `ibm-platform-services` 0.77.0 (Beta classifier, 0.x),
`ibm-vpc` 0.34.0 (Beta classifier, 0.x), `ibm-cos-sdk` 2.16.2 (a fork of boto3).

Least-privilege: IBM separates **platform access roles** (Viewer / Operator / Editor / Administrator)
from **service access roles** (Reader / Writer / Manager). We need **both**, per service instance —
materially more work than one AWS policy attach, and our setup guide says so.

| Collector | Produces | Required access | Notes |
| --- | --- | --- | --- |
| `ibm.inventory.resources` | `account.scope` | Viewer (account) | Global Search for breadth + Resource Controller `list_resource_instances` for instance detail |
| `ibm.cos.buckets` | `object_storage.bucket` | Reader on the COS instance | `get_bucket_acl`, `get_bucket_policy`, `get_bucket_policy_status` — boto3-compatible. Imports are isolated because `ibm-cos-sdk` vendors its own botocore fork |
| `ibm.vpc.security_groups` | `network.firewall_ruleset`, `network.firewall_rule` | Viewer (VPC Infrastructure) | `list_security_groups`, `list_security_group_rules`, `list_security_group_targets`. API **version date is pinned explicitly** |
| `ibm.vpc.network_acls` | `network.firewall_ruleset`, `network.firewall_rule` | Viewer (VPC Infrastructure) | `list_network_acls`, `list_network_acl_rules` |
| `ibm.iam.policies` | `identity.policy_binding` | Viewer (IAM) | `iam_policy_management_v1.list_policies`, `list_roles` |
| `ibm.iam.identity` | `identity.principal`, `account.scope` | Viewer (IAM) | `list_service_ids`, `list_api_keys`, `get_account_settings`, `get_mfa_status`, `get_mfa_report` |

**Not covered in v0.1.0 — audit logging and key management.** See §6.3. This is a scope decision made
from verified SDK availability, not a gap to be quietly filled later with an unmaintained dependency.

---

## 6. Documented gaps

### 6.1 IBM object storage encryption — ⚠️ Partial

`ibm-cos-sdk` exposes bucket ACL and policy cleanly, but IBM's key-management posture (which
customer-managed key protects a bucket, and whether it rotates) requires Key Protect, for which no
maintained official Python SDK exists (§6.3). Encryption facts are therefore populated as
`provider_managed` or `unknown`, never asserted as `customer_managed` without evidence, so
`MCS-STOR-003` returns `insufficient_data` on IBM rather than a false pass or a false failure.

### 6.2 GCP audit logging — ⚠️ Partial

Two verified constraints, both handled by returning `insufficient_data` rather than a finding:

1. **Data Access audit logs are disabled by default**, so absence is the norm and is not by itself
   evidence of misconfiguration.
2. **Configuration set at a parent folder or organization is invisible to a project-scoped read.**
   A project-scoped scan genuinely cannot determine effective audit configuration.

`MCS-LOG-001` therefore returns `insufficient_data` on GCP at project scope, with the reason
"parent-scope audit configuration not visible". Reporting a failure here would be a false positive by
construction. Organization-scoped scanning is post-MVP and would resolve this properly.

### 6.3 IBM audit logging and key management — ❌ Not covered

Verified 2026-08-05:

| Needed | Status |
| --- | --- |
| Activity Tracker Python SDK | Does not exist — `IBM/atracker-python-sdk`, `IBM/activity-tracker-python-sdk`, `IBM/logs-python-sdk`, `IBM/logs-router-python-sdk` all 404; no corresponding PyPI packages |
| IBM Cloud Logs Python SDK | Does not exist |
| Key Protect Python SDK | No official SDK. `keyprotect` 2.3.1 is community-adjacent, hand-written, last released 2024-06-12 |
| Hyper Protect Crypto Services SDK | Does not exist; HPCS exposes KMIP/PKCS#11 |
| Security and Compliance Center SDK | `IBM/scc-python-sdk` is **archived** |

The alternatives were hand-rolling REST clients against `ibm-cloud-sdk-core` or depending on a
two-year-stale third-party package. Both were rejected for v0.1.0: a security tool that reports on
audit logging must be confident in its reads, and neither option supports that confidence. The
adapter declares these capabilities as absent, the UI shows IBM audit/KMS coverage as unavailable
with this reason, and no policy silently passes. Revisit when IBM ships maintained SDKs (risk R-05).

### 6.4 Azure identity — ⚠️ Partial

`azure-mgmt-authorization`'s stable release is **4.0.0 from 2023-07-25**; only preview releases have
followed. We use the 2023 stable rather than take a preview dependency, which means role-assignment
reads may lag newer Azure IAM features. Recorded as risk R-19.

### 6.5 GCP identity — ⚠️ Partial

`roles/iam.securityReviewer` provides list and `getIamPolicy` but **not `get`**, so full per-resource
configuration requires `roles/viewer` in addition. Where only `securityReviewer` is granted,
configuration facts resolve to `unknown` and dependent policies return `insufficient_data`. The
connectivity test reports this as `degraded` with the specific role needed.

---

## 7. AWS credential report — read-only handling

`iam:GenerateCredentialReport` starts a server-side job, creates account-level state, can fail with
`LimitExceeded` (HTTP 409), and regenerates only every ~4 hours. It is not a pure read, even though
AWS includes it in `SecurityAudit`.

Default behaviour (no opt-in):

1. Call `GetCredentialReport`.
2. If a fresh report exists, use it.
3. If it is absent or expired, return `insufficient_data` for credential-report-dependent facts and
   fall back to `ListUsers` + `ListAccessKeys` + `ListMFADevices` — all pure reads — for degraded
   coverage.

Generation is available only behind an explicit, default-off flag. "Read-only by default" is a
testable property here, not an assumption.

---

## 8. Policy catalog

Cross-provider policies operate on normalized facts and apply wherever the resource type exists.
Provider-specific policies declare a narrowed applicability and a declared `provider_specific` fact
path ([ADR-0008](../architecture/decisions/0008-normalized-asset-and-fact-model.md)).

### 8.1 Cross-provider

| ID | Title | Severity | AWS | Azure | GCP | IBM |
| --- | --- | --- | :-: | :-: | :-: | :-: |
| `MCS-STOR-001` | Object storage allows public read access | critical | ✅ | ✅ | ✅ | ✅ |
| `MCS-STOR-002` | Object storage allows public write access | critical | ✅ | ✅ | ✅ | ✅ |
| `MCS-STOR-003` | Object storage not protected by a customer-managed key | low | ✅ | ✅ | ✅ | ⚠️ `insufficient_data` |
| `MCS-STOR-004` | Object storage access logging not enabled | low | ✅ | ✅ | ✅ | ⚠️ `insufficient_data` |
| `MCS-STOR-005` | Object storage does not require encrypted transport | medium | ✅ | ✅ | ✅ | ✅ |
| `MCS-NET-001` | Unrestricted inbound access to administrative ports | high | ✅ | ✅ | ✅ | ✅ |
| `MCS-NET-002` | Unrestricted inbound access to all ports | critical | ✅ | ✅ | ✅ | ✅ |
| `MCS-NET-003` | Unrestricted inbound access to data-store ports | high | ✅ | ✅ | ✅ | ✅ |
| `MCS-IAM-001` | Interactive principal without multi-factor authentication | high | ✅ | ⚠️ | ⚠️ | ✅ |
| `MCS-IAM-002` | Long-lived credential older than the configured threshold | medium | ✅ | ❌ n/a | ❌ n/a | ✅ |
| `MCS-LOG-001` | Audit logging not enabled for the account scope | high | ✅ | ✅ | ⚠️ §6.2 | ❌ §6.3 |
| `MCS-LOG-002` | Audit log destination is publicly accessible | critical | ✅ | ✅ | ⚠️ | ❌ §6.3 |
| `MCS-KMS-001` | Key rotation not enabled | medium | ✅ | ✅ | ✅ | ❌ §6.3 |

`MCS-IAM-002` is `not_applicable` on Azure and GCP because neither has a directly comparable
long-lived user credential in the scope we read — Azure identities are Entra ID objects outside the
subscription boundary, and GCP service account **keys** are the analogue but require
`roles/iam.serviceAccountKeyAdmin`-adjacent read scope we do not request in v0.1.0. Inventing a
loosely-equivalent check to fill these cells would produce findings that do not mean what they say.

### 8.2 Provider-specific

| ID | Title | Severity | Provider | Rationale for provider-specific |
| --- | --- | --- | --- | --- |
| `MCS-AWS-S3-001` | Account-level Block Public Access not fully enabled | high | AWS | No cross-provider equivalent of an account-wide storage override |
| `MCS-AWS-IAM-001` | Root account has active access keys | critical | AWS | Root-account model is AWS-specific |
| `MCS-AWS-IAM-002` | Account password policy weaker than baseline | medium | AWS | Account-level policy object is AWS-specific |
| `MCS-AWS-CT-001` | Trail is not multi-region or lacks log file validation | medium | AWS | CloudTrail-specific properties |
| `MCS-AZ-STOR-001` | Storage account permits shared key authorization | medium | Azure | Shared-key auth is Azure-specific |
| `MCS-AZ-KV-001` | Key Vault soft delete not enabled | high | Azure | Key Vault lifecycle property |
| `MCS-AZ-KV-002` | Key Vault purge protection not enabled | medium | Azure | Key Vault lifecycle property |
| `MCS-GCP-STOR-001` | Uniform bucket-level access not enabled | medium | GCP | GCS-specific ACL model |
| `MCS-GCP-STOR-002` | Public access prevention not enforced | high | GCP | GCS-specific control |
| `MCS-IBM-IAM-001` | Account-level multi-factor authentication not enforced | high | IBM | IBM account settings model |

**23 policies in v0.1.0.** Deliberately modest. The product bet is depth — normalization, evidence,
lifecycle — not check count ([vision.md](../product/vision.md) §6). Every one of these ships with
fixtures covering pass, fail, and `insufficient_data`.

---

## 9. Deliberately out of scope for v0.1.0

Not gaps — decisions, so that a contributor does not read absence as an invitation.

| Area | Why not now |
| --- | --- |
| Compute instance posture (public IPs, IMDSv1, disk encryption) | Large surface across four providers; the five chosen domains give better coverage per unit of effort |
| Managed database posture | Same reasoning; the strongest post-MVP candidate after compute |
| Serverless, container registries, Kubernetes services | Each is a domain of its own |
| Secrets management posture | Reading secret *metadata* is fine, but the check surface is small and provider models diverge sharply |
| Certificate and TLS posture | Deferred |
| Cost and quota checks | Not security posture ([vision.md](../product/vision.md) §3) |
| Organization / folder / management-group hierarchy scanning | Post-MVP; would resolve §6.2 |
| Data-plane inspection (object contents, database rows) | **Permanently out of scope.** No collector may read data-plane content |
