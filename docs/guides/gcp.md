# Connect a Google Cloud project

MultiCloudShield v0.1.0 scans one registered Google Cloud project at a time with Application Default
Credentials (ADC). The worker uses read-only Google APIs; it does not accept, store, log, or export a
credential value.

## Recommended authentication

Use keyless credentials. In order of preference:

1. Workload Identity Federation for a worker running outside Google Cloud.
2. An attached service account for a worker running on Google Cloud, optionally with service account
   impersonation.
3. A service account key file only for a legacy environment that cannot use federation or
   impersonation. Google discourages service account keys; keep any legacy key outside
   MultiCloudShield and expose it only through the worker's ADC environment.

The API process must not receive ADC credentials or cloud egress. Only the worker needs them. The
connection records the project ID, credential mechanism, and a non-secret reference such as a
service account email. It never records a token, private key, federation subject token, or environment
variable value.

Before registering the connection, verify ADC in the worker environment using Google's supported
authentication tooling. Do not paste the resulting token or credential JSON into MultiCloudShield.

## Required permissions

The baseline documented by Google Cloud is:

- `roles/cloudasset.viewer`
- `roles/iam.securityReviewer`
- `roles/viewer` where the storage, Compute Engine, and KMS configuration collectors need detailed
  per-service configuration

`roles/iam.securityReviewer` grants list and IAM-policy reads, but not every resource `get` operation.
Omitting `roles/viewer` therefore produces explicit permission gaps and `insufficient_data`; it does
not produce a pass.

For tighter control, create a project-level custom role containing only the permissions used by the
v0.1.0 collectors:

```yaml
includedPermissions:
  - cloudasset.assets.searchAllResources
  - storage.buckets.list
  - storage.buckets.get
  - storage.buckets.getIamPolicy
  - compute.firewalls.list
  - resourcemanager.projects.getIamPolicy
  - cloudkms.keyRings.list
  - cloudkms.cryptoKeys.list
```

Review the custom role against the collector list after every MultiCloudShield upgrade. Grant it to a
dedicated audit principal on only the project registered in the connection. Organization- and
folder-scoped discovery are outside v0.1.0.

## APIs that must already be enabled

The project administrator must enable the APIs needed for the selected collectors:

- Cloud Asset Inventory (`cloudasset.googleapis.com`)
- Cloud Storage (`storage.googleapis.com`)
- Compute Engine (`compute.googleapis.com`)
- Cloud Resource Manager (`cloudresourcemanager.googleapis.com`)
- Cloud KMS (`cloudkms.googleapis.com`)

Enabling a service changes the Google Cloud project, so MultiCloudShield never does it. If an API is
disabled, the adapter reports `SERVICE_DISABLED`, the target is skipped, and dependent checks return
`insufficient_data`. A disabled API is never interpreted as an empty project.

## What the scan reads

The adapter reads Cloud Asset Inventory search results, bucket configuration and IAM policy, Compute
Engine firewall rules, the project IAM policy (including its `auditConfigs` block), and KMS key-ring
and cryptokey metadata. It never calls Cloud Asset Inventory `ExportAssets` because that operation
writes to Cloud Storage or BigQuery.

Two GCP limitations are deliberately visible:

- Project IAM policy reads cannot see audit configuration inherited from a folder or organization.
  Audit logging is therefore `unknown` with parent-scope visibility set to `no` for a project scan,
  even when the project policy contains an audit configuration.
- Cloud KMS asymmetric signing and asymmetric decryption keys do not support automatic rotation.
  Their facts set `supports_rotation=no`, so rotation policy evaluation is not applicable rather than
  a finding.

## Validate access

Run the connection access check before the first scan and after changing IAM. The capability report
lists each collector as available, permission denied, or service disabled. Resolve only the named
permission or API gap; do not replace the audit role with Owner, Editor, or another write-capable
role.

ADC may select a different local identity than the deployed worker. Treat a successful developer
laptop check as a convenience only, and always validate from the actual worker environment.
