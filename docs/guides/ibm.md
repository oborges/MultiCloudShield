# IBM Cloud connection guide

MultiCloudShield v0.1.0 reads IBM Cloud inventory, Cloud Object Storage (COS), VPC network controls,
and IAM posture. It never changes IBM Cloud resources. Audit logging and key-management posture are
not available in this release because IBM does not publish maintained official Python SDKs for
Activity Tracker / Cloud Logs, Key Protect, or HPCS. Those checks remain explicitly unavailable; they
do not silently pass.

## Recommended authentication

Use an IBM Cloud trusted profile for Global Search, Resource Controller, VPC, and IAM whenever the
worker runs on IBM Cloud. Register only the trusted profile name or ID with MultiCloudShield. Do not
store a token, API key, or credential file in a connection.

The COS SDK uses the trusted profile authenticator's token manager when available. A service ID API
key supplied to the worker through a dedicated environment variable is the supported fallback. The
connection stores the environment variable **name**, never its value, and the COS SDK path refuses to
fall back to ambient credentials.

Example non-secret connection references:

```json
{
  "profile_name": "multicloudshield-audit",
  "regions": "us-south,eu-de",
  "cos_service_instance_id": "<COS service instance GUID>"
}
```

For the `ibm_api_key_env` fallback, replace the profile reference with
`"api_key_env": "MCS_IBM_COS_API_KEY"`; the value of that variable exists only in the worker.

Set `region_allowlist` on the connection to the regions MultiCloudShield may scan. When both
`regions` and `region_allowlist` are present, only their intersection is used. Regional discovery is
never expanded beyond this registered boundary.

## Least-privilege access

IBM Cloud has two independent role families. Grant both only at the scopes shown below:

| Scope | Platform role | Service role | Used for |
| --- | --- | --- | --- |
| Account / resource group | Viewer | — | Global Search and Resource Controller inventory |
| Each COS service instance | Viewer | Reader | Bucket list, ACL, policy, and policy-status reads |
| VPC Infrastructure service in each scanned region | Viewer | — | Security groups, rules, targets, network ACLs, and rules |
| IAM service at account scope | Viewer | — | Policies, roles, service IDs, API-key metadata, account MFA settings and report |

Do not grant Operator, Editor, Administrator, Writer, or Manager for MultiCloudShield. The adapter
does not use create, update, delete, action, export, or content-read operations. COS object bodies are
never requested.

IBM's exact IAM action names and role composition can change independently of this project. Confirm
the role assignments in IBM Cloud's current IAM interface, then use **Verify access**. The report
identifies each unavailable collector and its first required read permission without exposing a
credential.

## Collection limits and expected gaps

Every list operation checks cancellation between pages and consumes the scan's page/item budget.
The IBM VPC API version is pinned to `2026-08-05`; upgrades are reviewed rather than inherited from a
drifting SDK default.

COS encryption is partial in v0.1.0. IBM-managed encryption is recorded where the COS control plane
provides sufficient evidence. Customer-managed-key and rotation posture remains unknown without a
maintained Key Protect SDK. Versioning, access logging, and bucket-level TLS enforcement also remain
unknown when they cannot be proven from the allowlisted reads. Policies consuming those facts return
`insufficient_data`, not a false pass or failure.

## Troubleshooting

- `SDK_NOT_INSTALLED`: install MultiCloudShield with the `ibm` provider extra in the worker image.
- `NO_REGIONS_CONFIGURED`: add explicit IBM Cloud regions to `regions` or `region_allowlist`.
- `CREDENTIAL_NOT_AVAILABLE`: define the referenced API-key environment variable in the worker only.
- `permission_denied`: grant the role named for the collector at the exact account, service instance,
  or regional VPC scope. Authorization failures are not retried.

Never add provider credentials to the API process, connection JSON, logs, test fixtures, or support
bundles.
