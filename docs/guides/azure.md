# Azure read-only setup

MultiCloudShield v0.1.0 scans one registered Azure subscription at a time. The worker uses Azure's
native `DefaultAzureCredential` chain and does not accept or store a client secret, certificate,
access token, storage-account key, or SAS token.

## Recommended identity

Prefer workload identity federation in CI or Kubernetes and managed identity on Azure-hosted
workers. Environment-based service-principal credentials are supported by the Azure SDK but are a
fallback because their secret must be managed outside MultiCloudShield.

The worker forces `AZURE_TOKEN_CREDENTIALS=prod` immediately before it constructs
`DefaultAzureCredential`. This limits the chain to deployed-service credentials and prevents a scan
on an operator workstation from silently using an `az login`, Azure PowerShell, VS Code, or Azure
Developer CLI identity.

Configure the selected native credential mechanism according to Microsoft's documentation, then
register only the subscription UUID and mechanism in MultiCloudShield. Do not put a credential value
in the connection's credential reference.

## Least privilege

At the subscription scope, grant the scanning identity the built-in **Reader** and **Security
Reader** roles. Grant **Key Vault Reader** only where vault lifecycle posture is required. A tighter
custom role can use the actions below:

| Collector | Required read actions |
| --- | --- |
| Inventory | `Microsoft.ResourceGraph/resources/read` |
| Storage accounts | `Microsoft.Storage/storageAccounts/read` |
| Blob containers | `Microsoft.Storage/storageAccounts/blobServices/containers/read`, `Microsoft.Storage/storageAccounts/read` |
| Network security groups | `Microsoft.Network/networkSecurityGroups/read` |
| Role assignments | `Microsoft.Authorization/roleAssignments/read`, `Microsoft.Authorization/roleDefinitions/read` |
| Diagnostic settings | `Microsoft.Insights/diagnosticSettings/read`, `Microsoft.ResourceGraph/resources/read` |
| Key Vault lifecycle | `Microsoft.KeyVault/vaults/read` |

Do not grant Owner, Contributor, Storage Account Contributor, Storage Blob Data Contributor, or any
role solely to make a scan work. MultiCloudShield reads configuration from the ARM control plane and
does not need object contents or other data-plane access.

In particular, the adapter never calls
`Microsoft.Storage/storageAccounts/listkeys/action`. Azure classifies that endpoint as a write/POST
action, and its response contains credentials with data-plane access. Container anonymous-read
posture instead comes from the OAuth-authorized ARM operation
`storageAccounts/blobServices/containers/read` (`blob_containers.list()`).

## Connectivity test

The connectivity test first reads the registered subscription and then performs the cheapest read
probe for every collector. It returns a degraded capability report when an individual action is
denied or a resource provider is not registered. Authentication failure, an unavailable SDK, or an
unexpected API failure is reported as a provider error; it is never represented as an empty,
successful scan.

Resource Graph is used only to discover resource IDs. Storage, network, role-assignment, diagnostic,
and Key Vault properties that determine posture are read again from their ARM management clients.
This avoids treating Resource Graph's eventually consistent replica as current security evidence.

## Scope, bounds, and expected gaps

The connection's subscription UUID is the hard scan boundary. An optional Azure location allowlist
filters observations but cannot expand that boundary. Every SDK page and every per-resource
diagnostic-settings response consumes the scan page/item budget, and cancellation and deadline checks
run between pages and resources.

Diagnostic settings require one read per discovered resource and are normally the slowest Azure
collector. A budget or deadline failure produces a partial scan, not a clean result.

Azure role-assignment coverage is partial: the stable `azure-mgmt-authorization` client may lag newer
IAM features, and Entra ID principal MFA or credential posture is outside a subscription-scoped scan.
Those unavailable facts remain `unknown`; dependent policies return `insufficient_data`.

## Troubleshooting

- `authentication`: no deployed-service credential was available, it expired, or Azure rejected it.
- `permission_denied`: grant the exact read action shown for the affected collector.
- `service_disabled`: register the named Azure resource provider if organizational policy permits.
- `throttled`: the orchestrator retries with bounded backoff; reduce scope if limits persist.
- `COLLECTION_LIMIT_EXCEEDED` or a timeout: narrow the location allowlist or adjust operator-owned scan
  limits after reviewing the estate size.

Never paste a token, secret, certificate, storage connection string, account key, or SAS URL into a
support request, connection record, log, or issue.
