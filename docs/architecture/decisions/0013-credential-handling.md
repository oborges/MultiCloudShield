# ADR-0013: Provider-native credential chains, no stored secrets

Status: accepted
Date: 2026-08-05

## Context

To read a customer's cloud, MultiCloudShield needs cloud credentials. Every CSPM faces the same
question, and most SaaS products answer it by storing a credential (encrypted at rest) or by holding
a cross-account role they can assume. Both make the product a high-value target: a single breach
yields read access to every connected cloud estate.

We are self-hosted and open source. We can make a stronger choice.

## Decision

**MultiCloudShield never possesses a cloud secret.** Credentials are resolved by the provider SDK's
own credential chain, in the worker process, at call time. The database stores only *which mechanism*
to use and *non-secret* configuration for it.

| Stored | Never stored |
| --- | --- |
| `CredentialMechanism` enum | Access keys, secret keys, session tokens |
| Role ARN, service account email, trusted profile ID | Client secrets, certificates, private keys |
| **Names** of environment variables holding secrets | The values of those variables |
| Region allowlist, scope ID | Refresh tokens, SSO tokens |

Supported mechanisms per provider are enumerated in
[domain-model.md](../domain-model.md) §3.1 and map to each vendor's own recommended chain: default
credential chains, role assumption, workload identity federation, managed/instance identity, service
account impersonation, and trusted profiles.

Four enforcement layers, because one is never enough:

1. **Schema allowlist** — permitted keys, types, and patterns per mechanism; unknown keys rejected
   with `422`.
2. **Secret screening** — every string value is checked against known credential patterns and an
   entropy threshold. Rejections never echo the offending value back in the error.
3. **No read-back** — flagged fields are omitted from API responses and from all exports.
4. **Redaction on egress** — the logging filter and the `ScanError` writer scrub credential-shaped
   strings, because provider SDK exceptions can quote request headers and signatures.

`external_id` (AWS confused-deputy protection) is treated as secret-adjacent: accepted only as an
environment variable *name*, never as a literal.

Resolved credential objects live only inside an SDK client in the worker. They are never serialized,
cached to disk, attached to exceptions, or passed to any function outside `providers/`.

## Rejected alternatives

- **Encrypted credential storage in our database.** The standard answer, and it converts the product
  into a credential vault: the encryption key must live somewhere the application can reach, so a
  full application compromise yields plaintext. Storing nothing is categorically stronger than
  storing something encrypted, and we can afford it because we are self-hosted next to the
  operator's own identity infrastructure.
- **Integrating an external secret manager** (Vault, cloud secret managers) to fetch credentials at
  scan time. Better than storing them ourselves, but it makes a secret manager a hard dependency for
  every deployment and still routes plaintext secrets through our process. The environment-variable
  and workload-identity paths already integrate with secret managers *at the deployment layer*,
  where the operator chooses the tool.
- **A hosted MultiCloudShield that assumes cross-account roles.** Not the product ([vision.md](../../product/vision.md) §3).
- **Accepting credentials as API parameters for convenience.** They would be logged by proxies,
  appear in shell history, land in CI logs, and end up pasted into issues. The API rejects
  secret-shaped input by design.
- **Per-connection credentials supplied at scan time via the API.** Same exposure as above, plus it
  would make scheduled scans impossible later.

## Consequences

- **Setup is less convenient than a SaaS.** Connecting a cloud means configuring the worker's
  environment or identity, not pasting a key into a form. This is the deliberate trade, and the
  documentation must make the setup path excellent to compensate — per-provider guides with the exact
  least-privilege role definition.
- One worker process holds credentials for **all** connections in its environment. Documented as a
  deployment consideration: operators needing separation between estates should run separate workers.
  The mechanism (env var names per connection) already supports that.
- Credential rotation is entirely the operator's, handled by their existing tooling. We never hold a
  stale credential.
- The connectivity test becomes essential: without stored credentials, "is this configured
  correctly?" cannot be answered by inspecting a database row. It must be answered by attempting a
  real read and reporting `ok` / `degraded` / `failed` with specifics.
- A worker compromise yields exactly the cloud access the operator granted — which is why the
  least-privilege documentation and per-collector permission declarations
  ([ADR-0007](0007-provider-adapter-contract.md)) are security controls, not nice-to-haves.
