# Security Policy

MultiCloudShield is a security tool that runs with read access to cloud environments. We take its
own security seriously, and we would rather hear about a problem early and awkwardly than late and
publicly.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through [GitHub Security Advisories](https://github.com/oborges/MultiCloudShield/security/advisories/new).
If that is unavailable to you, open a public issue containing only the words "security report,
requesting private contact" and no details, and a maintainer will arrange a private channel.

Please include, as far as you can:

- affected version or commit, and component (API, worker, CLI, dashboard, a provider adapter, a policy);
- impact — what an attacker gains, and what access they need to start;
- reproduction steps or a proof of concept;
- configuration required (deployment mode, provider, authentication method).

**Never include real cloud credentials, real account identifiers, or customer data in a report.**
Redact them, or reproduce against demo mode (`mcs scan --local --provider demo`), which needs no
cloud access.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or documented mitigation for critical/high | 30 days from confirmation |
| Public advisory | After a fix is available, coordinated with you |

This is a volunteer-maintained open-source project. These are honest targets, not a contractual SLA.
If a target slips, we will tell you where things stand rather than go quiet.

We support **coordinated disclosure** and will credit you in the advisory unless you prefer
otherwise. We do not operate a paid bug bounty.

## Scope

### In scope

- Authentication, session handling, API token handling, and authorization/RBAC bypass.
- Cross-organization or cross-connection data exposure.
- Injection of any kind (SQL, command, template, log, CSV/spreadsheet formula).
- Exposure of cloud credentials or credential references in logs, errors, exports, or API responses.
- Server-side request forgery, or any path that lets user input control an outbound request target.
- Insecure direct object references.
- Any code path that performs a **write** operation against a customer cloud. v0.1.0 must have none;
  finding one is a valid and high-severity report.
- Evidence or scan-provenance forgery — anything letting a finding claim facts that were not observed.
- Denial of service through unbounded scans, pagination, exports, or request handling.
- Unsafe deserialization, dependency or supply-chain issues in our build and release pipeline.
- Container configuration weaknesses in our published Dockerfiles and Compose files.
- Dashboard security issues: XSS, CSRF, clickjacking, unsafe rendering of provider-supplied strings.
- CI/CD workflow weaknesses that could expose secrets or allow unauthorized releases.

### Out of scope

- Vulnerabilities in AWS, Azure, Google Cloud, or IBM Cloud themselves — report those to the provider.
- Misconfiguration of *your* deployment (exposing the API to the internet without TLS, granting the
  scanner write permissions, running as root against our documentation).
- A policy producing a false positive or false negative. That is a correctness bug — please open a
  normal issue with the fixture that reproduces it.
- Missing hardening that is documented as out of scope for v0.1.0 (see below).
- Social engineering, physical attacks, or attacks requiring a compromised maintainer account.
- Reports from automated scanners with no demonstrated impact.
- Absence of rate limiting on endpoints that require authentication and are not resource-intensive.

### Known and accepted limitations in v0.1.0

These are deliberate design decisions, documented in
[docs/architecture/security-boundaries.md](docs/architecture/security-boundaries.md) §4. Reporting
them as vulnerabilities is welcome as *feedback*, but they are not treated as new findings.

- **Tenant isolation is application-layer only.** There is no PostgreSQL row-level security. v0.1.0
  supports a single organization; run separate deployments for mutually distrusting parties.
- **The worker process holds cloud credentials for all connections in its environment.** Compromise
  of the worker yields exactly the cloud access the operator granted — hence the emphasis on
  least-privilege roles.
- **Policy bundles and provider adapters are executable code** and are trusted. Only install bundles
  you trust.
- **No MFA in-product.** Deferred to OIDC SSO post-MVP.
- **Scan cancellation is best-effort**, bounded by the per-call timeout.

## Our security model in brief

Full detail in [docs/architecture/threat-model.md](docs/architecture/threat-model.md) and
[docs/architecture/security-boundaries.md](docs/architecture/security-boundaries.md). The properties
we commit to:

1. **Read-only.** No code path in v0.1.0 performs a cloud mutation. This is enforced by an operation
   allowlist in the adapter layer and by a CI check, not by convention. Remediation guidance is text
   you review and run yourself.
2. **No cloud secrets are stored.** We store which credential mechanism to use and non-secret
   references (role ARNs, service account emails, environment variable *names*). The API rejects
   secret-shaped input.
3. **Process separation.** The API process has no cloud credentials and no cloud egress. The worker
   process accepts no user requests.
4. **Provider data is untrusted.** Every provider response is strictly parsed, size- and depth-capped,
   and treated as attacker-controlled — because a resource name, tag, or IAM document can be.
5. **Redaction on egress.** Logs, errors, and exports pass through a redaction filter.
6. **Unknown is not safe.** Facts we cannot read are `unknown` and produce `insufficient_data`, never
   a silent pass.

## Deploying MultiCloudShield securely

- Grant the **minimum** read-only permissions. Per-collector permission requirements are in
  [docs/planning/provider-coverage-matrix.md](docs/planning/provider-coverage-matrix.md); the
  connectivity test reports exactly what is missing.
- Do not expose the API directly to the internet. Put it behind a reverse proxy with TLS.
- Provide cloud credentials to the **worker** service only, via your own secret management. Never
  put them in the API service's environment — the API asserts this at startup and refuses to run.
- Use workload identity, instance identity, or role assumption rather than long-lived keys wherever
  the provider supports it.
- Restrict worker egress to the provider API domains listed in the deployment documentation.
- Keep the deployment updated; watch releases for security advisories.
- Treat the database as sensitive: it holds your complete cloud inventory and posture, which is a
  map of your weaknesses even though it holds no credentials.

## Supported versions

Until v1.0.0, only the **latest release** receives security fixes. Backports to older 0.x releases
are not provided.

| Version | Supported |
| --- | --- |
| Latest 0.x release | ✅ |
| Older 0.x releases | ❌ |
| `main` branch | Best effort — not intended for production |

## Security in our development process

- Dependencies are pinned with hashes and scanned for known vulnerabilities on every pull request.
- Third-party GitHub Actions are pinned to commit SHAs; workflow tokens are least-privilege; fork
  pull requests never receive repository secrets.
- An SBOM is generated for each release.
- Containers run as a non-root user with no build toolchain in the runtime layer.
- No live cloud credentials exist in CI. All provider tests run against recorded fixtures or demo mode.
- Automated secret scanning runs on the repository; a credential-pattern check runs over fixtures and
  test data specifically, since fixtures are the most common place for a real identifier to slip in.
