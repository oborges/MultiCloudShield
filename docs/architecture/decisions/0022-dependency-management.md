# ADR-0022: uv lockfiles and reviewed update PRs

Status: accepted
Date: 2026-08-05

## Context

Two ecosystems (Python and npm), a security product whose users must be able to trust its build, and
OWASP Top 10:2025 ranking **A03 Software Supply Chain Failures** third. Dependency management is a
security control here, not housekeeping.

## Decision

**`uv` 0.12.x with a committed `uv.lock` for Python; `npm` with `package-lock.json` for the frontend;
Dependabot for updates; every update reviewed by a human.**

### uv

- Committed, cross-platform `uv.lock`; `uv sync --frozen` in CI and in the Docker build, so a build
  cannot silently resolve differently.
- uv manages the Python version too, which removes a class of "works on my machine" from CI and
  contributor setup.
- **Workspaces** are the intended path if `core` / `providers` / `api` are ever split into separate
  distributions — Cargo-style members sharing one root lockfile, which fits the modular monolith
  ([ADR-0002](0002-modular-monolith.md)) without requiring the split now.
- **Hash pinning** for the release build: `uv pip compile --generate-hashes` plus
  `pip install --require-hashes`. Note pip requires *every* transitive requirement to be hashed —
  "partial hashing is of little use and thus likely an error".

`uv` is still 0.x. Given its adoption and backing this reads as a versioning convention rather than an
instability signal, but the uv version itself is **pinned in CI**.

### Dependency confusion — no standard defence exists

**PEP 708 was rejected on 2026-04-02** after three years as provisionally accepted, so Python has no
standardized index-priority mechanism. Our operational defences:

- A **single `--index-url`**. `--extra-index-url` is never used — it is the mechanism that makes
  dependency confusion work.
- Hash pinning on release builds.
- Our own distribution name registered on PyPI defensively.

### Updates

**Dependabot**, grouped, weekly, covering Python, npm, GitHub Actions, and Docker base images.

**No auto-merge.** For a security tool, a dependency change is a supply-chain event: a maintainer
reads the changelog, checks the diff for anything surprising, and confirms CI. This is slower, and it
is the point.

Renovate is the documented alternative if PR volume across two ecosystems becomes genuinely noisy —
it offers better grouping and scheduling. Dependabot is the boring default because it is GitHub-native
with no infrastructure and contributors already understand it.

### Scanning

`pip-audit` (PyPA) on every pull request; **Trivy** on the container image, covering OS packages,
language dependencies, IaC, and secrets. A known vulnerability with no fix available is documented as
an exception with a rationale and an expiry date — never silently ignored.

### Adding a dependency

The pull request must state what it does, why a standard-library or existing solution is insufficient,
its licence, and its maintenance status (last release, open issue ratio, bus factor). Rejecting a
dependency for poor maintenance is a legitimate review outcome — the research behind
[ADR-0009](0009-policy-representation.md) rejected a Rego binding on exactly that basis (47 stars for
a component deciding whether a bucket is public).

## Rejected alternatives

- **Poetry.** Maintained and capable, with a slower release cadence and no Python-version management.
  uv is faster, does more, and has become the ecosystem default.
- **pip-tools.** Solid, but `requirements.txt`-only with no workspace or Python-version support.
- **PDM.** Capable, smaller community.
- **Unpinned ranges resolved at build time.** Non-reproducible builds. Disqualifying for a security
  product.
- **Vendoring dependencies.** Removes the update path and hides vulnerabilities from scanners.
- **Auto-merging patch updates.** The convenience is real and so is the risk: a malicious patch release
  is precisely how supply-chain attacks land. A human reads the diff.
- **Renovate from day one.** More capable and more configuration to maintain than a young project
  needs.

## Consequences

- Lockfiles are large and churn in diffs. Reviewers check the `pyproject.toml` / `package.json` intent
  and the lockfile's *shape*, not every transitive line.
- Weekly update PRs need maintainer attention. That is the cost of not auto-merging.
- Builds are reproducible: the same commit yields the same dependency set.
- The SBOM ([ADR-0019](0019-ci-cd.md)) is accurate because the lockfiles are authoritative.
- Contributors need `uv` installed; the contributing guide covers it in one command.

## Sources

Accessed 2026-08-05: [uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/);
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/);
[PEP 708 (rejected)](https://peps.python.org/pep-0708/); [OWASP Top 10:2025](https://owasp.org/Top10/2025/).
