# Contributing to MultiCloudShield

Thank you for considering it. This is a security tool, so a few rules are stricter than you may be used
to — each one exists because of a specific way security tools fail.

**Everything in this repository is in English**: identifiers, filenames, comments, documentation, UI
copy, and commit messages.

---

## Current state

The repository is in **planning and architecture**. There is no application code yet.

The most useful contributions right now are reviews of the architecture — particularly if you have
operated a CSPM, run large multi-cloud estates, or have hit one of the provider quirks documented in
[provider-adapters.md](docs/architecture/provider-adapters.md).

Once implementation starts, [implementation-plan.md](docs/planning/implementation-plan.md) is the
ordered work list. Phases 8–11 (the four provider adapters) and Phase 12 (policies) are genuinely
parallel and are the natural place to start.

## Where to start

| You want to | Read | Then |
| --- | --- | --- |
| Add a policy | [policy-engine.md](docs/architecture/policy-engine.md) §7 | The most self-contained contribution. No cloud account needed |
| Add a collector | [provider-adapters.md](docs/architecture/provider-adapters.md) §7 | Three files change; nothing in the engine does |
| Add a provider | [provider-adapters.md](docs/architecture/provider-adapters.md) §6 | Start with an ADR |
| Fix a false positive | [policy-engine.md](docs/architecture/policy-engine.md) §6 | Open an issue with the fixture that reproduces it |
| Change the stack | [decisions/](docs/architecture/decisions/) | An ADR probably rejected it already, with reasons. If those reasons are wrong, say why |

**You do not need a cloud account to contribute.** Demo mode and fixture-based tests cover everything:
`mcs scan --local --provider demo` runs the full pipeline with no server, no database, and no network.

---

## Setup

```bash
git clone https://github.com/oborges/MultiCloudShield.git
cd MultiCloudShield
uv sync                      # installs Python and dependencies
uv run pre-commit install
docker compose up -d db
uv run alembic upgrade head
uv run pytest
```

Requires [uv](https://docs.astral.sh/uv/) and Docker. uv manages the Python version, so you do not need
to install one.

---

## The rules that matter

Nine things that will get a pull request rejected regardless of how good the code is.

1. **No cloud write operations.** v0.1.0 has no code path that mutates a customer's cloud. This is
   enforced by an operation allowlist and CI checks, not by trust. Remediation guidance is text the
   user runs themselves.
2. **No credentials anywhere.** Not in code, tests, fixtures, or documentation. Not real account IDs,
   ARNs, subscription GUIDs, or project IDs either. **Fixtures are where this actually happens** — CI
   checks them specifically, and the cassette recorder scrubs automatically, but check your own diff.
3. **Unknown is never a pass.** A fact you could not read is `TriState.UNKNOWN` and produces
   `insufficient_data`. Defaulting to `False` gives silent false negatives; defaulting to `True` gives
   alert fatigue. Both are worse than admitting ignorance, and the honest answer tells the user which
   permission to grant.
4. **Never resolve a finding without positive evidence.** A `PASS` on a *succeeded* target, or absence
   confirmed by a *successful* full collection. Never from `insufficient_data`, a failed target, or a
   cancelled scan.
5. **Provider data is untrusted.** An attacker who can create a resource in a scanned account controls
   the strings that reach our normalizer, database, UI, and exports. Parse strictly, cap size and
   depth, escape at every sink.
6. **No external framework control text.** Compliance mappings carry identifiers and *your own* note.
   No CIS, ISO, PCI, or AICPA prose — the licences do not permit it
   ([ADR-0024](docs/architecture/decisions/0024-compliance-mapping-policy.md)).
7. **Policies are pure.** No network, filesystem, clock, environment, or randomness. Enforced by lint.
8. **No new infrastructure.** PostgreSQL is the only backing service. No Redis, Kafka, Elasticsearch,
   or Kubernetes.
9. **Architectural changes need an ADR.** Stack, public contracts, security controls, tenancy.

---

## Writing a policy

The most valuable contribution, and the most self-contained. Full walkthrough in
[policy-engine.md](docs/architecture/policy-engine.md).

```
policy/bundle/<domain>/<name>/
    policy.yaml     # metadata — all prose original
    evaluate.py     # def evaluate(facts: FactView[...]) -> Verdict
    fixtures/       # pass, fail, insufficient_data (all three required)
    test_policy.py
```

```python
def evaluate(facts: FactView[ObjectStorageBucketFacts]) -> Verdict:
    if facts.public_read_access is TriState.UNKNOWN:      # unknown first, always
        return Verdict.insufficient_data("BUCKET_ACL_UNREADABLE")
    if facts.public_read_access is TriState.YES:
        return Verdict.fail("PUBLIC_READ_ALLOWED")
    return Verdict.pass_()
```

Review checklist, beyond the code:

- Is `unknown` handled **before** the failure branch?
- Does the severity match the [rubric](docs/architecture/domain-model.md) §6.3?
- Is the remediation something a platform engineer could actually follow, including the permission it
  requires?
- Could this fire on a legitimate configuration? If so, does the rationale say so? A public bucket may
  be a static website.
- Is every word yours?

If the facts you need do not exist yet, extend the fact schema and the collectors **first**. That is
where the permission cost of a check becomes visible, which is exactly where it should surface.

---

## Pull requests

**One coherent change.** Unrelated refactors go in a separate pull request.

Before opening:

```bash
uv run ruff format . && uv run ruff check --fix .
uv run mypy src
uv run lint-imports
uv run pytest
uv run mcs scan --local --provider demo     # for engine or adapter changes
```

Your description should say what changed, why, how you verified it, and — for a new dependency — its
licence and maintenance status. Rejecting a dependency for a thin bus factor is a normal outcome here.

CI runs format, lint, strict typing, module dependency rules, unit, policy, determinism, adapter
conformance, integration, API, Schemathesis, frontend, demo end-to-end, dependency audit, secret scan,
fixture credential check, and the read-only proof. It is a long list; each check prevents a specific
failure, and it runs entirely offline with no cloud credentials, so fork pull requests get the full
suite.

**One CI result needs care:** if the **determinism golden file** changes, that means findings on real
estates will change. Explain why in the pull request. Do not update it as though it were a fixture.

Commits use [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `docs`,
`refactor`, `test`, `chore`, `ci`, `perf`, `build`. Scope with the module (`feat(providers/aws): …`).

By contributing you agree your work is licensed under the [MIT Licence](LICENSE).

---

## Reporting issues

**Security vulnerabilities: do not open a public issue.** Follow [SECURITY.md](SECURITY.md).

**A false positive or false negative** is a correctness bug and a normal issue — please include the
fact fixture that reproduces it, or the sanitized provider response. These are among the most valuable
reports we can receive; a security tool that cries wolf gets muted, and a muted tool has negative
value.

**Feature requests** — check [backlog.md](docs/planning/backlog.md) first. Many things are deliberately
deferred with a reason, and §5 lists what is explicitly not planned. If a reason is wrong, that is a
useful conversation; if the item is simply unscheduled, a comment on its priority helps.

## Code of conduct

Be decent. Assume good faith. Critique the design, not the person. Maintainers may remove content and
contributors who make this an unpleasant place to work.
