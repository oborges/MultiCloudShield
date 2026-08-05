# ADR-0009: Declarative metadata plus Python predicates

Status: accepted
Date: 2026-08-05

## Context

Policies must be testable without a cloud account, carry rich metadata (severity, applicability,
references, remediation, compliance mappings), be contributable by cloud security engineers, and
produce deterministic results.

Four candidate representations: pure Python, declarative YAML/JSON DSL, Rego/OPA, or a hybrid. This is
the decision most likely to be revisited by a contributor, so the reasoning is recorded in detail.

### Prior art, verified by reading the repositories (2026-08-05)

| Tool | Representation |
| --- | --- |
| **Prowler** (14.5k★, active) | **Python check class + sibling JSON metadata file** — `<check_id>.py` with an `execute()` returning PASS/FAIL, plus `<check_id>.metadata.json` carrying severity, resource type, risk, and remediation |
| **CloudSploit/Aqua** (3.8k★) | JavaScript plugin module per check, with a colocated spec file |
| **ScoutSuite** (dormant — no commits for ~10 months) | Declarative JSON DSL: a nested boolean condition tree over a normalized resource tree, with `_ARG_n_` templating |
| **Cloud Custodian** (6k★, 1.7k open issues) | YAML `policies:` with `filters:`/`actions:`, where filter types are registered Python plugins |
| **Steampipe/Powerpipe** | HCL control blocks wrapping raw PostgreSQL SQL over `jsonb` |

**Nobody in this space uses Rego.** The two patterns that have scaled are *code plus structured
metadata* and *declarative data*. Prowler's split — metadata file carries severity, mappings, and
remediation; code carries only the predicate — is the pattern that has scaled furthest.

## Decision

**Hybrid: declarative YAML metadata + a pure Python `evaluate()` function**, one directory per policy.

```
policy/bundle/storage/public_read/
    policy.yaml       # id, version, title, description, rationale, severity + rubric cell,
                      # provider/resource applicability, requires_facts, references,
                      # remediation, compliance mappings, origin
    evaluate.py       # def evaluate(facts: FactView[...]) -> Verdict
    fixtures/         # pass.yaml, fail.yaml, insufficient_data.yaml, not_applicable.yaml
    test_policy.py
```

```python
def evaluate(facts: FactView[ObjectStorageBucketFacts]) -> Verdict:
    if facts.public_read_access is TriState.UNKNOWN:
        return Verdict.insufficient_data("BUCKET_ACL_UNREADABLE")
    if facts.public_read_access is TriState.YES:
        return Verdict.fail("PUBLIC_READ_ALLOWED")
    return Verdict.pass_()
```

Constraints on the Python half, enforced rather than requested:

- Signature is exactly `(FactView) -> Verdict`. No other arguments exist, so there is nothing else to
  reach for.
- **Purity is enforced by lint**: network, filesystem, clock, environment, and randomness imports are
  banned inside `policy/bundle/` ([ADR-0010](0010-determinism-and-evidence.md)).
- `requires_facts` is **verified against actual `FactView` access** in tests; reading an undeclared
  fact fails CI.
- Helper predicates (`allows_public_ingress`, `port_range_includes`, `is_admin_port`) keep typical
  policies to a handful of lines, so the common case is nearly as terse as a DSL.

Metadata is separate and declarative because it must be machine-readable without executing code: the
API serves the policy catalog from it, the dashboard renders it, the coverage matrix is generated
from it, and a reviewer can audit compliance mappings without reading Python.

## Rejected alternatives

- **Pure Python, metadata in decorators or class attributes.** Simplest to write, but metadata
  becomes unreadable without importing the module, which makes the catalog harder to render, harder
  to validate, and harder to review. Prowler's split exists for this reason.
- **Pure declarative YAML/JSON DSL** (ScoutSuite, Cloud Custodian). Genuinely attractive: safe,
  contributable by non-programmers, trivially sandboxed. Rejected because every such DSL hits an
  expressiveness ceiling and then grows a bad programming language — conditionals, then negation,
  then quantifiers over rule lists, then arithmetic on port ranges. Our checks already need "any
  ingress rule whose port range intersects an administrative port and whose source is
  internet-routable", which is where these DSLs start to hurt. The sharper signal: **ScoutSuite, the
  purest DSL implementation, has had no commits in roughly ten months.**
- **Rego/OPA.** The strongest theoretical fit — purpose-built for policy, sandboxed, portable. The
  Python integration story kills it:
  - **No official Python SDK.** OPA's own integration documentation lists REST, Go SDK, Go package,
    WASM, and IR. Python is absent.
  - `opa eval` subprocess: ships a ~50 MB per-architecture binary and pays process spawn per
    evaluation.
  - OPA server: adds a second process/container — **directly violates the no-extra-infrastructure
    constraint**.
  - WASM: `opa-wasm` on PyPI was **last released 2022-02-11**. Unmaintained.
  - `regorus` (Microsoft, Rust): Python bindings exist but the README states they are **not published
    to PyPI** and must be built manually.
  - `regopy` 1.5.2 is the only real `pip install` option, and it wraps `microsoft/rego-cpp` — **47
    stars**. That is too thin a bus factor for the component that decides whether a bucket is public.
  Adopting Rego means operating a sidecar we said we would not, or betting correctness on a 47-star
  C++ binding. Reconsider if a maintained pure-Python Rego appears, or if third-party policy
  portability becomes a real user requirement.
- **CEL (`cel-python` 0.5.0).** Sandboxed, non-Turing-complete, Google/Kubernetes-blessed, pure
  Python, and a good fit for *user-authored* expressions. Rejected as the primary representation
  because it is a second language for first-party policies with no compensating benefit, and its last
  release was ~6 months ago. **Retained as the intended mechanism for user-defined policies
  post-MVP** ([mvp-scope.md](../../product/mvp-scope.md) §5).
  *Supply-chain note for whoever implements this: the package is `cel-python` and the import is
  `celpy`. The PyPI package literally named `celpy` is an unrelated squat.*
- **JMESPath/JSONPath predicates over raw payloads.** JMESPath is well-maintained and already the AWS
  query lingua franca, so contributors know it. Rejected as the primary representation because it
  implies policies query **provider-shaped payloads**, which is exactly the leak
  [ADR-0008](0008-normalized-asset-and-fact-model.md) exists to prevent. Reconsider only as a
  convenience layer over normalized facts.
- **SQL over stored facts** (Steampipe's model). Elegant, and our storage shape would support it. But
  it couples policy evaluation to the database, which breaks `mcs scan --local`
  ([ADR-0025](0025-stateless-local-scan-mode.md)), makes offline policy unit tests require
  PostgreSQL, and makes purity/determinism much harder to enforce.
- **JSONLogic.** The maintained-Python-implementation question answers itself: the available packages
  were last released in 2018 and 2021.

## Consequences

- **A policy bundle is executable code.** This is the significant cost. Only first-party bundles ship
  in v0.1.0; loading external bundles is opt-in with an explicit trust statement
  ([security-boundaries.md](../security-boundaries.md) §8), and the purity constraints make review
  tractable. CEL is the intended path to safe user-authored policies.
- Policy authors need Python. Acceptable — the target contributor is a cloud security engineer, and
  the helper predicates keep most policies to three or four lines.
- Full typing over fact schemas: mypy catches a policy reading a field that does not exist, which a
  YAML DSL would only discover at runtime on a customer's estate.
- Metadata validation happens at bundle load, so a malformed policy fails at startup, not mid-scan.
- The metadata layer is representation-independent. If a future engine replaces Python predicates,
  `policy.yaml`, the fixtures, and the compliance mappings survive unchanged.
