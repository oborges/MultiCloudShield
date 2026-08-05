# ADR-0010: Determinism contract and recorded evidence

Status: accepted
Date: 2026-08-05

## Context

Two requirements interact: findings must be deterministic and reproducible from collected facts, and
every finding must carry evidence explaining it.

Handled naively these are separate features — evaluation logic, plus an "evidence" field the policy
author fills in. That design fails predictably: the evidence drifts from the logic as the policy is
edited, evidence quality varies per contributor, and authors dump whole resource payloads into the
field because it is easier than selecting the relevant facts.

Determinism handled naively also fails: a policy that reads the clock, iterates an unordered set, or
consults an environment variable produces different findings on different runs, and nobody notices
until an operator asks why a finding appeared and vanished.

## Decision

**Evidence is a by-product of evaluation, not an input to it, and evaluation is a pure function.**

### Evidence by recording

Policies receive facts through a `FactView` proxy that records every attribute access. When the
verdict is produced, the recorded access set *is* the evidence.

```python
def evaluate(facts: FactView[ObjectStorageBucketFacts]) -> Verdict:
    if facts.public_read_access is TriState.UNKNOWN:
        return Verdict.insufficient_data("BUCKET_ACL_UNREADABLE")
    if facts.public_read_access is TriState.YES:
        return Verdict.fail("PUBLIC_READ_ALLOWED")
    return Verdict.pass_()
```

Evidence for the FAIL is exactly `{"public_read_access": "yes"}`. Combined with the adapter's
call-recorder (which API calls produced those facts, with parameters allowlisted and responses
reduced to digests), `Evidence` is complete provenance that no human authored.

Three consequences fall out at no cost: evidence can never contradict the logic, evidence is minimal
by construction, and `requires_facts` is **verifiable** — a conformance test compares declared facts
against actually-accessed facts and fails on undeclared reads.

### Determinism contract

> Given identical `facts`, `policy_bundle_version`, and `engine_version`, evaluation MUST produce
> identical `result`, `reason_code`, `severity`, and `observed_facts`.

Enforced by construction, not by convention:

- No I/O in evaluation: no network, clock, filesystem, environment, or randomness. A lint rule bans
  those imports inside `policy/bundle/`, and `FactView` is the only argument.
- Collections are sorted before iteration, so multi-item verdicts are order-stable.
- Severity adjustment, where used, is a declared pure function of declared facts.
- Canonical JSON (sorted keys, RFC 3339 UTC) for `Evidence.content_digest`, so digests match across
  machines.
- A CI job replays a frozen fact corpus twice and diffs against a committed golden file. Any
  difference fails the build.

Timestamps live on `Scan` and `Evidence` (`collected_at`), never inside evaluation logic.

The contract begins **at the facts**. Collection is not deterministic — the cloud changes between
scans, and pretending otherwise would be a lie. Facts-onward is the boundary where reproducibility is
both meaningful and achievable, and it is the boundary at which a disputed finding is actually
re-litigated.

## Rejected alternatives

- **Author-written evidence strings.** Drifts from logic, varies in quality, and tempts authors to
  paste entire payloads. Rejected as the primary mechanism; a policy may add a short human-readable
  `detail` string, but it supplements the recorded facts and never replaces them.
- **Storing the full raw provider payload as evidence.** Complete, and wrong: it warehouses customer
  cloud metadata we have no need for, enlarges the blast radius of a database compromise, and buries
  the one relevant fact in a thousand irrelevant ones. Response digests give provenance without the
  payload.
- **Re-fetching from the cloud to explain a finding on demand.** The cloud has changed by then, so it
  explains a *different* state than the one that produced the finding — the opposite of evidence.
- **Hash-chaining or signing evidence for tamper-evidence.** Genuine value against forged evidence,
  but in v0.1.0 the database is trusted infrastructure and the signing key would live beside the data
  it protects, which is theatre. `content_digest` gives integrity checking against accidental
  corruption and a foundation for real signing later.
- **Determinism enforced only by code review.** Nondeterminism is invisible in review and obvious in
  a golden-file diff. Automate it.

## Consequences

- `FactView` adds an indirection on every fact read. Irrelevant at MVP scale (thousands of
  evaluations per scan, in-memory attribute access).
- Policies cannot consult anything outside their facts. If a policy needs more data, the *collector*
  must provide it as a fact — which is the correct place for that requirement to surface, and the
  place where its permission cost becomes visible.
- The frozen fact corpus must be maintained as fact schemas evolve. It doubles as regression
  protection: a change in evaluation output for unchanged facts is always intentional and always
  visible in review.
- Findings can be recomputed from stored facts without touching any cloud, which makes policy
  changes safely reviewable ("what would this edit do to existing findings?") — a capability that
  becomes a post-MVP feature almost for free.
