# ADR-0008: Normalized asset and fact model

Status: accepted
Date: 2026-08-05

## Context

The product's core value is answering one question across four clouds — "which of my resources are
exposed?" — instead of four vendor-specific questions. That requires a shared asset model. But cloud
concepts are not isomorphic: an S3 bucket, an Azure storage account with containers, a GCS bucket,
and an IBM COS bucket differ in granularity, in access-control model, and in what is even knowable.

Two failure modes bracket the design. Over-normalize, and facts become lowest-common-denominator
booleans that lose the information a security engineer needs. Under-normalize, and every policy is
provider-specific and the shared model is decorative.

## Decision

**A three-part model: a small normalized taxonomy, typed fact schemas with explicit unknowns, and a
declared provider-specific namespace.** Full definitions in
[domain-model.md](../domain-model.md) §5.

1. **`NormalizedResourceType`** — a deliberately small enum, one entry per area we actually collect
   (`object_storage.bucket`, `network.firewall_ruleset`, `identity.principal`,
   `logging.audit_trail`, `kms.key`, `account.scope`, …). Speculative taxonomy entries are not added.
   Policies dispatch on this, never on `provider_resource_type`.

2. **Typed `AssetFacts` per resource type**, versioned Pydantic models. Every field a policy may read
   is declared here. Provider payloads are validated into these models at the normalization boundary.

3. **`TriState` (`yes` / `no` / `unknown`) instead of `bool`** for every security-relevant fact, and
   `EncryptionPosture` (`none` / `provider_managed` / `customer_managed` / `unknown`) instead of a
   boolean "encrypted".

4. **`facts.provider_specific.<provider>.<service>.<field>`** — a typed, namespaced sub-model for
   concepts with no cross-provider analogue. A policy reading one must declare it in `requires_facts`
   **and** narrow `provider_applicability`; the loader rejects a policy that reads a provider-specific
   fact while claiming to apply to all providers.

5. **`asset_urn`** — `mcs:{provider}:{scope_id}:{resource_type}:{provider_local_id}` — the stable
   identity used for upsert, finding fingerprints, and cross-scan continuity. Built from
   provider-stable identifiers only: never a display name, an IP, or a tag.

### Why `TriState` is the central decision

A boolean cannot distinguish "not public" from "we could not read whether it is public". Both
collapses are harmful in opposite directions: `unknown → False` yields silent false negatives (the
tool says you are safe when it does not know), and `unknown → True` yields false positives that
train operators to ignore the tool. `unknown` propagates to
`EvaluationResult.insufficient_data`, which the UI surfaces as a permission gap with the exact
missing IAM action.

This is what makes least-privilege credentials safe to recommend. A tool that silently passes on
unreadable resources punishes operators for granting narrow permissions; this one tells them
precisely what to grant.

## Rejected alternatives

- **Store raw provider payloads and let policies query them (JSONPath/JMESPath).** Fast to build; it
  is the design of several existing scanners. But every policy becomes provider-specific, the
  cross-cloud question is unanswerable, provider API changes break policies directly with no
  translation layer to absorb them, and we would be warehousing customer cloud metadata we do not
  need (see [domain-model.md](../domain-model.md) §9).
- **A universal resource schema (one model for all resource types).** Becomes a bag of optional
  fields, defeats typing, and makes dispatch dynamic and unverifiable.
- **Booleans with a separate `unreadable_fields` set.** Same information, but the unknown state is
  now something every policy author must remember to check, and forgetting it silently produces a
  wrong verdict. `TriState` makes the check unavoidable — the type system enforces it.
- **Provider-specific facts as an untyped `dict[str, Any]`.** Convenient, unverifiable, silently
  misspelled, and it would let provider concepts spread without review. The typed namespace costs a
  little friction and buys auditability.
- **Composite natural key `(provider, scope, type, id)` instead of a URN string.** Equivalent
  information, but a single canonical string is far easier to index, log, export, deduplicate, and
  paste into a support conversation.
- **Deriving normalized facts lazily at query time.** Would make findings non-reproducible: the same
  scan re-read later could yield different facts as the derivation code changed. Normalization must
  happen once, at collection time, and be stored.

## Consequences

- Adding a collector usually means extending a fact schema, which is a versioned, reviewed change.
  This friction is intentional — the fact schema is the contract policies depend on.
- Fact schemas are versioned (`schema_version`). Adding an optional field is backward compatible;
  changing a field's meaning requires a version bump and a migration decision for stored facts.
- Adapters must explicitly populate `unknown` rather than omitting fields. Adapter conformance tests
  assert that every declared fact is either populated or explicitly `unknown` — silence is a bug.
- Some genuinely valuable provider-specific checks will exist (S3 Block Public Access, GCS uniform
  bucket-level access). They are first-class, not second-class, and the coverage matrix shows them as
  provider-specific rather than pretending the other clouds have an equivalent.
- Cross-provider queries ("all public storage") work by construction, which is the point.
