# ADR-0007: Provider adapter contract

Status: accepted
Date: 2026-08-05

## Context

Four providers with genuinely different APIs, authentication models, scoping hierarchies, error
vocabularies, and pagination styles must feed one engine. Requirements: provider SDK calls wrapped
behind stable internal interfaces; no provider representation in the core domain; a failed provider,
scope, or call must not crash a scan; new collectors addable without touching unrelated modules; and
no cloud write operation anywhere in the codebase.

The design pressure is to let "just this one" provider concept leak into the engine — a region
string that is really an Azure location, an ARN used as a primary key, a boto3 exception caught in
shared code. Each leak is individually harmless and collectively fatal to the abstraction.

## Decision

Three narrow interfaces, none of which exposes an SDK type. Full signatures and lifecycle in
[provider-adapters.md](../provider-adapters.md).

```python
class ProviderAdapter(Protocol):
    provider: CloudProvider
    def describe_capabilities(self) -> ProviderCapabilities: ...
    def resolve_scopes(self, conn: ConnectionDescriptor) -> list[ScanScope]: ...
    def verify_access(self, conn: ConnectionDescriptor) -> CapabilityReport: ...
    def collectors(self) -> list[Collector]: ...

class Collector(Protocol):
    id: str                       # "aws.s3.buckets"
    version: str
    produces: frozenset[NormalizedResourceType]
    scope_kind: ScopeKind         # global | region | location | …
    required_permissions: tuple[str, ...]
    def collect(self, ctx: CollectionContext) -> Iterator[RawObservation]: ...

class Normalizer(Protocol):
    accepts: str                  # provider_resource_type
    produces: NormalizedResourceType
    def normalize(self, obs: RawObservation) -> NormalizedAsset: ...
```

Load-bearing properties:

1. **`collect` yields, it does not return a list.** Streaming keeps memory bounded on large estates
   and lets the orchestrator apply cancellation and page caps between items.
2. **Collectors do not persist, evaluate, log business events, or retry.** Retry, backoff, timeout,
   concurrency, cancellation, and error classification live in the orchestrator. A collector is a
   paginated read plus a yield, which is why collectors are easy to contribute and easy to review.
3. **Errors are raised as adapter exceptions and classified by the adapter**, into the shared
   `ScanErrorCategory` taxonomy. Provider exception types never escape the `providers/` package —
   the orchestrator has no `except ClientError`.
4. **`required_permissions` is declared, not documented.** It drives the connectivity test, the
   generated least-privilege policy documents, and the coverage matrix, so those cannot drift.
5. **`ProviderCapabilities` makes asymmetry explicit.** An adapter declares what it supports; the
   coverage matrix is generated from it. A provider that lacks an equivalent concept declares that,
   rather than shipping a hollow collector.
6. **Read-only is structural.** `CollectionContext` exposes SDK clients through a wrapper that
   allowlists operation names against a registry of read operations. An unlisted operation raises
   before any request is made. A CI check additionally greps the provider packages for mutating
   verbs. Two independent controls, because a policy statement alone would not survive contributors.

`CollectionContext` carries: resolved SDK clients, the scope, a deadline, a cancellation token, a
call-recorder for provenance, and a page-budget. It carries **no** database session and **no**
policy access.

## Rejected alternatives

- **One generic "cloud client" abstraction over all four SDKs.** Attractive, and it always collapses:
  the abstraction ends up shaped like whichever provider was implemented first (invariably AWS), and
  the others get bent to fit. Adapters that share only a *contract*, not an implementation, are the
  honest structure.
- **Provider-agnostic bulk inventory APIs only** (AWS Config / Azure Resource Graph / GCP Cloud Asset
  Inventory / IBM Global Search). Fewer calls and less pagination, but they require additional
  enablement or permissions the operator may not have, their coverage of security-relevant
  sub-resources is incomplete (bucket policy status, trail status, key rotation), and they differ
  enough per provider that they do not actually unify anything. Kept as a **post-MVP optimization
  behind the same `Collector` interface**, which the contract permits without change.
- **Collectors owning their own retry and pagination.** Four inconsistent implementations, four
  places to fix a throttling bug, and no central place to enforce budgets or cancellation.
- **Returning provider payloads directly to the engine and normalizing at query time.** Would put
  provider-shaped data in the database and provider knowledge in the policy engine — precisely the
  leak this ADR exists to prevent.
- **A plugin system loading adapters from arbitrary paths in v0.1.0.** An adapter is executable code
  with cloud credentials in scope; loading untrusted ones is a supply-chain decision we are not ready
  to make. Entry-point discovery is defined in [ADR-0021](0021-extension-mechanism.md) with an
  explicit trust statement.

## Consequences

- Four adapters means four implementations of pagination-shaped code. Accepted: shared helpers
  (`paginate()`, `classify_error()`) reduce duplication without forcing a false abstraction.
- Adding a collector touches exactly three places: the collector, its normalizer, and the registry
  entry. Nothing in the engine changes. This is the modularity requirement, made concrete.
- Adapter conformance is testable generically: one parameterized suite runs every registered adapter
  against contract invariants (yields typed observations, classifies errors, honours cancellation,
  declares permissions, produces valid URNs, performs no writes).
- The orchestrator cannot special-case a provider — it has no provider-specific types to branch on.
  Provider quirks must be solved inside the adapter, which is where they belong.
- Provider-specific facts still reach policies, but only through the declared
  `facts.provider_specific.<provider>.…` namespace ([ADR-0008](0008-normalized-asset-and-fact-model.md)),
  so the escape hatch is auditable rather than ad hoc.
