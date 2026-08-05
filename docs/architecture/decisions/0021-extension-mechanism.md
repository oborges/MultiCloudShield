# ADR-0021: Registries plus Python entry points

Status: accepted
Date: 2026-08-05

## Context

The system must accept new collectors, providers, policies, and exporters without modifying unrelated
modules. It must also not become a plugin system that loads arbitrary code into the process holding
cloud credentials.

## Decision

**Four typed registries, populated by explicit in-tree registration and — for out-of-tree code —
Python entry points, with an explicit trust statement.**

| Extension point | Contract | Registered by |
| --- | --- | --- |
| Provider adapter | `ProviderAdapter` | `multicloudshield.providers` entry point |
| Collector | `Collector` | Declared by its adapter's `collectors()` |
| Normalizer | `Normalizer` | Keyed on `(provider_resource_type → NormalizedResourceType)` |
| Policy | `policy.yaml` + `evaluate()` | Discovered by directory scan within a bundle |
| Exporter | `Exporter` | `multicloudshield.exporters` entry point |

Registry rules:

- **Validation at load, not at use.** Duplicate IDs, missing normalizers for a declared `produces`
  type, a policy declaring an unknown fact path, or a provider-specific fact read by an
  all-provider policy all fail at startup. A malformed extension never reaches a scan.
- **Registries are read-only after startup.** No dynamic registration at request or scan time, so the
  set of loadable code is fixed and inspectable.
- **Loading is opt-in for out-of-tree code.** By default only first-party entry points from the
  installed package are loaded. Third-party discovery requires `MCS_ALLOW_THIRD_PARTY_PLUGINS=true`,
  which logs a prominent warning at startup and records the loaded plugin set in every `Scan`.
- **Adding an extension touches only its own files plus one registry entry.** Nothing in the engine
  changes ([ADR-0007](0007-provider-adapter-contract.md) §7).

### The trust statement, stated plainly

**A provider adapter and a policy bundle are executable code running in the process that holds cloud
credentials.** There is no sandbox in v0.1.0. Installing a third-party adapter or bundle is exactly as
consequential as installing any Python dependency, and the documentation says so in those words rather
than implying that "plugin" means "contained".

The policy purity constraints ([ADR-0010](0010-determinism-and-evidence.md)) make policy code far
easier to review than adapter code — banned imports, a single argument, no I/O — but they are a review
aid, not a security boundary. **CEL is the intended path to genuinely safe user-authored policies**
([ADR-0009](0009-policy-representation.md)).

## Rejected alternatives

- **Loading plugins from a configured directory path by default.** A directory that anything can write
  to becomes code execution in a credential-holding process. Entry points at least require a
  deliberate package installation.
- **Dynamic import by module name from configuration.** Turns a configuration value into an arbitrary
  import — a classic escalation from configuration access to code execution.
- **A subprocess or WASM sandbox for third-party extensions in v0.1.0.** The right long-term answer for
  untrusted policies, and unjustifiable now: v0.1.0 ships only first-party extensions, so the sandbox
  would protect against nothing while adding a serialization boundary to every fact access.
- **Automatic discovery of any installed package matching `multicloudshield-*`.** Naming-based
  discovery is a dependency-confusion vector — and PEP 708, which would have standardized an
  index-priority defence, was **rejected on 2026-04-02**, so no standard mitigation exists.
- **A configuration-driven plugin manifest listing modules to import.** Equivalent to dynamic import,
  with extra indirection.
- **Requiring all extensions to be in-tree.** Would keep the trust story simple and defeat the purpose
  of an open-source, extensible CSPM. The entry-point mechanism plus an explicit opt-in flag is the
  balance.

## Consequences

- v0.1.0 effectively ships a closed extension set; the mechanism exists and is documented, but
  third-party loading is off by default.
- Contributors add providers, collectors, and policies **in-tree**, which is what we want at this
  stage: it gets them reviewed, tested, and covered by the conformance suite.
- Startup does slightly more work (registry validation). Milliseconds, and it converts a class of
  runtime failures into startup failures.
- The `Scan` record includes the loaded plugin set, so a finding produced with a third-party extension
  is identifiable after the fact.
- A future sandbox is not blocked: the `Collector` and policy contracts are narrow enough to serialize
  across a process boundary if that becomes necessary.
