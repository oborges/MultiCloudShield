# Adding policies, collectors, and providers

## Policy

Add validated metadata to `src/multicloudshield/policy/bundle/catalog.yaml`, choose only facts in the
typed fact model, and add pass, fail, not-applicable, and unknown tests. Policy evaluation is pure:
no filesystem, network, clock, environment, dynamic imports, or arbitrary expressions.

## Collector

Implement the `Collector` protocol in the provider package. Declare the exact resource types and
read permissions, wrap SDK clients in the reviewed operation allowlist, call `ctx.checkpoint()` and
`ctx.budget.add_page()`, normalize errors, and return `RawObservation` with bounded provenance. Add
pagination, denial, malformed-response, timeout, and cancellation tests and update the provider guide.

## Provider

Implement `ProviderAdapter`, keep SDK imports lazy, use the official native credential chain, register
the adapter in `providers/registry.py`, and document fixed API domains and least privileges. A new
provider changes the public compatibility surface and requires an ADR and coverage-matrix update.
