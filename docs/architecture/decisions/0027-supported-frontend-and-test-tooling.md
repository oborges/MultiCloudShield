# ADR-0027: Use supported dependency versions available to the locked build

Status: superseded by ADR-0028
Date: 2026-08-05
Supersedes: ADR-0014 and the HTTP-client selection in ADR-0017

## Context

The package versions projected during planning were not available from the configured public
registries during implementation. Specifically, TypeScript 6, Vite 8, Tailwind 4.3, and the
projected `httpx2` package could not be resolved into a reproducible lockfile. Waiting for future
artifacts would make v0.1.0 unbuildable. React Router 8.3 became available during the security audit
and was adopted because it also fixes GHSA-qwww-vcr4-c8h2.

## Decision

Keep the chosen architecture but lock the supported available lines: React 19, TanStack Query 5,
TypeScript 5.9, Vite 7, React Router 8.3, and plain CSS with design tokens. Python API tests use the
maintained `httpx` line required by Starlette/FastAPI tooling. No production HTTP client is added.

## Consequences

- The component, router, query, accessibility, and security boundaries are unchanged.
- The smaller CSS stack removes build-time styling dependencies.
- Major upgrades are dependency-update work, not product redesign, and require full frontend tests.
