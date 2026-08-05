# ADR-0028: Upgrade the compatible frontend toolchain to Vite 8

Status: accepted
Date: 2026-08-05
Supersedes: the frontend version baseline in ADR-0027

## Context

Vite 8 and `@vitejs/plugin-react` 6 became available after the v0.1.0 implementation baseline was
locked. Dependabot proposed them independently, but each isolated update failed because plugin-react
6 requires Vite 8. Updating only those two then exposed a second type conflict: Vitest 3 embeds Vite
7 types, which are not assignable to Vite 8's Rolldown-based plugin types.

TypeScript 7 was proposed at the same time, but `typescript-eslint` 8.66 supports TypeScript only
below 6.1. Its independent update fails strict npm resolution and the production container build.

## Decision

Upgrade the build and test toolchain as one compatible unit:

- Vite 8.2
- `@vitejs/plugin-react` 6.0.5
- Vitest 4.1

Keep TypeScript on 5.9 and `typescript-eslint` on 8.x until their declared peer ranges support a
newer TypeScript line. Do not bypass peer constraints in installation or CI.

## Verification

The combined dependency graph passes strict `npm ci`, ESLint, five Vitest tests, the TypeScript
project build, the Vite production build, `npm audit --audit-level=high`, and the multi-stage
production container build.

## Consequences

- Vite and Vitest share compatible Vite 8 plugin types.
- The build uses Vite 8's Rolldown-based pipeline; product behavior and browser support remain
  unchanged.
- Major frontend-tool updates must continue to be tested as a compatible set rather than merged only
  because each package was proposed independently.
- TypeScript 7 remains explicitly blocked, not ignored or installed with relaxed peer resolution.
