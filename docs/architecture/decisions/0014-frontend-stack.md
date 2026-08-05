# ADR-0014: React, TypeScript, Vite, and a generated API client

Status: accepted
Date: 2026-08-05

## Context

A responsive dashboard with eleven views, filtering across seven dimensions, and four designed states
per view (empty, loading, partial failure, error). The API is the same team's; the client should not
be hand-written.

## Decision

**React 19.2 + TypeScript 6.0 + Vite 8.2 + TanStack Query 5 + React Router 8 + Tailwind CSS 4.3 +
shadcn/ui + Recharts 3.10, with the API client generated from OpenAPI.** Node 24 LTS. Versions
verified 2026-08-05.

| Concern | Choice | Why |
| --- | --- | --- |
| Framework | React 19.2.8 | Largest contributor pool; stable |
| Build | Vite 8.2.0 | Fast, boring, the default for React SPAs |
| Types | **TypeScript 6.0.3** | See below |
| Server state | TanStack Query 5.101 | Caching, polling for scan progress, request dedup — most of our state *is* server state |
| Routing | React Router 8.3 (declarative mode) | No SSR needed. Note `react-router-dom` no longer exists in v8; import from `react-router` |
| Styling | Tailwind CSS 4.3.3 via `@tailwindcss/vite` | CSS-first config, no PostCSS chain |
| Components | shadcn/ui, base **pinned** in `components.json` | Copy-in components, no runtime dependency churn |
| Charts | Recharts 3.10.1 | Declarative, SVG, actively maintained |
| API client | `openapi-typescript` + `openapi-fetch` + `openapi-react-query` | Types-only generation |
| E2E | `@playwright/test` 1.62 | Better fixtures, traces, parallelism than the Python runner |

### TypeScript 6, not 7 — deliberately

TypeScript **7.0 shipped 2026-07-08** as a native Go port advertised at ~10× faster. It is one month
old. Third-party tooling that hooks the compiler API (type-aware ESLint rules, custom transformers,
bundler plugins) has had one month to catch up.

"Prefer boring, mature, actively maintained technology" is a mandatory principle here, so v0.1.0
starts on **6.0.3**, the final stable JS-based line. **TypeScript 7 adoption is a tracked post-MVP
task**, not an accident of inertia — `typescript-eslint` 8.66 is already shipping actively, so the
migration is likely to be cheap within a few months. This is the one place where a reviewer could
reasonably argue the other way; the reasoning is recorded so the decision can be revisited on
evidence rather than re-litigated from scratch.

### Pin the shadcn/ui base

As of **July 2026, shadcn/ui changed its default primitive to Base UI**; Radix remains fully
supported and React Aria is also a first-class base. Because we are adopting shadcn *during* a
primitive transition, the base is **pinned explicitly in `components.json`** so later `shadcn add`
calls cannot mix Base UI and Radix components in one codebase.

If accessibility ever becomes a stated compliance requirement, `react-aria-components` (Adobe) offers
the strongest guarantees and is the documented migration target.

### Generated client

`openapi-typescript` consumes FastAPI's OpenAPI **3.1** output directly and emits **types only** — no
generated runtime code to review, a ~6 kB fetch wrapper, and clean composition with TanStack Query.
Generation runs in CI and the result is diffed: a backend schema change that breaks the frontend
fails the build rather than production.

`orval` was the close second (it generates TanStack Query hooks and MSW mocks directly, with a more
active release cadence). Rejected because generated hooks are code we would have to review and own;
types-only is the smaller commitment. `@hey-api/openapi-ts` is feature-rich but still 0.x.

### Serving

The SPA is built to static assets and **served by the API in production**. One origin, so no CORS, no
second deployment unit, and the `__Host-` cookie prefix ([ADR-0011](0011-authentication-model.md))
works. Development uses Vite's dev server with a proxy to the API.

## Rejected alternatives

- **Server-rendered templates (Jinja) with htmx.** Genuinely tempting: less JavaScript, no build step,
  fewer dependencies. Rejected because the dashboard's core interaction is multi-dimensional
  filtering with shareable URL state and periodic scan-progress polling — client-side state that htmx
  would fight. Also, a generated typed client against our own OpenAPI is a real correctness win we
  would forgo.
- **Next.js.** SSR, routing conventions, and a server runtime we do not need for an authenticated
  internal dashboard. It would add a second server process to deploy.
- **Vue or Svelte.** Both fine; React's contributor pool is larger, which matters for an open-source
  project.
- **Remix.** Not the successor here: what was planned as Remix v3 shipped as React Router v7
  (framework mode), and Remix has since pivoted to a separate, non-React direction still in beta.
  **React Router is the continuation.**
- **TanStack Router.** Credible and better-typed, but React Router is the boring default with more
  answers available.
- **Chart.js.** Canvas-based (weaker accessibility and SSR), needs a React wrapper, and its last
  publish was ~10 months before this decision. **visx** is more powerful but far more code for the
  handful of charts we need.
- **Material UI / Ant Design.** Heavy runtime dependencies with opinionated design languages; shadcn's
  copy-in model gives us ownership of the components without a version-upgrade treadmill.
- **Tailwind 3.4.** Would avoid v4's migration, but v4 is stable and the CSS-first config is simpler.
  Note v4's browser floor (Safari 16.4+, Chrome 111+, Firefox 128+) and that `safelist` is
  unsupported — so we never build class names dynamically.

## Consequences

- A Node toolchain is required to build the frontend. The Dockerfile handles it in a build stage, so
  backend-only contributors never install Node.
- The generated client must be regenerated when the API changes; CI enforces it.
- Tailwind 4's browser floor excludes very old enterprise browsers. Documented; v3.4 is the fallback
  if a real user reports it.
- shadcn components are copied into the repository, so we own their maintenance. That is the trade
  for not depending on a component library's release cycle — and it means accessibility fixes are
  ours to make.
- TypeScript 7 remains an open follow-up with a documented rationale, not an oversight.
