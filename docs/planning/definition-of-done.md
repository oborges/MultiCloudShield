# Definition of Done

Status: accepted for v0.1.0
Last updated: 2026-08-05

"Done" means merged, verified, and safe to build on. Three levels apply: every change, every phase,
and the v0.1.0 release. Per-feature behaviour is in
[acceptance-criteria.md](acceptance-criteria.md); this document is the process gate.

---

## 1. Every change (pull request)

A change is not done until all of the following hold. Items marked **(CI)** are enforced
automatically; the rest are reviewer responsibilities.

### Correctness

- [ ] Implements exactly one coherent change. Unrelated refactors go in a separate pull request.
- [ ] All new behaviour is covered by tests that fail without the change **(CI: coverage delta)**.
- [ ] Existing tests pass **(CI)**.
- [ ] Error paths are handled, not just the happy path — particularly partial failure, permission
      denied, and empty results.
- [ ] No `TODO` without a linked issue **(CI)**.

### Code quality

- [ ] Formatting and linting clean **(CI)**.
- [ ] Static typing clean, in strict mode, with no new `# type: ignore` lacking a reason comment **(CI)**.
- [ ] Module dependency rules respected — `core`/`facts` import nothing above them; `api` imports no
      provider SDK; `policy` imports no provider or persistence code **(CI: import-linter)**.
- [ ] Naming, comment density, and idiom match the surrounding code.
- [ ] Everything in English: identifiers, filenames, comments, docs, UI copy, commit message.

### Security

- [ ] No secret, credential, token, or real cloud account identifier in code, tests, fixtures, or
      documentation **(CI: secret scan + fixture credential-pattern check)**.
- [ ] No new cloud write/mutation call **(CI: read-only operation allowlist + mutating-verb check)**.
- [ ] User- and provider-supplied input is validated at the boundary it enters.
- [ ] New log statements pass through the redaction filter and contain no payloads, credential
      references, or principal identifiers in the message body.
- [ ] New API endpoints declare authentication, authorization role, and use an `OrgScope`-requiring
      repository **(CI: route-authorization audit test)**.
- [ ] New dependencies are justified in the pull request description and pass the vulnerability
      scan **(CI)**.

### Documentation

- [ ] Public behaviour change reflected in `README.md`, the relevant `docs/` page, or CLI help.
- [ ] Architectural change (stack, public contract, security control, tenancy) has an ADR **(CI: ADR index check)**.
- [ ] New configuration is documented with its default, valid range, and effect.
- [ ] New policy ships with metadata, original prose, fixtures for pass/fail/insufficient-data, and
      declared `required_permissions`.

### Verification

- [ ] The author ran the change and observed it working, not only its tests. For API changes, a real
      request; for UI changes, the actual view; for engine changes, a demo scan.
- [ ] For engine or adapter changes, `mcs scan --local --provider demo` still completes and produces
      the expected finding count **(CI)**.

---

## 2. Every phase

A phase is done when the repository is in a **working, demonstrable state** — someone can clone it,
follow the README, and see the phase's capability. A phase that leaves the repository broken is not
done, regardless of how much code it landed.

- [ ] All pull requests in the phase meet §1.
- [ ] The phase's acceptance criteria in [acceptance-criteria.md](acceptance-criteria.md) are
      demonstrably met, with the evidence named in the implementation plan captured (command output,
      screenshot, or test run).
- [ ] `docker compose up` produces a running system; the documented demo workflow succeeds on a clean
      machine from a fresh clone.
- [ ] Migrations apply cleanly forward from empty **and** from the previous phase's schema, and each
      new migration has a tested downgrade or an explicit note that it is irreversible.
- [ ] No regression in the golden-file determinism corpus; any intentional change to it is reviewed
      as a behaviour change, not a fixture update.
- [ ] The risk register is reviewed; risks that closed are marked, new ones are added.
- [ ] Documentation is consistent with the code as it now exists — no doc describing an unbuilt
      behaviour in the present tense.

---

## 3. v0.1.0 release

### Functional

- [ ] All items marked **In (v0.1.0)** in [mvp-scope.md](../product/mvp-scope.md) are implemented.
- [ ] All four providers plus demo have at least one working collector and one policy, with actual
      coverage recorded in [provider-coverage-matrix.md](provider-coverage-matrix.md) — including
      what was cut and why.
- [ ] A newcomer reaches populated demo findings for four providers in under 10 minutes on a clean
      machine, verified by someone who did not write the documentation.
- [ ] Every dashboard view has designed empty, loading, partial-failure, and error states.
- [ ] JSON and CSV exports validate against their documented schemas and carry a provenance block.
- [ ] The CLI works in both remote and `--local` modes, with documented exit codes.

### Quality

- [ ] Test coverage at or above the agreed threshold on `core`, `facts`, `policy`, and `engine` — the
      modules where a bug produces a wrong security verdict.
- [ ] Adapter conformance suite passes for all five adapters.
- [ ] Determinism test passes: two runs over the frozen fact corpus are byte-identical.
- [ ] **Regression gate:** a scan in which every target fails resolves zero findings and marks none
      as passed. This test is a release blocker (see risk R-15).
- [ ] Fault-injection test passes: worker killed mid-scan, scan recovers without duplicate assets,
      evaluations, or findings.
- [ ] Load check: a 10 000-asset synthetic estate completes within the scan deadline without
      unbounded memory growth.
- [ ] End-to-end test passes: demo connection → scan → findings visible in the dashboard.

### Security

- [ ] Threat model reviewed against the implementation; every mitigation marked "implemented" has a
      test or a structural control naming it.
- [ ] Confirmed by code inspection **and** automated check: no cloud write path exists.
- [ ] Confirmed: no cloud credential is persisted, logged, exported, or returned by the API.
- [ ] Dependency vulnerability scan clean, or every exception documented with a rationale and expiry.
- [ ] Container image scan clean at high/critical, running as non-root.
- [ ] SBOM generated and attached to the release.
- [ ] `SECURITY.md` reporting channel verified to work.

### Documentation and release hygiene

- [ ] `README.md` describes what exists, with no aspirational feature in the present tense.
- [ ] Per-provider setup guides include the exact least-privilege role definition, generated from the
      collectors' declared permissions.
- [ ] `CLAUDE.md`, `CONTRIBUTING.md`, and `SECURITY.md` reflect the shipped system.
- [ ] Every ADR is `accepted` or explicitly `superseded`; none left `proposed`.
- [ ] All limitations in [mvp-scope.md](../product/mvp-scope.md) and
      [security-boundaries.md](../architecture/security-boundaries.md) §4 are stated in user-facing
      docs, not only in architecture docs.
- [ ] Tagged `v0.1.0` with release notes covering features, known limitations, and upgrade notes.
- [ ] Licence and third-party attributions correct.

---

## 4. What "done" explicitly does not require

Stated so these are not used to block a release:

- 100% test coverage. High coverage on the security-critical modules; pragmatic elsewhere.
- Every provider having equal coverage. Asymmetry is expected and recorded
  ([ADR-0008](../architecture/decisions/0008-normalized-asset-and-fact-model.md)).
- Performance tuning beyond the documented bounds.
- Published container images or a Helm chart — post-MVP.
- Zero known issues. Known and documented beats unknown; an issue list is honest.
