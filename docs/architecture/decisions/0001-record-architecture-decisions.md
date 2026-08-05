# ADR-0001: Record architecture decisions

Status: accepted
Date: 2026-08-05

## Context

MultiCloudShield is an open-source project intended to accept contributions that add providers,
collectors, and policies. Contributors need to know not only what the architecture is, but why
alternatives were rejected — otherwise every rejected option is re-proposed, and the reasoning is
reconstructed from memory or lost with the original author.

The project also makes several decisions that look unusual without their context (no SQLite, an
in-repo job queue, `TriState` instead of booleans, demo mode as a real adapter). Those are exactly
the decisions that get "cleaned up" by a well-meaning contributor if the reasoning is not recorded.

## Decision

Use lightweight Architecture Decision Records in `docs/architecture/decisions/`, numbered
sequentially, in the form: context → decision → rejected alternatives → consequences.

- One decision per ADR. If it needs two decisions, it is two ADRs.
- ADRs are immutable once accepted. Changing a decision means a new ADR that supersedes the old one,
  with both `Status` lines updated.
- **Rejected alternatives are mandatory**, with the actual reason for rejection. An ADR that lists no
  alternatives is documentation of a preference, not a decision.
- ADRs state consequences including the ones we dislike. An ADR with no downsides is not honest.
- Architecture documents carry the detail; ADRs carry the choice and its justification.

Any change to the technology stack, a public contract (adapter interface, policy interface, API
shape, fact schema), a security control, or the tenancy model requires an ADR before merge.

## Rejected alternatives

- **A single `ARCHITECTURE.md`.** Decisions get edited in place, so the history of *why* is destroyed
  by the next edit. Git history is a poor substitute — it records diffs, not rationale.
- **Wiki or issue-tracker discussions.** Not versioned with the code, not reviewable in a pull
  request, and lost if the project moves hosts.
- **Full MADR/Nygard-with-all-sections template.** The ceremony discourages writing them. We keep the
  two sections that carry the value (alternatives, consequences) and drop the rest.

## Consequences

- Reviewers can reject a pull request for "no ADR" on architectural changes, which is a legitimate
  and cheap gate.
- The ADR index in `README.md` must be updated with each new ADR; a CI check verifies every ADR file
  is indexed and every index row resolves to a file.
- Some ADRs will be short. That is fine — a three-paragraph ADR that names the rejected option is
  more valuable than a long one that does not.
