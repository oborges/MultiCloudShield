# ADR-0012: Org-scoped RBAC with a tenancy seam

Status: accepted
Date: 2026-08-05

## Context

v0.1.0 is a single-organization, self-hosted product. Building full multi-tenancy now would be
speculative work on unvalidated requirements. Building *no* tenancy concept would make multi-tenancy
a rewrite later, because tenant scoping cannot be retrofitted onto queries without auditing every
one of them.

We also need real authorization within the single organization: a scan costs cloud API calls, and
finding status changes are audit history. Not everyone with access should be able to do either.

## Decision

**Three roles, and an `organization_id` seam enforced at the repository layer from the first
migration.**

### Roles

| Capability | `owner` | `analyst` | `viewer` |
| --- | --- | --- | --- |
| Read assets, findings, scans, policies; export | ✅ | ✅ | ✅ |
| Start / cancel scans | ✅ | ✅ | ❌ |
| Change finding status (reason required) | ✅ | ✅ | ❌ |
| Create / edit / test / delete connections | ✅ | ❌ | ❌ |
| Manage users and API tokens | ✅ | ❌ | ❌ |

Three roles, not five: each exists because a real person needs exactly it. `viewer` is for an auditor
or stakeholder who must not spend cloud API quota or alter triage history. `analyst` is the daily
security engineer. `owner` is the administrator. A fourth role would be speculation.

### The tenancy seam

Every tenant-scoped table carries `organization_id` from the first migration, and every repository
method that touches one **requires an `OrgScope` argument**:

```python
class FindingRepository:
    async def list(self, scope: OrgScope, filters: FindingFilters, cursor: Cursor) -> Page[Finding]:
        stmt = select(FindingRow).where(FindingRow.organization_id == scope.organization_id, ...)
```

`OrgScope` is constructed only by the authentication dependency from the resolved principal. There is
no default, no `None`, and no unscoped variant — omitting it is a type error, not a security bug that
review must catch.

Enforcement is two-layered: route-level RBAC dependency **and** repository-level scoping. Route
checks are the ones forgotten when a new endpoint is added; repository scoping is the backstop.

Cross-organization access returns `404`, not `403` — we do not confirm the existence of another
tenant's objects.

## Rejected alternatives

- **No tenancy concept in v0.1.0; add later.** Retrofitting requires auditing every query, every
  index, and every API path — exactly the migration that never gets done safely. The column plus the
  required argument costs almost nothing now.
- **Full multi-tenancy in v0.1.0** (org provisioning, invitations, cross-org admin, per-tenant
  quotas, RLS). Weeks of work on requirements nobody has validated, and it would expand the threat
  model considerably. The seam preserves the option without paying for it.
- **PostgreSQL row-level security now.** The strongest control, and the right end state. It requires a
  per-request session variable, careful interaction with connection pooling, a separate migration
  role, and thorough testing to avoid a false sense of protection. Deferred to post-MVP, and named as
  such in [security-boundaries.md](../security-boundaries.md) §4 rather than implied.
- **Per-connection authorization** (user X may only see AWS account Y). A real requirement for
  consultancies, but it multiplies the authorization matrix and every filter path. v0.1.0 keeps
  authorization at the organization level; per-connection scoping is post-MVP.
- **Attribute/policy-based authorization (Casbin, OPA).** Vastly more machinery than six capabilities
  across three roles need.
- **Unguessable UUIDs as the access control mechanism.** UUIDv4 identifiers are used, but they are
  defence in depth, not authorization. Every fetch is authorized ([threat-model.md](../threat-model.md) §T7).

## Consequences

- We must be honest in documentation that v0.1.0's tenant isolation is application-layer only, and
  that mutually distrusting parties should get separate deployments. This is stated normatively in
  [security-boundaries.md](../security-boundaries.md) §4 rather than left to inference.
- A single `Organization` row is created at bootstrap. Org creation endpoints do not exist.
- Every new tenant-scoped table must include `organization_id` and its repository must take
  `OrgScope`. A CI check asserts that every model inheriting `TenantScoped` has the column and a
  composite index leading with it.
- Adding RLS later is a migration plus a session-variable hook, not a query audit, because the column
  and the scoping discipline already exist.
