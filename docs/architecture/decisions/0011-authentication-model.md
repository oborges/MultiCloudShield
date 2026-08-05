# ADR-0011: Sessions for humans, hashed tokens for machines

Status: accepted
Date: 2026-08-05

## Context

v0.1.0 is self-hosted and single-organization. Two very different principals need to authenticate: a
person using a dashboard in a browser, and a CLI or CI job. We must not build an identity provider,
and we must not require one.

## Decision

**Opaque server-side sessions in cookies for browsers; hashed high-entropy API tokens for machines;
a pluggable `AuthProvider` seam for OIDC later.** All parameters below are the current OWASP
recommendations, verified 2026-08-05.

### Passwords

**Argon2id with `m=19456` (19 MiB), `t=2`, `p=1`** — the OWASP Password Storage Cheat Sheet's stated
minimum configuration, used verbatim so the choice is citable rather than invented. Implementation:
`argon2-cffi`.

We do not pre-hash before Argon2id, so bcrypt's 72-byte truncation and password-shucking hazards do
not apply. Work factors are upgraded lazily at next login. Bootstrap refuses weak passwords and never
echoes them.

### Browser sessions

- Session ID from a CSPRNG, well above the 64-bit minimum (`secrets.token_urlsafe(32)`).
- Cookie: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, with the **`__Host-`
  prefix**.
- Server-side row in PostgreSQL → **revocation is immediate and correct**.
- Idle expiry 30 minutes, absolute expiry 8 hours, both configurable.
- **Session ID is regenerated on authentication and on any privilege change**, with the previous ID
  invalidated server-side.
- CSRF protection on all cookie-authenticated state-changing requests.
- Session lifecycle events are logged with a **salted hash** of the session ID, never the raw value.

### API tokens

Format `mcs_pat_<public_id>_<secret><checksum>`:

- 256 bits from a CSPRNG; shown exactly once at creation.
- Stored as **SHA-256**, not Argon2id. These are high-entropy random secrets, not human passwords, so
  a slow KDF buys nothing and prevents indexed lookup. The `public_id` provides O(1) lookup; the
  secret is compared in constant time.
- The `mcs_` prefix plus a trailing checksum follows GitHub's documented scheme (`ghp_`,
  `github_pat_`, …), which exists so that secret scanners can both **find** leaked tokens and reject
  false positives without an API call. We publish the pattern so scanners can detect leaks of our
  tokens.
- Role-scoped, optional expiry (default 90 days), revocable with immediate effect, `last_used_at`
  recorded. The token value is never logged.

### The OIDC seam

An `AuthProvider` interface exists from the first implementation with one backend (`local`). An
`oidc` backend is post-MVP. We ship **no** identity provider and require none.

When it lands, the documented options are **Keycloak** (36k★, releases monthly, Apache-2.0 — the
boring choice, heavy) and **Dex** (CNCF, Apache-2.0 — a federating proxy to an existing corporate
IdP, ideal as a bridge). Noted for whoever implements it: **Zitadel is AGPL-3.0**, which needs legal
review before being bundled or distributed in a compose file, and **Ory Hydra has no user database or
login UI** — it is an OAuth2 provider, not a drop-in IdP.

## Rejected alternatives

- **JWTs in the browser.** Rejected decisively. Revocation is the core problem: a stateless JWT
  cannot be invalidated before `exp`, and both remedies (a denylist or a status list) **reintroduce
  server-side state, which is the entire benefit JWT was supposed to provide**. OWASP's JWT cheat
  sheet additionally warns that keying a denylist on the raw token or `SHA-256(token)` is *not safe*
  due to JWT malleability, and documents real algorithm-confusion CVEs in Python libraries. Storing a
  token in `localStorage` makes it XSS-exfiltratable, whereas an `HttpOnly` cookie is unreachable
  from JavaScript. For one backend and one PostgreSQL, a session table is simpler *and* more secure.
- **JWTs for API tokens.** Same revocation problem, plus a much larger token, plus algorithm-choice
  footguns — for a token whose only job is to identify a CI job.
- **Requiring an external IdP in v0.1.0.** Would make the 10-minute quickstart impossible and add a
  hard dependency for a single-user deployment.
- **Building an identity provider.** Explicitly out of scope, and a category error.
- **Basic auth for the CLI.** Would require the user's password in CI, with no independent revocation
  and no scoping.
- **MFA in v0.1.0.** Deferred to the IdP once OIDC lands. Building TOTP now duplicates what operators
  already have and expands the account-recovery surface — which, without an email dependency, we are
  not equipped to handle well. Stated as a known limitation in
  [SECURITY.md](../../../SECURITY.md) rather than left implicit.
- **Password reset via email.** No mail dependency in v0.1.0; `owner` resets via CLI.

## Consequences

- Sessions require a database read per request. Trivial at this scale, and it is what makes immediate
  revocation possible.
- The session table needs periodic cleanup of expired rows — a maintenance job, not manual work.
- Users cannot self-serve password resets in v0.1.0; the CLI path is documented.
- No MFA until OIDC. Recorded as an accepted limitation.
- The `__Host-` cookie prefix requires the app to be served from a single origin over HTTPS, which
  matches the documented deployment (SPA served by the API behind a TLS-terminating proxy) and is why
  CORS is disabled by default.
- API tokens are bearer credentials: whoever holds one has that role. Mitigated by scoping, expiry,
  revocation, `last_used_at` visibility, and a scanner-detectable prefix.

## Sources

Accessed 2026-08-05: OWASP [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html),
and [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
cheat sheets; [GitHub token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github);
GitHub release/licence metadata for Keycloak, Authentik, Zitadel, Ory Hydra, and Dex.
