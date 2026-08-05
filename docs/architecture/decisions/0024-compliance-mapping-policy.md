# ADR-0024: Compliance mappings reference identifiers only

Status: accepted
Date: 2026-08-05

## Context

Users want to know how findings relate to frameworks they are measured against — CIS Benchmarks,
NIST SP 800-53, ISO/IEC 27001, PCI DSS, SOC 2, CSA CCM. Mapping findings to controls is genuinely
useful.

It is also a licensing hazard, and the actual terms are more restrictive than the folklore. Verified
2026-08-05:

| Framework | Terms |
| --- | --- |
| **CIS Benchmarks** (non-member) | CC BY-**NC**-SA 4.0, *plus* Additional Use Restrictions that narrow it further: may not "sell, rent, lease, sublicense or otherwise transfer or exploit any rights" (B); **may not "post any Non-Member CIS Product on any website, bulletin board, ftp server, newsgroup"** (C); **may not "create any derivative work"** (E); **may not "represent or claim a particular level of compliance or consistency"** (G) |
| **CIS Controls** | CC BY-NC-**ND** 4.0 (no derivatives) |
| **PCI DSS 4.0.1** | The most restrictive of the set: licensed only to "view, download and print … solely for your own personal, non-commercial, review, study and informational purposes" |
| **ISO/IEC 27001:2022** | Fully copyrighted; "any use of ISO content, including copying in whole or in part, is prohibited" without permission; POCOSA forbids free public posting |
| **AICPA Trust Services Criteria** | Copyright, all rights reserved; permission required to reproduce |
| **CSA Cloud Controls Matrix 4.1** | Custom licence — free for internal use, but a licence is explicitly required to "leverage the CCM within your products" |
| **NIST** (SP 800-53 Rev. 5, CSF 2.0, SSDF) | **Public domain** — 17 U.S.C. §105; NIST requests but does not require attribution |
| **HIPAA** (45 CFR 160/164) | **Public domain** — US federal regulation |

The NC and ND terms are directly incompatible with an MIT-licensed repository, which by definition
permits commercial use and derivative works. Clause (C) prohibits the one thing an open-source
project must do — post the content on a website. Clause (G) prohibits the compliance-score feature
every CSPM is tempted to build.

Prior art, verified by reading the repositories:

- **ScoutSuite** (GPL-2.0) ships CIS rulesets containing only NCC-authored rule names plus a bare
  `"comment": "Recommendation 2.4"` pointer. Zero framework prose. **The conservative model.**
- **ComplianceAsCode** (BSD-3) splits cleanly: original `title`/`description`/`rationale` per rule,
  plus a `references:` block of bare identifiers across many frameworks at once
  (`cis@sle15: 1.1.1.1`, `nist: CM-7(a)`, `iso27001-2013: A.12.1.2`). **The best-engineered model.**
- **Prowler** (Apache-2.0) reproduces CIS `Description`/`RationaleStatement`/`RemediationProcedure`/
  `AuditProcedure` verbatim — and is listed on cisecurity.org as a CIS Product Vendor Member, which
  is very likely what makes that lawful. Prowler *also* reproduces ISO Annex A and AICPA TSC text,
  which a CIS membership does not cover. **Not safe precedent.**
- **Steampipe/Powerpipe** reproduces CIS Description/Rationale/Remediation with no CIS attribution or
  licence notice found in the repository. Legal basis unclear. **Not safe precedent.**

## Decision

**Store and display framework identifiers. Write all prose ourselves. Never reproduce control text.**
We follow the ComplianceAsCode pattern: one original policy, N framework identifier references, zero
framework prose.

```jsonc
{ "framework": "CIS_AWS_FOUNDATIONS", "framework_version": "7.0.0", "control_id": "1.14",
  "relationship": "supports",
  "note": "Our own sentence explaining why this check relates to that control." }
```

No control title, description, audit procedure, or remediation text. The UI renders
`CIS AWS Foundations 7.0.0 — 1.14` as a label, hyperlinked to the publisher's own page, which is also
where the authoritative current text lives.

Four supporting rules:

1. **`Policy.origin`** distinguishes `mcs_best_practice` (we think this check is valuable; mappings
   are advisory) from `external_control_derived` (the check exists because an external control
   expects it). Conflating them is how tools imply certification.
2. **`relationship`** is `supports` or `partially_supports` — never "complies with" or "satisfies".
   A configuration check is evidence toward a control, not fulfilment of it.
3. **No compliance score, percentage, or pass-rate per framework, anywhere.** CIS clause (G)
   explicitly prohibits representing "a particular level of compliance," and a percentage is the
   artefact that gets screenshotted out of context. We report per-policy results and coverage counts.
4. A `NOTICE` states that framework names are trademarks of their owners, that our descriptions are
   original works, and that we are not endorsed by or affiliated with CIS, PCI SSC, ISO, AICPA, or CSA.

**We apply this rule uniformly, including to NIST and HIPAA text that is public domain.** We are
permitted to ship NIST SP 800-53 control text and could treat that as a differentiator. We choose not
to in v0.1.0: one uniform rule is simpler to enforce in review, and a single consistent authorial
voice across the catalog is better product writing than a mixture of our prose and quoted federal
text. Adding public-domain NIST text later is a purely additive change, since identifiers and
versions are already stored — it is recorded in [backlog.md](../../planning/backlog.md), not lost.

Enforcement: a CI check flags policy metadata containing long strings matching known control-text
shapes, and pull requests adding mappings require reviewer confirmation that no external text was
copied.

## Rejected alternatives

- **Ship full control text for offline convenience.** Would require CIS SecureSuite Product Vendor
  Membership (paid) for CIS alone, and separate licences for ISO, AICPA, PCI, and CSA. Not viable for
  a volunteer open-source project, and shipping it *without* those licences is what two of the four
  prior-art tools appear to do.
- **Ship only frameworks with permissive terms** (NIST, HIPAA). Would exclude CIS and PCI — the
  frameworks users most want — while still requiring per-version legal review. Identifier-only
  mapping works uniformly across all of them.
- **No compliance mappings at all.** Safest, and it discards real user value that identifiers plus
  our own notes captures almost entirely.
- **Let users supply control text via configuration.** Moves the legal question onto the user without
  telling them. Worse than not offering it.
- **Report "compliant / non-compliant" per control.** A configuration scanner cannot determine
  compliance — controls include process, documentation, and scope decisions we cannot observe. It is
  also specifically prohibited by CIS clause (G).

## Consequences

- The compliance view is less immediately informative than a competitor's that embeds control text.
  We compensate with a well-written `note` per mapping and a link to the publisher.
- Mapping quality depends on our own writing, so mappings are reviewed like policy prose.
- Framework versions are explicit in every mapping, so a mapping to a superseded version (PCI DSS 4.0
  is retired; CIS AWS Foundations is at 7.0.0) is visible rather than silently stale.
- Adding a framework is metadata work with no licensing negotiation.
- **We forgo the compliance-percentage feature permanently under current CIS terms.** Product should
  not treat this as a gap to close.
- This is not legal advice. The interaction between CIS's CC BY-NC-SA grant and its Additional Use
  Restrictions, and the enforceability of bare-identifier citation, are the questions to put to
  counsel before v1.0. Bare identifiers and version numbers are short factual references rather than
  protected expression, and this is what the conservative prior art does — but CIS publishes no
  safe-harbour statement, so this remains a documented assumption
  ([risk-register.md](../../planning/risk-register.md) R-16).

## Sources

Accessed 2026-08-05. [CIS terms of use for non-member products](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products);
[CIS SecureSuite product vendor](https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor);
[PCI SSC terms and conditions](https://www.pcisecuritystandards.org/terms_and_conditions/);
[ISO copyright](https://www.iso.org/copyright.html) (retrieved via search index; direct fetch 403);
[AICPA 2017 TSC](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022);
[CSA CCM licensing FAQ](https://cloudsecurityalliance.org/artifacts/ccm-aicm-licensing-faq);
[NIST copyright](https://www.nist.gov/oism/copyrights); [17 U.S.C. §105](https://www.copyright.gov/title17/92chap1.html#105);
repositories of ScoutSuite, ComplianceAsCode/content, Prowler, and steampipe-mod-aws-compliance.
