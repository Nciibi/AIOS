# RFC-NNNN: Title

| Property | Value |
|----------|-------|
| Type | [Constitutional \| Bible \| Architecture \| Feature \| Bugfix \| Clerical] |
| Status | Draft |
| Priority | [Standard \| Critical] |
| Author | [your_identity_id] |
| Source Law(s) | [Law(s) this RFC derives from] |
| Source Physics | [Physics document(s) affected] |
| Supersedes | [RFC-NNNN if applicable, or Nothing] |
| Superseded By | [RFC-NNNN if applicable, or Nothing] |
| Created | [YYYY-MM-DD] |
| Amended By | [RFC-NNNN if applicable, or Nothing] |

## Problem Statement

Describe the problem this RFC solves. Include:
- What is the current state?
- What is wrong or missing?
- Who is affected?
- What evidence supports the need for change?

## Proposed Solution

Describe the proposed change. Include:
- What is the new state after implementation?
- How does this solve the problem?
- What alternatives were considered and rejected? (R10)

## Impact Analysis

### Affected Documents
- [List Bible documents, Standards, or Reference docs that need changes]

### Affected Services
- [List services/code that need changes]

### Breaking Changes
- [Yes/No — if Yes, describe migration below]

## Evidence

List the evidence supporting this RFC:
- [Academy analysis results]
- [Incident reports or gap analysis]
- [Reference implementation or prototype]
- [Test results or performance data]

## Constitutional Review

### Law Compliance
- Does this RFC violate any Law? [Yes/No — explain]
- Does this RFC require a Law amendment? [Yes/No — explain]
- Does this RFC require a Physics change? [Yes/No — explain]

### Design DNA Compliance

| Rule | Assessment |
|------|------------|
| R1 — Modulsingularity | [How does this respect single responsibility?] |
| R2 — Dependency Order | [Does this maintain acyclic dependencies?] |
| R3 — DRY | [Is every concept defined once?] |
| R4 — Builder Pattern | [Is construction separate from use?] |
| R5 — Liskov Substitution | [Are interfaces substitutable?] |
| R6 — Dependency Injection | [Are dependencies injected?] |
| R7 — Tests Exist | [What tests will be added/changed?] |
| R8 — Fast Tests | [Are tests within time limits?] |
| R9 — Deterministic | [Are results deterministic?] |
| R10 — Simpler Over Complex | [Why is this the simplest valid solution?] |
| R11 — Refactor over Rewrite | [Is this a refactor or a rewrite?] |
| R12 — Embrace Errors | [Are new error codes defined?] |
| R13 — Design for Failure | [What happens when dependencies fail?] |
| R14 — Paved Path | [Does this define or follow the paved path?] |
| R15 — Open/Closed | [Is this open for extension, closed for modification?] |

## Migration Plan

*Required only for breaking changes. Otherwise: N/A.*

- Migration steps
- Backward compatibility period
- Rollback plan
- Verification after migration

---

## Review Notes

*This section is filled by the Security Council during review.*

### Review Outcome
- [Approved \| Rejected \| Amendments Required]
- Reviewer: [identity_id]
- Date: [YYYY-MM-DD]

### Conditions
- [Any conditions or amendments required]

### ADG Review Outcome (Architecture RFCs only)
- [ADG reference / outcome]

---

## Changelog

| Version | Date | Author | Change Description |
|---------|------|--------|-------------------|
| 1.0 | [YYYY-MM-DD] | [Author] | Initial submission |
| | | | |
| | | | |

---

*This template follows the format defined in Bible/01-Governance/003-CRP.md.*
