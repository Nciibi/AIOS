# AIOS Contributing Guide
## 000 — How to Contribute

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Contributing |
| Document ID | CONTRIB-000 |
| Source Laws | Law 4 — Evidence, Law 9 — Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document is the entry point for anyone who wants to contribute to AIOS. It covers the contribution lifecycle, standards, workflow, and conventions for both documentation and code. Every contribution must comply with the AIOS Constitution, Physics, and Bible — these are not optional.

## Contribution Types

| Type | Description | RFC Required? |
|------|-------------|---------------|
| Bible document | New or amended specification in the Bible | Yes |
| Physics change | New or amended Law or invariant | Yes |
| Constitution change | Constitutional amendment | Yes (Article V) |
| RFC | Technical proposal | N/A (is the proposal itself) |
| Code | Implementation in Rust crates | No (must implement existing spec) |
| Tests | Unit, integration, property, or simulation tests | No |
| Bug fix | Defect correction | No (must reference issue) |
| Documentation fix | Typo, broken link, formatting | No |

## Getting Started

### 1. Understand the Architecture

Before contributing, read these foundational documents in order:

| Reading Order | Document | Purpose |
|---------------|----------|---------|
| 1 | Physics/000-Laws.md | The 10 universal invariants — everything derives from these |
| 2 | Bible/00-Foundations/001-AIOS-Philosophy.md | Core philosophy: constitutional AI, evidence-driven operations |
| 3 | Bible/00-Foundations/002-Design-DNA.md | The 15 Design DNA rules (R1–R15) |
| 4 | Bible/0000-Master-Architecture-Plan.md | Overall system map and volume structure |
| 5 | Bible/02-Core/Brain/000-Overview.md | The Brain — cognitive subsystem housing Sou |
| 6 | Bible/02-Core/Brain/Sou/000-Overview.md | Sou — the single constitutional intelligence |

### 2. Find Something to Work On

| Source | Description |
|--------|-------------|
| `RFC/` directory | Open RFCs seeking implementation |
| `Bible/10-Research/` | Research areas needing exploration |
| `ideas_suggest.md` | Documented suggestions for stub population |
| GitHub Issues | Bug reports and feature requests (if available) |
| `Research/` directory | Open research stubs needing content |

### 3. Understand the Doc Hierarchy

```
Constitution (immutable law)
    ↑
Physics (mathematical invariants)
    ↑
Bible (normative specifications)
    ↑
RFC (change proposals)
    ↑
Implementation (code)
```

Changes flow upward as RFCs, then propagate downward to Bible, and if necessary, to Physics or Constitution amendments.

## Documentation Standards

### Frontmatter

Every document starts with a frontmatter table:

```markdown
| Property | Value |
|----------|-------|
| Status | [Draft \| Active \| Deprecated \| Superseded] |
| Version | [SemVer] |
| Category | [Bible — {Volume} \| Physics \| RFC \| SDK \| Contributing \| Examples \| Tests] |
| Document ID | [Unique identifier per category] |
| Source Laws | [Law references] |
| Source Physics | [Physics document references] |
| Supersedes | [Previous document identifier or "Nothing"] |
| Superseded By | [Newer document identifier or "Nothing"] |
| Amended By | [How amendments are accepted, typically "RFC"] |
```

### Document ID Convention

| Prefix | Category | Example |
|--------|----------|---------|
| `AIOS-BBL-{VOL}-{PREFIX}-{NUM}` | Bible document | AIOS-BBL-003-ORG-000 |
| `AIOS-PHY-{NUM}` | Physics document | AIOS-PHY-000 |
| `SDK-{NAME}-{NUM}` | SDK document | SDK-RUNTIME-000 |
| `RFC-PROCESS-000` | RFC process | RFC-PROCESS-000 |
| `CONTRIB-{NUM}` | Contributing | CONTRIB-000 |
| `EXAMPLES-{NUM}` | Examples | EXAMPLES-000 |
| `TESTS-{NUM}` | Tests | TESTS-000 |
| `RESEARCH-{NUM}` | Research | RESEARCH-000 |

### Required Sections

| Section | Required? | Content |
|---------|-----------|---------|
| Purpose | Always | What this document defines and why it exists |
| Invariants / Rules | Always for specs | Enforceable truths the document establishes |
| Architecture / Structure | For specs | Component diagrams, data flow, interfaces |
| Cross-Cutting Concerns | For specs | Security, Evidence, Lifecycle, Capability Bounds, Design DNA, Interoperability |
| Related Documents | Always | Cross-reference table to related specs |
| Events | For engine specs | Event types the component produces |

### Cross-Reference Format

Always use relative paths from the `full plan bible/` root:

- `Bible/02-Core/Brain/Sou/000-Overview.md`
- `Physics/003-Organizations.md`
- `RFC/000-RFC-Process.md`

Never use absolute filesystem paths or URLs for internal references.

### ASCII Diagrams

Use box-drawing characters (`┌`, `─`, `┐`, `│`, `└`, `┘`, `├`, `┤`, `┬`, `┴`, `┼`) for architecture diagrams. Indent consistently. Keep diagrams under 80 columns wide.

## Contribution Workflow

```
1. Identify need (bug, feature, gap, RFC)
2. Review existing docs (avoid duplication)
3. Draft contribution
4. Self-review against standards in this guide
5. Submit for review
6. Address review feedback
7. Final approval
8. Merge
```

### Branch Naming

| Prefix | Purpose | Example |
|--------|---------|---------|
| `docs/` | Documentation changes | `docs/brain-autonomy-phase` |
| `rfc/` | RFC proposals | `rfc/0042-agent-marketplace` |
| `fix/` | Bug fixes | `fix/identity-uuid-collision` |
| `feat/` | Feature implementation | `feat/acf-streaming` |
| `test/` | Test additions | `test/security-pipeline-property` |

### Commit Messages

```
{type}({scope}): {short description}

{optional detailed description}

Ref: {issue or RFC reference}
```

Types: `docs`, `rfc`, `fix`, `feat`, `test`, `chore`, `audit`

### Review Requirements

| Contribution Type | Minimum Reviewers | Review Body |
|-------------------|-------------------|-------------|
| Physics change | 3 | Security Council |
| Constitution change | 5 | Constitutional Convention |
| Bible document | 2 | Subject matter experts |
| RFC | 3 | RFC Review Board |
| Code change | 1 | Code maintainer |
| Documentation fix | 1 | Editor |

## Design DNA Compliance

Every contribution must be reviewed against R1–R15 from `Bible/00-Foundations/002-Design-DNA.md`:

| Rule | Check |
|------|-------|
| R1 (Modulsingularity) | Does each document or module have a single responsibility? |
| R2 (Dependency Order) | Are dependencies acyclic? Does it reference downward? |
| R3 (DRY) | Does this duplicate existing content? Should it reference instead? |
| R4 (Builder Pattern) | Is construction separated from representation? |
| R5 (Liskov Substitution) | Can implementations substitute for interfaces? |
| R6 (DI over Singletons) | Are dependencies injected, not hardcoded? |
| R7 (Composition over Inheritance) | Does it compose behavior rather than extend classes? |
| R8 (Promise over Callback) | Are async boundaries clean? |
| R9 (Fail Closed) | Does it deny on uncertainty? |
| R10 (Simpler Over Complex) | Is this the simplest valid solution? |
| R11 (Testable Separately) | Can this be tested in isolation? |
| R12 (Embrace Errors) | Are errors unique, descriptive, and recoverable? |
| R13 (Design for Failure) | Does it degrade gracefully? |
| R14 (Paved Path) | Is there one clear way to do things? |
| R15 (Open for Extension) | Can future changes add without modifying existing code? |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/00-Foundations/000-Overview.md | Foundations overview — reading guide |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA rules — compliance required for all contributions |
| Bible/00-Foundations/007-Naming-Conventions.md | Naming conventions — file, code, identifier standards |
| Bible/01-Governance/003-CRP.md | Change Request Pipeline — RFC lifecycle |
| Bible/01-Governance/005-ADG.md | Architectural Decision Gateway |
| Bible/0007-Implementation-Roadmap.md | Implementation phases — priority areas |
| Bible/0010-Brain-Restructuring-Plan.md | Brain restructuring — active paradigm |
| RFC/000-RFC-Process.md | RFC process guide |
| ideas_suggest.md | Open suggestions for stub content |
| Bible/09-Reference/001-Glossary.md | AIOS terminology |
| Standards/000-Design-Language.md | Design language and conventions |
| Standards/001-Naming-Conventions.md | Naming standards |
| Standards/002-BAS.md | Bible Authoring Standards |
