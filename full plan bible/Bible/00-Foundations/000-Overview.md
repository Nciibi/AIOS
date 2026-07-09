# AIOS Bible — Foundations
## 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-000 |
| Source Laws | All — Foundations interpret and operationalise every Law |
| Source Physics | All — Foundations abstract across all Physics documents |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Foundations is the root volume of the AIOS Bible. It defines the philosophical, architectural, and design principles that govern every decision, implementation, and operation within AIOS. Every other Bible volume builds on these foundations. Every RFC must be consistent with them.

## Structure

Foundations contains 10 documents:

| # | Document | Content | Reading Order |
|---|----------|---------|---------------|
| 000 | Overview (this file) | Map, purpose, relationship to Physics, reading guide | 1 |
| 001 | AIOS Philosophy | Constitutional AI, evidence-driven operations, entity autonomy | 2 |
| 002 | Design DNA | The 15 Design DNA rules (R1–R15) — normative reference | 3 |
| 003 | Core Principles | SOLID in AIOS, constitutional separation of concerns | 4 |
| 004 | System Layers | The 5-layer stack: Law → Physics → Bible → Implementation → Runtime | 5 |
| 005 | Architectural Patterns | Event sourcing, CQRS, pipeline, builder, dependency injection | 6 |
| 006 | Design Rules | Code review checklist, linting standards, enforcement | 7 |
| 007 | Naming Conventions | ID formats, file naming, code conventions, ACF addressing | 8 |
| 008 | Object Lifecycle | LMS-based lifecycle model for all constitutional entities | 9 |
| 009 | Versioning | SemVer for Bible, RFC versioning, implementation alignment | 10 |

## Relationship to Physics

Foundations and Physics are complementary:

- **Physics** defines *what* — the laws, invariants, and mechanisms of the AIOS universe (Identity, Sessions, Events, Lifecycles, Capabilities, Security, etc.)
- **Foundations** defines *why* and *how we decide* — the principles that drove the Physics design and guide its evolution

Physics documents reference Foundations Design DNA rules (R1–R15). Foundations documents reference Physics invariants. Neither supersedes the other; they form a dialectical pair.

## Invariants

1. **Constitutional Grounding**: Every Foundations principle is derived from or consistent with the AIOS Constitution. No principle may contradict a Constitutional Law.
2. **Internal Consistency**: No two Foundations documents contradict each other. Conflicts are resolved by the earlier document in the reading order.
3. **Implementation Guidance**: Every Foundations document must provide actionable guidance for implementors. Purely abstract philosophy without practical consequence has no place in Foundations.
4. **Living Document**: Foundations evolves through RFCs. No rewrite — only amendments.
5. **Referenceable**: Every principle, rule, and pattern in Foundations must have a stable identifier for cross-reference (e.g., `FND-001`, `R3`, `CL-005`).

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Constitutional Laws — Foundations interprets and operationalises |
| Physics/011-Design-DNA.md | Design DNA — Foundations references and contextualises these rules |
| Bible/01-Governance | Governance — built on Foundations principles |
| Bible/02-Core | Core engines — implement Foundations design rules |
| Constitution, Article I | Foundational principles — Bible Foundations operationalises |