# AIOS DNA
## 000 — The 15 Design DNA Rules

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | DNA |
| Document ID | DNA-000 |
| Source Laws | Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document is a compact reference to the 15 Design DNA invariants that govern all AIOS system design. Every line of code, every component, every test, every document must comply with these rules. For the complete normative specification including edge cases and enforcement details, see `Physics/011-Design-DNA.md`.

## The Design DNA Invariants

### Structural Rules

#### R1 — Modulsingularity: One Thing Well

Every module does one thing and does it well. Modules are small, focused, singular in purpose. One public API, one dependency direction, one test file.

#### R2 — Dependency Order: Simpler Depends on Simpler

Dependencies flow from complex to simple. A module may depend only on modules that are simpler than itself. The system is a directed acyclic graph.

#### R3 — DRY: Do Not Repeat Yourself

Every piece of knowledge has one and only one representation. No copy-pasted code, no duplicate data structures, no configuration drift.

### Engineering Rules

#### R4 — Builder Pattern: Separate Construction from Use

Construction and use are separated. Objects are built by Builders and used by Clients. A Client never constructs an object directly.

#### R5 — Liskov Substitution: Any Implementation Works

Any implementation of an interface can be substituted for any other without changing correctness. Runtime-neutral, template-neutral, engine-neutral.

#### R6 — DI over Singletons: Inject, Don't Global

Shared services are injected through constructors. No service is a singleton. No hidden global state.

### Testing Rules

#### R7 — Tests Exist at All Levels

Every level has tests. Unit (<1ms), Integration (<1s), System (<30s), Constitutional (<5min). No code is merged without tests.

#### R8 — Tests Are Fast

The full test suite runs in under 5 minutes. Slow tests are refactored or moved. Fast tests mean frequent testing.

#### R9 — Tests Are Deterministic

Tests must pass every time. Same code + same inputs = same result. No flaky tests, no environment dependencies, no shared state.

### Evolution Rules

#### R10 — Prefer Simpler: Simple over Complex

The simplest design that satisfies requirements is the best. Complexity is deferred until demonstrated necessary. Premature abstraction is a violation.

#### R11 — Refactor over Rewrite

Existing code is refactored, not rewritten. The system evolves through incremental improvement. Rewrites require constitutional approval.

#### R12 — Embrace Errors

Every error has a unique identity, a known location, and a single source of truth. Errors are designed into the system, not discovered late.

### Constitutional Rules

#### R13 — Design for Failure

Every component assumes other components will fail. Graceful degradation, retry with backoff, circuit breakers, fallbacks, bulkheading.

#### R14 — Paved Path: One Way to Do Things

For every common task, there is one canonical way. The paved path is the simplest, safest, most performant. Custom paths are more costly.

#### R15 — Open/Closed: Open for Extension, Closed for Modification

Modules are extended through interfaces, hooks, and plugins — never modified at source for new use cases.

## Rule Reference Table

| ID | Name | Category | Severity |
|----|------|----------|----------|
| R1 | Modulsingularity | Structural | Build-breaking |
| R2 | Dependency Order | Structural | Build-breaking |
| R3 | DRY | Structural | Build-breaking (>5%) |
| R4 | Builder Pattern | Engineering | Advisory |
| R5 | Liskov Substitution | Engineering | Build-breaking |
| R6 | DI over Singletons | Engineering | Advisory |
| R7 | Tests Exist | Testing | Build-breaking |
| R8 | Tests Fast | Testing | Advisory |
| R9 | Deterministic Tests | Testing | Build-breaking |
| R10 | Prefer Simpler | Evolution | Advisory |
| R11 | Refactor over Rewrite | Evolution | Policy |
| R12 | Embrace Errors | Evolution | Advisory |
| R13 | Design for Failure | Constitutional | Advisory |
| R14 | Paved Path | Constitutional | Advisory |
| R15 | Open/Closed | Constitutional | Advisory |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/011-Design-DNA.md | Normative specification — edge cases, enforcement, constitutional expression for each rule |
| DNA/001-Brain-DNA.md | Brain architectural invariants (BRAIN-001-009, SOU-001-007) |
| DNA/002-Entity-DNA.md | Entity lifecycle genetics — LMS state machine patterns |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA in the Bible — operational guidance |
| Bible/00-Foundations/003-Core-Principles.md | Core principles — SOLID applied to AIOS |
| Bible/00-Foundations/006-Design-Rules.md | Design rules — code review checklist, enforcement |
| Bible/00-Foundations/005-Architectural-Patterns.md | Patterns — event sourcing, CQRS, pipeline, builder |
| Standards/000-Design-Language.md | Design language conventions |
| Contributing/000-Contributing-Guide.md | Contributor workflow — Design DNA compliance checklist |
