# AIOS Bible — Foundations
## 002 — Design DNA (R1–R15)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-002 |
| Source Laws | All — Design DNA operationalises constitutional discipline into engineering practice |
| Source Physics | Physics/011-Design-DNA.md — original source |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The 15 Design DNA rules are the engineering discipline of AIOS. Every RFC, every implementation, every code review must be measured against these rules. They are not optional. They are not guidelines. They are engineering law.

## The 15 Rules

### R1 — Modulsingularity

> Every module does exactly one thing.

**Test**: Can you describe the module in one sentence without using "and" or "but"? If yes, the module satisfies R1.

**Example**: IDS does identity. ATS does authentication. The verification pipeline does verification. None of these do more than one thing.

**Violation**: A module that creates identities AND manages Sessions AND authorises actions.

### R2 — Dependency Order

**Layers depend on layers below. No layer depends on a layer above.**

The canonical dependency order: Constitution → Physics → Bible → Core Engines → Institutions → Services → Domains.

**Test**: Can you draw the dependency graph without cycles? If there is a cycle, the dependency is invalid.

**Violation**: The verification pipeline depending on ACF, AND ACF depending on the verification pipeline.

### R3 — Don't Repeat Yourself (DRY)

**Every piece of knowledge has a single, unambiguous, authoritative representation.**

**Test**: If you need to change behaviour, how many places must you change? If more than one, DRY is violated.

**Violation**: Capability bounds defined in both the CCA Bible document and the Security Council pipeline document.

### R4 — Builder Pattern

**Complex objects are built by builders. Clients receive pre-built, validated objects.**

**Test**: Is object construction separate from object use? If the client both constructs and uses, R4 is violated.

**Example**: Identity Factory builds identity records. Sessions receive pre-built identity records. Token Factory builds tokens. Engines receive pre-built tokens.

### R5 — Liskov Substitution Principle

**Derived types must be substitutable for their base types without altering correctness.**

**Test**: Can you replace a base implementation with a derived implementation and all tests still pass? If not, LSP is violated.

**Example**: All authentication methods (password, API key, cryptographic) implement the same AuthMethod interface. They are interchangeable.

### R6 — Dependency Injection over Singletons

**Dependencies are injected, not accessed as singletons.**

**Test**: Can you construct the module without global state? If the module calls a static factory or accesses global state, R6 is violated.

**Example**: The verification pipeline receives its dependencies (IDS, ATS, CCA, ROS) through its constructor, not through static accessors.

### R7 — Tests Exist

**Every module has unit tests, integration tests, and (where applicable) contract tests.**

**Test**: Is there at least one test for every produced Event? Every error code? Every lifecycle transition? If not, R7 is violated.

### R8 — Fast Tests

**Unit tests complete in milliseconds. Integration tests complete in seconds. No test takes longer than 10 seconds.**

**Test**: Run the full test suite. If any single test takes longer than 10 seconds, R8 is violated.

### R9 — Deterministic

**Given the same inputs, the same program always produces the same outputs.**

**Test**: Run the same test twice. Did the output change? If yes, R9 is violated (unless randomness is explicitly part of the specification, e.g., ID generation).

### R10 — Simpler Over Complex

**Every design choice should favour simplicity over complexity.**

**Test**: If a simpler solution exists that satisfies all constraints, the more complex solution is a violation of R10.

**Example**: The verification pipeline is linear and sequential (7 stages, no branching). A complex branching pipeline with parallelism would violate R10.

### R11 — Refactor over Rewrite

**Evolve through refactoring, not through rewriting.**

**Test**: Can the change be made as a series of small, reversible refactorings? If the change requires a rewrite, it must go through the RFC process.

### R12 — Embrace Errors

**Errors are first-class citizens. Every error has a unique code, actionable context, and a defined escalation path.**

**Test**: Does every error code appear in a test? Does every error code have a human-readable explanation? If not, R12 is violated.

**Example**: `VERIFY_ID_001` — identity does not exist. The error includes the identity_id, the stage, the timestamp, and the action.

### R13 — Design for Failure

**Every component assumes that every dependency will fail. Systems fail closed.**

**Test**: What happens when every dependency of this module is unavailable? If the answer is anything other than "deny and report", R13 is violated.

**Example**: If the verification pipeline cannot reach IDS, it denies the action. It does not allow the action (fail-open).

### R14 — Paved Path

**For every operation, there is exactly one paved path. All optimisations, shortcuts, and bypasses are explicitly forbidden.**

**Test**: Can an engineer implement this operation without making a choice about how? If there are multiple valid paths, R14 is violated.

**Example**: The paved path for action execution is: Identity → Auth → Authorization → Policy → Capability → Risk → Execution. There is no other path.

### R15 — Open/Closed Principle

**Modules are open for extension but closed for modification.**

**Test**: Can new functionality be added without modifying existing code? If extension requires modification, R15 is violated.

**Example**: New authentication methods implement the AuthMethod interface without modifying the auth core. New verification stages extend the pipeline without modifying existing stages.

---

## Rule Hierarchy

When rules conflict, the following precedence applies:

1. R14 (Paved Path) — the paved path is always correct
2. R13 (Design for Failure) — safety overrides simplicity
3. R10 (Simpler Over Complex) — simplicity over patterns
4. All other rules — equal precedence; resolve by RFC

## Cross-Cutting Concerns

### Enforcement

Design DNA compliance is checked at multiple levels:
- **Code review**: Every PR is checked against R1–R15
- **Architecture review**: Every RFC is checked against R1–R15
- **Automated linting**: Where possible, rules (R3, R4, R6, R7, R8, R9) are enforced by tooling
- **Tests**: R7 (Tests Exist) and R8 (Tests Fast) are checked by CI

### Relationship to Physics

| Physics Document | Key Design DNA Rules |
|-----------------|---------------------|
| Physics/004-Sessions.md | R1 (Modulsingularity), R10 (Simpler Over Complex) |
| Physics/005-Events.md | R3 (DRY), R12 (Embrace Errors) |
| Physics/006-Lifecycles.md | R14 (Paved Path) |
| Physics/007-Capabilities.md | R1 (Modulsingularity), R13 (Design for Failure) |
| Physics/008-Security.md | R13 (Design for Failure), R14 (Paved Path) |
| Physics/009-Interaction.md | R6 (DI over Singletons), R10 (Simpler Over Complex) |
| Physics/010-Execution.md | R13 (Design for Failure), R14 (Paved Path) |