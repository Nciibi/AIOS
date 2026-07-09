# AIOS Bible — Foundations
## 006 — Design Rules

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-006 |
| Source Laws | All — Design Rules operationalise Laws into engineering practice |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Code Review Checklist

Every PR must satisfy all applicable rules from this checklist:

### Structure
- [ ] Module does one thing (R1)
- [ ] No circular dependencies (R2)
- [ ] No duplicated logic or configuration (R3)
- [ ] No global state — dependencies are injected (R6)
- [ ] Object construction is separate from use (R4)

### Correctness
- [ ] All state transitions are authorised by LMS
- [ ] All operations produce at least one Event
- [ ] Every error has a unique code (R12)
- [ ] Identity is verified before any action
- [ ] Tokens are validated before any execution

### Resilience
- [ ] Failures are handled explicitly (not caught-and-ignored)
- [ ] Dependencies have timeouts
- [ ] Degradation path exists for each dependency failure (R13)
- [ ] Circuit breakers are in place for upstream services

### Testability
- [ ] Module has unit tests (R7)
- [ ] Module has integration tests at boundaries (R7)
- [ ] No test takes >10 seconds (R8)
- [ ] Tests are deterministic (R9) — no flaky tests
- [ ] All error codes appear in at least one test

### Simplicity
- [ ] A simpler solution was considered and documented (R10)
- [ ] The PR introduces no new infrastructure or pattern unless justified (R10)
- [ ] The change is a refactoring, not a rewrite (R11)

## Linting Standards

### Automated Lint Rules

| Rule | Tool | Enforced |
|------|------|----------|
| No unused imports | linter | Yes |
| No global mutable state | static analysis | Yes |
| No hardcoded secrets | secret scanner | Yes |
| All functions documented | doc linter | Yes |
| No `unwrap()` in production code | clippy / eslint | Yes |
| All errors handled (no silent ignores) | linter | Yes |

### Manual Review Focus

| Concern | Reviewer |
|---------|----------|
| R1 (Modulsingularity) | Architecture reviewer |
| R2 (Dependency Order) | Architecture reviewer |
| R3 (DRY) | Code reviewer |
| R4 (Builder Pattern) | Architecture reviewer |
| R10 (Simpler Over Complex) | Code reviewer |
| R13 (Design for Failure) | Security reviewer |
| R14 (Paved Path) | Architecture reviewer |

## Enforcement

| Rule | Enforced At | Method |
|------|-----------|--------|
| R1 | Architecture review | Manual review |
| R2 | Architecture review | Dependency graph analysis |
| R3 | Code review | Manual review + linter |
| R4 | Code review | Manual review |
| R5 | Test review | Contract tests |
| R6 | Code review | Static analysis |
| R7 | CI | Test runner |
| R8 | CI | Test runner with timeout |
| R9 | CI | Flaky test detector |
| R10 | Architecture review | Manual review |
| R11 | Architecture review | PR size analysis |
| R12 | Code review | Error code registry check |
| R13 | Security review | Chaos engineering |
| R14 | Architecture review | Manual review |
| R15 | Architecture review | Interface analysis |