# AIOS Physics
## 011 — Design DNA Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-011 |
| Applies To | All System Design, Engineering, Architecture, Code Structure, Libraries, Components, Tests, Documentation |
| Source Laws | Law 9 — Law of Design DNA |
| Supersedes | All earlier "Design DNA" formulations in the Constitution corpus |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the 15 Design DNA invariants governing all AIOS system design. Design DNA is the constitutional engineering framework — the foundational rules for how AIOS is built, structured, and evolved. Every line of code, every component, every test, every document reflects Design DNA.

These invariants extend Law 9 (Design DNA) of Physics/000-Laws.md. Design DNA is the operational expression of the Constitution in code.

---

## What Is Design DNA?

Design DNA is the constitutional engineering framework that governs how AIOS is designed, built, and maintained. It comprises 15 rules organized into five categories:

1. **Structural Rules** (R1–R3): How the system is organized
2. **Engineering Rules** (R4–R6): How code is written
3. **Testing Rules** (R7–R9): How correctness is verified
4. **Evolution Rules** (R10–R12): How the system grows
5. **Constitutional Rules** (R13–R15): How the system aligns with the Constitution

These rules are not optional. They are constitutional invariants. Every component, every library, every test, every line of code must comply with Design DNA.

---

## The Design DNA Invariants

### R1 — Modulsingularization: One Thing Well

**Every module does one thing and does it well. Modules are small, focused, and singular in purpose.**

A module is the smallest deployable unit of AIOS code. Each module has: one clear purpose (the module's name communicates its job), one public API (a small, well-defined surface area for interacting with the module), one dependency direction (modules depend on simpler modules, never circular), one test file that validates that single purpose, and no hidden side effects.

If a module has more than one responsibility, split it. If a module's name does not clearly communicate its purpose, rename it. If a module's public API grows beyond 3–5 functions, reorganize it.

Modulsingularity ensures: readability (developers know where to look), testability (each module is independently testable), maintainability (changes to one module do not ripple), composability (modules combine to form larger systems), and constitutional clarity (the architecture mirrors the Constitution's structure).

*Constitutional Expression*: Law 9, Rule 1. The Constitution's modular structure reflects Modulsingularity — each article, each institution, each section is a focused unit. The file structure (Physics/, Bible/, Constitution/) is itself modular.

*Enforcement*: Code review checks for module responsibility violations. Static analysis enforces singlularity. Module dependency graphs are validated. Circular dependencies are rejected.

*Edge Case*: A module that needs to perform two closely related things (e.g., read and write a configuration file) — the module may have two internal functions but one public API. The module's purpose is "manage configuration" — it is one thing. Internal composition is allowed as long as the public surface area is singular.

*Edge Case*: A module that grows over time — the module should be refactored when it exceeds its singular purpose. The refactoring should happen proactively. The module should be split into multiple modules before it becomes unmanageable.

*Violation*: A module with multiple public APIs for unrelated purposes. A module that depends on a module that depends on it (circular). A module whose name does not describe its content.

---

### R2 — Dependency Ordering: Simpler Depends on Simpler

**Dependencies flow from complex to simple. A module may depend only on modules that are simpler than itself.**

Simplicity is measured by: dependency depth (fewer transitive dependencies), abstraction level (more abstract is simpler), and surface area (smaller API is simpler).

A module that implements business logic may depend on a module that provides data structures. A module that provides data structures may depend on a module that provides primitives. A module that provides primitives has no dependencies.

Dependency ordering ensures: the system is a DAG (Directed Acyclic Graph), no circular dependencies (by definition), the foundation is stable (primitives change rarely, features change more), and refactoring is safe (change a leaf module without fear of breaking the system).

*Constitutional Expression*: Law 9, Rule 2. The Constitution itself follows dependency order — Article I (User Sovereignty) depends on nothing. Article II (Universal Laws) depends on Article I. Article III (Institutions) depends on Articles I and II.

*Enforcement*: Build tools validate the dependency graph. Circular dependencies are build-breaking errors. Dependency depth is monitored. A module that adds a dependency on a more complex module is flagged.

*Edge Case*: A module that legitimately needs to depend on a "more complex" module for a simple utility function — the utility function should be extracted to a simpler module. If that is not possible, the dependency is flagged and reviewed.

*Edge Case*: Two modules at the same complexity level that legitimately interact — they should be: either merged (if they are the same level of complexity and closely related) or reorganized into a parent module with two children (if they are cohesive).

*Violation*: A module that depends on a more complex module. A circular dependency. A module at the foundation level that depends on a higher-level module.

---

### R3 — Do Not Repeat Yourself

**Every piece of knowledge has one and only one representation in the system.**

Duplication takes many forms: copy-pasted code (same logic in multiple places), parallel data structures (the same concept expressed differently in different modules), configuration drift (the same value defined in multiple places), knowledge duplication (the same business rule implemented in multiple modules), and conceptual duplication (the same concept modeled as types in multiple modules).

When duplication is found: extract the duplicated code into a shared module, create a canonical representation of the duplicated data structure, centralize configuration in a single location, implement the business rule once and call it from all places, and create a shared type definition for the concept.

DRY is not about code length — it is about knowledge representation. A system that repeats knowledge has a single source of truth for each piece of knowledge.

*Constitutional Expression*: Law 9, Rule 3. The Constitution avoids duplication — the same principle appears in one location (cross-referenced from elsewhere) rather than being restated.

*Enforcement*: CI/CD runs static analysis. Code review validates DRY compliance. Coverage tools flag duplicate code. Duplication above 5% triggers review.

*Edge Case*: Duplication that is intentional for performance (e.g., inlining a function for hot path optimization) — the duplication is documented. The inlined code is linked to the source module. The documentation explains why DRY was violated and under what conditions the violation is acceptable.

*Edge Case*: Duplication across different abstraction levels (e.g., a business rule expressed in domain logic and in the database schema) — the rule is defined in the domain logic module. The database schema references the domain logic module. Changes flow from the source.

*Violation*: Undocumented duplicate code. Duplicate knowledge. Duplicate logic. Configuration defined in multiple places.

---

### R4 — Builder Pattern: Separate Construction from Use

**Construction and use are separated. Objects are built by Builders and used by Clients. A Client never constructs an object directly.**

The Builder Pattern means: every object has a Builder that knows how to construct it, the Builder validates the construction (required parameters, valid configuration, constitutional constraints), the Builder can have a constitutional lifecycle — delegated to specific entities, and the Client receives a fully constructed, valid object.

Construction includes: object creation, configuration loading, dependency injection, initialization, capability assignment, and lifecycle registration. The Client receives a pre-built object through dependency injection.

*Constitutional expression*: Law 9, Rule 4. Constitutional entities are constructed by constitutional authority — the Identity Registry builds identities, the Capability Certification Authority builds capabilities. Clients (Sessions, Missions, Organizations) receive pre-built constitutional objects.

*Enforcement*: Code review validates Builder pattern usage. New objects require Builders. Direct construction by Clients is flagged.

*Edge Case*: A simple value object (e.g., a Point, a Color) — it may be constructed directly as it has no dependencies and no validation. The Builder pattern applies to objects with dependencies, configuration, or validation.

*Edge Case*: An object that is constructed by a factory function rather than a Builder — the factory function is acceptable if it follows the same principles (separation of construction from use, validation before return). The factory function is a Builder in function form.

*Violation*: A Client constructing an object directly. An object that is constructed without validation. An object that is used before it is fully constructed.

---

### R5 — Liskov Substitution: Any Implementation Works

**Any implementation of an interface can be substituted for any other without changing the correctness of the system.**

Liskov requires: interface contracts are well-defined and enforced, implementations strictly follow the interface contract, and no implementation violates the contract.

Liskov applies at all scales: within a module (any implementation of an internal interface), across modules (any module that provides a service), at the API level (any implementation of an API endpoint), and at the entity level (any Session, any Runtime, any Engine).

Liskov ensures: Run-time neutrality (any Runtime can substitute any Runtime), Template neutrality (any Template can create any Session), Engine neutrality (any Engine that implements an Engine interface can be substituted), and tool neutrality (any tool that implements a tool interface can be substituted).

*Constitutional Expression*: Law 9, Rule 5. Article III, Part B, Section 010 (Runtime Neutrality) is a direct expression of Liskov. The Constitution does not depend on specific implementations — it depends on interfaces.

*Enforcement*: Interfaces are defined with contracts. Contract tests validate implementations. CI/CD runs contract tests for every implementation. Interface violations are build-breaking.

*Edge Case*: An implementation that adds behavior beyond the interface contract — this is allowed as long as it does not violate the contract. Extra behavior cannot break existing callers.

*Edge Case*: An implementation that is "more capable" than the interface requires — this is allowed as long as it does not change the contract semantics. A faster implementation is fine. An implementation that returns incorrect results is not.

*Violation*: An implementation that violates the interface contract. An implementation that produces different behavior for the same inputs. An implementation that breaks callers.

---

### R6 — Dependency Injection, Not Singletons

**Shared services are injected. No service is a singleton.**

Services are injected: through constructors (primary method), through configuration (the system configuration provides service instances), through dependency injection containers (Dependency Injection is lightweight — no heavyweight frameworks), and through constitutional mechanisms (the ACF, Security Council, LMS, and other constitutional institutions are injected into entities).

Singletons are forbidden because: singletons create hidden global state, singletons make testing difficult (cannot isolate test instances), singletons violate modularity (they are invisible dependencies), and singletons violate constitutional principles (the Constitution does not create hidden authorities).

*Constitutional Expression*: AIOS Law 9, Rule 6. The Constitution defines institutions and their authorities transparently — there are no "global" processes. The Constitution is not instantiated as a singleton; it is the context within which all entities operate.

*Enforcement*: Static analysis flags singleton patterns. DI frameworks (if used) enforce injection. Code review validates injection usage.

*Edge Case*: A Read-Only Configuration Store that never changes — it could be a singleton because it has no mutable state. However, injection is still preferred. The configuration store is injected into tests with test-specific configuration.

*Edge Case*: A cache that is shared across the system — the cache is a service. It is injected into entities that need it. The cache's lifecycle management (eviction, invalidation) follows the same patterns as any other service.

*Violation*: A service that uses a singleton. A service that creates global state. A service that cannot be replaced in tests.

---

### R7 — Tests Exist at All Levels

**Every level of the system has tests. Tests are constitutional. No code is merged without tests.**

Testing levels:

| Level | Scope | Tool | Fast | Run Frequency |
|-------|-------|------|------|---------------|
| Unit | Single module or function | Unit test framework | <1ms/test | Every commit |
| Integration | Module interactions | Integration test framework | <1s/test | Every merge |
| System | Full system end-to-end | E2E test framework | <30s/test | Every release |
| Constitutional | Constitution compliance | Constitutional test suite | <5min/suite | Before every release |

Tests are code. Tests follow Design DNA. Tests have their own module structure. Tests are maintained with the same rigor as production code.

*Constitutional Expression*: AIOS Law 9, Rule 7. The Constitution establishes institutions. Test levels correspond to institutional boundaries — unit tests verify institutions in isolation, integration tests verify institutional interactions, system tests verify the full constitutional system.

*Enforcement*: CI/CD enforces test coverage minimums. Coverage thresholds: Unit: 90%+ branch coverage, Integration: 80%+ service coverage, and E2E: 100% of critical paths. Code review validates test quality. Test failures block merges.

*Edge Case*: A module that cannot be tested in isolation (e.g., a module that depends on external hardware) — the external dependency is mocked or stubbed. The mock is defined in the same module structure as the test. Metamorphic testing, invariant testing, or other strategies may be used.

*Edge Case*: A test that is flaky (passes sometimes, fails sometimes) — the flaky test is removed or fixed. Failing tests block merges. Flaky tests erode trust in the test suite.

*Violation*: Code merged without tests. A test that does not test the claimed level. A test that is flaky without investigation.

---

### R8 — Tests Are Fast

**Tests are fast. The test suite runs in under 5 minutes. Every developer runs the full test suite before merging.**

Test speed is achieved through: unit tests (fastest — run on every keystroke), integration tests (fast — run on every merge), contract tests (fast — validate interfaces), optimization (parallel execution, test selection, caching), and isolation (tests are independent — no shared state, no order dependencies).

A test suite that takes 5+ minutes slows development, reduces testing frequency, and decreases code quality.

*Constitutional Expression*: AIOS Law 9, Rule 8. The Constitution establishes institutions. Institutional testing (integration, contract, constitutional) is done at merge time, similar to how the Constitution is tested when institutions interact.

*Enforcement*: CI/CD enforces test suite time limits. Tests exceeding time limits are flagged. Slow tests are refactored or moved to a slower test level.

*Edge Case*: A test that legitimately requires significant computation (e.g., a stress test, a correctness test for a cryptographic function) — the test is tagged as a "slow test." Slow tests are run in CI but not on every commit. The developer runs the full suite before release.

*Edge Case*: A test suite that grows and gradually slows down — the test suite is regularly reviewed for speed. Slow tests are optimized or split. Developer feedback is tracked: how long does the test suite take to run on average?

*Violation*: A test that takes longer than expected. A test suite that takes longer than the time limit. A developer who does not run the test suite before committing.

---

### R9 — Tests Must Be Deterministic

**Tests must pass every time. Tests must fail when the code is wrong, not when the environment changes.**

A deterministic test: produces the same result every time it is run with the same code and same inputs, uses its own data (tests create their own data — never shares data with other tests), controls its environment (tests do not depend on external state — network, time, filesystem, environment variables), and is isolated.

Non-deterministic tests include: tests that depend on the current time, tests that depend on random data without a seed, tests that depend on external services, tests that share mutable state with other tests, and tests whose results depend on test order.

*Constitutional Expression*: AIOS Law 9, Rule 9. The Constitution is deterministic — the same constitutional question always gets the same constitutional answer. Deterministic tests reflect this constitutional principle.

*Enforcement*: CI/CD runs tests multiple times. Flaky tests are blocked. Deterministic test patterns are enforced via static analysis. Random data is seeded. Time-dependent code is testable.

*Edge Case*: A test that must use real random data (e.g., a cryptographic test) — the random data is seeded. The seed is logged in the test output. The test is deterministic for a given seed.

*Edge Case*: A test that must use real time (e.g., a timeout test) — the time is injected. The test controls the time through a clock abstraction. Real time is never used directly.

*Violation*: A test that passes sometimes and fails sometimes. A test that depends on test order. A test that uses real network calls without mocking.

---

### R10 — Prefer Simpler: Simple over Complex

**The simplest design that satisfies the requirements is the best design. Complexity is avoided, not embraced.**

Simplicity means: fewer classes, fewer modules, fewer functions, fewer dependencies, fewer configuration options, fewer conditional branches, fewer inheritance levels, fewer design patterns, and fewer abstractions.

Complexity is deferred until it is demonstrated to be necessary. Premature abstraction is a violation. Every abstraction has a cost.

*Constitutional Expression*: AIOS Law 9, Rule 10. The Constitution avoids complexity: it defines clear Institutions, clear Authorities, and clear Processes. The Constitution does not define abstractions for possible future situations — it defines for the current reality.

*Enforcement*: Code review validates simplicity. Complex code is flagged. Cyclomatic complexity limits are enforced. Abstraction count limits are monitored.

*Edge Case*: A design that is simpler now but creates more work later (e.g., hardcoding a value instead of making it configurable) — simplicity now is preferred. The value is extracted when a second use case arises. Premature configuration is avoided.

*Edge Case*: A design that is simple for the developer but complex for the user — user-facing simplicity has higher priority than developer-facing simplicity. A more complex internal design is acceptable if it provides simpler user API.

*Violation*: A design that uses design patterns unnecessarily. A design that adds abstraction levels for "future flexibility". A design that has more layers than necessary.

---

### R11 — Refactor Over Rewrite

**Existing code is refactored, not rewritten. The system evolves through incremental improvement, not wholesale replacement.**

Refactoring preserves: code behavior (the refactored code produces the same results), test coverage (tests are preserved and updated to match the new structure), design intent (the refactored code continues to serve the original purpose while improving structure), and knowledge (the refactored code incorporates lessons from the existing code).

Refactoring is the default. Rewriting is allowed only when: the existing code cannot be refactored (fundamental design flaw, no tests, no modular structure), the cost of refactoring exceeds the cost of rewriting, and the rewrite is done incrementally, not as a big bang.

*Constitutional Expression*: AIOS Law 9, Rule 11. The Constitution can be amended (Article VII). Amendments are constitutional changes, not replacements. Amendments preserve the Constitution's intent while improving its structure.

*Enforcement*: Rewrites require constitutional approval. Refactoring is preferred. Rewrite justification is documented.

*Edge Case*: A module that was poorly designed and cannot be refactored without breaking everything — the module is rewritten incrementally. The rewrite is done in phases, with each phase tested and merged independently. No big bang rewrite.

*Edge Case*: A module that was written by a developer who is no longer on the team — it is still refactored, not rewritten. Refactoring is based on the code's structure, not the author's availability.

*Violation*: A big bang rewrite. A rewrite that is not justified. A rewrite that discards knowledge from the original implementation.

---

### R12 — Embrace Errors: Each Error Is Identifiable, Isolated, and a Single Source of Truth

**Errors are designed into the system, not discovered late. Every error has a unique identity, a known location, and a single source of truth for its handling.**

Every error is identifiable: each error has a unique error code, a human-readable message, and a link to documentation. Every error is isolated: errors are scoped to the module that produced them, errors do not propagate unintendedly, and error handling is local. Every error has a single source of truth: error definitions live in one location, error messages come from one module, and error handling logic follows one pattern.

*Constitutional Expression*: AIOS Law 9, Rule 12. The Constitution defines what happens when things go wrong: violations, enforcement, escalation, failure, and amendment.

*Enforcement*: Error codes are standardized. Error taxonomy is defined. Error handling is validated. Unhandled errors are flagged.

*Edge Case*: An error that propagates across module boundaries (e.g., a database error causes an API error) — the error identity should indicate the originating module. The error chain must be preserved.

*Edge Case*: An error that is expected (e.g., a validation error) — expected errors are handled as errors, not as return values. The error is documented. The error's handling is tested.

*Violation*: An error without a unique identifier. An error that is caught but not handled. An error that is hidden (caught and ignored). An error that propagates without context.

---

### R13 — Design for Failure

**The system is designed for failure. Every component assumes that other components will fail.**

Failure is assumed at every level: network calls fail, filesystem operations fail, model calls fail, and despite the Constitution's design, components fail.

Design for failure includes: graceful degradation (when a component fails, the system degrades gracefully — it continues to provide reduced functionality), retry with backoff (failed operations are retried with exponential backoff), circuit breakers (repeated failures open a circuit breaker to prevent cascading failure), fallback (when the primary option fails, a fallback option is available), and bulkheading (resources are bulkheaded — one failure does not exhaust shared resources).

*Constitutional Expression*: AIOS Law 9, Rule 13. The Constitution has provisions for scenarios when Institutions fail: escalation processes, amendment mechanisms, oversight.

*Enforcement*: Resilience patterns are required. Failure testing is part of the test suite. Chaos engineering validates failure handling.

*Edge Case*: A critical component that must never fail (e.g., the Security Council's verification pipeline) — the component is designed for redundancy, failover, and zero-downtime updates. The component is tested for failure scenarios.

*Edge Case*: A component whose failure mode is unclear — the failure mode is documented. The component's failure behavior is tested.

*Violation*: A component that has no failure handling. A component that fails silently. A component whose failure cascades to other components.

---

### R14 — Paved Path: There Is One Way to Do Things

**For every common task, there is one canonical way to do it. The paved path is the simplest, safest, and most performant way.**

The paved path covers: how to create a component, how to add a dependency, how to structure a module, how to write a test, how to handle an error, how to configure a service, how to deploy a changes, and how to evolve the API.

The paved path is well-documented, well-tested, and instrumented by default. The paved path is the default — developers choose the paved path unless they have a compelling reason not to. Custom paths are allowed but are more costly.

*Constitutional Expression*: AIOS Law 9, Rule 14. The Constitution provides one canonical path for each constitutional process. There is one mechanism for amending the Constitution. There is one mechanism for creating an Organization. The paved path principle pervades all constitutional design.

*Enforcement*: Code review validates paved path use. Custom paths are flagged and documented. Paved path documentation is maintained.

*Edge Case*: A custom path that is clearly superior to the paved path — the custom path should become the new paved path. The paved path is updated. The custom path is documented as the transition plan.

*Edge Case*: A custom path that is needed for a specific performance requirement — the custom path is benchmarked against the paved path. The results are documented.

*Violation*: A custom path without justification. A custom path that is not documented. A custom path that is less safe than the paved path.

---

### R15 — Open Closed Principle: Open for Extension, Closed for Modification

**Modules are open for extension but closed for modification. You can extend a module's behavior without modifying its source code.**

Open for extension means: modules define interfaces that can be implemented by external modules; modules provide extension points (hooks, callbacks, events, plugins) for customization; and modules can be composed with other modules to create new behavior.

Closed for modification means: module source code is not modified for new use cases; module internals are not visible to external modules; and module behavior is changed through configuration, composition, or interface implementation.

The Open/Closed Principle ensures that modules are stable. The system grows through extension, not modification.

*Constitutional Expression*: AIOS Law 9, Rule 15. The Constitution is open for extension through the amendment process. The Constitution is closed for modification except through the amendment process. The Constitution is extended by adding new articles and sections that reference existing articles and sections.

*Enforcement*: Module stability is monitored. Modules that are frequently modified are flagged. Extension points are validated.

*Edge Case*: A module that cannot be extended — the module should be redesigned to support extensions. The redesign is phased in over time. The extension point is documented so other modules can plan for it.

*Edge Case*: A module that is modified because the original design was wrong — the modification is a fix, not a feature addition. Fixes are allowed to bypass OCP because the module's design was already violated.

*Violation*: A module that is modified to add a feature instead of extended. A module's source code that is changed for each new use case. A module that is not extensible.

---

## Design DNA Enforcement

| Rule | Enforcement Mechanism | Severity |
|------|---------------------|----------|
| R1 — Modulsingularity | Static analysis, module size limits, API surface limits | Build-breaking |
| R2 — Dependency Order | Dependency graph validation, cycle detection | Build-breaking |
| R3 — DRY | Duplication detection, CI/CD thresholds | Build-breaking above 5% |
| R4 — Builder Pattern | Review, static analysis for direct construction | Advisory |
| R5 — Liskov | Contract tests, CI/CD per implementation | Build-breaking |
| R6 — DI over Singletons | Static analysis, code review | Advisory |
| R7 — Tests Exist | CI/CD coverage thresholds | Build-breaking below thresholds |
| R8 — Tests Fast | CI/CD time limits, test profiling | Advisory (flagged) |
| R9 — Deterministic Tests | CI/CD flaky test detection, static analysis | Build-breaking (flaky tests) |
| R10 — Prefer Simpler | Cyclomatic complexity limits, code review | Advisory |
| R11 — Refactor over Rewrite | Code review, approval required for rewrites | Policy requirement |
| R12 — Test Errors | Error taxonomy validation, error coverage | Advisory |
| R13 — Design for Failure | Integration tests, chaos engineering | Advisory |
| R14 — Paved Path | Code review, path validation | Advisory |
| R15 — Open/Closed | Module modification history | Advisory |

---

## Design DNA File Structure

- `Rules/R1-Modulsingularity.md`
- `Rules/R2-DependencyOrder.md`
- `Rules/R3-DRY.md`
- `Rules/R4-BuilderPattern.md`
- `Rules/R5-Liskov.md`
- `Rules/R6-DIOverSingletons.md`
- `Rules/R7-TestsExist.md`
- `Rules/R8-TestsFast.md`
- `Rules/R9-Deterministic.md`
- `Rules/R10-PreferSimpler.md`
- `Rules/R11-RefactorOverRewrite.md`
- `Rules/R12-TestErrors.md`
- `Rules/R13-FailureDesign.md`
- `Rules/R14-PavedPath.md`
- `Rules/R15-OpenClosed.md`

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 9 (Design DNA) — source law |
| Constitution, Article VIII (Design DNA) | Formal Design DNA definition in the Constitution |
| Bible/08-Standards/Design-DNA/ | Detailed implementation of each rule |
| Bible/08-Standards/Coding-Standards/ | Code-level implementation of Design DNA |

---

*End of AIOS Physics 011 — Design DNA Invariants*