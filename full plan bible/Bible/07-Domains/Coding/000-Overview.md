# AIOS Bible — Domains
## Coding — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-COD-000 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Coding domain enables AIOS to plan, generate, modify, review, and verify source code across programming languages and frameworks. It provides the capability set for AI-assisted software development — from single-file edits to multi-repository refactors, from documentation generation to test suite creation.

This domain defines the entities, capabilities, resource profiles, and integration patterns that allow AIOS Workers to operate as software engineering agents. Coding is one of the most resource-intensive domains — it consumes tokens at high velocity, requires context windows large enough to hold codebase fragments, and depends on execution sandboxes for compilation, linting, and testing.

## Domain Entities

The Coding domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| CodeWorker | A Worker specialized for coding tasks | AGS: Coding/CodeWorker |
| CodeReviewer | A Worker specialized for code review | AGS: Coding/CodeReviewer |
| CodebaseIndex | A knowledge artifact indexing a repository | Academy: Knowledge |
| BuildSandbox | An OIS-type sandbox for compilation and testing | AGS: Coding/BuildSandbox |
| CodePlan | A structured plan for code modification | Sou: Planner output |

## Capabilities

The Coding domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Code Generation | `generate_file`, `generate_function`, `generate_test`, `generate_docstring` | High token, medium compute |
| Code Modification | `edit_file`, `refactor_symbol`, `rename_across_files`, `patch_generation` | High token, low compute |
| Code Review | `review_diff`, `review_pr`, `analyze_complexity`, `check_style` | Medium token, low compute |
| Code Analysis | `parse_ast`, `compute_dependencies`, `find_dead_code`, `detect_smells` | Low token, high compute |
| Build Operations | `compile`, `lint`, `format`, `run_tests`, `run_coverage` | Low token, variable compute |
| Documentation | `generate_docs`, `update_readme`, `generate_changelog`, `write_api_ref` | High token, low compute |
| Repository Management | `init_repo`, `manage_branch`, `merge_pr`, `resolve_conflicts` | Low token, low compute |

## Domain Resources

Coding operations consume these resource types:

| Resource | Unit | Typical Consumption | Provider Type |
|----------|------|-------------------|---------------|
| Tokens (Input) | tokens | 1K–100K per operation | LLM Provider |
| Tokens (Output) | tokens | 100–10K per operation | LLM Provider |
| Context Window | tokens | 8K–200K per Worker | LLM Provider |
| Compute (Build) | CPU-seconds | 1–300 per build | Compute Provider |
| Storage (Repo clone) | MB | 10–5000 per repo | Storage Provider |
| Execution Time | seconds | 1–600 per task | Runtime |

## Domain Integration with Core

| Core System | Integration Point | Purpose |
|-------------|------------------|---------|
| Sou/002-Planner.md | Code plan generation | Sou produces structured plans for code modifications |
| AGS | CodeWorker Genomes | AGS provides Code Genome templates |
| Academy | Codebase knowledge | Academy indexes codebases as knowledge artifacts |
| DTS | Code quality confidence | DTS scores confidence in generated code |
| ROS | Resource allocation | ROS budgets tokens, compute, storage for coding tasks |
| OSYS | Coding Organizations | OSYS manages orgs that own codebases |

## Coding Workflow

A typical coding workflow in AIOS follows this pattern:

```
1. Task received (e.g., "Add pagination to user list")
2. Sou Planner decomposes into code plan
3. DGP routes to Coding Organization
4. CodeWorker instantiated from CodeWorker Genome
5. Worker loads codebase context (CodebaseIndex from Academy)
6. Worker generates code modifications
7. Worker runs build (compile, lint, test)
8. DTS evaluates confidence in output
9. CodeReviewer reviews diff (parallel or sequential)
10. If confidence < threshold → revise loop
11. If confidence >= threshold → commit/merge
12. Academy indexes updated codebase
13. Sou learns from outcome
```

## Invariants

1. **COD-I-001 — Generated Code Is Verified**: Every piece of generated code must pass linting and compilation before being marked as complete. Untested code is not considered delivered.

2. **COD-I-002 — Deterministic Generation**: The same code plan and context must produce identical code output when the same seed and model are used. Non-deterministic generation is flagged for review.

3. **COD-I-003 — Context-Bounded**: A CodeWorker operates only within the code context loaded at session start. It cannot access files outside the authorized repository scope.

4. **COD-I-004 — Evidence per Change**: Every code modification produces an Event recording the diff, the originating plan step, and the authorization chain. No change is untracked.

5. **COD-I-005 — Review Before Merge**: All generated code must pass review before being committed to a protected branch. Direct commits to protected branches are prohibited.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Generated code fails compilation | Build failure Event produced. CodeWorker enters review loop with error details. Revision attempted up to 3 retries. |
| Context window exceeds model limit | CodeWorker generates file-by-file with dependency stubs. Cross-file references documented for follow-up pass. |
| Repository unavailable (network error) | CodeWorker pauses, retries with exponential backoff (max 5 attempts). If still unavailable, task fails with repository connectivity error. |
| Generated test suite is empty or trivial | DTS confidence score reduced. CodeReviewer escalates for human review if confidence < 0.5. |
| Code plan step count exceeds max | CodePlan is returned to Sou Planner for decomposition into multiple sub-plans. Each sub-plan executed sequentially. |
| Security vulnerability detected in generated code | Build is blocked. VulnerabilityReport created in Security domain. CodeWorker notified with vulnerability details. |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Coding.CodeGenerated` | Code is generated by a CodeWorker | worker_id, file_path, language, lines_added, lines_removed |
| `Coding.CodeReviewed` | Code review is completed | review_id, diff_hash, issues_found, confidence_score |
| `Coding.BuildCompleted` | Build operation finishes | build_id, outcome (pass/fail), duration_seconds, error_count |
| `Coding.CodebaseIndexed` | Codebase is indexed in Academy | index_id, repo_url, commit_hash, file_count, language_breakdown |
| `Coding.TestRunCompleted` | Test suite execution finishes | test_run_id, passed, failed, skipped, coverage_pct, duration_ms |
| `Coding.CodePlanCreated` | A code plan is produced | plan_id, task_description, estimated_tokens, steps, estimated_duration |

## Cross-Cutting Concerns

### Security

Code Workers operate in sandboxed environments (OIS). Generated code is analyzed for security vulnerabilities before execution. Repository access is governed by Organization policies. Build sandboxes have no network access by default. Secrets and credentials are never exposed to Code Workers. (Physics/008-Security.md)

### Evidence

Every code operation produces an Event: generation, review, build, test, commit. Code quality evidence feeds into DTS confidence scoring. All code changes are traceable to the originating task and Worker. (PHI-008)

### Lifecycle

Code Workers follow the canonical Worker lifecycle (Created → Planned → Assigned → Running → Completed → Archived). Codebases follow their own lifecycle through indexing, modification, and archival. Build sandboxes are ephemeral — created per task and destroyed after completion. (Physics/006-Lifecycles.md)

### Capability Bounds

Coding capabilities are bounded by token budgets, context window limits, and execution timeouts. A CodeWorker cannot exceed its Genome-defined capability bounds. Language-specific capabilities require appropriate runtimes. (Physics/007-Capabilities.md)

### Communication

All Coding domain communication flows through ACF. Code plan proposals travel from Sou to DGP to the Coding Organization. Code review results flow back through ACF to the originating Worker. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Coding capability (generate, review, build, analyze) is a separate concern |
| R5 (Liskov) | All Coding Workers implement the CodeWorker interface with interchangeable backends |
| R9 (Deterministic) | Code generation with same inputs and seed produces identical output |
| R10 (Simpler Over Complex) | Code plans use linear step sequences — no branching plans |
| R13 (Design for Failure) | Build failures return partial results; review proceeds on available artifacts |
| R14 (Paved Path) | Single paved path: plan → generate → build → review → commit |

## Integration with Execution Pipeline

Coding operations participate in Stage 7 (Execution Authorization) of the verification pipeline:

| Stage | Name | Coding Domain Role |
|-------|------|-------------------|
| 1 | Identity Verification | IDS validates CodeWorker identity |
| 2 | Authentication | ATS validates CodeWorker session token |
| 3 | Authorization | AZS checks repository write permissions |
| 4 | Policy Evaluation | Repository policy, language policy, license check |
| 5 | Capability Check | CodeWorker capabilities validated via Genome |
| 6 | Risk Assessment | DTS scores confidence in generated code |
| 7 | Execution Authorization | ROS reserves token budget for generation |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — Coding domain structure and taxonomy |
| Physics/005-Events.md | Evidence — Coding operations produce Events |
| Physics/007-Capabilities.md | Capabilities — Coding capability bounds and resource profiles |
| Physics/010-Execution.md | Execution — Coding verification pipeline stage |
| Physics/012-Experience.md | Experience — Coding outcomes drive Sou learning |
| Bible/02-Core/Sou/002-Planner.md | Planner — Sou produces code plans |
| Bible/02-Core/AGS/000-Overview.md | AGS — CodeWorker Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — Codebase knowledge indexing |
| Bible/02-Core/DTS/000-Overview.md | DTS — Code quality confidence scoring |
| Bible/02-Core/ROS/000-Overview.md | ROS — Token and compute budget allocation |
| Bible/03-Institutions/Workers/005-Playbook-Manager.md | Playbook Manager — Automated code review playbooks |
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Runtime SDK — CodeWorker runtime execution |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK — LLM provider integration |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
