# AIOS Bible â€” Domains
## Coding â€” 003: Code Review

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COD-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Code Review provides automated analysis of generated and modified code to ensure quality, security, and compliance with project standards. The review pipeline examines diffs and full files across multiple dimensions: style consistency, complexity metrics, security vulnerabilities, code smells, and test coverage. Results are aggregated into a scored review that determines whether code can proceed to merge.

This component acts as a quality gate in the Coding workflow. Every code change must pass review before being committed to a protected branch. The review process is configurable per repository and language, with severity thresholds that can escalate findings to human reviewers. Review findings are recorded as Events for evidence chain compliance.

## Architecture

```
Code Diff / File â”€â”€â–¶  Diff Analyzer
                         â”‚
                    â”Œâ”€â”€â”€â”€â”´â”€â”€â”€â”€â”
                    â–¼         â–¼
            Style Checker   Complexity Analyzer
                    â”‚              â”‚
                    â–¼              â–¼
            Security Scanner   Smell Detector
                    â”‚              â”‚
                    â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                         â–¼
                   Scoring Engine
                         â”‚
                         â–¼
                  Review Report
                    â”‚       â”‚
                    â–¼       â–¼
               Approved   Escalated (human review)
```

The review pipeline processes diffs through parallel analysis stages. Style checking runs against language-specific style guides. Complexity analysis computes cyclomatic complexity, nesting depth, and cognitive load. Security scanning checks for common vulnerability patterns. Code smell detection identifies anti-patterns and maintainability issues. Results are aggregated by the Scoring Engine into a weighted score that determines the review outcome.

## Data Model

```typescript
interface ReviewRequest {
  reviewId: string
  workerId: string
  diffHash: string
  baseCommit: string
  headCommit: string
  filesChanged: FileChange[]
  languageId: string
  repositoryId: string
  reviewScope: ReviewScope
  thresholds: ReviewThresholds
}

interface ReviewResult {
  reviewId: string
  status: ReviewStatus
  score: ReviewScore
  findings: ReviewFinding[]
  summary: string
  durationMs: number
  reviewedBy: string
  reviewedAt: timestamp
}

interface ReviewFinding {
  findingId: string
  category: FindingCategory
  severity: FindingSeverity
  filePath: string
  lineStart: number
  lineEnd: number
  ruleId: string
  message: string
  suggestion: string
  context: string
  score: number
}

interface ReviewScore {
  overall: number
  style: number
  complexity: number
  security: number
  smells: number
  coverage: number
  thresholds: ReviewThresholds
  passed: boolean
}

interface FileChange {
  filePath: string
  changeType: ChangeType
  linesAdded: number
  linesRemoved: number
  oldHash: string
  newHash: string
}

interface ReviewThresholds {
  minOverallScore: number
  maxComplexity: number
  maxFindingsPerCategory: number
  maxCriticalFindings: number
  maxHighFindings: number
  escalateOnCritical: boolean
}

interface ComplexityMetrics {
  cyclomaticComplexity: number
  cognitiveComplexity: number
  nestingDepth: number
  linesOfCode: number
  dependencyCount: number
  functionCount: number
}

enum ReviewStatus {
  Pending = "pending",
  InProgress = "in_progress",
  Approved = "approved",
  ChangesRequested = "changes_requested",
  Escalated = "escalated",
}

enum ReviewScope {
  Diff = "diff",
  FullFile = "full_file",
  PullRequest = "pull_request",
  Module = "module",
}

enum FindingCategory {
  Style = "style",
  Complexity = "complexity",
  Security = "security",
  CodeSmell = "code_smell",
  Performance = "performance",
  Maintainability = "maintainability",
  TestCoverage = "test_coverage",
  Documentation = "documentation",
}

enum FindingSeverity {
  Critical = "critical",
  High = "high",
  Medium = "medium",
  Low = "low",
  Info = "info",
}

enum ChangeType {
  Added = "added",
  Modified = "modified",
  Deleted = "deleted",
  Renamed = "renamed",
}
```

## Core Operations

| Operation | Precondition | Postcondition |
|-----------|-------------|---------------|
| review_diff | Diff is produced by CodeWorker | Review result with findings and score is returned |
| review_pr | Pull request is opened with changes | Comprehensive PR review across all changed files |
| analyze_complexity | Source code is available | Complexity metrics are computed and returned |
| check_style | Code and style guide are provided | Style violations are listed with line-level precision |
| scan_security | Code is generated or modified | Security vulnerabilities are identified with severity ratings |
| detect_smells | Code is analyzed for patterns | Code smells are catalogued with refactoring suggestions |
| escalate_review | Score falls below threshold | Review is escalated to human reviewer; event is emitted |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IReviewPipeline | Code Review Pipeline | CodeWorker, CodeReviewer | ACF command |
| IStyleChecker | Style Checker | Code Review Pipeline | Internal |
| IComplexityAnalyzer | Complexity Analyzer | Code Review Pipeline | Internal |
| ISecurityScanner | Security Scanner | Code Review Pipeline | Internal |
| ISmellDetector | Smell Detector | Code Review Pipeline | Internal |
| IScoringEngine | Scoring Engine | Code Review Pipeline | Internal |
| IEscalationHandler | Escalation Handler | Code Review Pipeline | ACF event |

## Events

| COD.EventType |    Produced When | Fields |
|-----------|--------------|--------|
| COD.ReviewStarted |    A review request enters the pipeline | review_id, worker_id, file_count, lines_changed |
| COD.ReviewCompleted |    Review finishes with a result | review_id, status, overall_score, finding_count |
| COD.ReviewEscalated |    Review score falls below threshold | review_id, overall_score, threshold, critical_findings |
| COD.ReviewFindingCreated |    A specific finding is recorded | finding_id, review_id, category, severity, file_path, line |
| COD.ReviewThresholdViolated |    A severity threshold is breached | review_id, threshold_name, actual_value, max_value |
| COD.ReviewApproved |    Review passes all thresholds | review_id, overall_score, max_severity, reviewer_id |
| COD.ReviewChangesRequested |    Review requires modifications | review_id, finding_count, critical_count, summary |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COD_REV_001 | Review timeout (diff too large) | Error | Partition diff into chunks; review each chunk sequentially |
| COD_REV_002 | Massive diff exceeds analysis capacity | Warning | Request developer to split PR; review available portions |
| COD_REV_003 | Unreviewable code (binary or generated) | Warning | Skip review; flag as unreviewable with explanation |
| COD_REV_004 | Style guide not found for language | Warning | Apply default style rules; log missing style guide |
| COD_REV_005 | Security scanner unavailable | Error | Proceed without security scan; flag review as incomplete |
| COD_REV_006 | Scoring engine conflict (contradictory findings) | Error | Escalate conflicting findings to human reviewer |
| COD_REV_007 | Repository policy prohibits automated review | Error | Bypass automated review; route directly to human reviewer |
| COD_REV_008 | Diff hash mismatch (concurrent modification) | Error | Request fresh diff; invalidate current review |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COD-REV-I-001 | Every code change on a protected branch must have a review result | Pre-commit hook checks for review_id before merge |
| COD-REV-I-002 | Review scores are deterministic for the same diff and thresholds | Scoring engine is a pure function of findings and thresholds |
| COD-REV-I-003 | Critical findings always trigger review escalation | Pipeline enforces escalateOnCritical threshold |
| COD-REV-I-004 | Each review finding is traceable to a specific line range | Finding includes filePath, lineStart, and lineEnd fields |
| COD-REV-I-005 | Review results are immutable after publication | Review store enforces append-only for completed reviews |


## Cross-Cutting Concerns

### Security

Coding operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Coding emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Coding instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Coding declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Each review dimension (style, complexity, security, smells) is a separate module |
| R2 - Dependency Order | Review depends on Language Registry; CodeWorker depends on Review |
| R3 - DRY | Style rules and smell patterns are defined once per language; reused across reviews |
| R4 - Builder Pattern | Review result is built incrementally through parallel analysis stages |
| R5 - Liskov Substitution | All analysis stages implement IAnalysisStage interface |
| R6 - DI over Singletons | Analysis stages are injected into pipeline; no shared state |
| R9 - Deterministic | Same diff + thresholds + rules produces identical review score |
| R10 - Simpler Over Complex | Review pipeline uses parallel fan-out with linear aggregation |
| R13 - Design for Failure | Failed analysis stage degrades gracefully; partial results with warning |
| R14 - Paved Path | Single paved path: diff -> analyze -> score -> approve/escalate |
| R15 - Open/Closed | New analysis stages added by implementing IAnalysisStage; pipeline unchanged |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Coding/000-Overview.md | Coding domain overview â€” code review is a mandatory quality gate |
| Bible/07-Domains/Coding/001-Languages.md | Language Support Registry â€” provides style guides and rules per language |
| Bible/07-Domains/Coding/002-Code-Generation.md | Code Generation â€” reviewed code originates from generation pipeline |
| Bible/07-Domains/Coding/004-Refactoring.md | Refactoring â€” review validates refactoring transformations |
| Physics/005-Events.md | Evidence â€” every review finding is an auditable Event |
| Physics/007-Capabilities.md | Capabilities â€” review scope bounded by Worker capability profile |
| Physics/010-Execution.md | Execution â€” review is part of the verification pipeline stage |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” review scores feed confidence scoring for generated code |
| Bible/03-Institutions/Workers/005-Playbook-Manager.md | Playbook Manager â€” review playbooks define custom review rules |
| Bible/00-Foundations/003-Core-Principles.md | CPR â€” review enforces constitutional compliance of generated code |
