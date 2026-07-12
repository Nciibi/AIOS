# AIOS Bible â€” Domains
## Coding â€” 004: Refactoring

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COD-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Refactoring Engine enables AIOS to perform cross-file structural changes to source code while preserving behavioral semantics. It transforms code by applying refactoring operations such as symbol renaming, method extraction, variable inlining, and module relocation across entire codebases. The engine builds a dependency graph, resolves all symbol references, computes impact scope, applies transformations, and verifies that behavior is preserved.

This component is the most architecturally complex in the Coding domain because it must handle cross-file references, name collision detection, language-specific syntax rules, and transformation ordering. Refactoring operations are planned by Sou, executed by the CodeWorker using this engine, and then validated by CodeReview and build verification. Behavior preservation is verified through before-and-after comparison of test execution results.

## Architecture

```
Refactoring Plan (from Sou)  â”€â”€â–¶  Symbol Resolution
                                      â”‚
                                      â–¼
                              Dependency Graph Builder
                                      â”‚
                                      â–¼
                              Impact Analysis
                                      â”‚
                                      â–¼
                              Transformation Engine
                                      â”‚
                                      â–¼
                              Change Set Generation
                                      â”‚
                                      â–¼
                              Verification (build + test)
                                      â”‚
                                      â–¼
                              Applied Changes
```

The refactoring pipeline operates in two phases: analysis and transformation. The analysis phase resolves all symbols referenced in the plan, builds a complete dependency graph across affected files, and computes the full impact scope. The transformation phase generates ChangeSet entries for each file, applies them in dependency order, and runs verification to confirm behavior preservation. If verification fails, the entire operation is rolled back.

## Data Model

```typescript
interface RefactoringPlan {
  planId: string
  workerId: string
  operationType: RefactoringType
  targetSymbol: SymbolRef
  parameters: RefactoringParameters
  scope: RefactoringScope
  affectedFiles: string[]
  estimatedImpact: ImpactEstimate
}

interface SymbolRef {
  symbolId: string
  name: string
  kind: SymbolKind
  filePath: string
  line: number
  column: number
  namespace: string[]
  visibility: Visibility
  references: SymbolReference[]
}

interface DependencyGraph {
  nodes: DependencyNode[]
  edges: DependencyEdge[]
  entryPoints: string[]
  circularDependencies: CircularDependency[]
  unresolvedSymbols: UnresolvedSymbol[]
}

interface ChangeSet {
  changeSetId: string
  planId: string
  changes: FileChange[]
  rollbackInstructions: RollbackStep[]
  verificationStatus: VerificationStatus
  appliedAt: timestamp
}

interface FileChange {
  changeId: string
  filePath: string
  originalHash: string
  modifiedHash: string
  diff: string
  operations: CodeOperation[]
  backupPath: string
}

interface SymbolReference {
  referenceId: string
  symbolId: string
  filePath: string
  line: number
  column: number
  referenceType: ReferenceType
  resolved: boolean
}

interface DependencyNode {
  nodeId: string
  filePath: string
  symbols: string[]
  incomingEdges: number
  outgoingEdges: number
  changeCount: number
}

interface DependencyEdge {
  sourceNodeId: string
  targetNodeId: string
  edgeType: EdgeType
  symbols: string[]
}

interface CodeOperation {
  operationType: OperationType
  filePath: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
  oldText: string
  newText: string
}

interface ImpactEstimate {
  filesAffected: number
  symbolsChanged: number
  referencesUpdated: number
  estimatedComplexity: number
  riskLevel: RiskLevel
  requiresFullBuild: boolean
}

interface RollbackStep {
  filePath: string
  operation: string
  restoreHash: string
}

interface CircularDependency {
  cycle: string[]
  severity: string
  resolution: string
}

interface UnresolvedSymbol {
  name: string
  sourceFile: string
  possibleMatches: string[]
  resolutionStrategy: string
}

enum RefactoringType {
  RenameSymbol = "rename_symbol",
  ExtractMethod = "extract_method",
  InlineVariable = "inline_variable",
  MoveModule = "move_module",
  ExtractInterface = "extract_interface",
  ChangeSignature = "change_signature",
  ExtractConstant = "extract_constant",
  ReorderParameters = "reorder_parameters",
}

enum SymbolKind {
  Class = "class",
  Function = "function",
  Method = "method",
  Variable = "variable",
  Constant = "constant",
  Interface = "interface",
  Type = "type",
  Module = "module",
  Parameter = "parameter",
}

enum ReferenceType {
  Direct = "direct",
  Indirect = "indirect",
  Dynamic = "dynamic",
  StringReference = "string_reference",
}

enum OperationType {
  Insert = "insert",
  Delete = "delete",
  Replace = "replace",
  Move = "move",
}

enum Visibility {
  Public = "public",
  Protected = "protected",
  Private = "private",
  Internal = "internal",
}

enum EdgeType {
  Import = "import",
  Extension = "extension",
  Implementation = "implementation",
  Composition = "composition",
  Invocation = "invocation",
}

enum RiskLevel {
  Low = "low",
  Medium = "medium",
  High = "high",
  Critical = "critical",
}

enum VerificationStatus {
  Pending = "pending",
  Passed = "passed",
  Failed = "failed",
  RolledBack = "rolled_back",
}
```

## Core Operations

| Operation | Precondition | Postcondition |
|-----------|-------------|---------------|
| refactor_symbol | Symbol existence is confirmed in codebase | Symbol is renamed/refactored across all files; ChangeSet is produced |
| rename_across_files | Symbol references are fully resolved | All references updated; no stale references remain |
| extract_method | Code block is contiguous and side-effect free | New method is created; original block is replaced with invocation |
| inline_variable | Variable is assigned once and used in limited scope | Variable usages are replaced with value; declaration is removed |
| move_module | Module has no circular dependencies | Module is moved to target path; all imports are updated |
| change_signature | All call sites are identified | Signature is updated; all call sites are updated with new parameters |
| extract_constant | Literal value appears in multiple locations | Constant is created; all occurrences are replaced with constant reference |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IRefactoringEngine | Refactoring Engine | CodeWorker | ACF command |
| ISymbolResolver | Symbol Resolution | Refactoring Engine | Internal parse query |
| IDependencyGraphBuilder | Dependency Graph Builder | Refactoring Engine | Internal |
| IImpactAnalyzer | Impact Analysis | Refactoring Engine | Internal |
| ITransformationEngine | Transformation Engine | Refactoring Engine | Internal |
| IVerificationRunner | Verification | Refactoring Engine | BuildSandbox command |
| IRollbackManager | Rollback Manager | Refactoring Engine | Internal |

## Events

| COD.EventType |    Produced When | Fields |
|-----------|--------------|--------|
| COD.RefactoringPlanned |    A refactoring plan is created and analyzed | plan_id, operation_type, symbol_name, files_affected, risk_level |
| COD.RefactoringApplied |    Transformation changes are written to files | plan_id, changeset_id, files_modified, operations_count |
| COD.RefactoringVerified |    Verification confirms behavior preservation | plan_id, build_result, test_results, verification_duration_ms |
| COD.RefactoringFailed |    Refactoring pipeline encounters an error | plan_id, error_code, error_message, failed_stage |
| COD.RefactoringRolledBack |    Changes are reverted after verification failure | plan_id, changeset_id, files_restored, rollback_duration_ms |
| COD.SymbolResolved |    A symbol reference is resolved in the codebase | symbol_id, file_path, reference_count, resolution_duration_ms |
| COD.DependencyCycleDetected |    A circular dependency is found during analysis | plan_id, cycle_path, severity, suggested_resolution |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COD_REF_001 | Unresolved symbol reference in refactoring scope | Error | Report unresolved symbol; block transformation until resolved |
| COD_REF_002 | Circular dependency prevents safe transformation | Error | Report cycle with path; suggest reordering or splitting |
| COD_REF_003 | Transformation conflict (overlapping changes) | Error | Compute safe merge order; escalate if automatic resolution fails |
| COD_REF_004 | Verification failure after transformation | Error | Automatic rollback to original state; emit rollback Event |
| COD_REF_005 | Refactoring scope exceeds capability bounds | Warning | Partition refactoring into smaller steps; execute sequentially |
| COD_REF_006 | Dynamic reference cannot be statically resolved | Warning | Flag dynamic references for manual verification; proceed with static refs |
| COD_REF_007 | Language parser unsupported for refactoring | Error | Report unsupported language; refactoring cannot proceed |
| COD_REF_008 | BuildSandbox unavailable for verification | Error | Defer verification; mark changeset as unverified |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COD-REF-I-001 | Behavior is preserved before and after refactoring | Verification stage runs build and tests on both old and new code |
| COD-REF-I-002 | Every symbol reference is resolved before transformation | Pipeline blocks transformation if any reference is unresolved |
| COD-REF-I-003 | All changes are atomically rollback-able | ChangeSet includes complete rollback instructions; backup files are created |
| COD-REF-I-004 | No circular dependency is introduced by refactoring | Post-transformation dependency graph is checked for cycles |
| COD-REF-I-005 | Refactoring does not change public API signatures unless explicitly planned | Default operation mode preserves public API; explicit opt-in for API changes |
| COD-REF-I-006 | Each file change is hash-verified before and after transformation | Original and modified file hashes are recorded in ChangeSet |


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
| R1 - Modulsingularity | Each refactoring type (rename, extract, inline, move) is a separate module |
| R2 - Dependency Order | Refactoring depends on Language Registry and CodebaseIndex |
| R3 - DRY | Symbol resolution logic is shared across all refactoring types |
| R4 - Builder Pattern | ChangeSet is built incrementally through analysis + transformation phases |
| R5 - Liskov Substitution | All refactoring operations implement IRefactoringOperation interface |
| R6 - DI over Singletons | Analysis and transformation services are injected; no global state |
| R9 - Deterministic | Same plan + codebase state produces identical ChangeSet |
| R10 - Simpler Over Complex | Refactoring uses sequential transformation with dependency ordering |
| R13 - Design for Failure | Verification failure triggers automatic rollback; no partial state persists |
| R14 - Paved Path | Single paved path: analyze -> plan -> transform -> verify -> commit |
| R15 - Open/Closed | New refactoring types added by implementing IRefactoringOperation interface |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Coding/000-Overview.md | Coding domain overview â€” refactoring is a core code modification capability |
| Bible/07-Domains/Coding/001-Languages.md | Language Support Registry â€” provides language-specific parsing and symbol rules |
| Bible/07-Domains/Coding/002-Code-Generation.md | Code Generation â€” refactoring may trigger regeneration of dependent code |
| Bible/07-Domains/Coding/003-Review.md | Code Review â€” refactored code must pass review before merge |
| Physics/005-Events.md | Evidence â€” every refactoring stage produces auditable Events |
| Physics/007-Capabilities.md | Capabilities â€” refactoring scope bounded by Worker capability profile |
| Physics/010-Execution.md | Execution â€” verification is part of the execution pipeline |
| Bible/02-Core/Sou/002-Planner.md | Planner â€” Sou produces refactoring plans as structured code modifications |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” CodebaseIndex provides symbol graph for resolution |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” confidence scoring validates refactoring quality |
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Runtime SDK â€” BuildSandbox used for verification |
