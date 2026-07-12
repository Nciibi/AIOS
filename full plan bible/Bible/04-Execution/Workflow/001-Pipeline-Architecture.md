# AIOS Bible — Execution
## 001 — Pipeline Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Workflow |
| Document ID | AIOS-BBL-004-WFE-001 |
| Source Laws | Law 8 — Law of Verification-First, Law 6 — Law of Lifecycle Compliance, Law 4 — Law of Evidence |
| Source Physics | Physics/010-Execution.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Detail the internal pipeline architecture of the Workflow Engine — how workflow definitions are parsed, validated, compiled into execution DAGs, and dispatched.

## Architecture

The WFE internal pipeline is a staged architecture through which every workflow definition passes. Each stage performs a discrete transformation or validation, with strict gates between stages. A stage cannot begin until the previous stage reports success.

```
WorkflowDef (raw)
     │
     ▼
┌─────────────┐
│  Register   │  — validate schema, assign ID, record evidence
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Validate   │  — cycle detection, orphan detection, type validation
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Compile    │  — topological sort, parallel branch detection, DAG assembly
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Execute    │  — dispatch ready steps, handle retries/approvals
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Monitor    │  — health checks, metrics collection, alert evaluation
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Complete   │  — final evidence, state finalization, cleanup
└─────────────┘
```

Errors at any stage propagate to the pipeline error handler, which decides whether to retry the stage or fail the entire pipeline.

## Data Model

```typescript
type PipelineStage = 'register' | 'validate' | 'compile' | 'execute' | 'monitor' | 'complete';

interface DAGCompiler {
  compile(def: WorkflowDef): ExecutionDAG;
  validateDAG(dag: ExecutionDAG): ValidationResult;
  detectCycles(dag: ExecutionDAG): CycleReport;
  detectParallelBranches(dag: ExecutionDAG): Branch[];
  topologicalSort(dag: ExecutionDAG): OrderedStep[];
}

interface ExecutionDAG {
  workflowId: string;
  nodes: DAGNode[];
  edges: DAGEdge[];
  topologicalOrder: string[];
  parallelBranches: Branch[];
  entryNodes: string[];        // nodes with no inbound edges
  terminalNodes: string[];     // nodes with no outbound edges
  compiledAt: Timestamp;
}

interface DAGNode {
  stepId: string;
  stepType: WorkflowStep['type'];
  config: StepConfig;
  retryPolicy: RetryPolicy;
  timeout: Duration;
  dependsOn: string[];         // stepIds that must complete before this node
  branchId?: string;           // parallel branch identifier, if part of a parallel group
  isEntry: boolean;
  isTerminal: boolean;
}

interface DAGEdge {
  source: string;              // upstream stepId
  target: string;              // downstream stepId
  edgeType: 'dependency' | 'conditional' | 'loop-back';
  condition?: string;          // expression evaluated at runtime for conditional edges
}

interface StageResult {
  stage: PipelineStage;
  success: boolean;
  output: Record<string, unknown>;
  errors: StageError[];
  startedAt: Timestamp;
  completedAt: Timestamp;
  evidenceRef: string;
}

interface StageError {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

interface CycleReport {
  hasCycle: boolean;
  cycles: string[][];          // each cycle is a list of stepIds
  cycleEdges: { source: string; target: string }[];
}

interface Branch {
  branchId: string;
  nodeIds: string[];
  isParallel: boolean;
}
```

## Core Concepts / Operations

### Pipeline Stages

| Stage | Input | Output | Validation Gate |
|-------|-------|--------|-----------------|
| Register | Raw WorkflowDef | Registered WorkflowDef with ID and evidence ref | Schema conformance, required fields, naming rules |
| Validate | Registered WorkflowDef | Validation report (pass/fail) | Cycle-free, no orphan steps, all types known, edge targets exist |
| Compile | Validated WorkflowDef | ExecutionDAG (topologically sorted) | DAG integrity, topological order covers all nodes, no duplicate edges |
| Execute | ExecutionDAG | Execution results per step | Step readiness (all deps satisfied). EAS token present before dispatch |
| Monitor | Runtime execution context | Metrics snapshots, health status | Metrics schema, non-negative counters |
| Complete | Final state | Final evidence record, state sealed | Terminal state, all evidence recorded, no dangling references |

### DAG Compilation

The DAGCompiler transforms a validated WorkflowDef into an executable ExecutionDAG:

1. **Node construction** — each WorkflowStep becomes a DAGNode with dependency metadata
2. **Edge construction** — each DependencyEdge becomes a DAGEdge with type classification
3. **Entry/terminal marking** — nodes with zero inbound edges are entry nodes; nodes with zero outbound edges are terminal nodes
4. **Topological sort** — Kahn's algorithm produces a linear ordering respecting all dependencies
5. **Parallel branch detection** — groups of nodes that share no transitive dependency path between them; identified via reachability analysis
6. **Cycle detection** — DFS-based cycle detection ran again on the compiled DAG as a safety invariant check; cycles trip WFE_PIPE_002

### Cycle Detection Algorithm

```
Input: ExecutionDAG
Output: CycleReport

1. Build adjacency list from DAGEdge[]
2. For each node not yet visited:
   a. Mark node as visiting
   b. For each neighbor:
        - If neighbor is visiting, cycle detected
        - If neighbor is unvisited, recurse
   c. Mark node as visited
3. Return report with all detected cycles and their edges
```

Cycle detection runs during Validate (to reject bad definitions) and again during Compile (as an invariant check). The second run can only fail due to a compiler bug, making it a runtime safety net.

### Stage-Level Validation Gates

Each stage gate is a boolean predicate. When a gate fails, the pipeline records the error and rejects the workflow rather than proceeding.

| Gate | Stage | Condition |
|------|-------|-----------|
| Schema Gate | Register | Definition conforms to WorkflowDef schema |
| Cycle Gate | Validate | No cycles exist in the step graph |
| Orphan Gate | Validate | Every step is reachable and has at least one path from an entry node |
| Type Gate | Validate | All step types are in the registered type registry |
| Sort Gate | Compile | Topological order includes every node exactly once |
| Integrity Gate | Compile | Number of edges equals number of dependency declarations |
| Evidence Gate | Execute | Every step execution has an EAS token before dispatch |
| Completion Gate | Complete | All steps are in a terminal state, no dangling branches |

### Pipeline Error Propagation

When a stage fails, the pipeline follows this escalation:

1. **Stage retry** — the failed stage is retried up to a configurable limit (default 3)
2. **Pipeline pause** — if stage retries exhausted, the entire pipeline transitions to paused; operator intervention required
3. **Pipeline failure** — if operator intervention fails or timeout elapses, the pipeline transitions to failed; rollback initiated for any partially executed steps

Error codes carry the originating stage so operators can pinpoint where the pipeline broke.

## Internal Interfaces

```typescript
interface PipelineOrchestrator {
  submit(def: WorkflowDef): Promise<PipelineResult>;
  getPipelineStatus(pipelineId: string): PipelineStatus;
  cancelPipeline(pipelineId: string): Promise<void>;
  retryStage(pipelineId: string, stage: PipelineStage): Promise<StageResult>;
}

interface StageGate {
  evaluate(context: PipelineContext): GateResult;
}

interface PipelineErrorHandler {
  handle(error: PipelineError, context: PipelineContext): Promise<ErrorResolution>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `WFE.Pipe.DefinitionReceived` | workflowId, name, version, rawDef | Raw workflow definition received by Register stage |
| `WFE.Pipe.DefinitionValidated` | workflowId, validationReport, passed | Validate stage completed with pass/fail outcome |
| `WFE.Pipe.DAGCompiled` | workflowId, nodeCount, edgeCount, branchCount | DAG compiled successfully from validated definition |
| `WFE.Pipe.DAGValidationPassed` | workflowId, topologicalOrderHash, cycleReport | Integrity check on compiled DAG passed |
| `WFE.Pipe.ExecutionStarted` | workflowId, entryNodeCount | Execute stage began dispatching steps |
| `WFE.Pipe.StageEntered` | workflowId, stage, previousStage | Pipeline entered a new stage |
| `WFE.Pipe.StageExited` | workflowId, stage, success, duration | Pipeline exited a stage with outcome |
| `WFE.Pipe.PipelineCompleted` | workflowId, totalStages, totalDuration | All pipeline stages completed successfully |
| `WFE.Pipe.PipelineFailed` | workflowId, failedStage, error, resolution | Pipeline terminated due to stage failure |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Definition fails schema validation at Register | `WFE_PIPE_001` | Return validation errors; definition not stored |
| Cycle detected in step graph at Validate | `WFE_PIPE_002` | Return cycle edges; definition rejected |
| Orphan step (unreachable from any entry node) | `WFE_PIPE_003` | Return orphan step IDs; definition rejected |
| Unknown step type referenced | `WFE_PIPE_004` | Reject definition; list registered types |
| DAG topological sort fails (cycle survived validation) | `WFE_PIPE_005` | Critical compiler bug; pipeline paused for operator |
| Stage retry limit exhausted | `WFE_PIPE_006` | Pipeline paused; operator must intervene or fail |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WFE-PIPE-001 | Every pipeline stage runs a validation gate before producing output | Architectural — Gate executed before state transition in each stage |
| WFE-PIPE-002 | DAG compilation is idempotent for identical WorkflowDef inputs | Algorithmic — Deterministic topological sort and branch detection |
| WFE-PIPE-003 | The pipeline cannot skip a stage | Architectural — Stage progression gated by prior stage success |
| WFE-PIPE-004 | Every pipeline event is recorded as evidence (Law 4) | Architectural — EVS emission on every WFE.Pipe.* event |
| WFE-PIPE-005 | A failed pipeline preserves partial execution state for recovery | Algorithmic — State persisted before any irreversible action |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Pipeline owns the full lifecycle of a workflow definition from submission through completion |
| R2 — Dependency Order | Pipeline depends on DAGCompiler, StageGate, and PipelineErrorHandler; no cycles between stages |
| R3 — DRY | Stage gate logic is defined once per gate; reused across all definitions |
| R4 — Builder Pattern | Pipeline stages are composed via builder for testability |
| R9 — Deterministic | Same WorkflowDef produces identical ExecutionDAG across compilations |
| R10 — Simpler Over Complex | Default pipeline skips no stages; all gates enabled for safety |
| R13 — Design for Failure | Pipeline error handler retries stages; operator intervention is the last resort |
| R15 — Open/Closed | New pipeline stages can be added via RFC; existing stages unchanged |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — WFE architecture and component map |
| 002-State-Machine.md | State Machine drives Execute stage transitions |
| 003-Monitoring.md | Monitor stage collects metrics and evaluates alerts |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime executes individual steps dispatched by Execute stage |
| Bible/05-Platform/004-EVS.md | EVS stores evidence records for every pipeline event |
| Bible/05-Platform/005-AUS.md | AUS audits pipeline stage transitions |
| Physics/010-Execution.md | Execution invariants including verification-first |
