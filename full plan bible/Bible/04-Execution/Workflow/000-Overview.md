# AIOS Bible — Execution
## 000 — Workflow Engine (WFE)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Workflow |
| Document ID | AIOS-BBL-004-WFE-000 |
| Source Laws | Law 8 — Law of Verification-First, Law 6 — Law of Lifecycle Compliance, Law 4 — Law of Evidence |
| Source Physics | Physics/010-Execution.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Workflow Engine orchestrates long-running, multi-step workflows with reliability guarantees. It manages DAG-based execution pipelines with built-in retry, checkpointing, pause/resume, human approval gates, rollback, and recovery capabilities. Every workflow step is verified before execution (Law 8), and every state transition produces evidence (Law 4).

WFE is distinct from Missions — Missions define strategic intent; Workflows define tactical execution sequences. Missions may spawn Workers directly (simple operations) or delegate to WFE (complex multi-step processes). WFE is also distinct from the Execution Planner (which produces execution graphs) — WFE executes DAGs, not plans.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Workflow Engine                     │
│  ┌─────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │  State   │  │ Retry    │  │ Approval           │  │
│  │  Machine │  │ Handler  │  │ Manager            │  │
│  └────┬─────┘  └────┬─────┘  └─────────┬──────────┘  │
│       │              │                  │             │
│  ┌────▼──────────────▼──────────────────▼──────────┐  │
│  │              Step Executor                        │  │
│  │  dispatches steps to Workers via ACF             │  │
│  └──────────────────────┬───────────────────────────┘  │
│                         │                              │
│  ┌──────────────────────▼───────────────────────────┐  │
│  │              Checkpoint Service                   │  │
│  │  periodic state snapshots for recovery           │  │
│  └──────────────────────┬───────────────────────────┘  │
└─────────────────────────┼─────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   ┌──────────┐    ┌──────────┐    ┌──────────────┐
   │  State   │    │  Event   │    │   Worker     │
   │  Store   │    │  Store   │    │   Pool       │
   └──────────┘    └──────────┘    └──────────────┘
```

## Core Concepts

### 1. Workflow Definition

A DAG of steps where edges define dependency relationships. A step cannot execute until all its upstream dependencies are satisfied. The DAG is validated at registration time (cycle detection, orphan step detection, type-specific validation) and is immutable once execution begins.

### 2. Step Types

| Type | Behavior | Output |
|------|----------|--------|
| Atomic | Execute a single task via a Worker | Success or Failure |
| Parallel | Fan out to N child branches; wait for all | Aggregated results |
| Conditional | Branch based on upstream step output | Selected branch path |
| Loop | Iterate over a collection or until condition | Aggregated results |
| Approval | Pause for human input via ACF | Approved or Rejected |
| SubWorkflow | Execute another workflow as a step | Nested workflow result |

### 3. Workflow State Machine

```
Pending ──► Ready ──► Running ──► Paused ──► Running
   │                   │            │
   │                   ▼            ▼
   └─────► Cancelled   │            │
                       ▼            ▼
                  Completed     Failed ──► RolledBack
```

| State | Description |
|-------|-------------|
| Pending | Definition registered, not yet started |
| Ready | All dependencies validated, awaiting execution |
| Running | Steps actively executing |
| Paused | Execution suspended (human approval or manual) |
| Completed | All steps finished successfully |
| Failed | A step failed with no retry remaining |
| RolledBack | Compensating actions executed on failure |
| Cancelled | Explicit cancellation before completion |

### 4. Checkpointing

Periodic state snapshots of workflow execution: current step, completed steps, step results, variable values, and execution context. Checkpoints are stored in the State Store and enable crash recovery. The checkpoint interval is configurable per workflow (default: after every step completion).

### 5. Retry Policy

Configurable per step: maximum retry count, backoff strategy (fixed, exponential, linear), backoff multiplier, maximum backoff duration, and timeout. Retries are recorded as evidence. When retries are exhausted, the step fails and the workflow transitions to the failure handling path.

### 6. Human Approval Gates

Workflow pauses execution at designated approval steps until a human operator provides input via ACF. The gate specifies the approver identity, required context, decision options, and optional timeout. If the gate times out, the configured timeout action is taken (retry, fail, or notify escalation).

### 7. Rollback

When a step fails and recovery is not possible, WFE executes compensating actions in reverse dependency order. Each step type may declare a compensating action that undoes its effects. Rollback is itself a workflow-like process with checkpointing and evidence production.

### 8. Recovery

Automated resume from the last checkpoint after system restart or crash. The Workflow Engine reads the latest checkpoint, validates consistency, and resumes execution from the interrupted step(s). Recovery is transparent to the workflow definition.

## Data Model

```typescript
interface WorkflowDef {
  workflowId: string;
  name: string;
  version: number;
  steps: WorkflowStep[];
  edges: DependencyEdge[];
  checkpointConfig: CheckpointConfig;
  createdAt: Timestamp;
  evidenceRef: string;
}

interface WorkflowStep {
  stepId: string;
  type: 'atomic' | 'parallel' | 'conditional' | 'loop' | 'approval' | 'subWorkflow';
  config: StepConfig;
  retryPolicy: RetryPolicy;
  timeout: Duration;
  compensatingAction?: CompensatingAction;
}

interface WorkflowState {
  workflowId: string;
  status: 'pending' | 'ready' | 'running' | 'paused' | 'completed' | 'failed' | 'rolledBack' | 'cancelled';
  currentStepId: string | null;
  completedSteps: string[];
  failedSteps: string[];
  stepResults: Record<string, StepResult>;
  previousCheckpointIds: string[];  // refs to prior checkpoints (historical, never self-referencing)
  error: WorkflowError | null;
}

interface Checkpoint {
  checkpointId: string;
  workflowId: string;
  stateSnapshot: WorkflowState;  // frozen state at checkpoint time; checkpoint is appended to previousCheckpointIds
  timestamp: Timestamp;
  evidenceRef: string;
}

interface RetryPolicy {
  maxRetries: number;
  backoffStrategy: 'fixed' | 'exponential' | 'linear';
  backoffMultiplier: number;
  maxBackoff: Duration;
  timeout: Duration;
}
```

## Interfaces

### WFE API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `createWorkflow(def)` | Sou, Organization | Register a new workflow definition |
| `executeWorkflow(workflowId)` | Sou, Organization | Start asynchronous execution |
| `pauseWorkflow(workflowId)` | Sou, Human Operator | Suspend execution |
| `resumeWorkflow(workflowId)` | Sou, Human Operator | Resume from current state |
| `cancelWorkflow(workflowId)` | Sou, Organization | Cancel pending or running workflow |
| `approveGate(gateId, decision, rationale)` | Human Operator | Provide input at approval gate |
| `getWorkflowStatus(workflowId)` | Any authenticated | Return current state |
| `getCheckpoint(workflowId)` | Security Council | Return latest checkpoint |

### Internal Interfaces

```typescript
interface StepExecutor {
  execute(step: WorkflowStep, context: ExecutionContext): Promise<StepResult>;
  validateStep(step: WorkflowStep): ValidationResult;
}

interface StateMachine {
  transition(current: WorkflowState, event: StateEvent): WorkflowState;
  validateTransition(from: string, to: string): boolean;
}

interface CheckpointService {
  createCheckpoint(state: WorkflowState): Promise<Checkpoint>;
  restoreCheckpoint(checkpointId: string): Promise<WorkflowState>;
  listCheckpoints(workflowId: string): Promise<Checkpoint[]>;
}

interface ApprovalManager {
  createGate(step: WorkflowStep, context: ApprovalContext): Promise<Gate>;
  resolveGate(gateId: string, decision: ApprovalDecision): Promise<void>;
  timeoutGates(): Promise<Gate[]>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Workflow Engine | Central orchestrator — manages lifecycle, dispatches steps, coordinates components |
| State Machine | Enforces workflow lifecycle transitions; validates every state change |
| Step Executor | Dispatches individual steps to Workers via ACF; handles step-level retry |
| State Store | Persistent key-value store for workflow and step state |
| Checkpoint Service | Periodic state snapshots; recovery from last good checkpoint |
| Retry Handler | Configurable retry logic with backoff; manages retry state |
| Approval Manager | Human approval gate lifecycle; timeout and escalation |
| Rollback Coordinator | Executes compensating actions in reverse dependency order |

## Data Flow

```
Workflow definition submitted via ACF
        │
        ▼
Workflow Engine validates DAG (cycle check, type validation)
        │
        ▼
State machine: Pending ──► Ready
        │
        ▼
Step Executor picks ready steps (all dependencies satisfied)
        │
        ▼
Execute step via Worker (ACF dispatch)
        │
        ├── Success ──► Checkpoint ──► Next step(s)
        │
        └── Failure ──► Retry Handler
                           │
                    ├── Retries left ──► Re-execute step
                    │
                    └── Retries exhausted ──► Rollback Coordinator
                                                    │
                                              Compensating actions
                                                    │
                                              State: Failed ──► RolledBack
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `WFE.WorkflowCreated` | workflowId, name, version | Workflow definition registered |
| `WFE.WorkflowStarted` | workflowId, stepCount | Execution initiated |
| `WFE.StepStarted` | workflowId, stepId, type | Individual step execution began |
| `WFE.StepCompleted` | workflowId, stepId, result | Step finished successfully |
| `WFE.StepFailed` | workflowId, stepId, error, retriesLeft | Step execution failed |
| `WFE.StepRetrying` | workflowId, stepId, attempt, backoff | Retry scheduled |
| `WFE.WorkflowPaused` | workflowId, reason, stepId | Execution suspended |
| `WFE.WorkflowResumed` | workflowId, stepId | Execution resumed |
| `WFE.GateAwaitingApproval` | workflowId, gateId, approver | Approval gate waiting for human input |
| `WFE.GateApproved` | workflowId, gateId, decision | Human approval received |
| `WFE.GateTimedOut` | workflowId, gateId | Approval gate exceeded timeout |
| `WFE.CheckpointCreated` | workflowId, checkpointId | State snapshot saved |
| `WFE.WorkflowCompleted` | workflowId, totalSteps, duration | All steps completed |
| `WFE.WorkflowFailed` | workflowId, failedStep, error | Workflow terminated with failure |
| `WFE.RollbackInitiated` | workflowId, cause | Rollback of compensating actions started |
| `WFE.RollbackCompleted` | workflowId | All compensating actions executed |
| `WFE.WorkflowCancelled` | workflowId, reason | Explicit cancellation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Workflow definition fails validation | `WFE_INVALID_DEFINITION` | Reject creation; return validation errors |
| DAG contains a cycle | `WFE_CYCLE_DETECTED` | Reject definition; cycle edges identified |
| Step exceeded execution timeout | `WFE_STEP_TIMEOUT` | Mark step failed; initiate retry logic |
| All retry attempts exhausted | `WFE_RETRY_EXHAUSTED` | Transition workflow to Failed |
| Compensating action failed | `WFE_ROLLBACK_FAILED` | Log critical error; system intervention required |
| State persistence error | `WFE_CHECKPOINT_FAILED` | Retry checkpoint; if persists, pause workflow |
| Approval gate timed out | `WFE_APPROVAL_TIMEOUT` | Execute gate timeout policy (notify / fail / skip) |
| Invalid state transition requested | `WFE_INVALID_STATE_TRANSITION` | Reject; return valid next states |
| Workflow not found | `WFE_NOT_FOUND` | Return error; no side effects |
| Step type not supported | `WFE_UNKNOWN_STEP_TYPE` | Reject definition; type must be registered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WFE-001 | Every workflow step is verified before execution (Law 8) | Architectural — EAS token required before Worker dispatch |
| WFE-002 | Every state transition produces an evidence record (Law 4) | Architectural — EVS event emitted on every transition |
| WFE-003 | Workflow state is always recoverable from the last checkpoint | Algorithmic — consistency check on State Store read |
| WFE-004 | Rollback executes compensating actions in reverse dependency order | Algorithmic — topological sort of completed steps |
| WFE-005 | A workflow in a terminal state cannot transition | Algorithmic — State Machine rejects transitions from terminal states |
| WFE-006 | Human approval gates are the only mechanism that pauses workflow execution | Constitutional — pause reason must be authorization or manual gate |
| WFE-007 | Every retry attempt records a distinct evidence event | Architectural — Retry Handler emits StepRetrying before re-execution |
| WFE-008 | The workflow DAG is immutable once execution begins | Architectural — WorkflowDef is sealed on first execute |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | WFE owns workflow execution exclusively; Planning System owns execution graphs; Missions own strategic intent |
| R2 — Dependency Order | WFE depends on ACF (dispatch), State Store (persistence), EVS (evidence), EAS (authorization); no cycles |
| R3 — DRY | Workflow step types are defined once in the type registry; steps reference types, not duplicate logic |
| R4 — Builder Pattern | WorkflowDef and WorkflowStep use builder construction for complex validation during registration |
| R9 — Deterministic | Given the same WorkflowDef and identical input, two executions produce identical state transitions |
| R10 — Simpler Over Complex | Default retry policy and checkpoint interval work for most workflows; tuning is explicit |
| R13 — Design for Failure | Rollback, checkpoint recovery, and retry exhaust all failure modes; compensating actions are first-class entities |
| R14 — Paved Path | Default workflow template (Atomic steps with retry) covers 80% of use cases |
| R15 — Open/Closed | New step types can be registered via RFC; step executor is extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime executes individual workflow steps via Workers |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | EAS authorizes each step before execution |
| Bible/02-Core/Brain/Planning/000-Overview.md | Planning System produces execution graphs that WFE can execute |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Missions define the strategic context for workflows |
| Bible/04-Execution/Security/000-Overview.md | Security Council verifies every step before execution |
| Bible/05-Platform/004-EVS.md | EVS stores workflow evidence records |
| Bible/05-Platform/005-AUS.md | AUS audits workflow execution |
| Bible/05-Platform/Observability/000-AOP.md | AOP monitors workflow health and performance |
| Bible/06-Services/ACF/000-Overview.md | ACF is the transport layer for step dispatch |
| Physics/010-Execution.md | Execution invariants |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants |
