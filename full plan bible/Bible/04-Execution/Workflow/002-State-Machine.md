# AIOS Bible — Execution
## 002 — State Machine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Workflow |
| Document ID | AIOS-BBL-004-WFE-002 |
| Source Laws | Law 8 — Law of Verification-First, Law 6 — Law of Lifecycle Compliance, Law 4 — Law of Evidence |
| Source Physics | Physics/010-Execution.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Formal state machine definition for workflow lifecycle — all states, transitions, transition guards, and state-dependent capabilities.

## Architecture

The state machine is a deterministic finite automaton governing workflow lifecycle. Every state transition is validated against the transition table, checked by guards, and recorded as evidence. The state machine is the single source of truth for what a workflow may do at any point in its lifecycle.

```
                        ┌──────────────────────────────────────────┐
                        │                                          │
                        ▼                                          │
Pending ───► Ready ───► Running ───► Paused ───────────────────────┘
   │                      │  ▲          │
   │                      │  └──────────┘
   │                      │
   │                      ▼              ┌──────────┐
   └──────────► Cancelled            ┌──►│ Completed │
                                      │   └──────────┘
                        Running ──────┤
                        (all steps     │   ┌──────────┐
                         terminal)    └──►│  Failed   │
                                          └─────┬────┘
                                                │
                                                ▼
                                          ┌───────────┐
                                          │ RolledBack │
                                          └───────────┘
```

## Data Model

```typescript
type WorkflowState = 'pending' | 'ready' | 'running' | 'paused' | 'completed' | 'failed' | 'rolledBack' | 'cancelled';

interface StateTransition {
  from: WorkflowState;
  to: WorkflowState;
  trigger: string;               // event name that initiates the transition
  guardIds: string[];            // preconditions that must pass
  requiredRole: string;          // actor role required to request this transition
}

interface TransitionGuard {
  guardId: string;
  name: string;
  evaluate(context: GuardContext): Promise<GuardResult>;
  description: string;
}

interface GuardContext {
  workflowId: string;
  fromState: WorkflowState;
  toState: WorkflowState;
  currentState: WorkflowState;   // full state object for richer checks
  actor: string;
  timestamp: Timestamp;
}

interface GuardResult {
  allowed: boolean;
  reason?: string;
  evidenceRef?: string;
}

interface StateCapability {
  state: WorkflowState;
  operations: string[];          // operation names allowed in this state
  description: string;
}

interface ConcurrencyLock {
  workflowId: string;
  currentState: WorkflowState;
  lockedBy: string;              // process or actor holding the lock
  acquiredAt: Timestamp;
  expiresAt: Timestamp;
}
```

## Core Concepts / Operations

### Complete State Transition Table

| From | To | Trigger | Guard | Required Role |
|------|----|---------|-------|---------------|
| Pending | Ready | `validate.success` | All validation guards passed | System (WFE) |
| Pending | Cancelled | `cancel` | Workflow not yet started | Sou, Organization |
| Ready | Running | `execute` | All steps have valid type, dependencies resolved | Sou, Organization |
| Running | Paused | `pause` | No step in critical section; approval gate may trigger pause | Sou, Human Operator |
| Paused | Running | `resume` | Pause reason resolved; all prior state intact | Sou, Human Operator |
| Running | Completed | `step.completed` (last step) | All steps in terminal state; no failed steps | System (WFE) |
| Running | Failed | `step.failed` (retries exhausted) | At least one step exhausted retries; no compensating action in progress | System (WFE) |
| Running | Cancelled | `cancel` | No irreversible operation in progress | Sou, Organization |
| Failed | RolledBack | `rollback.completed` | All compensating actions executed successfully | System (WFE) |
| Failed | Paused | `pause` (operator intervention) | Operator assessment required | Human Operator |
| Paused | Cancelled | `cancel` | No irreversible operation in progress | Sou, Organization |
| Paused | Failed | `step.timeout` (approval gate expired) | Gate timeout policy = fail | System (WFE) |

Terminal states: Completed, Cancelled, RolledBack. No transitions out of terminal states.

### Transition Guards

| Guard ID | Name | Precondition |
|----------|------|-------------|
| G-001 | ValidationComplete | All validation stages passed; no unresolved validation errors |
| G-002 | StepsReady | At least one step has all dependencies satisfied (for Running entry) |
| G-003 | NoCriticalSection | No step is in an irreversible operation (I/O, compensating action) |
| G-004 | StateIntact | The persisted state matches expected state; no corruption detected |
| G-005 | RetryExhausted | The failing step has no remaining retry attempts |
| G-006 | CompensationsComplete | All compensating actions executed; none failed |
| G-007 | AuthorizationValid | Actor is authorized for the transition per required role |
| G-008 | PauseReasonResolved | The condition that triggered the pause has been addressed |
| G-009 | NotTerminal | Current state is not a terminal state |
| G-010 | EvidenceRecorded | All required evidence events for the current state are persisted |

### State-Dependent Capabilities

| State | Allowed Operations | Description |
|-------|-------------------|-------------|
| Pending | `cancel`, `updateDefinition`, `getStatus` | Definition can still be modified; no execution |
| Ready | `execute`, `cancel`, `getStatus` | Awaiting execution start; can be cancelled before first step |
| Running | `pause`, `cancel`, `getStatus`, `getCheckpoint` | Active execution; limited intervention |
| Paused | `resume`, `cancel`, `getStatus`, `getCheckpoint`, `updateConfig` | Suspended; configuration can be adjusted |
| Completed | `getStatus`, `getCheckpoint`, `getResults` | Read-only; terminal |
| Failed | `rollback` (auto), `pause`, `getStatus`, `getCheckpoint` | Failure state; operator can pause for assessment before rollback |
| RolledBack | `getStatus`, `getCheckpoint`, `getResults` | Read-only; terminal |
| Cancelled | `getStatus`, `getCheckpoint` | Read-only; terminal |

### Concurrency Handling

Multiple transitions on the same workflow are serialized via concurrency locks:

1. Before a transition is attempted, a concurrency lock is acquired on the workflow
2. The lock includes a lease duration; if the transition does not complete within the lease, the lock expires
3. If a transition is requested while another is in progress, a ConcurrencyConflict event is emitted and the request is queued
4. After the transition completes, the lock is released and the next queued request (if any) proceeds

The lock is stored in the State Store with the following guarantees:
- Pessimistic locking: a lock must be acquired before any state mutation
- Lease expiry: stale locks are detected and released after a configurable timeout
- Deadlock detection: if a process holds a lock beyond the lease and does not renew, the lock is forcibly released

### Persistence Model for State

State is persisted to the State Store on every transition with these guarantees:

- **Write-ahead log**: state mutation is first appended to a WAL, then applied to the state record
- **Snapshot isolation**: readers see the last committed state; in-flight transitions are invisible
- **Versioned records**: each state record carries a version number incremented on every transition
- **Evidence coupling**: every persisted state record references the EVS evidence event that caused the transition

### State Recovery After Crash

1. On startup, WFE loads all workflows from the State Store that are in non-terminal states
2. For each workflow, the latest checkpoint is loaded and compared with the current state record
3. If the checkpoint is ahead of the state record, the state is restored from the checkpoint
4. If the state record is ahead of the checkpoint, the state is used as-is (checkpoint may have failed to persist)
5. Workflows in Running or Paused state at the time of crash are returned to the appropriate predecessor state:
   - Running → Paused (with reason "crash recovery — manual resume required")
   - Paused → Paused (state is valid; resume can proceed)
6. A StateRecovered event is emitted for each recovered workflow

## Internal Interfaces

```typescript
interface StateMachine {
  transition(current: WorkflowState, event: StateEvent): WorkflowState;
  validateTransition(from: WorkflowState, to: WorkflowState): boolean;
  getAllowedTransitions(state: WorkflowState): StateTransition[];
  getCapabilities(state: WorkflowState): StateCapability;
}

interface GuardEvaluator {
  evaluate(guardIds: string[], context: GuardContext): Promise<GuardResult[]>;
  getGuard(guardId: string): TransitionGuard;
  registerGuard(guard: TransitionGuard): void;
}

interface ConcurrencyManager {
  acquireLock(workflowId: string, actor: string, leaseDuration: Duration): Promise<boolean>;
  releaseLock(workflowId: string, actor: string): Promise<void>;
  renewLock(workflowId: string, actor: string, leaseDuration: Duration): Promise<void>;
  isLocked(workflowId: string): Promise<ConcurrencyLock | null>;
}

interface StatePersistence {
  persistState(workflowId: string, state: WorkflowState, version: number): Promise<void>;
  loadState(workflowId: string): Promise<WorkflowState | null>;
  loadAllNonTerminal(): Promise<WorkflowState[]>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `WFE.SM.StateEntered` | workflowId, state, previousState, version | State machine entered a new state |
| `WFE.SM.StateExited` | workflowId, state, nextState, version | State machine exited a state |
| `WFE.SM.TransitionRequested` | workflowId, fromState, toState, trigger, actor | Transition was requested |
| `WFE.SM.TransitionApproved` | workflowId, fromState, toState, guardResults | All guards passed; transition approved |
| `WFE.SM.TransitionDenied` | workflowId, fromState, toState, failedGuard, reason | A guard blocked the transition |
| `WFE.SM.TransitionGuardFailed` | workflowId, guardId, error, context | Guard evaluation threw an error |
| `WFE.SM.StateExpired` | workflowId, state, duration | State exceeded its maximum allowed duration (configurable per workflow) |
| `WFE.SM.ConcurrencyConflict` | workflowId, requestedBy, currentLockHolder | Concurrent transition request detected and queued |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Invalid transition requested | `WFE_SM_001` | Reject; return list of valid transitions from current state |
| Transition guard evaluation failed | `WFE_SM_002` | Deny transition; emit TransitionDenied with guard reason |
| Concurrency lock acquisition timeout | `WFE_SM_003` | Queue request; emit ConcurrencyConflict; retry after lock release |
| State persistence write failure | `WFE_SM_004` | Retry persistence; if exhausted, emit StateExpired and pause workflow |
| State recovery inconsistency | `WFE_SM_005` | Log critical error; operator must reconcile checkpoint vs state record |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WFE-SM-001 | Every state transition is validated against the transition table | Architectural — StateMachine.validateTransition called before every mutation |
| WFE-SM-002 | Every state transition produces an evidence record (Law 4) | Architectural — EVS event emitted on every approved transition |
| WFE-SM-003 | A workflow in a terminal state cannot transition | Algorithmic — Transition table has zero outbound entries for terminal states |
| WFE-SM-004 | Concurrency locks prevent simultaneous state mutations on the same workflow | Algorithmic — Lock must be acquired before any state write |
| WFE-SM-005 | State recovery after crash produces a deterministic result from persisted data | Algorithmic — Recovery logic is a pure function of checkpoint + state record |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | State machine owns all lifecycle transitions; no other component mutates workflow state |
| R2 — Dependency Order | State machine depends on GuardEvaluator, ConcurrencyManager, StatePersistence; no cycles |
| R3 — DRY | Transition table is the single source of truth; guards are reusable across transitions |
| R4 — Builder Pattern | State machine configuration is built from transition table and guard registry |
| R9 — Deterministic | Same current state + same event produces same next state |
| R10 — Simpler Over Complex | Default transition guards cover common cases; custom guards are additive |
| R13 — Design for Failure | Concurrency locks expire; crash recovery is automatic and deterministic |
| R15 — Open/Closed | New states and transitions can be added via RFC without modifying existing transitions |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — WFE architecture including state machine component |
| 001-Pipeline-Architecture.md | Pipeline uses state machine to drive Execute stage transitions |
| 003-Monitoring.md | Monitoring tracks state transitions and alerts on state expiry |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime step execution triggers state transitions |
| Bible/05-Platform/004-EVS.md | EVS stores evidence for every state transition |
| Bible/05-Platform/005-AUS.md | AUS audits state machine lifecycle |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants |
