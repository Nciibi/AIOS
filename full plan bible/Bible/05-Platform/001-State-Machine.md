# AIOS Bible — Platform
## 001 — State Machine Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Platform |
| Document ID | AIOS-BBL-005-SM-000 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 9 — Law of Design DNA |
| Source Physics | Physics/006-Lifecycles.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Generic state machine implementation used by LMS and other stateful components. The State Machine Engine provides a reusable, deterministic, versioned state machine framework. Every state machine follows the same formal model: a finite set of states, a set of valid transitions, guard conditions for authorization, and side-effect actions triggered on transition.

## State Machine Definition

A state machine is defined by:

```
MachineDefinition {
  id: string,
  version: int,
  initial_state: string,
  terminal_states: string[],
  states: State[],
  transitions: Transition[],
  guards: Guard[],
  actions: Action[]
}
```

| Component | Description |
|-----------|-------------|
| **states** | Finite set of valid states for this machine |
| **transitions** | Allowed state transitions: (current, event) → next |
| **guards** | Authorization checks that must pass before transition executes |
| **actions** | Side effects triggered on successful transition |
| **initial_state** | The state every entity starts in |
| **terminal_states** | States from which no transitions are allowed |

### Transition Function

The canonical transition function is:

```
δ(current_state, event) → next_state
```

This function is deterministic (R9): given the same current state and the same event, it always produces the same next state. The function is defined by the transition table. If no transition exists for the given (current, event) pair, δ returns an error.

### State Definition

```
State {
  name: string,
  type: initial | normal | terminal,
  capabilities: string[],    // capabilities available in this state
  metadata: map<string, any>
}
```

### Transition Definition

```
Transition {
  id: string,
  from: string,           // source state
  to: string,             // target state
  event: string,          // triggering event
  guards: string[],       // guard function IDs
  actions: string[],      // action function IDs
  metadata: map<string, any>
}
```

## State Machine Operations

```
defineMachine(definition) → machine_id
getMachine(machine_id) → MachineDefinition
getValidTransitions(state) → Transition[]
executeTransition(entity_id, event, context) → Result
getMachineVersion(machine_id) → int
listMachines(filter?) → MachineDefinition[]
deleteMachine(machine_id) → void
```

### executeTransition

The heart of the engine. Steps:

1. Load entity's current state
2. Find transition matching (current_state, event)
3. If no transition exists, return InvalidTransition error
4. Evaluate all guards sequentially
5. If any guard fails, return GuardFailed error with guard name
6. Execute all actions sequentially
7. If an action fails, roll back executed actions
8. Commit new state
9. Return success with new state

### Guard Evaluation

Each guard receives:

```
GuardInput {
  entity_id: UUID,
  current_state: string,
  event: string,
  context: ExecutionContext,    // includes requesting entity
  machine: MachineDefinition
}
```

Guards return `{allowed: bool, reason: string, code: string}`.

## Versioning

State machines are versioned. Changing a machine definition creates a new version. Entities continue under the version they started with.

### Version Increment Triggers

| Change | Version Impact | Migration Required? |
|--------|---------------|---------------------|
| Add new state | Major | Optional |
| Remove state | Major | Required |
| Add transition | Minor | None |
| Remove transition | Major | Required |
| Change guard | Minor | None |
| Change action | Minor | None |
| Add terminal state | Major | Required |

### Migration Process

```
1. New machine version is published
2. Entities are notified of available upgrade
3. Entity owner initiates migration at safe point
4. Migration replays entity history through new machine
5. If valid, entity is upgraded to new version
6. Migration produces MigrationEvent
```

## Determinism Guarantees

The State Machine Engine enforces determinism at every level:

- Same input state + same event → same output state
- Same machine definition → same behavior across instances
- Same guard evaluation → same authorization result
- Same action execution → same side effects

### Guard Determinism

Guards must be pure functions — they cannot have side effects, cannot depend on external state, and must be reproducible. Guard inputs include all context needed to make a deterministic decision.

### Action Determinism

Actions may have side effects (that is their purpose), but they must be idempotent. Executing an action twice must produce the same final state as executing it once.

## Guards and Actions

### Guard Types

| Guard Type | Purpose | Evaluation |
|-----------|---------|------------|
| AuthorizationGuard | Who may trigger the transition | Match requester against allowlist |
| PreconditionGuard | Conditions that must be true | Evaluate predicate |
| StateGuard | Entity must be in valid state | Verify current state |
| ResourceGuard | Resources must be available | Query resource system |
| TimeGuard | Time-based constraints | Evaluate time condition |

### Action Types

| Action Type | Purpose | Idempotent? |
|------------|---------|-------------|
| EventAction | Produce Event | Yes |
| NotificationAction | Notify entities | Yes |
| ResourceAction | Freeze/release resources | Yes |
| CascadeAction | Trigger child transitions | Yes (with idempotency) |
| LogAction | Write to audit log | Yes |

## State Machine Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `SM.MachineDefined` | New machine registered | machine_id, version, machine_type, states, transitions |
| `SM.MachineVersioned` | Machine definition updated | machine_id, old_version, new_version, changes |
| `SM.MachineDeleted` | Machine definition removed | machine_id, version, entities_affected |
| `SM.TransitionExecuted` | Transition completes | machine_id, entity_id, event, from_state, to_state, duration_ns |
| `SM.TransitionFailed` | Transition rejected | machine_id, entity_id, event, guard_name, reason, error_code |
| `SM.GuardEvaluated` | Guard evaluated (audit) | machine_id, entity_id, guard_name, result, duration_ns |
| `SM.ActionExecuted` | Action completed | machine_id, entity_id, action_name, result |
| `SM.MigrationCompleted` | Entity migrated to new version | entity_id, old_version, new_version, transition_count |

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| max_guards_per_transition | 10 | Maximum guards per transition |
| max_actions_per_transition | 10 | Maximum actions per transition |
| action_timeout_ms | 5000 | Timeout for action execution |
| max_states | 50 | Maximum states per machine |
| max_transitions | 200 | Maximum transitions per machine |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| SM-001 | MachineNotFound | No machine with the given ID |
| SM-002 | InvalidState | State is not defined in the machine |
| SM-003 | InvalidTransition | No transition for (current, event) |
| SM-004 | GuardFailed | A guard rejected the transition |
| SM-005 | ActionFailed | An action execution failed (rolled back) |
| SM-006 | TerminalState | Entity is in a terminal state |
| SM-007 | VersionConflict | Concurrent machine modification detected |
| SM-008 | EntityNotInMachine | Entity is not registered with this machine |

## Cross-Cutting Concerns

### Security

State machine definitions are protected artifacts. Only authorized entities (Security Council, LMS) may define or modify machines. Transitions are guarded by authorization checks integrated with the Security Council.

### Evidence

Every transition execution produces a TransitionExecuted Event. Every guard evaluation produces a GuardEvaluated Event for audit purposes. Failed transitions produce TransitionFailed Events with the reason.

### Lifecycle

State machine definitions follow their own lifecycle: Draft → Review → Published → Active → Deprecated → Retired. Definition changes are constitutional events that produce MachineVersioned Events.

### Capability Bounds

The State Machine Engine only manages transition logic. It has no authority over entity data, resource allocation, or domain execution. It is a pure computation engine — it evaluates guards and executes actions but does not interpret their meaning.

### Communication

The State Machine Engine communicates through ACF. It receives transition requests via ACF messages and publishes transition Events to ACF streams. It does not expose direct APIs.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | The engine does one thing: state machine evaluation |
| R2 — Dependency Order | Engine depends on ACF and Events; no circular dependencies |
| R3 — DRY | Machine definitions are stored once in the Machine Registry |
| R4 — Builder Pattern | Machine definitions are built by MachineBuilders |
| R5 — Liskov | All machines implement the same MachineDefinition interface |
| R6 — DI over Singletons | Engine receives ACF and Event Store as injected dependencies |
| R7 — Tests Exist | Every machine definition has contract tests |
| R8 — Tests Fast | Transition evaluation completes in <1ms |
| R9 — Deterministic | Transition function is mathematically deterministic |
| R10 — Simpler Over Complex | State machines are finite and explicit; no complex branching |
| R11 — Refactor Over Rewrite | Machine definitions evolve via versioning |
| R12 — Embrace Errors | Every guard failure has a unique error code |
| R13 — Design for Failure | Failed actions cause rollback; transition is not committed |
| R14 — Paved Path | State Machine Engine is the only path for state transitions |
| R15 — Open/Closed | New machine types extend without modifying the engine core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-LMS.md | LMS uses this engine for lifecycle management |
| 002-Transition-Validator.md | Validation rules integrate with guard system |
| Physics/006-Lifecycles.md | Lifecycle invariants that state machines implement |
| Physics/011-Design-DNA.md | R9 determinism is a core invariant |
| Foundations/008-Object-Lifecycle.md | Canonical lifecycle state machine definition |
