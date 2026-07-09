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

This function is deterministic (R9): given the same current state and the same event, it always produces the same next state. The function is defined by the transition table. If no transition exists for the given (current, event) pair, δ returns an error — the transition is invalid.

## State Machine Operations

```
defineMachine(definition) → machine_id
getMachine(machine_id) → MachineDefinition
getValidTransitions(state) → Transition[]
executeTransition(entity_id, event) → Result
getMachineVersion(machine_id) → int
listMachines() → MachineDefinition[]
```

## Versioning

State machines are versioned. Changing a machine definition creates a new version. Entities continue to operate under the version of the machine definition they started with. Version increment occurs when: states are added or removed, transitions are added or removed, guard conditions change, or action definitions change.

Versioning ensures that existing entities are not disrupted by definition changes. Migration to a new version is optional and entity-driven. LMS may initiate migration when safe.

```
Version 1: [Created → Planned → Running → Completed]
Version 2: [Created → Planned → Assigned → Running → Completed]
           Entities on v1 stay on v1 until migrated
```

## Determinism Guarantees

The State Machine Engine enforces determinism at every level:

- Same input state + same event → same output state (transition function)
- Same machine definition → same behavior across instances
- Same guard evaluation → same authorization result
- Same action execution → same side effects

Determinism is verified by contract tests. Every machine definition includes a set of deterministic test vectors.

## Guards and Actions

### Guards

Guards are predicate functions that evaluate whether a transition is allowed. Each guard receives the current entity state, the requested event, and the requesting entity's identity. Guards return allow or deny. All guards for a transition must pass for the transition to execute.

Guard types:
- **Authorization guards**: Does the requester have authority for this transition?
- **Precondition guards**: Are the preconditions for this transition met?
- **State guards**: Is the entity in a valid state for this transition?
- **Resource guards**: Are sufficient resources available for the target state?

### Actions

Actions are side-effect functions triggered after a successful transition. Actions execute in the order defined by the machine definition. Action failure causes the transition to roll back.

Action types:
- **Event production**: Generate a StateChanged Event
- **Notification**: Notify relevant entities of the state change
- **Resource management**: Freeze or release resources
- **Cascading transitions**: Trigger child entity transitions

## State Machine Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `SM.MachineDefined` | A new machine is registered | machine_id, version, states_count, transitions_count |
| `SM.MachineVersioned` | A machine definition is updated | machine_id, old_version, new_version, changelog |
| `SM.TransitionExecuted` | A transition completes | machine_id, entity_id, event, from_state, to_state |
| `SM.TransitionFailed` | A transition is rejected by a guard | machine_id, entity_id, event, guard_name, reason |
| `SM.GuardEvaluated` | A guard is evaluated (for audit) | machine_id, entity_id, guard_name, result |

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
