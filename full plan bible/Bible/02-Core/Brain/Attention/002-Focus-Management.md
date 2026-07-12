# AIOS Bible â€” Brain
## 002 â€” Focus Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-002 |
| Source Laws | Law 3 â€” Law of Communication, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/009-Interaction.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Focus Management tracks what Sou is currently attending to and governs transitions between attention states. It prevents cognitive thrashing by enforcing rate limits on context switching, protecting deep work periods from unnecessary interruption, and ensuring that focus transitions are deliberate, recorded, and traceable.

Under ATT-006, every focus state transition is recorded as evidence in the Event Store. Focus Management is the sole authority on what state Sou is in at any moment.

## Data Model

### FocusState

```typescript
FocusState {
  current_task: string
  current_goal_id?: string
  active_signals: AttentionSignal[]
  ignored_signals: string[]             // signal_ids deliberately dismissed
  focus_duration_ms: number             // How long in current state
  focus_started_at: timestamp
  interrupt_cooldown_until: timestamp
  consecutive_interrupts: number
  state: "idle" | "processing" | "deep_work" | "interrupted" | "multi_tasking"
}
```

### FocusTransition

```typescript
FocusTransition {
  transition_id: string
  from_state: FocusState["state"]
  to_state: FocusState["state"]
  task: string
  trigger: "signal_received" | "interrupt" | "task_complete" | "timeout" |
           "user_dismiss" | "deep_work_start" | "deep_work_end"
  duration_ms: number                   // How long Sou was in `from_state`
  context_switch_cost_ms: number        // Estimated cognitive cost of this switch
  timestamp: timestamp
}
```

### SwitchRecord

```typescript
SwitchRecord {
  switch_id: string
  from_task: string
  to_task: string
  switch_type: "voluntary" | "interrupt" | "resume"
  duration_ms: number
  cost_ms: number
  timestamp: timestamp
}
```

### DeepWorkSession

```typescript
DeepWorkSession {
  session_id: string
  task: string
  goal_id?: string
  started_at: timestamp
  guaranteed_uninterrupted_ms: number   // Default: 300000 (5 min)
  elapsed_ms: number
  protected: boolean                    // True when within guaranteed window
  completed: boolean
}
```

## Core Concepts

### Focus States

Sou operates in one of five focus states:

| State | Description | Enter Condition | Exit Condition |
|-------|-------------|-----------------|----------------|
| Idle | Sou is waiting for input, no active signals | No signals in focus, no active task | Any signal enters focus |
| Processing | Sou is actively handling a signal | Signal passes threshold and enters focus | Signal resolved or dismissed |
| Deep Work | Sou is executing a complex task without distraction | Task explicitly marked as deep work | Task completed or critical interrupt |
| Interrupted | Sou was pulled out of an active task by a higher-priority signal | Interrupt with priority >= high arrives | Interrupt acknowledged, task resumed |
| Multi-tasking | Sou is handling multiple signals concurrently | 2+ signals above focus threshold | All but one resolved |

### Focus Transitions

Transitions are directional and guarded:

```
                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                â”‚                                     â”‚
                â–¼                                     â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”   signal    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   complete   â”Œâ”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Idle  â”‚ â”€â”€â”€â”€â”€â”€â–ºâ”€â”€â”€â”€ â”‚Processingâ”‚ â”€â”€â”€â”€â”€â”€â–ºâ”€â”€â”€â”€â”€â”€â”‚    Idle    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜             â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â–²                       â”‚   â”‚                        â–²
    â”‚                       â”‚   â”‚                        â”‚
    â”‚                timeoutâ”‚   â”‚interrupt               â”‚
    â”‚                       â”‚   â”‚                        â”‚
    â”‚                       â–¼   â–¼                        â”‚
    â”‚                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    resume          â”‚
    â”‚                â”‚ Interrupted  â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â–ºâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚                       â–²
    â”‚                       â”‚
    â”‚                criticalâ”‚interrupt
    â”‚                       â”‚
    â”‚                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
    â”‚                â”‚Deep Work â”‚
    â”‚                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚                       â”‚
    â”‚                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
    â”‚                â”‚Multi-tasking â”‚
    â”‚                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    â”‚                       â”‚
    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          all resolved
```

Transitions are rejected if they violate focus state guards (e.g. Idle â†’ Interrupted is invalid without passing through Processing first).

### Context Switch Tracking

Every focus switch is recorded with its cost:

```typescript
trackSwitch(from_task: string, to_task: string): SwitchRecord
```

Switch cost is estimated based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Task complexity delta | 0.40 | How different the two tasks are |
| Saved state size | 0.30 | How much context must be preserved |
| Interrupt depth | 0.20 | How many nested interruptions |
| Time since last switch | 0.10 | Shorter intervals = higher residual cost |

Total cost is capped at 5000ms and used to extend the interrupt cooldown window.

### Focus Duration Limits

Each state has a recommended maximum duration:

| State | Maximum Duration | Behavior on Exceed |
|-------|-----------------|-------------------|
| Idle | 5 min | Suggest activity or enter standby |
| Processing | 15 min | Suggest checkpoint (timebox) |
| Deep Work | 30 min | Suggest break or checkpoint |
| Interrupted | 2 min | Escalate if not acknowledged |
| Multi-tasking | 5 min | Flag: suggest focus on one task |

Durations are configurable per-session. On exceed, the Focus Manager emits a warning event but does not force a state change.

### Switch Rate Limiting

The Focus Manager enforces a maximum switch rate to prevent thrashing:

```
Switches per minute: max 12
Sliding window: 60 seconds
Behavior on exceed:
  - New non-critical signals are queued instead of processed
  - Critical signals still pass through (ATT-001 override)
  - An OverloadEscalation event is emitted at 15+ switches/min
```

### Deep Work Protection

When Sou enters Deep Work, the Focus Manager guarantees a minimum uninterrupted window:

```typescript
protectDeepWork(task: string, guaranteed_minutes?: number): DeepWorkSession
```

During the protection window:
- Non-critical interrupts (priority < high) are automatically snoozed with condition `on_completion`
- Non-critical signals are queued with `on_idle` or `on_completion`
- Only security alerts (ATT-001) and user input (priority = critical) can penetrate
- The protection window is extendable by Sou via `extendDeepWork()`

If an interrupt penetrates deep work, the Focus Manager records the breach and adjusts protection metadata.

### Focus State Persistence

Focus state is not persisted across sessions. When a session ends, focus state is cleared:

```typescript
clearFocus(): void
```

However, within a session, focus state survives transient conditions (e.g. a brief interruption that is immediately resolved). The Focus Manager tracks whether the current state was "resumed" from interruption and adjusts switch cost accordingly.

## Internal Interface

```typescript
interface FocusManager {
  setFocus(
    task: string,
    goal_id?: string,
    options?: { deep_work?: boolean; expected_duration_ms?: number }
  ): Promise<FocusState>

  getFocusState(): Promise<FocusState>

  switchFocus(
    new_task: string,
    trigger: FocusTransition["trigger"],
    options?: { save_state?: boolean }
  ): Promise<FocusState>

  resumeFocus(previous_task: string): Promise<FocusState>

  trackSwitch(
    from_task: string,
    to_task: string,
    switch_type: SwitchRecord["switch_type"]
  ): Promise<SwitchRecord>

  protectDeepWork(
    task: string,
    guaranteed_minutes?: number
  ): Promise<DeepWorkSession>

  extendDeepWork(session_id: string, extension_ms: number): Promise<DeepWorkSession>
  endDeepWork(session_id: string): Promise<DeepWorkSession>

  getSwitchHistory(window_ms: number): Promise<SwitchRecord[]>
  getSwitchRate(window_ms: number): Promise<number>

  getDeepWorkSessions(active_only?: boolean): Promise<DeepWorkSession[]>

  clearFocus(): Promise<void>

  setDeepWorkProtection(enabled: boolean): Promise<void>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| ATT.ATT.FOC.StateChanged | from_state, to_state, task, trigger, duration_ms | Focus state transition executed |
| ATT.ATT.FOC.SwitchRecorded | switch_id, from_task, to_task, cost_ms, switch_type | Context switch tracked |
| ATT.ATT.FOC.DeepWorkStarted | session_id, task, goal_id, guaranteed_window_ms | Deep work session initiated |
| ATT.ATT.FOC.DeepWorkEnded | session_id, task, elapsed_ms, completed | Deep work session ended |
| ATT.ATT.FOC.DeepWorkProtected | session_id, interrupt_attempted, blocked | Deep work protection blocked an interrupt |
| ATT.ATT.FOC.DeepWorkBreached | session_id, interrupt_id, priority | Critical interrupt penetrated deep work |
| ATT.ATT.FOC.DurationLimitExceeded | state, current_duration_ms, limit_ms | Sou exceeded recommended state duration |
| ATT.ATT.FOC.SwitchRateExceeded | current_rate, limit, exceeded_by | Switch rate exceeded 12/min threshold |
| ATT.ATT.FOC.Resumed | previous_state, task, interrupt_duration_ms | Sou resumed previous focus after interruption |
| ATT.ATT.FOC.Cleared | previous_state, task | Focus cleared on session end |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-FOC-001 | Sou is always in exactly one focus state | Algorithmic â€” state is mutually exclusive |
| ATT-FOC-002 | Focus transitions are always logged as evidence | Architectural â€” every transition emits an event |
| ATT-FOC-003 | Deep work protection guarantees a minimum uninterrupted window | Algorithmic â€” enforced before any interrupt is routed |
| ATT-FOC-004 | Switch rate is computed over a sliding 60-second window | Algorithmic â€” rolling window, not fixed interval |
| ATT-FOC-005 | State duration limits are advisory; no forced state change on exceed | API-level â€” emit event, do not force exit |
| ATT-FOC-006 | Focus state is per-session and is cleared when the session ends | Architectural â€” `clearFocus` called by Session Manager |
| ATT-FOC-007 | Context switch cost is monotonic (switch cost never decreases within a transition) | Algorithmic â€” cost is computed before the switch |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| State transition violates state machine | `ATT_FOC_INVALID_TRANSITION` | Reject transition; remain in current state |
| Deep work session already active for different task | `ATT_FOC_DEEP_WORK_CONFLICT` | Reject; suggest ending prior session |
| Switch rate limit exceeded, signal is non-critical | `ATT_FOC_SWITCH_RATE_EXCEEDED` | Queue signal; do not switch |
| Resume with no saved state | `ATT_FOC_NO_STATE_TO_RESUME` | Switch to Idle; log warning |
| Extend deep work on expired session | `ATT_FOC_SESSION_EXPIRED` | Reject extension; session already ended |
| Unknown focus state requested | `ATT_FOC_UNKNOWN_STATE` | Default to Processing; log error |
| getSwitchHistory with window < 1000ms | `ATT_FOC_WINDOW_TOO_SMALL` | Clamp to 1000ms; log warning |


## Cross-Cutting Concerns

### Security

Attention System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Attention System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Attention System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Attention System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Focus Management handles only focus state and transitions |
| R2 â€” Dependency Order | Depends on Interrupt Manager for interrupt classification; no upward deps |
| R3 â€” DRY | Focus states defined once in FocusState union type |
| R4 â€” Builder Pattern | Focus built by explicit transitions through state machine |
| R5 â€” Liskov Substitution | Any FocusManager implements the interface |
| R6 â€” DI over Singletons | State guards and rate limit config injected |
| R9 â€” Deterministic | Same signals + state produce same transitions |
| R10 â€” Simpler Over Complex | Finite state machine with 5 states, not probabilistic model |
| R13 â€” Design for Failure | Switch rate limiting prevents thrashing |
| R14 â€” Paved Path | All focus changes flow through `setFocus` or `switchFocus` |
| R15 â€” Open/Closed | New states added via state machine config, not core logic |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Attention/000-Overview.md | Focus Manager is one of five Attention System components |
| Attention/001-Priority-Scoring.md | Scores determine which signals enter focus |
| Attention/003-Interruption-Handling.md | Interrupt Manager triggers focus transitions |
| Attention/004-Salience.md | Salience scores influence deep work protection decisions |
| Brain/Context/000-Overview.md | Context window size affected by focus state |
| Brain/Sou/000-Overview.md | Sou reads focus state and triggers transitions |
| Bible/05-Platform/004-EVS.md | All focus transitions recorded in Event Store |

(End of file - total 329 lines)
