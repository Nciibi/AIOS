# AIOS Bible â€” Brain
## 000 â€” Attention System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-000 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Attention System manages what Sou pays attention to, when, and for how long. In a system where multiple signals compete for Sou's awareness â€” user input, memory recall, tool output, system alerts, mission status changes, federation messages â€” the Attention System determines what is salient, what can wait, and what should be ignored.

The Attention System is the Brain's filter. It prevents Sou from being overwhelmed by information and ensures that Sou's finite cognitive capacity is directed at what matters most at any moment.

## Architecture

```
Sou (reads attention-gated context, receives interrupt)
   â–²                                    â”‚
   â”‚                                    â–¼
   â”‚                         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
   â”‚                         â”‚   Interrupt Bus       â”‚
   â”‚                         â”‚  (time-sensitive)     â”‚
   â”‚                         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
   â”‚                                    â–²
   â”‚                                    â”‚
   â–¼                                    â”‚
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Attention System                        â”‚
â”‚                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚ Salience  â”‚  â”‚ Focus    â”‚  â”‚ Interrupt â”‚      â”‚
â”‚  â”‚ Scanner   â”‚â”€â–ºâ”‚ Manager  â”‚â”€â–ºâ”‚  Manager  â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â”‚                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                      â”‚
â”‚  â”‚ Attention â”‚  â”‚ Snooze   â”‚                      â”‚
â”‚  â”‚ Budget    â”‚  â”‚ Queue    â”‚                      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

The Attention System sits between the Context System and Sou. Context provides the WINDOW of available information; Attention determines what Sou actually SEES.

## Core Concepts

### Attention Model

```
AttentionSignal {
  signal_id: string
  source: string
  type: "user_input" | "system_alert" | "mission_update" | "memory_recall" |
        "tool_result" | "federation_message" | "internal_thought"
  salience: number          // 0.0â€“1.0, computed by Salience Scanner
  urgency: number           // 0.0â€“1.0, time-sensitivity of signal
  payload: unknown
  timestamp: timestamp
  ttl_ms: number            // How long this signal is relevant
}

FocusState {
  current_task: string
  current_goal_id?: string
  active_signals: AttentionSignal[]
  ignored_signals: string[]         // signal_ids deliberately ignored
  focus_duration_ms: number         // How long Sou has been in current focus
  interrupt_cooldown_ms: number     // Minimum time between interrupts
}

Interrupt {
  interrupt_id: string
  signal: AttentionSignal
  priority: "critical" | "high" | "normal" | "low"
  reason: string
  suggested_action: string
}
```

### 1. Salience Scanner

Every incoming signal is scored for salience â€” how relevant it is to Sou's current goals and context:

| Factor | Weight | Description |
|--------|--------|-------------|
| Goal alignment | 0.35 | How relevant the signal is to Sou's active goal |
| Urgency | 0.25 | Time-sensitivity of the signal |
| Source authority | 0.15 | Trust level of the signal source |
| Novelty | 0.10 | How different the signal is from recent signals |
| User proximity | 0.15 | How directly the signal relates to the user |

Salience score = weighted sum of all factors. Signals above the salience threshold enter Sou's focus; signals below are either snoozed or dropped.

### 2. Focus Manager

The Focus Manager tracks what Sou is currently attending to and manages attention transitions:

| Focus State | Description | Enter Condition | Exit Condition |
|-------------|-------------|-----------------|----------------|
| Idle | Sou is waiting for input | No active signals | Signal received |
| Processing | Sou is handling a signal | Signal assigned to Sou | Signal resolved |
| Deep Work | Sou is executing a complex task | Task initiated | Task completed or interrupted |
| Interrupted | Sou was interrupted mid-task | High-priority interrupt | Interrupt resolved, resume previous |
| Multi-tasking | Sou is handling multiple signals simultaneously | Multiple signals above threshold | All but one resolved |

Focus switching has a cost. The Focus Manager tracks context-switch overhead and prevents thrashing:

| Metric | Limit | Behavior on Exceed |
|--------|-------|-------------------|
| Switches per minute | 12 | Queue non-critical signals |
| Consecutive interrupts | 3 | Escalate to user: "I'm being overwhelmed" |
| Deep work duration | 30 min | Suggest break or checkpoint |

### 3. Interrupt Manager

Not all signals can wait. The Interrupt Manager handles time-sensitive signals that demand immediate attention:

| Interrupt Type | Source | Latency Requirement | Behavior |
|----------------|--------|---------------------|----------|
| Security alert | Security Council | < 100ms | Immediately interrupt Sou |
| User input | Conversation OS | < 500ms | Interrupt unless in critical task |
| System error | Runtime | < 1s | Interrupt with error details |
| Mission status | Institution OS | < 5s | Notify but don't force interrupt |
| Federation message | Federation | < 10s | Snooze unless high priority |

Interrupts follow a cooldown: after an interrupt, the Interrupt Manager waits `interrupt_cooldown_ms` before allowing another. This prevents Sou from being constantly interrupted.

Cooldown values are dynamic â€” if Sou is in Deep Work, cooldown increases. If Sou is Idle, cooldown is zero.

### 4. Attention Budget

Sou has a limited attention budget â€” it can only process a finite number of signals per unit time:

| Resource | Budget | Refill Rate |
|----------|--------|-------------|
| Concurrent signals | 5 | N/A (capacity) |
| Interrupts per minute | 12 | 1 per 5 seconds |
| Focus switches per minute | 12 | 1 per 5 seconds |
| Deep work uninterrupted | 5 min guarantee | Reset on task completion |

When the attention budget is exceeded, non-critical signals are snoozed (re-queued with delay) or dropped (if no longer relevant).

### 5. Snooze Queue

Signals that are relevant but not urgent can be snoozed â€” deferred until either a condition is met or a timeout expires:

```
SnoozeEntry {
  signal_id: string
  signal: AttentionSignal
  snooze_until: timestamp
  snooze_condition?: string     // "on_idle" | "on_completion" | "on_timeout"
  max_snooze_count: number
  current_snooze_count: number
}
```

Snooze conditions:
- `on_idle`: Re-queue when Sou enters Idle state
- `on_completion`: Re-queue when current task completes
- `on_timeout`: Re-queue after a fixed duration

Signals that exceed `max_snooze_count` are dropped with a notification to the source.

## Interfaces

### Attention System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `injectSignal(signal, source)` | Any Brain Service | Inject an attention signal for Sou |
| `getFocusState()` | Sou only | Get current focus state |
| `setFocus(task, goal_id?)` | Sou only | Manually set focus |
| `acknowledgeInterrupt(interrupt_id)` | Sou only | Acknowledge an interrupt |
| `snoozeSignal(signal_id, condition, duration)` | Sou only | Defer a signal |
| `dismissSignal(signal_id)` | Sou only | Discard a signal |
| `getSnoozeQueue()` | Sou only | List snoozed signals |
| `setSalienceOverride(source, override_score)` | Sou only | Manually set salience for a source |

### Internal Interfaces

```
interface SalienceScorer {
  score(signal: AttentionSignal, context: FocusState): number
}

interface InterruptRouter {
  route(signal: AttentionSignal): InterruptPriority
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| ATT.SignalReceived |      signal_id, source, type, salience | Signal entered Attention System |
| ATT.SignalFocused |      signal_id, salience, focus_state | Signal promoted to Sou's focus |
| ATT.SignalSnoozed |      signal_id, condition, duration | Signal deferred |
| ATT.SignalDropped |      signal_id, reason, snooze_count | Signal dropped (budget exceeded) |
| ATT.SignalDismissed |      signal_id | Sou explicitly dismissed signal |
| ATT.InterruptTriggered |      interrupt_id, priority, reason | High-priority interrupt fired |
| ATT.InterruptAcknowledged |      interrupt_id, latency_ms | Sou acknowledged interrupt |
| ATT.FocusChanged |      from_state, to_state, task | Focus state transitioned |
| ATT.BudgetExceeded |      resource, current_usage, limit | Attention budget exceeded |
| ATT.OverloadEscalation |      switch_rate, consecutive_interrupts | Sou overwhelmed, escalating |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-001 | Security alerts always interrupt immediately | Algorithmic â€” Interrupt Manager bypasses budget |
| ATT-002 | Sou can dismiss any signal at any time | API-level â€” `dismissSignal` is Sou-only |
| ATT-003 | Signals are never dropped without being evaluated | Architectural â€” all signals pass through Salience Scanner |
| ATT-004 | The Attention System is stateless â€” signal history lives in Event Store | Architectural â€” no internal persistence |
| ATT-005 | Sou cannot be interrupted more than once per cooldown period | Algorithmic â€” enforced by Interrupt Manager |
| ATT-006 | Focus state transitions are always recorded as evidence | Architectural â€” logged to Event Store |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Attention System is a Brain Service |
| Brain/Context/000-Overview.md | Context window feeds signals to Attention System |
| Brain/Sou/000-Overview.md | Sou consumes the attention-gated output |
| Brain/Decision/000-Overview.md | Interrupt handling is a decision Sou makes |
| Brain/Personality/000-Overview.md | Personality influences salience scoring |
| Bible/04-Execution/Security/ | Security alerts are the highest-priority interrupt |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Signal from unknown source | `ATT_UNKNOWN_SOURCE` | Drop signal; log security event |
| Interrupt cooldown active, critical signal arrives | `ATT_COOLDOWN_OVERRIDE` | Allow interrupt; log as override |
| Snooze queue full | `ATT_SNOOZE_FULL` | Drop oldest snoozed signal |
| Signal already in focus | `ATT_ALREADY_FOCUSED` | Update salience; no duplicate |


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
| R1 â€” Modulsingularity | Attention System does one thing: manage what Sou attends to |
| R2 â€” Dependency Order | Depends on Context System, Event Store; no upward deps |
| R3 â€” DRY | Signal types defined once in Attention Model |
| R4 â€” Builder Pattern | Focus built by Salience Scanner â†’ Focus Manager â†’ Interrupt Manager |
| R5 â€” Liskov Substitution | Any SalienceScorer implements the interface |
| R6 â€” DI over Singletons | Scoring factors and interrupt routes injected |
| R9 â€” Deterministic | Same signals produce same attention outcome |
| R10 â€” Simpler Over Complex | Salience uses weighted linear model |
| R13 â€” Design for Failure | Interrupt cooldown prevents thrashing |
| R14 â€” Paved Path | All signals flow through `injectSignal` |
| R15 â€” Open/Closed | New signal sources added via Registry, not by modifying core |
