# AIOS Bible — Brain
## 003 — Interruption Handling

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-003 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Interruption Handling manages time-sensitive signals that demand immediate attention from Sou. Not all signals can wait in the priority queue — security alerts, user inputs, and system errors require immediate routing to Sou's awareness. The Interrupt Manager classifies interrupts by type and priority, enforces cooldown periods to prevent thrashing, queues interrupts when Sou is overloaded, and provides escalation pathways when the interruption rate becomes unsustainable.

Under ATT-001, security alerts always interrupt immediately, bypassing all budget and cooldown checks.

## Data Model

### InterruptRequest

```typescript
InterruptRequest {
  interrupt_id: string
  signal_id: string
  interrupt_type: "security" | "user" | "system" | "mission" | "federation"
  priority: "critical" | "high" | "normal" | "low"
  source: string
  reason: string
  payload: unknown
  suggested_action?: string
  acknowledged: boolean
  acknowledged_at?: timestamp
  created_at: timestamp
  ttl_ms: number
}
```

### InterruptCooldown

```typescript
InterruptCooldown {
  current_cooldown_ms: number       // Minimum time between interrupts
  base_cooldown_ms: number          // Default: 2000ms
  last_interrupt_at: timestamp
  dynamic_multiplier: number        // Based on focus state and load
  cooldown_until: timestamp         // Computed: last_interrupt_at + (base * multiplier)
  overrides: number                 // Count of ATT-001 bypasses
}
```

### InterruptQueue

```typescript
InterruptQueue {
  queue_id: string
  items: QueuedInterrupt[]
  max_size: number                  // Default: 20
  overflow_policy: "drop_lowest" | "reject_newest" | "escalate"
}

QueuedInterrupt {
  interrupt: InterruptRequest
  enqueued_at: timestamp
  expiry: timestamp
  position: number
}
```

### OverloadState

```typescript
OverloadState {
  is_overloaded: boolean
  interrupts_last_minute: number
  switches_last_minute: number
  consecutive_interrupts: number
  escalated: boolean
  escalated_at?: timestamp
  suggested_action: string
}
```

## Core Concepts

### Interrupt Types and Latency Requirements

Every interrupt is classified by its source type, which determines latency and bypass behavior:

| Interrupt Type | Source Examples | Latency Requirement | Cooldown Bypass | Snoozable |
|----------------|-----------------|---------------------|-----------------|-----------|
| Security | Security Council, Auth failures | < 100ms | Always (ATT-001) | Never |
| User | Conversation OS, Input handler | < 500ms | If Sou is Idle | If Deep Work |
| System | Runtime errors, Resource limits | < 1s | Never | If normal priority |
| Mission | Institution OS, Mission planner | < 5s | Never | Always |
| Federation | Federation messages, Peer alerts | < 10s | Never | Always |

### Interrupt Priorities

Within each type, interrupts carry a priority level:

| Priority | Description | Typical Sources | Behavior |
|----------|-------------|-----------------|----------|
| Critical | Immediate action required | Security breach, User safety | Bypasses cooldown, always interrupts |
| High | Important but not instantly critical | System error, High-priority user | Interrupts unless Deep Work |
| Normal | Standard interrupt | Mission update, Medium user | Snoozed if budget exceeded |
| Low | Informational | Federation broadcast, Telemetry | Snoozed unless Idle |

Priority is assigned by the Interrupt Manager based on signal content and source authority. Priority can be overridden by the source for specific well-known alert types.

### Interrupt Cooldown

After an interrupt is delivered to Sou, the Interrupt Manager enforces a cooldown:

```
cooldown_ms = base_cooldown_ms * dynamic_multiplier

Base cooldown: 2000ms (configurable)

Dynamic multiplier based on focus state:
  Idle:        0.5×  (Sou can handle more)
  Processing:  1.0×  (standard)
  Deep Work:   3.0×  (protect focus)
  Interrupted: 1.5×  (Sou already handling one)
  Multi-tasking: 2.0× (Sou is busy)
```

During cooldown, only Critical-priority interrupts bypass (ATT-001). All other interrupts are queued.

### Dynamic Cooldown Adjustment

The Interrupt Manager adjusts cooldown dynamically based on system conditions:

| Condition | Adjustment | Notes |
|-----------|------------|-------|
| Consecutive interrupts > 3 | multiplier +1.0× | Sou may be overwhelmed |
| Switch rate > 12/min | multiplier +0.5× | Too many context switches |
| High memory pressure | multiplier +0.3× | System resource strain |
| User has not responded to last 2 interrupts | multiplier +0.5× | User fatigue |
| Sou has been Idle > 30s | multiplier reset to 0.5× | Ready to respond |
| Mission-critical flag set | multiplier min 2.0× | Protect mission focus |

Dynamic adjustments are bounded: multiplier is never less than 0.5× or greater than 5.0×.

### Interrupt Acknowledgment

Every interrupt must be acknowledged by Sou within a mandatory window:

```typescript
acknowledge(interrupt_id: string): Promise<void>
```

| Priority | Acknowledgment Window | Behavior on Miss |
|----------|----------------------|------------------|
| Critical | 500ms | Escalate: auto-acknowledge, log breach |
| High | 2s | Escalate: remind Sou, then queue |
| Normal | 5s | Queue: re-present later if still relevant |
| Low | 10s | Drop: signal no longer relevant |

Acknowledgment latency is recorded in every `ATT.InterruptAcknowledged` event.

### Interrupt Queuing

When Sou cannot accept a new interrupt (cooldown active, Deep Work protection, budget exceeded), interrupts are queued:

```typescript
QueuedInterrupt {
  interrupt: InterruptRequest
  enqueued_at: timestamp
  expiry: timestamp       // signal TTL
  position: number
}
```

Queue behavior:

| Policy | Behavior |
|--------|----------|
| `drop_lowest` (default) | When full, drop lowest-priority interrupt, notify source |
| `reject_newest` | Reject incoming interrupt if queue full |
| `escalate` | Escalate overload when queue exceeds 80% capacity |

Queue is processed FIFO within priority bands: all Critical items first, then High, then Normal, then Low.

### Security Alert Bypass (ATT-001)

Security alerts are exempt from all attention budget constraints:

- No cooldown check
- No Deep Work protection blocking
- No queueing — always delivered immediately
- Bypasses switch rate limiting
- Logged as `cooldown_override: true` in event

Security alerts still emit events for auditability.

### Escalation for Overwhelming Interrupts

When the interrupt rate indicates Sou is overwhelmed, the Interrupt Manager escalates:

```typescript
escalateOverload(): OverloadState
```

Escalation triggers:

| Trigger | Threshold | Action |
|---------|-----------|--------|
| Interrupts per minute | > 20 | Auto-snooze all non-critical signals |
| Consecutive interrupts without ack | > 5 | Suggest user: "I'm being overwhelmed" |
| Switch rate > 15/min for 2+ windows | > 15/min | Stop accepting non-critical interrupts |
| Queue depth > 80% | > 16/20 | Escalate to Sou, suggest clearing queue |

Escalation actions:

1. Emit `ATT.OverloadEscalation` event
2. Auto-snooze all non-critical signals with `on_idle` condition
3. Set cooldown multiplier to 5.0× (maximum)
4. Suggest Sou clear queue or delegate tasks
5. If escalation persists > 30s, log critical warning to System Log

## Internal Interface

```typescript
interface InterruptManager {
  inject(
    signal: AttentionSignal,
    options?: { bypass_cooldown?: boolean; force_priority?: InterruptPriority }
  ): Promise<InterruptRequest | null>

  acknowledge(
    interrupt_id: string,
    response?: { action_taken: string; notes?: string }
  ): Promise<InterruptRequest>

  acknowledgeAll(interrupt_type?: InterruptType): Promise<number>

  getCooldown(): Promise<InterruptCooldown>
  resetCooldown(): Promise<InterruptCooldown>

  getQueue(options?: { priority?: InterruptPriority; type?: InterruptType }): Promise<InterruptQueue>
  dequeue(interrupt_id: string): Promise<void>
  flushQueue(priority_threshold?: InterruptPriority): Promise<number>

  escalateOverload(): Promise<OverloadState>
  isOverloaded(): Promise<boolean>
  getOverloadState(): Promise<OverloadState>

  getInterruptHistory(window_ms: number): Promise<InterruptRequest[]>
  getInterruptRate(window_ms: number): Promise<number>

  setCooldownMultiplier(multiplier: number): Promise<InterruptCooldown>
  setQueuePolicy(policy: InterruptQueue["overflow_policy"]): Promise<void>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `ATT.INT.InterruptCreated` | interrupt_id, interrupt_type, priority, source, reason | New interrupt request created |
| `ATT.INT.InterruptDelivered` | interrupt_id, latency_ms, cooldown_remaining | Interrupt delivered to Sou |
| `ATT.INT.InterruptAcknowledged` | interrupt_id, latency_ms, action_taken | Sou acknowledged interrupt |
| `ATT.INT.InterruptQueued` | interrupt_id, queue_position, reason | Interrupt queued due to cooldown/budget |
| `ATT.INT.InterruptDequeued` | interrupt_id, queue_duration_ms | Interrupt removed from queue and delivered |
| `ATT.INT.InterruptDropped` | interrupt_id, reason, snooze_count | Interrupt expired or queue full, dropped |
| `ATT.INT.CooldownAdjusted` | old_multiplier, new_multiplier, reason | Cooldown multiplier dynamically adjusted |
| `ATT.INT.CooldownBypass` | interrupt_id, bypass_reason | Critical security alert bypassed cooldown |
| `ATT.INT.QueueFull` | queue_size, policy, dropped_id | Interrupt queue exceeded capacity |
| `ATT.INT.OverloadEscalation` | interrupt_rate, switch_rate, consecutive, action | Sou overwhelmed, escalation triggered |
| `ATT.INT.EscalationResolved` | duration_ms, interrupts_cleared | Overload condition resolved |
| `ATT.INT.AcknowledgmentMissed` | interrupt_id, priority, window_ms | Sou did not ack within required window |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-INT-001 | Security alerts (ATT-001) always bypass cooldown and budget checks | Algorithmic — checked before any routing logic |
| ATT-INT-002 | At most one interrupt is delivered per cooldown period | Algorithmic — enforced by cooldown timer |
| ATT-INT-003 | Every interrupt must be acknowledged by Sou or expired by TTL | Architectural — requeue/ack/drop is exhaustive |
| ATT-INT-004 | Cooldown multiplier is bounded between 0.5× and 5.0× | Algorithmic — clamping enforced on every adjustment |
| ATT-INT-005 | The interrupt queue processes items FIFO within priority bands | Algorithmic — sorted before dequeue |
| ATT-INT-006 | Overload escalation is idempotent (calling it multiple times is safe) | Architectural — guard on `is_overloaded` flag |
| ATT-INT-007 | Acknowledgment latency is measured from delivery to ack, never negative | Algorithmic — computed as `max(0, ack_time - deliver_time)` |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Interrupt from unregistered source | `ATT_INT_UNKNOWN_SOURCE` | Accept interrupt; log security event; tag as `untrusted` |
| Acknowledge on non-existent interrupt | `ATT_INT_NOT_FOUND` | Return error; interrupt may have expired |
| Acknowledge on already-acknowledged interrupt | `ATT_INT_ALREADY_ACKED` | Return current state; no-op, log warning |
| Inject during overload with queue full | `ATT_INT_OVERLOAD_REJECT` | Drop interrupt; emit escalation event |
| Interrupt TTL already expired | `ATT_INT_EXPIRED` | Drop; notify source signal expired |
| Set cooldown multiplier outside [0.5, 5.0] | `ATT_INT_INVALID_MULTIPLIER` | Clamp to nearest bound; log warning |
| Dequeue from empty queue | `ATT_INT_QUEUE_EMPTY` | Return null; no error |
| Flush queue with no items matching threshold | `ATT_INT_NO_MATCHING_ITEMS` | Return 0; log informational |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Interruption Handling manages only interrupt lifecycle |
| R2 — Dependency Order | Depends on Focus Manager for state; no upward deps |
| R3 — DRY | Interrupt types defined once in InterruptRequest union |
| R4 — Builder Pattern | Interrupt built from Signal → Classification → Queue/Deliver |
| R5 — Liskov Substitution | Any InterruptManager implements the interface |
| R6 — DI over Singletons | Cooldown config and priority rules injected |
| R9 — Deterministic | Same signals + state produce same interrupt outcome |
| R10 — Simpler Over Complex | Uses typed priorities and cooldowns, not AI scheduling |
| R13 — Design for Failure | Escalation pathway prevents cascade failure |
| R14 — Paved Path | All interrupts flow through `inject()` entry point |
| R15 — Open/Closed | New interrupt types added via Registry, not core routing |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Attention/000-Overview.md | Interrupt Manager is one of five Attention System components |
| Attention/001-Priority-Scoring.md | Scores determine which signals become interrupts |
| Attention/002-Focus-Management.md | Focus state affects cooldown multiplier and queuing |
| Attention/005-Snooze-Queue.md | Non-critical interrupts are snoozed instead of queued |
| Brain/Context/000-Overview.md | Context can be frozen during high-priority interrupts |
| Brain/Sou/000-Overview.md | Sou consumes and acknowledges interrupts |
| Bible/04-Execution/Security/000-Overview.md | Security alerts are the highest priority interrupt type |
| Bible/05-Platform/004-EVS.md | Every interrupt lifecycle event recorded |

(End of file - total 354 lines)
