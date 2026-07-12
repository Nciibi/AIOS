# AIOS Bible â€” Brain
## 003 â€” Interruption Handling

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Interruption Handling manages time-sensitive signals that demand immediate attention from Sou. Not all signals can wait in the priority queue â€” security alerts, user inputs, and system errors require immediate routing to Sou's awareness. The Interrupt Manager classifies interrupts by type and priority, enforces cooldown periods to prevent thrashing, queues interrupts when Sou is overloaded, and provides escalation pathways when the interruption rate becomes unsustainable.

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
  Idle:        0.5Ã—  (Sou can handle more)
  Processing:  1.0Ã—  (standard)
  Deep Work:   3.0Ã—  (protect focus)
  Interrupted: 1.5Ã—  (Sou already handling one)
  Multi-tasking: 2.0Ã— (Sou is busy)
```

During cooldown, only Critical-priority interrupts bypass (ATT-001). All other interrupts are queued.

### Dynamic Cooldown Adjustment

The Interrupt Manager adjusts cooldown dynamically based on system conditions:

| Condition | Adjustment | Notes |
|-----------|------------|-------|
| Consecutive interrupts > 3 | multiplier +1.0Ã— | Sou may be overwhelmed |
| Switch rate > 12/min | multiplier +0.5Ã— | Too many context switches |
| High memory pressure | multiplier +0.3Ã— | System resource strain |
| User has not responded to last 2 interrupts | multiplier +0.5Ã— | User fatigue |
| Sou has been Idle > 30s | multiplier reset to 0.5Ã— | Ready to respond |
| Mission-critical flag set | multiplier min 2.0Ã— | Protect mission focus |

Dynamic adjustments are bounded: multiplier is never less than 0.5Ã— or greater than 5.0Ã—.

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
- No queueing â€” always delivered immediately
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
3. Set cooldown multiplier to 5.0Ã— (maximum)
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
| ATT.ATTEvent |  interrupt_id, interrupt_type, priority, source, reason | New interrupt request created |
| ATT.ATTEvent |  interrupt_id, latency_ms, cooldown_remaining | Interrupt delivered to Sou |
| ATT.ATTEvent |  interrupt_id, latency_ms, action_taken | Sou acknowledged interrupt |
| ATT.ATTEvent |  interrupt_id, queue_position, reason | Interrupt queued due to cooldown/budget |
| ATT.ATTEvent |  interrupt_id, queue_duration_ms | Interrupt removed from queue and delivered |
| ATT.ATTEvent |  interrupt_id, reason, snooze_count | Interrupt expired or queue full, dropped |
| ATT.ATTEvent |  old_multiplier, new_multiplier, reason | Cooldown multiplier dynamically adjusted |
| ATT.ATTEvent |  interrupt_id, bypass_reason | Critical security alert bypassed cooldown |
| ATT.ATTEvent |  queue_size, policy, dropped_id | Interrupt queue exceeded capacity |
| ATT.ATTEvent |  interrupt_rate, switch_rate, consecutive, action | Sou overwhelmed, escalation triggered |
| ATT.ATTEvent |  duration_ms, interrupts_cleared | Overload condition resolved |
| ATT.ATTEvent |  interrupt_id, priority, window_ms | Sou did not ack within required window |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-INT-001 | Security alerts (ATT-001) always bypass cooldown and budget checks | Algorithmic â€” checked before any routing logic |
| ATT-INT-002 | At most one interrupt is delivered per cooldown period | Algorithmic â€” enforced by cooldown timer |
| ATT-INT-003 | Every interrupt must be acknowledged by Sou or expired by TTL | Architectural â€” requeue/ack/drop is exhaustive |
| ATT-INT-004 | Cooldown multiplier is bounded between 0.5Ã— and 5.0Ã— | Algorithmic â€” clamping enforced on every adjustment |
| ATT-INT-005 | The interrupt queue processes items FIFO within priority bands | Algorithmic â€” sorted before dequeue |
| ATT-INT-006 | Overload escalation is idempotent (calling it multiple times is safe) | Architectural â€” guard on `is_overloaded` flag |
| ATT-INT-007 | Acknowledgment latency is measured from delivery to ack, never negative | Algorithmic â€” computed as `max(0, ack_time - deliver_time)` |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
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
| R1 â€” Modulsingularity | Interruption Handling manages only interrupt lifecycle |
| R2 â€” Dependency Order | Depends on Focus Manager for state; no upward deps |
| R3 â€” DRY | Interrupt types defined once in InterruptRequest union |
| R4 â€” Builder Pattern | Interrupt built from Signal â†’ Classification â†’ Queue/Deliver |
| R5 â€” Liskov Substitution | Any InterruptManager implements the interface |
| R6 â€” DI over Singletons | Cooldown config and priority rules injected |
| R9 â€” Deterministic | Same signals + state produce same interrupt outcome |
| R10 â€” Simpler Over Complex | Uses typed priorities and cooldowns, not AI scheduling |
| R13 â€” Design for Failure | Escalation pathway prevents cascade failure |
| R14 â€” Paved Path | All interrupts flow through `inject()` entry point |
| R15 â€” Open/Closed | New interrupt types added via Registry, not core routing |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Attention/000-Overview.md | Interrupt Manager is one of five Attention System components |
| Attention/001-Priority-Scoring.md | Scores determine which signals become interrupts |
| Attention/002-Focus-Management.md | Focus state affects cooldown multiplier and queuing |
| Attention/000-Overview.md | Non-critical signals can be snoozed per the Attention overview |
| Brain/Context/000-Overview.md | Context can be frozen during high-priority interrupts |
| Brain/Sou/000-Overview.md | Sou consumes and acknowledges interrupts |
| Bible/04-Execution/Security/000-Overview.md | Security alerts are the highest priority interrupt type |
| Bible/05-Platform/004-EVS.md | Every interrupt lifecycle event recorded |

(End of file - total 354 lines)
