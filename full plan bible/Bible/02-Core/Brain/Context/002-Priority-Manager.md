# AIOS Bible â€” Brain
## 002 â€” Priority Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Context |
| Document ID | AIOS-BBL-002-CTX-002 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Priority Manager assigns, decays, and overrides priority scores for every item in the context window. It implements the 5-tier priority model defined in CTX-000, ensuring that the most important information is retained while lower-value context is eligible for compression or eviction. Priority scores drive all downstream decisions â€” section ordering, compression target selection, TTL extension eligibility, and emergency eviction order.

## Data Model

### PriorityScore

```typescript
PriorityScore {
  item_id: string
  score: number              // 0.0â€“1.0
  tier: PriorityTier
  base_score: number         // Original score at insert time
  decay_rate: number         // Per-turn decay amount
  min_score: number          // Floor â€” score will not decay below this
  last_decayed_at: timestamp
  decay_count: number
  source_boost: number       // Bonus from source service priority
  pinned: boolean
  pin_priority?: number      // Explicit priority if pinned
  override_history: PriorityOverride[]
}

PriorityTier = "critical" | "high" | "medium" | "low" | "background"

PriorityOverride {
  overridden_at: timestamp
  old_score: number
  new_score: number
  reason: string             // "sou_pin" | "system_boost" | "decay" | "access_boost"
}
```

### PriorityConfig

```typescript
PriorityConfig {
  tiers: Record<PriorityTier, {
    min_score: number
    max_score: number
    default_decay_rate: number
    min_score_floor: number
    can_expire: boolean
    can_pin: boolean
  }>
  source_weights: Record<string, number>    // Source service â†’ priority boost
  access_boost: number                      // +0.1 per access
  reference_boost: number                   // +0.15 when referenced by Sou
  reflection_boost: number                  // +0.2 when referenced by Reflection
  age_decay_rate: number                    // -0.05 per 30 days
  default_priority_on_push: number          // If no explicit priority given
}
```

## Tier Definitions

| Tier | Score Range | Default Decay/Turn | Min Floor | Always in Context | Examples |
|------|-------------|-------------------|-----------|-------------------|----------|
| Critical | 0.9â€“1.0 | 0.0 | 0.9 | Yes | User input, active mission state, security alerts |
| High | 0.7â€“0.9 | 0.02 | 0.5 | Yes until resolved | Pinned goals, active tool calls, recent user messages (â‰¤5 turns) |
| Medium | 0.4â€“0.7 | 0.04 | 0.3 | If space permits | Conversation history (6â€“20 turns), system notifications |
| Low | 0.2â€“0.4 | 0.06 | 0.15 | Subject to compression | Historical context (21â€“50 turns), verbose tool output |
| Background | 0.0â€“0.2 | 0.10 | 0.0 | Excluded unless requested | Log entries, debug info, stale context |

### Default Tier Assignment by Item Type

| Item Type | Default Tier | Source | Notes |
|-----------|-------------|--------|-------|
| User input | Critical | Conversation | Always included; never decays |
| Sou response | High | Conversation | Decays after 5 turns |
| Active mission goal | Critical | Planning | Never decays |
| Mission milestone | High | Planning | Decays when completed |
| Working memory (goal) | Critical | Memory | Never decays |
| Working memory (task) | High | Memory | Decays after 10 turns inactivity |
| Working memory (note) | Medium | Memory | Fast decay |
| Working memory (reference) | Medium | Memory | Moderate decay |
| Tool result | High | Tools | Decays after 3 turns |
| System signal (critical) | Critical | System | Never decays |
| System signal (warning) | High | System | Decays after 5 turns |
| System signal (info) | Medium | System | Decays after 2 turns |
| Semantic fact lookup | Medium | Memory | Decays after 1 turn |
| Episodic recall | Low | Memory | Decays quickly |
| Procedural step result | Medium | Memory | Decays after 3 turns |

## Priority Scoring

### Insert-Time Scoring

```
scoreItem(item, source):
  base = getBasePriority(item.itemType)
  sourceBoost = getSourceBoost(source)
  computed = clamp(base + sourceBoost, 0.0, 1.0)
  tier = classifyTier(computed)
  decay = getDecayRate(tier)
  min = getMinFloor(tier)

  return PriorityScore {
    score: computed,
    tier: tier,
    base_score: computed,
    decay_rate: decay,
    min_score: min,
    pinned: false
  }
```

### Source Weights

| Source | Weight | Rationale |
|--------|--------|-----------|
| `conversation` | +0.0 | Baseline |
| `sou` | +0.05 | Sou's own responses are slightly prioritized |
| `planning` | +0.10 | Active missions and goals are important |
| `memory` | +0.0 | Memory items scored by their internal importance |
| `tools` | +0.05 | Tool results are action-relevant |
| `system` | +0.15 | System signals may indicate critical state changes |

## Priority Decay

### Turn-Based Decay

On every window pull, non-pinned items decay:

```
applyPriorityDecay(window):
  for each item in window:
    if item.pinned: skip
    decay = item.decayRate * turnsElapsed
    newScore = max(item.score - decay, item.minScore)
    if newScore != item.score:
      item.score = newScore
      item.tier = classifyTier(newScore)
      item.lastDecayedAt = now
      item.decayCount += 1
```

### Cross-Session Decay

For items surviving across sessions (e.g., pinned references):

```
applyCrossSessionDecay(item, elapsedDays):
  if item.pinned: skip
  ageDecay = ageDecayRate * elapsedDays
  newScore = max(item.score - ageDecay, item.minScore)
  adjust(item, newScore)
```

### Access-Based Boost

When an item is re-accessed (pulled in a snapshot):

```
applyAccessBoost(item):
  if item.pinned: skip
  boost = accessBoost  // +0.1
  newScore = min(item.score + boost, 0.95)  // Cap below Critical
  adjust(item, newScore)
  emit CTX.PriorityOverride, {
    item_id: item.itemId,
    old_priority: item.score - boost,
    new_priority: item.score,
    reason: "access_boost"
  }
```

## Priority Override

### Pinning

Sou can pin any item at an explicit priority:

```
pinItem(item_id, priority):
  item = registry.find(item_id)
  if not item: throw CTX_ITEM_NOT_FOUND

  oldScore = item.priorityScore.score
  item.priorityScore.score = priority
  item.priorityScore.tier = classifyTier(priority)
  item.priorityScore.pinned = true
  item.priorityScore.pinPriority = priority
  item.priorityScore.overrideHistory.push({
    overridden_at: now,
    old_score: oldScore,
    new_score: priority,
    reason: "sou_pin"
  })

  emit CTX.ItemPinned, {
    item_id,
    priority,
    old_priority: oldScore
  }
```

### Unpinning

```
unpinItem(item_id):
  item = registry.find(item_id)
  if not item: throw CTX_ITEM_NOT_FOUND

  item.priorityScore.pinned = false
  item.priorityScore.score = item.priorityScore.baseScore
  item.priorityScore.tier = classifyTier(item.priorityScore.baseScore)
  item.priorityScore.overrideHistory.push({
    overridden_at: now,
    old_score: item.priorityScore.pinPriority,
    new_score: item.priorityScore.baseScore,
    reason: "sou_unpin"
  })

  emit CTX.ItemUnpinned, { item_id }
```

### System Boost

Certain events can temporarily boost priority:

| Event | Boost | Duration | Notes |
|-------|-------|----------|-------|
| Item accessed again | +0.1 | Until next decay | Per access |
| Sou references item | +0.15 | 3 turns | Explicit mention |
| Reflection references item | +0.2 | 5 turns | Cognitive OS |
| User returns to topic | +0.1 | 2 turns | Topic resurfacing |
| Mission state change | +0.25 | Until next pull | Planning notification |

## Priority Thresholds

Thresholds control which items survive compression, eviction, and assembly:

```
PRIORITY_THRESHOLDS = {
  always_include: 0.7,       // Items above this are never removed
  compression_eligible: 0.4, // Items below this are compression targets
  eviction_eligible: 0.2,    // Items below this are eviction targets
  emergency_evict: 0.1,      // Items below this are first to go in emergency
  exclude_by_default: 0.0    // Background items excluded unless window has room
}
```

| Threshold | Purpose |
|-----------|---------|
| `always_include` | Items guaranteed in every snapshot (pinned + Critical + High) |
| `compression_eligible` | Items below this are candidates for summarization or truncation |
| `eviction_eligible` | Items below this are candidates for TTL-based removal |
| `emergency_evict` | Items below this are dropped first when hard limit is reached |
| `exclude_by_default` | Background items never included in normal assembly |

## Internal Interfaces

```typescript
interface PriorityManager {
  score(item: RawItem, source: string): PriorityScore
  getPriority(item_id: string): PriorityScore | null
  applyDecay(window: ContextWindow, turns_elapsed: number): DecayReport
  applyAccessBoost(item_id: string): void
  applyCrossSessionDecay(item_id: string, elapsed_days: number): void

  pin(item_id: string, priority: number): void
  unpin(item_id: string): void
  isPinned(item_id: string): boolean

  getThreshold(threshold_name: string): number
  classifyTier(score: number): PriorityTier

  getDecayReport(session_id: string): DecayReport
}

interface DecayReport {
  session_id: string
  items_decayed: number
  tier_shifts: Record<string, number>   // tier â†’ count of items that shifted
  total_score_delta: number
  turns_elapsed: number
  timestamp: timestamp
}
```

## Usage Patterns

### Pattern 1: Priority Lifecycle of a Tool Result

```
1. Tool executes â†’ result pushed with priority: 0.75 (High)
2. Next turn: priority = 0.75 - 0.02 = 0.73 (still High)
3. Sou references the result â†’ +0.15 â†’ priority = 0.88 (High)
4. After 3 turns without access: priority = 0.88 - 0.06 = 0.82 (High)
5. After 10 turns: priority = 0.82 - 0.14 = 0.68 (Medium)
6. After 20 turns: priority = 0.68 - 0.20 = 0.48 (Medium)
7. Sou never accesses again â†’ priority hits min 0.5 (if started High)
   OR continues to decay if it was never boosted above min
```

### Pattern 2: Emergency Priority Queue

```
1. Window reaches 95% of max_tokens (emergency threshold)
2. Emergency eviction scans all items ordered by priority ascending
3. All items with priority < 0.1 (emergency_evict) are immediately dropped
4. If still over 95%, items with priority < 0.2 are dropped
5. Continue until total_tokens < max_tokens
6. Pinned items and items with priority > always_include are never dropped
```

### Pattern 3: Sou Pin Recovery

```
1. Sou pins an item at priority 0.95 (Critical)
2. Item survives all compression and eviction cycles
3. Session ends â†’ item is still Critical â€” promoted to Episodic Memory
4. New session starts â†’ Sou queries for previous session
5. Episodic returns the pinned item with its historical priority
6. Sou can re-pin it in the new session
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CTX.ItemScored |    item_id, score, tier, source | Priority assigned at insert |
| CTX.ItemPinned |    item_id, priority, old_priority | Item pinned by Sou |
| CTX.ItemUnpinned |    item_id, old_priority | Pin removed |
| CTX.PriorityDecayed |    item_id, old_score, new_score, tier_shift | Turn-based decay applied |
| CTX.PriorityAdjusted |    item_id, old_score, new_score, reason | Manual or system override |
| CTX.PriorityBoosted |    item_id, boost_amount, reason, duration | Temporary boost applied |
| CTX.TierShifted |    item_id, old_tier, new_tier, score | Item crossed tier boundary |
| CTX.DecayApplied |    session_id, items_decayed, total_delta | Batch decay complete |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| PR-001 | Priority scores are bounded [0.0, 1.0] | Schema â€” clamped on every update |
| PR-002 | Non-pinned items decay monotonically (score never increases except by boost) | Algorithmic â€” boost is separate from decay |
| PR-003 | Priority tiers map to non-overlapping score ranges | Algorithmic â€” classifyTier uses strict bounds |
| PR-004 | Pinned items are immune to decay | Algorithmic â€” decay skips pinned items |
| PR-005 | Each item has exactly one priority score at any time | Schema â€” one-to-one with ContextItem |
| PR-006 | Priority overrides are logged immutably | Architectural â€” override_history is append-only |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-006 | The Context System owns the global context window. Single authority for context. | Architectural - no other component may persist or modify global context. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown item_id on pin | `CTX_ITEM_NOT_FOUND` | Return error; no context change |
| Pin with priority out of range | `CTX_INVALID_PRIORITY` | Clamp to [0.0, 1.0]; log warning |
| Pin on already-pinned item | `CTX_ALREADY_PINNED` | Update priority to new value; idempotent |
| Unpin on non-pinned item | `CTX_NOT_PINNED` | No-op; return success |
| Decay on closed session | `CTX_SESSION_NOT_FOUND` | Skip; session already terminated |
| Boost beyond 1.0 | `CTX_PRIORITY_CLAMPED` | Clamp to 1.0; log warning |


## Cross-Cutting Concerns

### Security

Context System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Context System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Context System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Context System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Priority Manager handles only scoring, decay, and pinning |
| R2 â€” Dependency Order | Depends on Context Registry; no upward deps |
| R3 â€” DRY | Tier definitions stored once in PriorityConfig |
| R4 â€” Builder Pattern | Score built by base â†’ source boost â†’ access boost â†’ decay |
| R5 â€” Liskov Substitution | Any PriorityConfig implements the interface |
| R6 â€” DI over Singletons | Tier config, source weights, decay rates injected |
| R9 â€” Deterministic | Same item + same context produces same score |
| R10 â€” Simpler Over Complex | 5-tier model with clear boundaries and behaviors |
| R13 â€” Design for Failure | Emergency threshold guarantees eviction always succeeds |
| R14 â€” Paved Path | All scoring flows through scoreItem â†’ applyDecay â†’ pin/unpin |
| R15 â€” Open/Closed | New tiers added via PriorityConfig, not by modifying scorer |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Context/000-Overview.md | Priority Manager implements the 5-tier model from CTX-000 |
| Context/001-Window-Management.md | Window Manager consumes priority scores for assembly |
| Context/003-Compression-Engine.md | Compression targets items below compression_eligible threshold |
| Context/004-TTL-Eviction.md | Eviction targets items below eviction_eligible threshold |
| Context/005-Context-Registry.md | Registry stores priority metadata per item |
| Brain/Sou/000-Overview.md | Sou exercises pin/unpin and priority override |
| Brain/Memory/000-Overview.md | Memory-supplied items carry internal importance scores |
