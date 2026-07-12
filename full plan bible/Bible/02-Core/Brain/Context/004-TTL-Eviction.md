# AIOS Bible â€” Brain
## 004 â€” TTL & Eviction Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Context |
| Document ID | AIOS-BBL-002-CTX-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/006-Lifecycles.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The TTL Manager owns the lifecycle of every item in the context window â€” tracking time-to-live, detecting expiry, executing eviction, and managing the soft-delete recovery window. Under CTX-003 the context window is ephemeral; the TTL Manager ensures items don't outlive their relevance. It coordinates with the Priority Manager (expired items below priority thresholds are evicted first) and the Compression Engine (expired items are purged before compression runs).

## Data Model

### TTLRecord

```typescript
TTLRecord {
  item_id: string
  item_type: string
  session_id: string
  inserted_at: timestamp
  ttl_policy: "turns" | "duration" | "session" | "indefinite"
  ttl_turns: number | null        // Turns remaining (decremented on pull)
  ttl_duration_ms: number | null  // Wall-clock TTL
  ttl_remaining_ms: number | null // Remaining wall-clock time
  turns_lived: number
  extendible: boolean              // Whether TTL can be extended
  extension_count: number          // How many times extended
  max_extensions: number           // Maximum times this item can be extended
  expired: boolean
  expired_at: timestamp | null
  eviction_phase: "active" | "expired" | "recovery" | "purged"
  eviction_reason: string | null
}
```

### TTLConfig

```typescript
TTLConfig {
  defaults: Record<string, ItemTTLConfig>
  sweep_interval_ms: number        // Default: 60000 (60s)
  recovery_window_ms: number       // Default: 86400000 (24h)
  max_extensions_per_item: number  // Default: 3
  batch_size: number               // Items processed per sweep batch
}

ItemTTLConfig {
  ttl_policy: "turns" | "duration" | "session" | "indefinite"
  ttl_turns: number | null
  ttl_duration_ms: number | null
  extendible: boolean
  max_extensions: number
  eviction_priority: number        // Lower = evicted first (1â€“100)
}
```

## TTL Defaults

| Item Type | Policy | Value | Extendible | Max Extensions | Eviction Priority |
|-----------|--------|-------|------------|----------------|-------------------|
| User input | Turns | 1 | No | 0 | 100 (never evicted by TTL) |
| Sou response | Turns | 5 | Yes | 2 | 80 |
| Working memory (goal) | Session | â€” | No | 0 | 90 |
| Working memory (task) | Turns | 10 | Yes | 3 | 70 |
| Working memory (note) | Turns | 5 | Yes | 1 | 40 |
| Working memory (reference) | Turns | 15 | Yes | 3 | 75 |
| Conversation history | Turns | 50 | No | 0 | 30 |
| Tool result | Turns | 3 | Yes | 2 | 60 |
| System signal (critical) | Duration | 300000 (5min) | No | 0 | 95 |
| System signal (warning) | Turns | 5 | No | 0 | 50 |
| System signal (info) | Turns | 2 | No | 0 | 20 |
| Mission state | Session | â€” | No | 0 | 90 |
| Compressed summary | Turns | 20 | Yes | 2 | 40 |
| Dedup reference | Turns | 50 | Yes | 3 | 30 |

## Eviction Phases

Items progress through a phased eviction lifecycle:

```
Insert
  â”‚
  â–¼
Active (item is in the context window, TTL counting down)
  â”‚
  â”œâ”€â”€ TTL expires â†’ marked expired
  â”‚
  â–¼
Expired (item flagged, remains in window until next pull)
  â”‚
  â”œâ”€â”€ Next pull sweep detects expiry
  â”‚
  â–¼
Recovery (soft-delete â€” item is out of window but recoverable)
  â”‚
  â”œâ”€â”€ Recovery window expires (24h default)
  â”‚
  â–¼
Purged (hard-delete â€” item removed from Registry, memory freed)
```

### Phase 1: Active

Item is in the context window. TTL is decremented on every pull (turn-based) or by wall clock (duration-based). Items with `session` policy live for the session duration. Items with `indefinite` policy never expire (only removed by explicit clearWindow).

### Phase 2: Expired

TTL reached zero. Item is flagged as expired but is NOT immediately removed from the window. Expired items remain visible until the next pull, at which point the sweep phase removes them:

```typescript
// On pullWindow, before snapshot assembly:
sweepExpired(window):
  now = Date.now()
  expired = []

  for each item in window:
    record = getTTLRecord(item.itemId)
    if record.expired: continue  // Already flagged

    expired = checkExpired(record, now)
    if expired:
      record.expired = true
      record.expiredAt = now
      record.evictionPhase = "expired"
      emit CTX.ItemExpired, {
        item_id: item.itemId,
        item_type: record.itemType,
        reason: "ttl_expired"
      }
      expired.push(item.itemId)

  // Remove expired items from sections
  for id in expired:
    removeFromSection(window, id)
    record.evictionPhase = "recovery"

  return expired
```

### Phase 3: Recovery (Soft Delete)

Expired items are moved to the recovery window. They are no longer in the context window but remain in the Context Registry with `eviction_phase = "recovery"`. During this phase:

- Items are NOT visible in pullWindow results
- Items ARE queryable via getRegistry with `filter: { phase: "recovery" }`
- Items CAN be restored via Sou override
- Recovery window duration: 24 hours (configurable)

```
restoreItem(session_id, item_id):
  record = getTTLRecord(item_id)
  if record.evictionPhase !== "recovery"
    throw CTX_ITEM_NOT_IN_RECOVERY

  record.expired = false
  record.expiredAt = null
  record.evictionPhase = "active"
  record.extensionCount += 1

  if record.extensionCount > record.maxExtensions
    record.maxExtensions += 1  // Allow one more grace extension

  // Re-insert into window
  pushItem(item_id, source="sou_recovery", priority=0.4)

  emit CTX.ItemRestored, {
    item_id,
    session_id,
    extension_count: record.extensionCount
  }
```

### Phase 4: Purged (Hard Delete)

After the recovery window expires, items are permanently removed:

```
purgeExpiredRecords():
  now = Date.now()
  for each record where phase === "recovery":
    if now - record.expiredAt > recoveryWindowMs:
      item = registry.get(record.itemId)
      if item:
        removeFromSection(window, record.itemId)
        registry.delete(record.itemId)
        deleteTTLRecord(record.itemId)

      emit CTX.ItemPurged, {
        item_id: record.itemId,
        item_type: record.itemType,
        turns_lived: record.turnsLived
      }

      memoryFreed += estimateMemoryUsage(record)
```

## TTL Sweep

A periodic sweep ensures timely eviction:

```typescript
sweep(window):
  now = Date.now()

  // Phase 1: Expire active items that reached TTL
  for each record where phase === "active":
    if checkExpired(record, now):
      record.expired = true
      record.expiredAt = now
      record.evictionPhase = "expired"
      removeFromSection(window, record.itemId)
      record.evictionPhase = "recovery"
      emit CTX.ItemExpired

  // Phase 2: Purge recovery items past window
  purgeExpiredRecords()
```

## Check Expiry Logic

```typescript
checkExpired(record, now): boolean {
  if record.ttlPolicy === "indefinite" || record.ttlPolicy === "session"
    return false  // Session-scoped items handled by session end

  if record.ttlPolicy === "turns":
    return record.ttlTurns !== null && record.ttlTurns <= 0

  if record.ttlPolicy === "duration":
    return record.ttlDurationMs !== null
      && (now - record.insertedAt) >= record.ttlDurationMs

  return false
}
```

## TTL Decrement

Turn-based TTL is decremented on each pull:

```typescript
decrementTTL(window, turnsElapsed = 1):
  for each item in window:
    record = getTTLRecord(item.itemId)
    if record.ttlPolicy !== "turns" || record.expired: continue

    record.ttlTurns -= turnsElapsed
    record.turnsLived += turnsElapsed

    if record.ttlTurns <= 0:
      record.ttlTurns = 0
      record.expired = true
      record.expiredAt = now
      emit CTX.ItemExpired, {
        item_id: item.itemId,
        item_type: record.itemType,
        reason: "ttl_expired"
      }
```

## TTL Extension

Items with `extendible: true` can have their TTL extended:

```typescript
extendTTL(session_id, item_id, additional_turns?): TTLRecord {
  record = getTTLRecord(item_id)
  if !record: throw CTX_ITEM_NOT_FOUND
  if !record.extendible: throw CTX_TTL_NOT_EXTENDIBLE
  if record.extensionCount >= record.maxExtensions
    throw CTX_MAX_EXTENSIONS_REACHED

  turns = additional_turns ?? defaultExtensionTurns(record.itemType)
  record.ttlTurns += turns
  record.extensionCount += 1

  if record.evictionPhase === "recovery" || record.evictionPhase === "expired":
    record.expired = false
    record.expiredAt = null
    record.evictionPhase = "active"
    // Re-insert into window
    pushItem(restoredItem, source="ttl_extension", priority=0.3)

  emit CTX.TTLExtended, {
    item_id,
    session_id,
    additional_turns: turns,
    total_turns: record.ttlTurns,
    extension_count: record.extensionCount
  }

  return record
}
```

Extension sources:

| Source | Can Extend | Notes |
|--------|------------|-------|
| Sou (explicit) | Yes | Manual extension |
| Priority Manager (access boost) | Yes | +3 turns on access |
| System (mission state change) | Yes | +5 turns |
| User returns to same topic | Yes | +3 turns |
| TTL Manager (auto-extension) | Conditional | Only if item has been accessed recently |

## Eviction Priority

When multiple items expire simultaneously, eviction order follows:

1. Items with lower eviction_priority number go first
2. Within same priority: lowest priority score first
3. Within same score: oldest first

```typescript
evictionComparator(a, b):
  // 1. Pinned items never evicted by TTL
  if a.pinned: return 1
  if b.pinned: return -1

  // 2. Compare eviction priority (lower = evicted first)
  if a.evictionPriority !== b.evictionPriority
    return a.evictionPriority - b.evictionPriority

  // 3. Compare priority score (lower = evicted first)
  if a.score !== b.score
    return a.score - b.score

  // 4. Compare age (older = evicted first)
  return a.insertedAt - b.insertedAt
```

## Emergency Eviction

When the window exceeds hard_limit even after compression, the TTL Manager runs emergency eviction:

```typescript
emergencyEvict(session_id, target_tokens):
  window = getWindow(session_id)
  items = sortByEvictionPriority(window)  // ascending

  for item in items:
    if item.pinned: continue
    if item.priority >= PRIORITY_THRESHOLDS.always_include: continue
    if window.total_tokens <= target_tokens: break

    removeItem(window, item.itemId)
    record = getTTLRecord(item.itemId)
    record.evictionPhase = "recovery"
    record.evictionReason = "emergency"

    emit CTX.ItemEmergencyEvicted, {
      item_id: item.itemId,
      item_type: record.itemType,
      priority: item.priority,
      eviction_priority: record.evictionPriority,
      reason: "emergency"
    }

  return window.total_tokens <= target_tokens
```

## Internal Interfaces

```typescript
interface TTLManager {
  // Record management
  createRecord(item: ContextItem, config: ItemTTLConfig): TTLRecord
  getRecord(item_id: string): TTLRecord | null
  deleteRecord(item_id: string): void

  // TTL operations
  decrementTTL(window: ContextWindow, turns_elapsed: number): string[]  // Returns expired item_ids
  checkExpired(record: TTLRecord, now: timestamp): boolean
  extendTTL(session_id: string, item_id: string, additional_turns?: number): TTLRecord
  isExpired(item_id: string): boolean

  // Sweep operations
  sweep(window: ContextWindow): SweepReport
  purgeExpiredRecords(): PurgeReport

  // Recovery
  restoreItem(session_id: string, item_id: string): void
  getRecoverableItems(session_id: string): TTLRecord[]

  // Emergency
  emergencyEvict(session_id: string, target_tokens: number): boolean

  // Config
  getDefaultConfig(item_type: string): ItemTTLConfig
  updateConfig(item_type: string, config: Partial<ItemTTLConfig>): void
}

interface SweepReport {
  session_id: string
  items_expired: number
  items_removed: number
  items_purged: number
  tokens_freed: number
  sweep_duration_ms: number
  timestamp: timestamp
}

interface PurgeReport {
  items_purged: number
  tokens_freed: number
  memory_freed_bytes: number
  duration_ms: number
}
```

## Usage Patterns

### Pattern 1: Normal Turn-Based Expiry

```
1. Tool result pushed with TTL = 3 turns
2. Turn 1: TTL = 3 â†’ 2 (decremented on pull)
3. Turn 2: TTL = 2 â†’ 1
4. Turn 3: TTL = 1 â†’ 0 â†’ expired
5. Next pull: sweep detects expiry, removes from window
6. Item moved to recovery phase (24h)
7. If Sou doesn't restore: purged after 24h
```

### Pattern 2: Session-Scoped Items

```
1. Working memory goal pushed with policy = "session"
2. Goal remains active for entire session (100+ turns)
3. Session ends â†’ closeWindow â†’ all session items flushed
4. Session-scoped items are NOT moved to recovery â€” directly purged
5. High-importance items may be promoted to Episodic Memory first
```

### Pattern 3: Item Recovery After Expiry

```
1. Critical system signal expires after 5 turns
2. Signal moves to recovery phase
3. 2 hours later, Sou needs to check the signal
4. Sou calls getRegistry({ phase: "recovery", type: "system_signal" })
5. Sou finds the signal and calls restoreItem()
6. Signal re-enters window with extended TTL (3 additional turns)
7. Sou can now reference it in the current context
```

### Pattern 4: Emergency Eviction Cascade

```
1. Window at 98% of hard_limit (9500/9011 tokens)
2. Compression failed to bring it under limit
3. emergencyEvict called with target = 8192
4. Items sorted by eviction priority: [info:20, conversation:30, note:40, signal:50, ...]
5. First pass: remove info-tier items (2 items, -300 tokens) â†’ 9200
6. Still over â†’ remove oldest conversation turns (5 turns, -1500 tokens) â†’ 7700
7. Under budget: 7700 < 8192
8. 7 items evicted, all moved to recovery
9. CTX.EmergencyEvictionCompleted emitted
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CTX.TTLRecordCreated |      item_id, item_type, ttl_policy, ttl_value | TTL tracking started |
| CTX.ItemExpired |      item_id, item_type, reason | Item reached TTL=0 |
| CTX.ItemRemoved |      item_id, session_id, phase | Item removed from window (expired phase) |
| CTX.ItemRestored |      item_id, session_id, extension_count | Item recovered from recovery phase |
| CTX.ItemPurged |      item_id, item_type, turns_lived | Item hard-deleted after recovery window |
| CTX.ItemEmergencyEvicted |      item_id, item_type, priority, reason | Emergency eviction triggered |
| CTX.TTLExtended |      item_id, session_id, additional_turns, total_turns | TTL extended for item |
| CTX.TTLSweepCompleted |      session_id, expired, removed, purged | Periodic sweep finished |
| CTX.EmergencyEvictionCompleted |      session_id, items_evicted, tokens_freed | Emergency eviction done |
| CTX.RecoveryWindowExpired |      item_id, item_type | Recovery window closed; item purged |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| TE-001 | Pinned items are never TTL-expired | Algorithmic â€” TTL decrement skips pinned items |
| TE-002 | Items with indefinite TTL never expire | Algorithmic â€” checkExpired returns false for indefinite |
| TE-003 | Session-scoped items are purged on session end | Architectural â€” closeWindow triggers purge |
| TE-004 | Expired items have a 24-hour recovery window before purge | Algorithmic â€” purgeExpiredRecords enforces window |
| TE-005 | TTL decrement is monotonic (turns_remaining only decreases) | Algorithmic â€” decrement never increases |
| TE-006 | Emergency eviction never targets pinned or Critical items | Algorithmic â€” emergencyEvict skips these |
| TE-007 | Each item has exactly one active TTLRecord | Schema â€” one-to-one with ContextItem |
| TE-008 | Items in recovery phase are not visible in normal pulls | Architectural â€” filter by phase in assembly |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-006 | The Context System owns the global context window. Single authority for context. | Architectural - no other component may persist or modify global context. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Extend TTL on non-extendible item | `CTX_TTL_NOT_EXTENDIBLE` | Return error; no change |
| Extend TTL past max extensions | `CTX_MAX_EXTENSIONS_REACHED` | Return error; item must expire |
| Restore non-recovery item | `CTX_ITEM_NOT_IN_RECOVERY` | Return error; only recovery-phase items can be restored |
| Unknown item_id on TTL operation | `CTX_ITEM_NOT_FOUND` | Return error; no such item |
| Emergency evict with all items pinned | `CTX_NOTHING_TO_EVICT` | Return false; caller must force-clear or accept overflow |
| Sweep on closed window | `CTX_WINDOW_NOT_FOUND` | No-op; session already terminated |
| Purge already-purged item | `CTX_ALREADY_PURGED` | Idempotent; skip |


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
| R1 â€” Modulsingularity | TTL Manager handles only item lifecycle and eviction |
| R2 â€” Dependency Order | Depends on Context Registry, Priority Manager; no upward deps |
| R3 â€” DRY | TTL config defined once in TTLConfig.defaults |
| R4 â€” Builder Pattern | Eviction built by expire â†’ remove â†’ recover â†’ purge |
| R5 â€” Liskov Substitution | Any TTLConfig implements the interface |
| R6 â€” DI over Singletons | TTL defaults and sweep interval injected |
| R9 â€” Deterministic | Same TTL inputs produce same expiry timeline |
| R10 â€” Simpler Over Complex | Clear phase model with graduated severity |
| R13 â€” Design for Failure | Emergency eviction always succeeds; recovery window prevents data loss |
| R14 â€” Paved Path | All items flow through createRecord â†’ decrement â†’ expire â†’ purge |
| R15 â€” Open/Closed | New item types added via TTLConfig.defaults, not by modifying evictor |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Context/000-Overview.md | TTL Manager implements TTL model from CTX-000 |
| Context/001-Window-Management.md | Window Manager calls TTL decrement on every pull |
| Context/002-Priority-Manager.md | Priority thresholds influence eviction ordering |
| Context/003-Compression-Engine.md | Compression runs before emergency eviction |
| Context/005-Context-Registry.md | Registry stores TTL metadata and recovery-phase items |
| Brain/Memory/002-Episodic-Memory.md | Expired high-importance items may be persisted before purge |
| Brain/Sou/000-Overview.md | Sou can restore items from recovery phase |
