# AIOS Bible â€” Brain
## 001 â€” Context Window Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Context |
| Document ID | AIOS-BBL-002-CTX-001 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/004-Sessions.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Context Window Manager owns the structure, lifecycle, and session binding of the global context window. Under BRAIN-006, it enforces that Sou is the sole reader and that all writes flow through the Context System API. It maintains the window's composition â€” which sections are present, their ordering, and the token budget â€” and coordinates with the Priority Manager, Compression Engine, TTL Manager, and Registry to produce a coherent snapshot on every pull.

## Data Model

### ContextWindow

```typescript
ContextWindow {
  window_id: string
  session_id: string
  turn_number: number
  user_input: InputMessage | null
  sections: ContextSection[]
  active_mission_state: MissionState | null
  metadata: {
    total_tokens: number
    max_tokens: number
    section_count: number
    turn_count: number
    priority_threshold: number
    created_at: timestamp
    expires_at: timestamp
    last_compressed_at: timestamp | null
    compression_count: number
  }
}

ContextSection {
  section_id: string
  section_type: "working_memory" | "conversation_history" | "tool_results"
    | "system_signals" | "mission_state" | "user_input"
  items: ContextItem[]
  priority_range: { min: number, max: number }
  total_tokens: number
  pinned_item_count: number
  ordering: number        // Display order (0 = first)
}
```

### ContextItem

```typescript
ContextItem {
  item_id: string
  item_type: string        // "user_input" | "memory" | "tool_result" | "system_signal"
  content: unknown
  section_type: string
  priority: number         // 0.0â€“1.0
  token_count: number
  pinned: boolean
  source: string           // Which service produced this item
  inserted_at: timestamp
  ttl_turns: number
  turns_remaining: number
}
```

### InputMessage

```typescript
InputMessage {
  text: string
  modality: "text" | "voice" | "image"
  metadata: {
    timestamp: timestamp
    source: string
    session_id: string
    language?: string
    input_tokens: number
  }
}
```

## Window Lifecycle

```
Session Start
    â”‚
    â–¼
Initialize Window
    â”‚
    â”œâ”€â”€ Create ContextWindow with session_id
    â”œâ”€â”€ Set max_tokens from LLMOS setBudget
    â”œâ”€â”€ Initialize empty sections in fixed order
    â”‚   [user_input, working_memory, mission_state,
    â”‚    conversation_history, tool_results, system_signals]
    â”œâ”€â”€ Register window with Context Registry
    â””â”€â”€ Emit CTX.WindowInitialized
    â”‚
    â–¼
Active Window
    â”‚
    â”œâ”€â”€ Items pushed via pushItem â†’ assigned to section
    â”œâ”€â”€ Priority scored at insert â†’ Registry updated
    â”œâ”€â”€ TTL ticks on each pull â†’ expired items flagged
    â”œâ”€â”€ Compression triggered when total_tokens > max_tokens
    â””â”€â”€ Window pulled by Sou â†’ snapshot assembled
    â”‚
    â–¼
Session End
    â”‚
    â”œâ”€â”€ Emit CTX.WindowClosing
    â”œâ”€â”€ Flush remaining items to Memory OS (if unpinned)
    â”œâ”€â”€ Clear all sections
    â”œâ”€â”€ Emit CTX.WindowCleared
    â””â”€â”€ Destroy ContextWindow
```

### Section Ordering

Sections are assembled in a fixed order on every pull:

| Order | Section | Always Present | Notes |
|-------|---------|----------------|-------|
| 0 | `user_input` | Yes | Current turn's user input |
| 1 | `working_memory` | Yes | Active goals, tasks, pinned items |
| 2 | `mission_state` | Conditional | Only if a mission is active |
| 3 | `conversation_history` | Yes | Sliding window of recent turns |
| 4 | `tool_results` | If any | Results from current turn's tool calls |
| 5 | `system_signals` | If any | Active alerts and notifications |

## Token Budget Management

The window operates within a token budget set by LLMOS. Budget enforcement is checked on every push and every pull:

```typescript
interface BudgetConfig {
  max_tokens: number
  hard_limit: number            // Absolute maximum (max_tokens * 1.1)
  warning_threshold: number     // 0.0â€“1.0, fraction of max_tokens
  compression_trigger: number   // 0.0â€“1.0, fraction of max_tokens
  emergency_threshold: number   // 0.0â€“1.0, fraction of max_tokens
}

// Default config
const DEFAULT_BUDGET: BudgetConfig = {
  max_tokens: 8192,
  hard_limit: 9011,
  warning_threshold: 0.80,
  compression_trigger: 0.90,
  emergency_threshold: 0.95,
}
```

| Threshold | Action |
|-----------|--------|
| total_tokens < warning_threshold | Normal operation |
| warning_threshold â‰¤ total_tokens < compression_trigger | Log warning; continue |
| compression_trigger â‰¤ total_tokens < emergency_threshold | Trigger compression |
| emergency_threshold â‰¤ total_tokens < hard_limit | Force compression with aggressive strategies |
| total_tokens â‰¥ hard_limit | Emergency eviction: drop lowest-priority items unconditionally |

## Pull Mechanics

When Sou calls `pullWindow(session_id)`:

```typescript
pullWindow(session_id: string): ContextWindow {
  window = getSession(session_id)
  if (!window) return emptyWindow()

  // 1. Apply TTL decay to all items
  expiredIds = applyTTL(window, turnsElapsed = 1)

  // 2. Remove expired items
  removeExpired(window, expiredIds)

  // 3. Apply priority decay to non-pinned items
  applyPriorityDecay(window)

  // 4. Check budget â€” compress if needed
  if (window.totalTokens > maxTokens * compressionTrigger)
    compressWindow(session_id, maxTokens)

  // 5. Assemble snapshot
  snapshot = assembleSnapshot(window)

  // 6. Emit event
  emit(CTX.WindowPulled, {
    session_id,
    item_count: countItems(snapshot),
    total_tokens: snapshot.totalTokens,
    expired_count: expiredIds.length
  })

  return snapshot
}
```

### Push Mechanics

When a service calls `pushItem(item, source, priority?)`:

```typescript
pushItem(item, source, priority?): ContextItem {
  // 1. Validate source is authorized
  authorized = validateSource(source)
  if (!authorized) throw CTX_UNAUTHORIZED_SOURCE

  // 2. Score priority (or use explicit)
  itemPriority = priority ?? scoreItem(item, source)

  // 3. Compute content hash for dedup
  contentHash = hashContent(item)

  // 4. Check dedup in Registry
  duplicate = registry.findByHash(contentHash, session_id)
  if (duplicate) {
    emit CTX.Deduplicated, { item_id, duplicate_of: duplicate }
    return duplicate // Return existing, don't insert
  }

  // 5. Create ContextItem
  contextItem = createContextItem(item, source, itemPriority, contentHash)

  // 6. Assign to section
  section = assignToSection(contextItem)
  section.items.push(contextItem)

  // 7. Register in Context Registry
  registry.register(contextItem)

  // 8. Update token count
  window.totalTokens += contextItem.tokenCount

  // 9. Check budget
  if (window.totalTokens > window.maxTokens)
    checkBudget(window)

  // 10. Emit event
  emit CTX.ItemPushed, {
    item_id: contextItem.itemId,
    source,
    item_type: contextItem.itemType,
    priority: contextItem.priority
  }

  return contextItem
}
```

## Window Snapshots

Every pull returns a snapshot. Snapshots are not stored â€” they are assembled on demand:

```typescript
interface WindowSnapshot {
  snapshot_id: string
  window_id: string
  session_id: string
  turn_number: number
  assembled_at: timestamp
  sections: AssembledSection[]
  total_tokens: number
  max_tokens: number
  priority_threshold: number
  expires_at: timestamp
  compression_info: {
    compressed: boolean
    strategy: string | null
    original_tokens: number | null
    compression_ratio: number | null
  }
}

AssembledSection {
  section_type: string
  ordering: number
  items: ContextItem[]
  is_truncated: boolean     // True if items were removed during assembly
  truncated_count: number
}
```

## Session Boundary

| Event | Behavior |
|-------|----------|
| Session start | Initialize window; load cross-session pinned items from Episodic Memory |
| Session end | Flush remaining items; emit final snapshot to Memory OS; destroy window |
| Session timeout (inactivity) | Auto-flush after configurable idle period (default: 30 min) |
| Session switch | Suspend current window; initialize new; restore on switch-back |

## Internal Interfaces

```typescript
interface WindowManager {
  // Session lifecycle
  initializeWindow(session_id: string, budget: BudgetConfig): ContextWindow
  getWindow(session_id: string): ContextWindow | null
  closeWindow(session_id: string): void
  suspendWindow(session_id: string): void
  restoreWindow(session_id: string): ContextWindow

  // Item operations
  pushItem(item: RawItem, source: string, priority?: number): ContextItem
  pullWindow(session_id: string): WindowSnapshot
  pinItem(window_id: string, item_id: string, priority: number): void
  unpinItem(window_id: string, item_id: string): void

  // Budget management
  setBudget(session_id: string, max_tokens: number): void
  checkBudget(window: ContextWindow): BudgetStatus
  enforceHardLimit(window: ContextWindow): void

  // Assembly
  assembleSnapshot(window: ContextWindow): WindowSnapshot
  assignToSection(item: ContextItem, window: ContextWindow): ContextSection
}

interface BudgetStatus {
  status: "normal" | "warning" | "critical" | "emergency"
  total_tokens: number
  max_tokens: number
  usage_pct: number
  actionable: boolean
}
```

## Usage Patterns

### Pattern 1: Turn Processing

```
1. User sends message
2. Conversation OS calls pushItem(userMessage, "conversation", priority=0.95)
3. Item lands in user_input section
4. Tool calls execute â†’ results pushed to tool_results section
5. Sou calls pullWindow() â†’ snapshot assembled
6. Sou processes and responds
7. Conversation OS pushes response as turn to conversation_history
8. TTL ticks â†’ some items may expire
```

### Pattern 2: Budget Recovery

```
1. Window reaches 85% of max_tokens (warning threshold)
2. Next push triggers checkBudget â†’ status = "warning"
3. Warning emitted; compression not triggered yet
4. Next push at 92% â†’ compression_trigger reached
5. CompressWindow called with target = max_tokens
6. Items with priority < 0.3 summarized or dropped
7. Tokens reduced to 75% of budget
8. Normal operation resumes
```

### Pattern 3: Session Restore

```
1. Sou switches from session A to session B
2. Window A suspended â†’ snapshot saved to Episodic Memory
3. Window B initialized â†’ if first time, empty; if resumed, loaded
4. Sou returns to session A â†’ restoreWindow(A)
5. Window A loaded from suspension snapshot
6. Items restored; TTL adjusted for elapsed time
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CTX.WindowInitialized |    session_id, window_id, max_tokens, section_count | Window created |
| CTX.WindowPulled |    session_id, item_count, total_tokens, expired_count | Snapshot assembled and returned |
| CTX.WindowClosing |    session_id, item_count, token_usage | Window about to close |
| CTX.WindowCleared |    session_id, items_flushed, tokens_freed | Window destroyed |
| CTX.WindowSuspended |    session_id, snapshot_size | Window paused |
| CTX.WindowRestored |    session_id, turns_missed | Window resumed |
| CTX.ItemPushed |    item_id, source, item_type, priority, section_type | Item added to window |
| CTX.BudgetAdjusted |    session_id, old_max, new_max, reason | Token budget changed |
| CTX.BudgetWarning |    session_id, total_tokens, max_tokens, usage_pct | Warning threshold reached |
| CTX.BudgetEmergency |    session_id, total_tokens, items_evicted | Hard limit enforced |
| CTX.SectionTruncated |    section_type, items_dropped, tokens_freed | Items removed during assembly |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WM-001 | Sou is the sole reader of the context window | API-level â€” `pullWindow` is Sou-only |
| WM-002 | Services write only through pushItem | Architectural â€” no direct context access |
| WM-003 | The window is ephemeral; persistence is Memory OS's responsibility | Architectural â€” Context System is stateless |
| WM-004 | Token budget is set only by LLMOS | API-level â€” `setBudget` is LLMOS-only |
| WM-005 | Pinned items survive compression and eviction | Algorithmic â€” verified during assembly |
| WM-006 | Window sections are assembled in fixed order | Algorithmic â€” ordering enforced in assembleSnapshot |
| WM-007 | Every context item has a unique item_id and source | Schema â€” required fields on push |
| WM-008 | User input is always the first section | Algorithmic â€” ordering = 0, always present |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-006 | The Context System owns the global context window. Single authority for context. | Architectural - no other component may persist or modify global context. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Push from unauthorized source | `CTX_UNAUTHORIZED_SOURCE` | Deny push; log security event |
| Window empty on pull | `CTX_EMPTY_WINDOW` | Return empty snapshot; not an error |
| Unknown session_id | `CTX_SESSION_NOT_FOUND` | Return null; caller must create session first |
| Item exceeds hard_limit individually | `CTX_ITEM_TOO_LARGE` | Return error; suggest compression before push |
| Budget set below minimum (1024) | `CTX_BUDGET_TOO_LOW` | Clamp to minimum; log warning |
| Window at capacity, no evictable items | `CTX_WINDOW_FULL` | Return error; caller must wait for space |
| Suspend on non-existent window | `CTX_WINDOW_NOT_FOUND` | Return error; no-op |


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
| R1 â€” Modulsingularity | Window Manager handles only window lifecycle and assembly |
| R2 â€” Dependency Order | Depends on Context Registry, Memory OS; no upward deps |
| R3 â€” DRY | Window structure defined once in Data Model |
| R4 â€” Builder Pattern | Snapshot assembled by pull â†’ decay â†’ compress â†’ order |
| R5 â€” Liskov Substitution | Any BudgetConfig implements the interface |
| R6 â€” DI over Singletons | Budget config and section ordering injected |
| R9 â€” Deterministic | Same inputs produce same window (time-dependent decays) |
| R10 â€” Simpler Over Complex | Fixed section ordering with clear slot responsibilities |
| R13 â€” Design for Failure | Hard limit prevents OOM; emergency eviction always succeeds |
| R14 â€” Paved Path | All context flows through push â†’ pull cycle |
| R15 â€” Open/Closed | New section types added via config, not by modifying assembly |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Context/000-Overview.md | Window Manager is the core orchestrator of the Context System |
| Context/002-Priority-Manager.md | Priority scores drive section ordering and eviction |
| Context/003-Compression-Engine.md | Compressor reduces window when budget exceeded |
| Context/004-TTL-Eviction.md | TTL Manager controls item expiry and removal |
| Context/005-Context-Registry.md | Registry tracks metadata and enables dedup |
| Brain/Memory/001-Working-Memory.md | Working Memory items populate the working_memory section |
| Brain/Sou/000-Overview.md | Sou is the sole consumer of pulled windows |
| Brain/LLMOS/006-Token-Budget-Manager.md | Sets the max_tokens budget consumed here |
