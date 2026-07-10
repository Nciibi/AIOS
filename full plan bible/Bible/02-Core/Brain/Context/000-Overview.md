# AIOS Bible — Brain
## 000 — Context System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Context |
| Document ID | AIOS-BBL-002-CTX-000 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/003-Communication.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Context System is the single authority for the global context window within the Brain. It manages what Sou sees, hears, and knows at any moment. Every piece of information entering Sou's awareness — user input, memory recall, tool output, system signals — passes through the Context System, which prioritizes, compresses, and structures it into a coherent context window.

Under BRAIN-006, the Context System owns the global context window exclusively. No other component writes to or reads from the context window directly. Sou reads from the context window. Services write to it through the Context System.

## Architecture

```
Sou (reads context)
   ▲
   │
   ▼
┌────────────────────────────────────────────┐
│           Context System                    │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Priority  │  │ Compress │  │ Window   │ │
│  │ Manager   │─►│ Engine   │─►│ Manager  │ │
│  └──────────┘  └──────────┘  └────┬─────┘ │
│                                    │       │
│  ┌──────────┐  ┌──────────┐       │       │
│  │ Context  │  │ TTL      │       │       │
│  │ Registry │  │ Manager  │       │       │
│  └──────────┘  └──────────┘       │       │
└────────────────────────────────────┼───────┘
                                     │
                                     ▼
                            ┌──────────────┐
                            │  Memory OS   │
                            │ (persistence)│
                            └──────────────┘
```

The Context System is stateless (per BRAIN-007). All context data is persisted through Memory OS. The Context System owns the *structure and management* of the context window, not the storage.

## Core Responsibilities

### 1. Context Window Management

The context window is a structured representation of everything Sou is aware of:

```
ContextWindow {
  session_id: string
  turn_count: number
  user_input: InputMessage
  working_memory: WorkingMemory[]
  conversation_history: ConversationTurn[]
  active_mission_state: MissionState | null
  tool_results: ToolResult[]
  system_signals: SystemSignal[]
  metadata: {
    total_tokens: number
    priority_threshold: number
    created_at: timestamp
    expires_at: timestamp
  }
}
```

| Property | Description |
|----------|-------------|
| `session_id` | Identifies the current session |
| `turn_count` | Monotonically increasing turn counter |
| `user_input` | The latest user input (always included) |
| `working_memory` | Active task state, pinned items, current goals |
| `conversation_history` | Recent message exchanges (sliding window) |
| `active_mission_state` | Current mission context if Sou is executing one |
| `tool_results` | Results from tool calls within this turn |
| `system_signals` | Notifications, alerts, state changes from infrastructure |

### 2. Priority Management

Not all information has equal importance. The Priority Manager assigns a priority score to each context item:

| Priority Level | Score Range | Retention | Examples |
|----------------|-------------|-----------|----------|
| Critical | 0.9–1.0 | Always included | User input, active mission state, security alerts |
| High | 0.7–0.9 | Included until resolved | Pinned goals, active tool calls, recent user messages |
| Medium | 0.4–0.7 | Included if space permits | Conversation history, system notifications |
| Low | 0.2–0.4 | Included subject to compression | Historical context, verbose tool output |
| Background | 0.0–0.2 | Excluded unless explicitly requested | Log entries, debug info, stale context |

Priority decay: items lose priority over time. A High-priority item from 10 turns ago may degrade to Medium or Low.

Priority override: Sou can explicitly pin items at a specific priority level. Pinned items bypass decay.

### 3. Context Compression

When the context window exceeds the token budget (set by LLMOS Token Budget Manager), the Compression Engine reduces size:

| Strategy | Behavior | Token Savings | Quality Impact |
|----------|----------|---------------|----------------|
| Truncation | Drop lowest-priority items | Variable | Loss of low-value context |
| Summarization | Replace conversation turns with summary | 60–80% | Moderate — summaries lose detail |
| Deduplication | Remove repeated information | 5–15% | None |
| Structured Pruning | Remove verbose fields from items | 10–30% | Minimal — metadata preserved |
| Sliding Window | Keep last N turns, drop earlier | Fixed N | Deterministic but lossy |

The Compression Engine respects Sou's priority overrides — pinned items are never compressed.

### 4. TTL Management

Every item in the context window has a time-to-live. Expired items are automatically evicted:

| Item Type | Default TTL | Maximum TTL | Extendible |
|-----------|-------------|-------------|------------|
| User input | Current turn | Current turn | No |
| Working memory | Session lifetime | Session lifetime | Yes (explicit pin) |
| Conversation turn | 20 turns | 50 turns | Yes |
| Tool result | 3 turns | 10 turns | Yes |
| System signal | 5 turns | 20 turns | No |

### 5. Context Registry

The Context Registry maintains metadata about all context items:

```
ContextRegistry {
  item_id: string
  source: string          // Which service produced this item
  item_type: string       // "user_input" | "memory" | "tool_result" | "system_signal"
  priority: number        // 0.0–1.0
  token_count: number
  created_at: timestamp
  ttl_turns: number
  hash: string            // Content hash for deduplication
  pinned: boolean
}
```

## Interfaces

### Context System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `pushItem(item, source, priority?)` | Brain Service | Push an item into the context window |
| `pullWindow(session_id)` | Sou only | Get the current context window |
| `pinItem(item_id, priority)` | Sou only | Pin an item at a specific priority |
| `unpinItem(item_id)` | Sou only | Remove a pin from an item |
| `compressWindow(session_id, target_tokens)` | Brain Service | Trigger manual compression |
| `clearWindow(session_id)` | Sou only | Clear the context window |
| `getRegistry(session_id, filter?)` | Sou only | Query context registry |
| `setBudget(session_id, max_tokens)` | LLMOS | Set token budget for current window |

### Internal Interfaces

```
interface PriorityScorer {
  score(item_type: string, source: string, age_turns: number, metadata: Record): number
}

interface CompressionStrategy {
  name: string
  compress(window: ContextWindow, budget: number): CompressedWindow
  estimatedSavings(window: ContextWindow): number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `CTX.ItemPushed` | item_id, source, item_type, priority | Item added to context window |
| `CTX.ItemExpired` | item_id, item_type, reason | Item evicted due to TTL |
| `CTX.WindowPulled` | session_id, item_count, total_tokens | Context window read by Sou |
| `CTX.WindowCompressed` | session_id, before_tokens, after_tokens, strategy | Compression triggered |
| `CTX.ItemPinned` | item_id, priority | Item pinned by Sou |
| `CTX.ItemUnpinned` | item_id | Pin removed |
| `CTX.BudgetUpdated` | session_id, new_budget | Token budget changed by LLMOS |
| `CTX.PriorityOverride` | item_id, old_priority, new_priority | Priority manually adjusted |
| `CTX.Deduplicated` | item_id, duplicate_of | Duplicate item removed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CTX-001 | Sou is the only reader of the context window | API-level — `pullWindow` is Sou-only |
| CTX-002 | Services push items; they never write directly | Architectural — no direct context access |
| CTX-003 | The context window is ephemeral — persistence is Memory OS's responsibility | Architectural — Context System is stateless |
| CTX-004 | Compression never removes pinned items | Algorithmic — checked during compression |
| CTX-005 | Every context item has a source and priority | Schema — required fields on push |
| CTX-006 | Token budget is set by LLMOS, never by the Context System | API-level — `setBudget` is LLMOS-only |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | BRAIN-006 establishes Context System authority over global context window |
| Brain/Sou/000-Overview.md | Sou reads context; SOU-004 gives Sou global context ownership |
| Brain/LLMOS/006-Token-Budget-Manager.md | Sets token budget consumed by context compression |
| Brain/LLMOS/004-Context-Builder.md | Consumes context window for LLMOS prompt assembly |
| Brain/Memory/ | Persists context data (stateless design) |
| Brain/Decision/000-Overview.md | Decision System consumes context for trade-off analysis |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Window exceeds budget, compression fails | `CTX_COMPRESSION_FAILED` | Drop lowest-priority items unconditionally |
| Unknown item_id on pin | `CTX_ITEM_NOT_FOUND` | Return error; no context change |
| Push from unauthorized source | `CTX_UNAUTHORIZED_SOURCE` | Deny push; log security event |
| Window empty on pull | `CTX_EMPTY_WINDOW` | Return empty window; not an error |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Context System does one thing: manage the context window |
| R2 — Dependency Order | Depends on Memory OS; no upward deps |
| R3 — DRY | Context structure defined once in Context Registry |
| R4 — Builder Pattern | Context window built by Priority Manager + Compression Engine |
| R5 — Liskov Substitution | Any CompressionStrategy implements the interface |
| R6 — DI over Singletons | Scorer and compression strategies injected |
| R9 — Deterministic | Same inputs produce same context window |
| R10 — Simpler Over Complex | Priority model uses simple 5-tier scale |
| R14 — Paved Path | All context flows through push/pull API |
| R15 — Open/Closed | New item types added via Registry, not by modifying core