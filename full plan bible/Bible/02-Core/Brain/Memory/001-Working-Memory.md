# AIOS Bible â€” Brain
## 001 â€” Working Memory

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/004-Sessions.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Working Memory holds the active state of Sou's current session â€” what Sou is doing right now. It is the fastest memory tier, designed for high-throughput read/write access to task state, current goals, pinned references, and the task stack. Working Memory is session-scoped: it is created when a session starts, persists throughout the session, and is cleared when the session ends.

Under MEM-005, Working Memory is strictly session-scoped. No Working Memory item outlives its session.

## Data Model

### WorkingMemoryItem

```typescript
WorkingMemoryItem {
  item_id: string
  session_id: string
  category: "goal" | "task" | "note" | "reference" | "decision" | "pinned"
  content: unknown
  priority: number               // 0.0â€“1.0, pinned items maintain priority
  parent_id?: string             // For task hierarchy (task stack)
  children: string[]             // Sub-items in the task stack
  created_at: timestamp
  updated_at: timestamp
  access_count: number
  last_accessed: timestamp
  metadata: {
    source: string               // Which service created this item
    token_estimate: number
    importance: number           // 0.0â€“1.0, influences retention
    tags: string[]
  }
}
```

### WorkingMemorySlot

```typescript
WorkingMemorySlot {
  slot_id: string
  label: string                  // "current_goal" | "active_task" | "task_stack" |
                                 // "pinned_items" | "recent_decisions" | "scratchpad"
  capacity: number               // Max items in this slot
  items: WorkingMemoryItem[]
  eviction_policy: "lru" | "fifo" | "priority" | "none"
}
```

### WorkingMemorySession

```typescript
WorkingMemorySession {
  session_id: string
  slots: Record<string, WorkingMemorySlot>
  current_task_stack: string[]   // Ordered list of task_ids (LIFO)
  total_items: number
  total_tokens_estimate: number
  max_tokens: number             // Configurable budget
  created_at: timestamp
  last_activity: timestamp
}
```

## Slots

Working Memory is organized into named slots, each with its own capacity and eviction policy:

| Slot | Capacity | Eviction | Contents |
|------|----------|----------|----------|
| `current_goal` | 1 | None | The single active goal Sou is working toward |
| `active_task` | 1 | None | The task Sou is executing right now |
| `task_stack` | 10 | FIFO | Nested sub-tasks (LIFO access pattern) |
| `pinned_items` | 5 | None | Items Sou explicitly pinned for retention |
| `recent_decisions` | 5 | LRU | Last N decisions made in this session |
| `scratchpad` | 3 | FIFO | Temporary notes, intermediate state |
| `references` | 10 | LRU | Important references Sou wants to keep handy |

### Slot Behavior

```
Slot: task_stack
  Access: push(task) â†’ pop() â†’ peek()
  Eviction: When full, oldest item at bottom of stack is removed
  Use case: Sou starts task A, within A starts subtask A1, within A1 starts A1a
    Stack: [A, A1, A1a] â†’ pop A1a â†’ back to A1 â†’ pop A1 â†’ back to A

Slot: recent_decisions
  Access: append(decision) â†’ getRecent(N)
  Eviction: When full, oldest decision is removed
  Use case: Sou made 5 decisions, needs to recall the last 2

Slot: pinned_items
  Access: pin(item) â†’ unpin(item_id) â†’ list()
  Eviction: Never (manual only)
  Use case: Sou pins the user's name and project requirements for the session
```

## CRUD Operations

### Store

```typescript
store(item: WorkingMemoryItem): WorkingMemoryItem
```

- Validates `session_id` matches current session
- Validates `category` is one of the defined slot categories
- If slot is at capacity, applies eviction policy before insert
- Sets `created_at` and `updated_at`
- Returns the stored item with assigned `item_id`

### Read

```typescript
get(item_id: string): WorkingMemoryItem | null
getSlot(slot_label: string, session_id: string): WorkingMemorySlot
getSessionState(session_id: string): WorkingMemorySession
peekTaskStack(session_id: string): WorkingMemoryItem | null
```

- `get` â€” direct lookup by item_id across all slots
- `getSlot` â€” returns all items in a named slot
- `getSessionState` â€” full session snapshot for Context System
- `peekTaskStack` â€” returns top of stack without popping

### Update

```typescript
update(item_id: string, updates: Partial<WorkingMemoryItem>): WorkingMemoryItem
pinItem(item_id: string, priority?: number): WorkingMemoryItem
unpinItem(item_id: string): WorkingMemoryItem
pushTask(item: WorkingMemoryItem): void
popTask(session_id: string): WorkingMemoryItem | null
```

- `update` â€” only mutable fields: `content`, `priority`, `metadata`
- `pinItem` â€” moves item to `pinned_items` slot, sets priority
- `pushTask` â€” pushes onto `task_stack` slot
- `popTask` â€” pops from `task_stack`, returns the task

### Delete

```typescript
delete(item_id: string): void
clearSession(session_id: string): void
```

- `delete` â€” removes a single item regardless of slot
- `clearSession` â€” clears all slots for a session (called on session end)

## Lifecycle

### Per-Session Lifecycle

```
Session Start
    â”‚
    â–¼
Initialize Working Memory
    â”‚
    â”œâ”€â”€ Create WorkingMemorySession with session_id
    â”œâ”€â”€ Initialize all slots with default capacities
    â”œâ”€â”€ Set max_tokens from LLMOS configuration
    â””â”€â”€ Load any cross-session pinned items from Episodic Memory
    â”‚
    â–¼
Active Session
    â”‚
    â”œâ”€â”€ Sou sets current_goal
    â”œâ”€â”€ Tasks pushed/popped from task_stack
    â”œâ”€â”€ Items pinned/unpinned
    â”œâ”€â”€ Decisions appended to recent_decisions
    â”œâ”€â”€ Scratchpad used for temporary state
    â””â”€â”€ priority decays applied periodically
    â”‚
    â–¼
Session End
    â”‚
    â”œâ”€â”€ Convert high-importance items to Episodic Memory
    â”œâ”€â”€ Clear all Working Memory slots
    â”œâ”€â”€ Emit MEM.SessionMemoryCleared event
    â””â”€â”€ Destroy WorkingMemorySession
```

### Priority Decay

Working Memory items lose priority over time. Priority decay ensures that old items don't consume budget:

| Category | Decay Rate | Minimum Priority | Notes |
|----------|-----------|------------------|-------|
| goal | None | 0.8 | Never decays |
| task | 0.05 per turn | 0.3 | Decays if not active |
| note | 0.10 per turn | 0.1 | Fast decay |
| reference | 0.05 per turn | 0.2 | Moderate decay |
| decision | 0.08 per turn | 0.2 | Decays as session progresses |
| pinned | None | User-set | Never decays |

Decay is applied:
- On every context window pull
- On every new item insert
- On explicit `decaySlot(slot_label)` call

## Token Budget Management

Working Memory operates within a token budget to prevent Sou's context from being overwhelmed:

```
Budget Calculation:
  total_tokens = sum of all item token_estimates
  If total_tokens > max_tokens:
    Apply eviction starting from lowest-priority items
    Skip: current_goal, active_task, pinned_items

Default max_tokens: 4096
Configurable: Per-session via LLMOS setBudget
```

## Memory OS Integration

Working Memory is exposed through Memory OS as the `working` memory type:

```typescript
// Store a working memory item
POST /memory/store {
  item: WorkingMemoryItem,
  memory_type: "working"
}

// Query working memory (by session_id)
POST /memory/query {
  memory_types: ["working"],
  filters: { session_id: "..." }
}

// Get full session state
GET /memory/session/{session_id}
```

## Internal Interfaces

```typescript
interface WorkingMemoryStore {
  initializeSession(session_id: string, config: WorkingMemoryConfig): WorkingMemorySession
  getSession(session_id: string): WorkingMemorySession | null
  destroySession(session_id: string): void

  store(session_id: string, item: WorkingMemoryItem): WorkingMemoryItem
  get(session_id: string, item_id: string): WorkingMemoryItem | null
  update(session_id: string, item_id: string, updates: Partial<WorkingMemoryItem>): WorkingMemoryItem
  delete(session_id: string, item_id: string): void

  pushTask(session_id: string, item: WorkingMemoryItem): void
  popTask(session_id: string): WorkingMemoryItem | null
  peekTask(session_id: string): WorkingMemoryItem | null

  pinItem(session_id: string, item_id: string, priority?: number): WorkingMemoryItem
  unpinItem(session_id: string, item_id: string): WorkingMemoryItem

  applyDecay(session_id: string, turns_elapsed: number): DecayReport
  clearSession(session_id: string): void
}

interface WorkingMemoryConfig {
  default_max_tokens: number
  slot_capacities: Record<string, number>
  decay_rates: Record<string, number>
  min_priorities: Record<string, number>
}
```

## Usage Patterns

### Pattern 1: Goal-Oriented Task Execution

```
1. Sou sets current_goal: "Implement user authentication"
2. Sou pushes task: "Design auth architecture" â†’ task_stack: [Design]
3. Sou pushes sub-task: "Research auth patterns" â†’ task_stack: [Design, Research]
4. Sou completes Research â†’ popTask â†’ task_stack: [Design]
5. Sou pushes next sub-task: "Design database schema" â†’ task_stack: [Design, Schema]
6. Sou completes Schema â†’ popTask â†’ task_stack: [Design]
7. Sou completes Design â†’ popTask â†’ task_stack: []
8. Sou pushes next task: "Implement backend" â†’ task_stack: [Backend]
```

### Pattern 2: Decision Tracking

```
1. Sou makes decision â†’ append to recent_decisions
2. 3 decisions later, Sou needs to recall earlier choice
3. Sou queries getSlot("recent_decisions", session_id)
4. Sliding window shows last 5 decisions with scores
```

### Pattern 3: Reference Pinning

```
1. User says "My name is Alice and I prefer Python"
2. Sou stores as note, then pins it: pinItem(note_id, priority=0.9)
3. Throughout session, the pinned reference is always in context
4. User ends session â†’ pinned items with high importance promoted to Episodic Memory
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.MEMEvent |      item_id, session_id, category, priority | Working Memory item created |
| MEM.MEMEvent |      item_id, session_id, updated_fields | Item content or priority changed |
| MEM.MEMEvent |      item_id, session_id, category | Item removed |
| MEM.MEMEvent |      task_id, session_id, stack_depth | Task added to stack |
| MEM.MEMEvent |      task_id, session_id, stack_depth, duration_ms | Task completed and popped |
| MEM.MEMEvent |      item_id, session_id, priority | Item pinned by Sou |
| MEM.MEMEvent |      item_id, session_id | Pin removed |
| MEM.MEMEvent |      session_id, items_decayed, total_delta | Priority decay executed |
| MEM.MEMEvent |      slot_label, evicted_item_id, reason | Item evicted due to capacity |
| MEM.MEMEvent |      session_id, item_count, tokens_freed | Session ended and cleared |
| MEM.MEMEvent |      session_id, total_tokens, max_tokens, items_evicted | Token budget exceeded |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WM-001 | Every Working Memory item belongs to exactly one session | Schema â€” `session_id` is required |
| WM-002 | Working Memory is cleared on session end | Algorithmic â€” `clearSession` called by Session Manager |
| WM-003 | The task stack is strictly LIFO | Algorithmic â€” push/pop enforce stack semantics |
| WM-004 | Pinned items are never evicted automatically | Algorithmic â€” eviction skips pinned items |
| WM-005 | Token budget enforcement never evicts current_goal or active_task | Algorithmic â€” budget eviction excludes these slots |
| WM-006 | Priority decay is monotonic (priority only decreases) | Algorithmic â€” decay never increases priority |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown session_id | `WM_SESSION_NOT_FOUND` | Return error; cannot operate on nil session |
| Slot at capacity, no evictable items | `WM_SLOT_FULL` | Return error; caller must unpin or free space |
| Item not found in session | `WM_ITEM_NOT_FOUND` | Return null; no error |
| Pin on non-existent item | `WM_ITEM_NOT_FOUND` | Return error; create item first |
| Pop on empty task stack | `WM_STACK_EMPTY` | Return null; no error |
| Item exceeds max_tokens individually | `WM_ITEM_TOO_LARGE` | Return error; suggest compression |


## Cross-Cutting Concerns

### Security

Memory OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Memory OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Memory OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Memory OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Working Memory handles only session-scoped active state |
| R2 â€” Dependency Order | Depends on Memory OS core; no upward deps |
| R3 â€” DRY | Slot definitions stored once in WorkingMemoryConfig |
| R4 â€” Builder Pattern | Session built by Config â†’ Slot Init â†’ Item Operations |
| R5 â€” Liskov Substitution | Any WorkingMemoryStore implements the interface |
| R6 â€” DI over Singletons | Config and decay strategies injected |
| R9 â€” Deterministic | Same operations produce same state |
| R10 â€” Simpler Over Complex | Uses clear slot model with named capacities |
| R13 â€” Design for Failure | Eviction protects critical slots from overflow |
| R14 â€” Paved Path | All operations flow through store/get/update/delete |
| R15 â€” Open/Closed | New slot types added via Config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Working Memory is one of 4 memory types |
| Memory/002-Episodic-Memory.md | High-importance items promoted to Episodic on session end |
| Brain/Context/000-Overview.md | Context System pulls Working Memory for its window |
| Brain/Planning/000-Overview.md | Plans reference Working Memory tasks |
| Brain/Sou/000-Overview.md | Sou reads/writes Working Memory directly |
| Bible/05-Platform/004-EVS.md | Events recorded throughout Working Memory lifecycle |
