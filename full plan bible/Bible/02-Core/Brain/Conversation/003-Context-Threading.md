# AIOS Bible â€” Brain
## 003 â€” Context Threading

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Conversation |
| Document ID | AIOS-BBL-002-CON-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md, Physics/004-Sessions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Context Threading manages the hierarchical organization of conversation topics into threads. It allows Sou and the user to maintain multiple simultaneous conversation threads, switch between them, split/merge threads, and maintain thread-level context independently of the session-level turn order.

Without Context Threading, every conversation is a single linear sequence of turns â€” when the topic shifts, earlier context is lost or diluted. Context Threading provides parallel conversation lanes where each thread accumulates its own independent context. When Sou switches threads, the relevant facts, decisions, and state for that thread are loaded, while other threads remain paused with their context preserved.

This enables natural conversation patterns like: returning to an earlier topic without losing progress on the current one, exploring a tangent as a sub-thread and merging it back, and maintaining multiple parallel investigations across a long session.

## Data Model

### ConversationThread

```typescript
ConversationThread {
  thread_id: string
  session_id: string
  parent_thread_id?: string           // null for root threads
  child_thread_ids: string[]          // sub-threads spawned from this thread
  topic: string                       // Human-readable topic label
  status: "active" | "paused" | "merged" | "archived"
  created_at: timestamp
  last_activity: timestamp
  turn_count: number
  turn_ids: string[]                  // Turns belonging to this thread (ordered)
  metadata: {
    priority: number                  // 0.0â€“1.0, influences context window allocation
    tags: string[]                    // Categorization tags
    summary: string                   // Auto-generated or user-provided summary
    depth: number                     // Nesting depth (0 for root)
    token_estimate: number            // Estimated tokens for this thread's accumulated context
  }
}
```

### ThreadTree

```typescript
ThreadTree {
  session_id: string
  root_threads: ConversationThread[]      // Top-level threads (depth 0)
  hierarchy: Map<string, string[]>        // thread_id â†’ child_thread_ids
  active_thread_id: string                // Currently active thread
  total_active: number                    // Count of active+paused threads
  last_modified: timestamp
}
```

### ThreadSwitch

```typescript
ThreadSwitch {
  switch_id: string
  from_thread_id: string
  to_thread_id: string
  switched_at: timestamp
  reason: "user_initiated"
        | "sou_suggested"
        | "topic_detected"
        | "auto_return"                 // Merged child auto-returns to parent
  trigger_turn_id?: string               // The turn that caused the switch
  metadata?: {
    user_explicit?: boolean              // User explicitly requested the switch
    confidence?: number                  // Detection confidence (0.0â€“1.0)
    detected_topic?: string              // Auto-detected topic that triggered switch
  }
}
```

### ThreadContext

```typescript
ThreadContext {
  thread_id: string
  key_facts: string[]                    // Important facts established in this thread
  decisions: {
    decision_id: string
    description: string
    turn_id: string
    timestamp: timestamp
    rationale?: string
  }[]
  unresolved_questions: {
    question: string
    asked_by: "user" | "sou"
    turn_id: string
    timestamp: timestamp
  }[]
  pending_items: {
    description: string
    status: "pending" | "in_progress" | "blocked"
    assigned_to: "user" | "sou" | "system"
    created_at: timestamp
  }[]
  state_summary: string                  // Condensed summary for context window injection
  last_updated: timestamp
  token_estimate: number                 // Token cost of this thread context
}
```

## Thread Hierarchy

Threads form a tree structure within each session:

```
Session (session_id)
  â”‚
  â”œâ”€â”€ Root Thread (depth 0, always exists, session-level default)
  â”‚     â”œâ”€â”€ Child Thread A (depth 1)
  â”‚     â”‚     â”œâ”€â”€ Grandchild A1 (depth 2)
  â”‚     â”‚     â””â”€â”€ Grandchild A2 (depth 2)
  â”‚     â””â”€â”€ Child Thread B (depth 1)
  â”‚
  â””â”€â”€ Root Thread 2 (depth 0, explicit second topic)
```

### Hierarchy Rules

| Rule | Value |
|------|-------|
| Root thread | Created automatically when session starts; cannot be archived |
| Child threads | Spawned from any active thread via split or explicit creation |
| Depth limit | Default: 5 levels deep (root = 0, max depth = 4) |
| Depth enforcement | `createThread` and `splitThread` reject if parent depth >= 4 |
| Active thread limit | Default: 20 active+paused threads per session |
| Limit enforcement | New thread creation rejected if limit reached; must archive first |

### Root Thread

Every session has exactly one root thread that is created when the session begins. The root thread:
- Has `parent_thread_id = null` and `depth = 0`
- Cannot be archived unless the entire session ends
- Serves as the default thread for all turns not assigned to a specific thread
- Is always present in the `ThreadTree.root_threads` array

## Thread Operations

### Create Thread

```typescript
createThread(session_id, topic, parent_thread_id?): ConversationThread
```

Creates a new thread with status `active`. If `parent_thread_id` is provided, the new thread becomes a child of that thread (depth = parent.depth + 1). If omitted, the new thread becomes a root thread.

Triggered by:
- Automatic topic detection during a turn
- User explicitly says "let's start a new thread about X"
- Sou suggests and user accepts

```typescript
// Example
thread = createThread("session_123", "Database Schema Design", "thread_root")
// Result: thread.depth = 1, thread.parent_thread_id = "thread_root"
//         thread_root.child_thread_ids includes new thread_id
```

### Switch Thread

```typescript
switchThread(session_id, thread_id, reason?): void
```

Pauses the currently active thread (sets status to `paused`) and sets the target thread to `active`. Records a `ThreadSwitch` event.

- Current active thread is paused
- Target thread context is loaded into the Context System window
- Target thread's `last_activity` is updated
- If the target thread was archived, it is reactivated (status â†’ active)

```typescript
// Example: User says "let's go back to the database topic"
switchThread("session_123", "thread_db_design", "user_initiated")
```

### Split Thread

```typescript
splitThread(session_id, thread_id, sub_topic): ConversationThread
```

Creates a child thread under the specified parent. The parent thread is paused; the new child thread becomes active. This represents a topic divergence where a sub-topic emerges within the current discussion.

- Validates parent thread is active
- Creates child with `parent_thread_id = thread_id`
- Parent status â†’ `paused`
- Child status â†’ `active`
- `child_thread_ids` updated on parent

### Merge Thread

```typescript
mergeThread(child_thread_id, parent_thread_id?): void
```

Resolves a child thread back into its parent. The child thread's accumulated context (key facts, decisions, unresolved questions) is merged into the parent's `ThreadContext`. The child thread status â†’ `merged`, and the parent thread becomes active.

- If `parent_thread_id` is omitted, the child's `parent_thread_id` is used
- Child's `key_facts` are appended to parent's `key_facts`
- Child's `decisions` are appended to parent's `decisions`
- Child's `unresolved_questions` not merged (remain unresolved in child)
- Child's `state_summary` is appended to parent's `state_summary`
- A `ThreadSwitch` is recorded for the auto-return to parent
- After merge, a new `ThreadContext` summary is generated for the parent

### Archive Thread

```typescript
archiveThread(thread_id): void
```

Marks a thread as archived. The thread's context is persisted to Memory OS (Episodic Memory) but is no longer active in the Context System window. Archived threads can be reactivated by switching to them.

- Thread status â†’ `archived`
- Thread's `ThreadContext` is serialized and stored in Episodic Memory with tag `conversation_thread_archived`
- If the archived thread was active, the parent or root thread becomes active
- Cannot archive the root thread

### Close Thread

```typescript
closeThread(thread_id): void
```

Explicitly ends a thread. Unlike archive, close finalizes the thread â€” it cannot be reactivated. The thread's final context is persisted to Episodic Memory, then the thread is removed from the active hierarchy.

- Thread status â†’ `closed` (terminal state, not in active hierarchy)
- Thread context is persisted to Episodic Memory with tag `conversation_thread_closed`
- Thread is removed from `ThreadTree.hierarchy`
- Remaining turns reference the closed thread_id but it's no longer listed in the thread tree
- Cannot close the root thread

## Thread Detection

### Automatic Topic-Based Detection

Context Threading monitors incoming user turns for topic shifts. Detection uses:

| Signal | Indicator | Weight |
|--------|-----------|--------|
| Lexical shift | Pronoun/noun distribution changes significantly from recent turns | 0.4 |
| Explicit topic mention | User names a new subject not present in current thread context | 0.3 |
| Question framing | "What about X?", "How does Y work?" with no prior Y in thread | 0.2 |
| Contrast markers | "On the other hand...", "Separately...", "Actually..." | 0.1 |

Detection produces a `ThreadDetection` result:

```typescript
ThreadDetection {
  detected: boolean
  confidence: number                     // 0.0â€“1.0
  detected_topic: string                 // Best guess topic label
  suggested_action: "create_new_thread"
                   | "switch_to_existing"
                   | "split_current"
                   | "none"
  matched_thread_id?: string             // If switching to an existing thread
  reason: string                         // Human-readable explanation
}
```

Detection runs after every user turn. If confidence >= 0.7, the detected action is proposed. If confidence >= 0.9, the action is executed automatically (with a user notification).

### Explicit Thread Creation

User can explicitly create threads:

| User Phrase | Action |
|-------------|--------|
| "Let's start a new thread about X" | Create thread with topic X |
| "New topic: X" | Create root thread with topic X |
| "Let's make a sub-topic for X" | Split current thread into child with topic X |
| "Save this for later as X" | Create thread with topic X, archive immediately |

### Thread Switch Detection

Context Threading detects when the user refers to a previous topic:

| User Phrase | Detection | Action |
|-------------|-----------|--------|
| "Going back to what we were saying about X" | Thread with topic matching X found | Switch to that thread |
| "Earlier you mentioned X, tell me more" | Thread with topic matching X found | Switch to that thread |
| "Let's continue our discussion about X" | Thread with topic matching X found | Switch to that thread |
| No existing thread found for X | Topic is new | Suggest creating a new thread |

Matching uses fuzzy topic comparison: case-insensitive substring match on thread `topic` and `metadata.tags`. If multiple threads match, the most recently active one is selected.

### Thread Suggestion

Sou can suggest thread operations:

```typescript
ThreadSuggestion {
  thread_id?: string
  action: "create" | "switch" | "split" | "merge" | "archive"
  suggested_topic?: string
  reason: string
  confidence: number
}
```

Sou suggests thread operations when:
- A topic shift is detected but confidence is moderate (0.5â€“0.7): "Should we create a new thread for this?"
- A sub-topic is developing depth: "This seems like a separate topic â€” should we split it off?"
- A thread has been paused for a long time: "We have an open thread about X â€” would you like to revisit it?"
- A child thread's topic seems resolved: "It looks like we resolved the sub-topic. Should I merge it back?"

The suggestion is presented to the user. If the user accepts, the operation is executed. If the user declines or ignores, the current thread continues.

## Thread Context

### Per-Thread Context Accumulation

Each thread maintains its own `ThreadContext` that accumulates over the thread's lifetime:

| Context Element | Accumulation Strategy | Max |
|-----------------|----------------------|-----|
| Key facts | Extracted from user and Sou turns in this thread | 50 |
| Decisions | Captured when Sou makes a definitive choice | 20 |
| Unresolved questions | Questions unanswered for more than 2 turns | 20 |
| Pending items | Tasks or action items identified in the thread | 10 |
| State summary | Compressed summary regenerated every 5 turns | 500 tokens |

### Context Load on Switch

When `switchThread` is called, the target thread's `ThreadContext` is loaded into the Context System window:

```
switchThread("session_123", "thread_X")
  â”œâ”€â”€ Read thread_X's ThreadContext
  â”œâ”€â”€ Compress to fit context window budget
  â”œâ”€â”€ Inject context preamble:
  â”‚     "You are returning to thread 'X'. Context:
  â”‚      - Key facts: [...]
  â”‚      - Decisions made: [...]
  â”‚      - Unresolved questions: [...]
  â”‚      - Last turn: <last user message in thread>"
  â”œâ”€â”€ Set thread_X as active in ThreadTree
  â””â”€â”€ Emit CONV.ThreadSwitched
```

### Thread Context Feeding

Thread context feeds into the Context System window according to the following rules:

| Condition | Context Included |
|-----------|-----------------|
| Active thread | Full thread context (up to thread's token budget) |
| Paused thread | Only thread summary and last 3 key facts |
| Recently active paused thread (< 5 switches ago) | Thread summary only |
| Archived thread | Not included (stored in Episodic Memory) |
| Merged thread | Context already absorbed into parent; not independently included |

### Context Updates

Thread context is updated:
- After every turn in that thread â€” new key facts extracted, decisions captured
- On `mergeThread` â€” child context merged into parent
- On `archiveThread` â€” final summary generated before archival
- On explicit `updateThreadContext(thread_id, updates)` â€” Sou can manually amend

## Thread Lifecycle

```
Session Start
    â”‚
    â–¼
Root Thread Created (depth=0, status=active)
    â”‚
    â–¼
Active Thread â†â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
    â”‚                                                       â”‚
    â”œâ”€â”€ Turn processed â†’ context updated                    â”‚
    â”‚                                                       â”‚
    â”œâ”€â”€ Topic detected (confidence >= 0.9)                  â”‚
    â”‚     â””â”€â”€ Auto-create child thread                      â”‚
    â”‚           Child status = active                       â”‚
    â”‚           Parent status = paused                      â”‚
    â”‚           â””â”€â”€ Child resolved?                         â”‚
    â”‚                 â”œâ”€â”€ Yes â†’ mergeThread()               â”‚
    â”‚                 â”‚        Child status = merged        â”‚
    â”‚                 â”‚        Parent status = active â”€â”€â”€â”€â”€â”€â”¤
    â”‚                 â””â”€â”€ No â†’ stays active                 â”‚
    â”‚                                                       â”‚
    â”œâ”€â”€ User says "switch to X"                             â”‚
    â”‚     â””â”€â”€ switchThread()                                â”‚
    â”‚           Current status = paused                     â”‚
    â”‚           Target status = active                      â”‚
    â”‚           â””â”€â”€ Target context loaded â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
    â”‚                                                       â”‚
    â”œâ”€â”€ User says "start new thread about Y"                â”‚
    â”‚     â””â”€â”€ createThread()                                â”‚
    â”‚           New thread status = active                  â”‚
    â”‚           Current thread status = active              â”‚
    â”‚           (User can switch between them)              â”‚
    â”‚                                                       â”‚
    â”œâ”€â”€ User or Sou archives thread                         â”‚
    â”‚     â””â”€â”€ archiveThread()                               â”‚
    â”‚           Thread status = archived                    â”‚
    â”‚           Context stored to Episodic Memory           â”‚
    â”‚           Parent or root becomes active â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
    â”‚                                                       â”‚
    â”œâ”€â”€ User or Sou closes thread                           â”‚
    â”‚     â””â”€â”€ closeThread()                                 â”‚
    â”‚           Thread status = closed (terminal)           â”‚
    â”‚           Context stored to Episodic Memory           â”‚
    â”‚           Thread removed from active hierarchy        â”‚
    â”‚                                                       â”‚
    â””â”€â”€ Session ends                                        â”‚
          â””â”€â”€ All non-archived threads archived             â”‚
                All thread contexts stored to               â”‚
                Episodic Memory                             â”‚
                â””â”€â”€ ThreadTree destroyed                    â”‚
```

### State Transitions

```
Thread Created â”€â”€â–º Active
                      â”‚
                      â”œâ”€â”€ (topic continues) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º stays Active
                      â”‚
                      â”œâ”€â”€ (user switches away) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Paused
                      â”‚       â”‚
                      â”‚       â””â”€â”€ (user switches back) â”€â”€â”€â”€â”€â–º Active
                      â”‚
                      â”œâ”€â”€ (sub-topic emerges) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Split
                      â”‚       â”‚
                      â”‚       â””â”€â”€ child thread created â”€â”€â”€â”€â”€â–º Active (child)
                      â”‚                                      Parent: Paused
                      â”‚
                      â”œâ”€â”€ (topic resolved) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Archived
                      â”‚       â”‚
                      â”‚       â””â”€â”€ (user switches back) â”€â”€â”€â”€â”€â–º Active (reactivated)
                      â”‚
                      â””â”€â”€ (explicit end) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Closed (terminal)

Child Thread: Active
    â”‚
    â”œâ”€â”€ (sub-topic resolved) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Merged
    â”‚       â”‚
    â”‚       â””â”€â”€ context merged to parent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Parent: Active
    â”‚
    â””â”€â”€ (closed explicitly) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º Closed (terminal)
```

## Internal Interfaces

```typescript
interface ThreadManager {
  // Lifecycle
  createThread(session_id: string, topic: string, parent_thread_id?: string): ConversationThread
  closeThread(thread_id: string): void

  // Retrieval
  getThread(thread_id: string): ConversationThread | null
  getThreadsBySession(session_id: string): ConversationThread[]
  getActiveThread(session_id: string): ConversationThread | null
  getThreadTree(session_id: string): ThreadTree | null

  // Navigation
  switchThread(session_id: string, thread_id: string, reason?: ThreadSwitchReason): void
  splitThread(session_id: string, thread_id: string, sub_topic: string): ConversationThread
  mergeThread(child_thread_id: string, parent_thread_id?: string): void
  archiveThread(thread_id: string): void

  // Context
  getThreadContext(thread_id: string): ThreadContext | null
  updateThreadContext(thread_id: string, updates: Partial<ThreadContext>): void
  mergeContexts(source_thread_id: string, target_thread_id: string): void

  // Detection
  detectThreadSwitch(session_id: string, turn_content: string): ThreadDetection | null
  suggestThreadAction(session_id: string, turn_content: string): ThreadSuggestion | null

  // Hierarchy
  getThreadDepth(thread_id: string): number
  getThreadPath(thread_id: string): string[]          // Root-to-thread path of thread_ids
  getSiblingThreads(thread_id: string): ConversationThread[]
  getDescendantThreads(thread_id: string): ConversationThread[]
  getAncestorThreads(thread_id: string): ConversationThread[]

  // Validation
  validateThreadLimit(session_id: string): boolean     // Returns false if limit reached
  validateDepthLimit(thread_id: string): boolean       // Returns false if depth limit reached
}

interface ThreadDetection {
  detected: boolean
  confidence: number
  detected_topic: string
  suggested_action: "create_new_thread" | "switch_to_existing" | "split_current" | "none"
  matched_thread_id?: string
  reason: string
}

interface ThreadSuggestion {
  thread_id?: string
  action: "create" | "switch" | "split" | "merge" | "archive"
  suggested_topic?: string
  reason: string
  confidence: number
}

type ThreadSwitchReason = "user_initiated" | "sou_suggested" | "topic_detected" | "auto_return"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CONV.ThreadCreated |     thread_id, session_id, parent_thread_id, topic, depth | New conversation thread created |
| CONV.ThreadSwitched |     from_thread_id, to_thread_id, session_id, reason | Active thread changed |
| CONV.ThreadSplit |     parent_thread_id, child_thread_id, session_id, sub_topic | Thread split into parent + child |
| CONV.ThreadMerged |     child_thread_id, parent_thread_id, session_id, facts_merged | Child thread merged back to parent |
| CONV.ThreadArchived |     thread_id, session_id, turn_count, final_summary | Thread archived with final summary |
| CONV.ThreadClosed |     thread_id, session_id, turn_count, duration_ms | Thread permanently closed |
| CONV.ThreadContextUpdated |     thread_id, session_id, new_fact_count, new_decision_count | Thread context accumulated new items |
| CONV.ThreadSuggested |     session_id, action, suggested_topic, confidence | Sou suggested a thread operation |
| CONV.ThreadDepthWarning |     session_id, thread_id, current_depth, max_depth | Thread depth limit approached or reached |
| CONV.ThreadAutoDetected |     session_id, detected_topic, confidence, action | Topic shift auto-detected from turn content |
| CONV.ThreadLimitReached |     session_id, active_count, max_threads | Session thread limit reached |
| CONV.ThreadTreeUpdated |     session_id, active_thread_id, total_threads | Thread hierarchy structure changed |
| CONV.ThreadSearchCompleted |     thread_id, session_id, match_type, matched_terms | Thread found during switch detection |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CTXTH-001 | Every thread belongs to exactly one session | Schema â€” `session_id` is required |
| CTXTH-002 | Every session has exactly one root thread | Algorithmic â€” root created on session init; cannot be deleted |
| CTXTH-003 | At most one thread is `active` per session at any time | Algorithmic â€” `switchThread` enforces single active thread |
| CTXTH-004 | A thread's depth never exceeds the configured maximum (default 5) | Algorithmic â€” `createThread`/`splitThread` validate depth limit |
| CTXTH-005 | A merged thread's context is absorbed into its parent and the child becomes read-only | Algorithmic â€” `mergeThread` transfers context; merged threads reject writes |
| CTXTH-006 | Thread status transitions follow the defined lifecycle (no illegal transitions) | Algorithmic â€” status machine enforces valid transitions (e.g., archived â†’ active allowed; closed â†’ active denied) |
| CTXTH-007 | Total active+paused threads per session never exceeds the configured limit (default 20) | Algorithmic â€” `validateThreadLimit` checked before creation |
| CTXTH-008 | Thread context is never lost â€” on session end, all non-closed threads are archived to Episodic Memory | Algorithmic â€” session teardown archives all remaining threads |
| CTXTH-009 | A thread can only be active if all its ancestors are active or paused (no orphaned active threads) | Algorithmic â€” if ancestor is archived/closed, descendant must be archived/closed first |
| CTXTH-010 | Thread topic matching for switch detection is deterministic (same input produces same match) | Algorithmic â€” fuzzy matching uses stable string comparison |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown thread_id | `CTXTH_THREAD_NOT_FOUND` | Return null; no error |
| Unknown session_id | `CTXTH_SESSION_NOT_FOUND` | Return error; session must exist |
| Thread depth limit exceeded | `CTXTH_DEPTH_LIMIT` | Return error; suggest merging or using sibling thread |
| Session thread limit reached | `CTXTH_THREAD_LIMIT` | Return error; suggest archiving inactive threads |
| Attempt to merge non-child thread | `CTXTH_MERGE_INVALID` | Return error; target thread must be a direct child |
| Attempt to switch to closed thread | `CTXTH_THREAD_CLOSED` | Return error; closed threads cannot be reactivated |
| Attempt to archive root thread | `CTXTH_CANNOT_ARCHIVE_ROOT` | Return error; root thread is permanent for session lifetime |
| Attempt to split archived/closed thread | `CTXTH_THREAD_NOT_ACTIVE` | Return error; only active threads can be split |
| Thread context too large for Context System budget | `CTXTH_CONTEXT_OVERFLOW` | Compress context summary; emit warning; trim low-priority facts |
| Circular parent-child relationship detected | `CTXTH_CIRCULAR_HIERARCHY` | Return error; parent_thread_id creates a cycle |

## Usage Patterns

### Pattern 1: Topic Branching

User starts with one topic, explores a tangent as a sub-thread, then returns:

```
Turn 1 â€” User: "I'm designing a database for my app"
         Sou & User discuss database schema in Root Thread
         Root thread context accumulates: table designs, relationships

Turn 5 â€” User: "What about authentication? Should I use JWT or sessions?"
         Detection: topic shift to "authentication" (confidence 0.85)
         Sou: "That's a separate concern. Should we create a sub-thread for auth?"
         User: "Sure"
         â†’ splitThread(root, "Authentication") â†’ child thread "auth" created
         Root thread paused, Auth thread active

Turn 6-10 â€” User & Sou discuss authentication in Auth thread
            Auth thread context accumulates: JWT chosen, session strategy defined

Turn 11 â€” User: "Alright, let's go back to the database design"
          â†’ switchThread("session_123", "root_thread", "user_initiated")
          Root thread context loaded, Auth thread paused
          User continues from where they left off on database design

Turn 15 â€” Sou: "We resolved the auth question. Should I merge it back?"
          User: "Yes"
          â†’ mergeThread(auth_thread, root_thread)
          Auth context merged into root thread context
          Root thread now includes: table designs + auth strategy
```

### Pattern 2: Thread Switching During Long Session

User maintains multiple parallel threads over an extended session:

```
Session Start â€” Root Thread "General Chat" created (active)

Thread A â€” "Project Planning" (created, active)
  User discusses project roadmap, milestones

Thread B â€” "Budget Review" (created, active)
  User asks about budget constraints, costs

Thread C â€” "Technical Architecture" (created, active)
  User explores architecture options

Throughout session, user switches between threads:
  "Let's look at the budget numbers" â†’ switch to Thread B
    Thread B context loaded: previous budget numbers visible
  "Now back to architecture" â†’ switch to Thread C
    Thread C context loaded: previous architecture discussion visible
  "Before I forget, about the project timeline..." â†’ switch to Thread A
    Thread A context loaded: previous milestones discussed visible

At any point, each thread's context is independently preserved.
The Context System window contains:
  - Active thread's full context
  - Paused threads' summaries (recently active ones)
```

### Pattern 3: Auto-Detection with User Confirmation

Context Threading detects topic shifts and asks for confirmation:

```
Turn 1 â€” User: "I need help debugging my Python code"
         Root thread topic: "Python Debugging"
         
Turn 2-4 â€” User & Sou debug Python issue
           Root thread context: error trace, attempted fixes

Turn 5 â€” User: "Also, can you recommend a good IDE for Python?"
         Detection: lexical shift, contrast marker "Also"
         Confidence: 0.72 (moderate)
         Sou: "That's a different topic. Should we create a new thread for IDE recommendations?"
         User: "Good idea"
         â†’ createThread("session_123", "IDE Recommendations")
         User continues discussing IDEs in new thread

Turn 6 â€” User: "I also need to set up my environment"
         Detection: topic shift within IDE thread
         Confidence: 0.65 (below auto-threshold)
         Sou: "This sounds like a sub-topic about environment setup. Should I split it off?"
         User: "No, let's keep it here"
         â†’ Thread continues without split
```

### Pattern 4: Merge and Summarize

Resolving sub-threads and generating comprehensive summaries:

```
Thread A â€” "API Design" (active)
  User designs REST API endpoints

Thread A1 â€” "Authentication Middleware" (child of A, split off)
  User explores auth middleware options
  Decision: Use OAuth2 with JWT
  Key fact: Must support refresh tokens

Thread A1 resolved â†’ mergeThread(A1, A)
  A1 context merged into A:
    - A.key_facts now includes "OAuth2 with JWT chosen"
    - A.decisions now includes "Must support refresh tokens"
    - A.state_summary regenerated: "API Design (merged auth middleware):
      REST endpoints designed, OAuth2 with JWT chosen, refresh tokens supported"

User can now see a comprehensive summary of the merged thread.
```


## Cross-Cutting Concerns

### Security

Conversation OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Conversation OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Conversation OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Conversation OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Context Threading manages one thing: hierarchical conversation thread organization |
| R2 â€” Dependency Order | Depends on Conversation OS (Session, Turn), Context System, Memory OS; no upward deps |
| R3 â€” DRY | Thread model defined once; ThreadContext stores state per thread, not duplicated |
| R4 â€” Builder Pattern | ThreadTree built from createThread â†’ split â†’ merge operations |
| R5 â€” Liskov Substitution | Any ThreadManager implements the same interface; detection strategies interchangeable |
| R6 â€” DI over Singletons | Topic detection strategy, depth limits, thread limits injected via config |
| R9 â€” Deterministic | Same topic input produces same thread detection result |
| R10 â€” Simpler Over Complex | Tree hierarchy with depth limit prevents unbounded complexity |
| R13 â€” Design for Failure | Thread limit enforcement prevents session blowup; context overflow compresses gracefully |
| R14 â€” Paved Path | All thread operations flow through ThreadManager interface |
| R15 â€” Open/Closed | New detection strategies added via ThreadDetection interface, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Conversation/000-Overview.md | Context Threading is a Conversation OS sub-component |
| Conversation/004-Session-Management.md | Threads are scoped to sessions; session lifecycle triggers thread lifecycle |
| Conversation/002-Multi-Turn.md | Turns are assigned to threads; turn processing updates thread context |
| Brain/Context/000-Overview.md | Thread context is injected into the Context System window |
| Brain/Context/001-Window-Management.md | Thread context feeds into the context window via priority-based allocation |
| Brain/Memory/002-Episodic-Memory.md | Archived/closed thread contexts persisted to Episodic Memory |
| Brain/Memory/001-Working-Memory.md | Active thread context lives in Working Memory |
| Brain/Sou/000-Overview.md | Sou reads/writes thread context and receives thread suggestions |
| Bible/05-Platform/004-EVS.md | Events emitted throughout thread lifecycle |

(End of file - total 469 lines)
