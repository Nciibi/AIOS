# AIOS Bible — Brain
## 002 — Multi-Turn

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Conversation |
| Document ID | AIOS-BBL-002-CONV-002 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Multi-Turn management handles the sequential flow of conversation turns — ensuring turns are processed in order, managing turn pairing (user message -> Sou response), enforcing turn timeouts, maintaining a sliding window of turn history, deduplicating identical inputs, and orchestrating concurrent input handling. It is the component within Conversation OS that guarantees every user message receives exactly one response (CONV-001) and that turns proceed in strict sequential order (CONV-002).

## Data Model

### TurnRecord

```typescript
TurnRecord {
  turn_id: string                     // Unique turn identifier (UUID v7)
  session_id: string                  // Owning session
  turn_number: number                 // Monotonically increasing per session
  role: "user" | "sou" | "system"
  content: string                     // Normalized text content
  modality: "text" | "voice" | "api" | "multimodal"
  timestamp: timestamp                // When the turn was received/created
  response_to?: string                // turn_id this is responding to
  status: "received" | "parsed" | "routing" | "processing" | "built" | "delivered" | "failed"
  processing_stages: {
    received_at: timestamp
    parsed_at?: timestamp
    routed_at?: timestamp
    processing_started_at?: timestamp
    processing_completed_at?: timestamp
    built_at?: timestamp
    delivered_at?: timestamp
    failed_at?: timestamp
  }
  metadata: {
    content_hash: string              // SHA-256 of normalized content
    idempotency_key?: string          // For deduplication
    intent?: string
    confidence?: number
    token_count?: number
    error?: string
    retry_count: number
    queue_wait_ms?: number
  }
}
```

### TurnPair

```typescript
TurnPair {
  pair_id: string                     // Unique pair identifier
  user_turn_id: string                // TurnRecord turn_id (role: user)
  sou_turn_id?: string                // TurnRecord turn_id (role: sou)
  started_at: timestamp               // When user turn was received
  completed_at?: timestamp            // When Sou response was delivered
  duration_ms?: number                // completed_at - started_at
  status: "pending" | "active" | "completed" | "failed"
  failure_reason?: string
}
```

### TurnHistory

```typescript
TurnHistory {
  session_id: string
  pairs: TurnPair[]
  sliding_window_size: number         // Default: 50
  current_turn_number: number
  total_pairs: number
  overflow_archived_to: string        // Episodic Memory key for overflow pairs
}
```

### TurnTimeout

```typescript
TurnTimeoutConfig {
  stage_timeouts: {
    receive: { timeout_ms: 100, action: "skip" }
    parse: { timeout_ms: 500, action: "skip" }
    route: { timeout_ms: 100, action: "skip" }
    process: { timeout_ms: 30000, action: "notify" }
    build: { timeout_ms: 5000, action: "force_deliver" }
    deliver: { timeout_ms: 10000, action: "retry" }
  }
  default_action: "notify"            // Fallback action
  notify_message: string              // "Sou is taking longer than expected..."
  max_retries: number                 // Per stage, default: 1
}

TimedOutTurn {
  turn_id: string
  session_id: string
  stage: string
  elapsed_ms: number
  action: "notify" | "retry" | "skip" | "force_deliver" | "interrupt"
  handled_at?: timestamp
}
```

## Turn Lifecycle

```
Receive → Parse → Route → Process → Build → Deliver
```

Each stage has strict timing requirements and validation:

| Stage | Max Duration | Validation | Failure Behavior |
|-------|-------------|------------|------------------|
| Receive | 100ms | Content non-empty, valid session, no duplicate | Reject with CONV_INVALID_INPUT |
| Parse | 500ms | Extract intent, entities, content hash | Skip parse, use raw content |
| Route | 100ms | ACF delivery acknowledgment | Retry once, then fail |
| Process | 30000ms | Sou produces valid response | Notify user, offer options |
| Build | 5000ms | Response packaged for modality | Force deliver partial response |
| Deliver | 10000ms | Delivery acknowledgment from channel | Retry once, then log failure |

### Stage Transitions

```
receive ──► parse ──► route ──► process ──► build ──► deliver
  │            │         │           │          │           │
  └── fail ────┴── fail ─┴── fail ──┴── fail ──┴── fail ──┴── fail
```

Transitions only move forward. A failed turn at any stage transitions to `failed` status and cannot resume.

## Turn Sequencing

### Strict Sequential Ordering

Turn N completes (reaches `delivered` or `failed`) before turn N+1 begins processing. Sequencing is enforced by:

```typescript
// Pseudo-enforcement rule
if (session.current_pending_turn !== null) {
  queue.enqueue(newTurn, priority)
} else {
  session.current_pending_turn = newTurn
  processTurn(newTurn)
}
```

### Turn Queue

When a user sends input while Sou is processing a previous turn, the input is enqueued:

| Queue Position | Priority Level | Description |
|---------------|---------------|-------------|
| 1 (Highest) | System message | Sou-injected system messages |
| 2 | User retry | Re-sent input after user timeout |
| 3 | New user input | Fresh user message |
| 4 (Lowest) | Sou inject | Sou-initiated interjections |

### Queue Depth

- Default depth: 5 queued turns
- When queue is full: oldest non-system entry is dropped with `CONV_QUEUE_FULL` warning
- System messages are never dropped from queue
- Each queued entry stores `enqueued_at` timestamp for wait-time metrics

## Turn Pairing

### Pairing Rule (CONV-001)

Every user turn must have exactly one Sou response. TurnPair enforces this:

```typescript
function pairResponse(userTurnId: string, souResponse: TurnRecord): TurnPair {
  const pair = new TurnPair({
    user_turn_id: userTurnId,
    sou_turn_id: souResponse.turn_id,
    started_at: getUserTurn(userTurnId).timestamp,
    status: "active"
  })
  return pairStore.save(pair)
}
```

### Orphan Detection

Orphan detection runs on a 5-second heartbeat:

| Condition | Duration Threshold | Action |
|-----------|-------------------|--------|
| User turn received, no pair created | 500ms after receive | Log warning, create pair in pending |
| Pair active > process timeout | 30s after active | Emit CONV.TurnTimeout, notify user |
| Pair active > 2x process timeout | 60s after active | Interrupt Sou, fail pair |

### Response Deduplication

A content hash comparison prevents the same Sou response from being delivered twice:

- On Build stage, compute SHA-256 of response content
- Compare against `last_delivered_hash` on the session
- If match: emit CONV.ResponseDuplicateSuppressed, skip delivery
- Hash cleared when new user turn begins

## Turn Timeout

| Stage | Default Timeout | Action | Details |
|-------|----------------|--------|---------|
| Receive | 100ms | Skip | Drop malformed input silently |
| Parse | 500ms | Skip | Use raw content, bypass parsing |
| Route | 100ms | Retry | Retry ACF delivery once |
| Process (Sou) | 30s | Notify | Emit CONV.TurnTimeout, tell user "Sou is taking longer than expected..." |
| Build | 5s | Force deliver | Deliver what is available, mark partial |
| Deliver | 10s | Retry | Retry delivery once, then log failure |

### Timeout Protocol

1. Stage timer starts when stage enters
2. Timer fires → emit `CONV.TurnTimeout` with stage, elapsed_ms, action
3. Action executed per table above
4. For Process timeout with "notify" action:
   - User notification: "Sou is taking longer than expected..."
   - Options offered: wait / retry / skip
   - If user chooses interrupt: send interrupt signal to Sou via ACF
   - Sou interrupt flow:
     ```
     CONV.TurnTimeout → user notified → user interrupts
       → send ACF.Interrupt(turn_id)
       → Sou halts processing
       → Turn marked failed
       → Queue advanced to next turn
     ```

## Turn History

### Sliding Window

The last N turn pairs are kept in-memory for rapid access:

| Property | Default | Configurable |
|----------|---------|-------------|
| Window size | 50 pairs | Per-session via configuration |
| Retention policy | FIFO eviction | Oldest pairs moved to Episodic Memory |
| Access method | getTurnHistory(session_id, limit?) | |

### Persistence

When pairs exceed the sliding window:

1. Overflow pairs are serialized to Episodic Memory via Memory OS
2. Episodic Memory key format: `conv:history:{session_id}:{start_turn}-{end_turn}`
3. On session resume, last N pairs are reloaded from Episodic Memory
4. Total history is unbounded (limited only by Episodic Memory capacity)

### Turn Replay

Turns can be replayed to restore context:

```typescript
function replayTurns(session_id: string, from_turn: number, count: number): TurnRecord[]
```

- Fetches turns from Episodic Memory if not in sliding window
- Returns ordered array of TurnRecords for context restoration
- Used when Sou needs to reconstruct conversation state after restart
- Events emitted per replayed turn: `CONV.TurnReplayed`

## Turn Deduplication

### Content Hash

Each incoming user turn gets a SHA-256 content hash (normalized: trimmed, lowercased):

```typescript
function computeContentHash(content: string): string {
  const normalized = content.trim().toLowerCase()
  return crypto.createHash("sha256").update(normalized).digest("hex")
}
```

### Idempotency Key

- Client may provide `idempotency_key` in the message header
- If not provided, server generates one from `session_id + turn_number + content_hash`
- Key stored on the TurnRecord metadata
- TTL of idempotency key: 5 minutes after turn completion

### Duplicate Detection Flow

```
Receive stage:
  1. Compute content_hash from input
  2. Look up hash in session's recent hashes (last 10 turns)
  3. If idempotency_key provided, check that first
  4. If duplicate found:
     a. Return existing turn_id
     b. Emit CONV.DuplicateSuppressed
     c. Skip processing — do not re-enter lifecycle
```

### Duplicate Behavior

| Scenario | Detection Method | Action |
|----------|-----------------|--------|
| Same content, same session | content_hash match | Return existing turn_id, skip |
| Same idempotency_key, same session | idempotency_key match | Return existing turn_id, skip |
| Same content, different session | Not a duplicate | Process normally |
| Same content, different turn_number | turn_number mismatch | Process normally (past window) |

## Concurrent Input Handling

### User Sends While Sou is Processing

```
User sends message M1
  → M1 enters Receive stage
  → M1 advances to Process stage → Sou starts processing
  
User sends message M2 while Sou processes M1
  → M2 enters Receive stage
  → Turn Manager detects current_pending_turn !== null
  → M2 is enqueued with priority "new user input"
  → User notified: "Message received, waiting for current response..."
  → Emit CONV.TurnQueued { turn_id: M2.turn_id, position: 1 }
  
Sou finishes processing M1
  → M1 advances Build → Deliver
  → Turn Manager dequeues M2
  → M2 begins lifecycle at Receive stage
```

### Queue Management

```typescript
function processQueue(session_id: string): void {
  const queue = sessionQueues.get(session_id)
  if (!queue || queue.isEmpty()) return

  const nextTurn = queue.dequeue()  // Priority-ordered dequeue
  session.current_pending_turn = nextTurn
  processTurn(nextTurn)
}
```

### "User is Typing" Indicator

User-typing indicators (e.g., WebSocket `typing` frames) do not create turns:

1. `typing` signal received → update `session.last_typing_at` timestamp
2. No turn record created
3. If typing persists > 5s without message: emit `CONV.TypingExpired` (no further action)
4. If message arrives: clear typing timer, proceed with normal receive

### Queue Flush

On session end, all queued turns are:

1. Marked as failed with reason `session_ended`
2. Emit `CONV.TurnQueueFlushed` with count of dropped turns
3. Memory is freed

## Internal Interface

```typescript
interface TurnManager {
  // Lifecycle
  startTurn(session_id: string, content: string, modality: string, options?: {
    idempotency_key?: string
    role?: "user" | "system"
  }): TurnRecord

  completeTurn(turn_id: string): void
  failTurn(turn_id: string, reason: string): void

  // Query
  getTurn(turn_id: string): TurnRecord | null
  getTurnPair(pair_id: string): TurnPair | null
  getTurnHistory(session_id: string, limit?: number): TurnPair[]

  // Pairing
  pairResponse(user_turn_id: string, sou_response: TurnRecord): TurnPair
  getOrphanedTurns(session_id: string): TurnRecord[]

  // Queue
  enqueueTurn(session_id: string, turn: TurnRecord): QueueResult
  processQueue(session_id: string): void
  flushQueue(session_id: string): void
  getQueueDepth(session_id: string): number

  // Timeouts
  checkTimeouts(session_id: string): TimedOutTurn[]
  interruptSou(session_id: string, turn_id: string): void

  // Deduplication
  computeHash(content: string): string
  isDuplicate(content_hash: string, session_id: string): boolean
  registerHash(session_id: string, turn_id: string, content_hash: string): void

  // History
  archivePairs(session_id: string, count: number): void
  replayTurns(session_id: string, from_turn: number, count: number): TurnRecord[]
}

type QueueResult = {
  position: number
  estimated_wait_ms: number
  queue_depth: number
  dropped?: {
    turn_id: string
    reason: string
  }
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `CONV.TurnStarted` | turn_id, session_id, turn_number, role, modality | A new turn enters the lifecycle |
| `CONV.TurnStageChanged` | turn_id, session_id, from_stage, to_stage, elapsed_ms | Turn advanced to next stage |
| `CONV.TurnCompleted` | turn_id, session_id, pair_id, duration_ms | Turn reached delivered status |
| `CONV.TurnFailed` | turn_id, session_id, stage, reason | Turn failed at a stage |
| `CONV.TurnQueued` | turn_id, session_id, position, queue_depth | Turn enqueued while another is active |
| `CONV.TurnTimeout` | turn_id, session_id, stage, elapsed_ms, action | Stage timer expired |
| `CONV.TurnPairCreated` | pair_id, user_turn_id, sou_turn_id | User-Sou turn pair established |
| `CONV.TurnPairCompleted` | pair_id, duration_ms | Turn pair fully completed |
| `CONV.DuplicateSuppressed` | turn_id, session_id, original_turn_id, match_type | Duplicate turn detected and suppressed |
| `CONV.TurnReplayed` | turn_id, session_id, turn_number | Historical turn replayed for context |
| `CONV.TurnQueueFlushed` | session_id, dropped_count, reason | Queue cleared on session end |
| `CONV.TypingExpired` | session_id, duration_ms | User typing indicator timed out without message |
| `CONV.TurnInterrupted` | turn_id, session_id, reason | Sou processing interrupted by user |
| `CONV.TurnOrphanDetected` | turn_id, session_id, elapsed_ms | User turn without paired response detected |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CONV-001 | Every user message has exactly one Sou response | Algorithmic — TurnPair enforces 1:1 mapping; orphan detection catches violations |
| CONV-002 | Turn ordering is strictly sequential (turn N completes before N+1 starts) | Architectural — current_pending_turn gate blocks concurrent lifecycle |
| CONV-007 | Turn stage transitions are monotonic (forward-only, never backwards) | Algorithmic — stage transition validation rejects reverse moves |
| CONV-008 | No turn is processed more than once (idempotency) | Algorithmic — deduplication via content_hash and idempotency_key |
| CONV-009 | The turn queue never exceeds max depth | Algorithmic — oldest non-system entry dropped when full |
| CONV-010 | Every TimedOutTurn has a corresponding action executed | Algorithmic — timeout handler executes action before returning |
| CONV-011 | Turn IDs are globally unique across all sessions | Schema — UUID v7 generation with collision detection |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Turn started on unknown session | `CONV_SESSION_NOT_FOUND` | Return error; caller must create session first |
| Duplicate turn detected at receive | `CONV_DUPLICATE_TURN` | Return existing turn_id, emit DuplicateSuppressed, skip lifecycle |
| Turn queue at max depth | `CONV_QUEUE_FULL` | Drop oldest non-system entry, enqueue new turn, emit warning |
| Stage transition violates order | `CONV_INVALID_TRANSITION` | Return error; stage cannot move backwards |
| Pairing user turn already paired | `CONV_TURN_ALREADY_PAIRED` | Return existing pair, do not create duplicate |
| Orphan turn exceeds max timeout | `CONV_ORPHAN_TIMEOUT` | Interrupt Sou, fail pair, notify user |
| Content hash collision with different content | `CONV_HASH_COLLISION` | Log warning, append salt and rehash |
| Queue entry dropped due to session end | `CONV_QUEUE_FLUSHED` | Fail all queued turns with session_ended reason |

## Usage Patterns

### Pattern 1: Normal Turn Flow

```
User sends: "What is the weather?"
  1. startTurn(session_id, "What is the weather?", "text")
     → TurnRecord created, status: received
  2. Parse stage completes → status: parsed
  3. Route stage → input delivered to Sou → status: routing
  4. Sou responds → status: processing → processing_completed_at set
  5. pairResponse(user_turn_id, sou_response)
     → TurnPair created, status: active
  6. Build stage → response formatted → status: built
  7. Deliver stage → response sent to user → status: delivered
  8. TurnPair completed → stats recorded
```

### Pattern 2: Timeout Recovery

```
User sends: "Analyze this 100-page document"
  → Turn enters Process stage
  → Sou starts processing
  → 30 seconds pass → Timeout fires
  
  1. CONV.TurnTimeout emitted
  2. User notified: "Sou is taking longer than expected..."
  3. User offered: wait / retry / skip
  4. User chooses "skip"
  5. interruptSou(session_id, turn_id) called
     → ACF.Interrupt signal sent to Sou
  6. failTurn(turn_id, "user_skipped_after_timeout")
  7. TurnPair marked failed
  8. processQueue(session_id) → next turn dequeued and started
```

### Pattern 3: Concurrent Input Queuing

```
User sends message A → starts processing
User sends message B while A is processing:
  1. B turn created, status: received
  2. enqueueTurn(session_id, B) → QueueResult { position: 1 }
  3. CONV.TurnQueued emitted
  4. User sees: "Message received, waiting for current response..."

System message injected during A's processing:
  1. Priority calculated: system > user input
  2. enqueueTurn(session_id, systemMsg) → QueueResult { position: 0 }
  3. System message jumps ahead of B in queue

A completes → processQueue dequeues system message first
  → system message processed and delivered
  → processQueue dequeues B
  → B begins lifecycle
```

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Turn Manager handles only turn lifecycle, sequencing, and pairing |
| R2 — Dependency Order | Depends on ACF (Sou) and Memory OS; no upward deps |
| R3 — DRY | Turn model defined once in Data Model; shared across all stages |
| R4 — Builder Pattern | Turn built through sequential stage transitions, each adding fidelity |
| R5 — Liskov Substitution | Any TurnManager implementation satisfies the interface |
| R6 — DI over Singletons | Timeout configs and queue strategies injected |
| R9 — Deterministic | Same input with same state produces same lifecycle outcome |
| R10 — Simpler Over Complex | Strict sequential ordering avoids concurrent state complexity |
| R13 — Design for Failure | Every stage has timeout; failed turns always notify user |
| R14 — Paved Path | All turns flow through startTurn → stages → complete/fail |
| R15 — Open/Closed | New stage behaviors added via stage handler config, not by modifying lifecycle core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Conversation/000-Overview.md | Multi-Turn is a sub-component of Conversation OS Turn Manager |
| Conversation/001-Session.md | Session Manager provides session context for turn processing |
| Brain/Context/000-Overview.md | Turn history is pushed to context window for Sou awareness |
| Brain/Memory/002-Episodic-Memory.md | Overflow turn pairs archived to Episodic Memory |
| Brain/Sou/000-Overview.md | Sou receives parsed turns and produces responses via ACF |
| Brain/Attention/000-Overview.md | Turn lifecycle emits events consumed by Attention System |
| Brain/Personality/000-Overview.md | Response Builder applies personality during Build stage |
| Bible/05-Platform/004-EVS.md | All lifecycle events routed through Event System |
