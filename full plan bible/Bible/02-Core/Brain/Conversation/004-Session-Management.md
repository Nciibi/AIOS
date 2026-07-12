# AIOS Bible â€” Brain
## 004 â€” Session Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Conversation |
| Document ID | AIOS-BBL-002-CON-004 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/004-Sessions.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Session Management owns the lifecycle of conversation sessions â€” creation, state transitions, timeout enforcement, persistence, restoration, and cleanup. It ensures every user interaction occurs within a valid session and that sessions are properly cleaned up on end or timeout.

Under CONV-004, sessions live in Memory OS with active state cached in Conversation OS. Under CONV-006, sessions auto-end after 24 hours.

## Data Model

### ConversationSession

```typescript
ConversationSession {
  session_id: string
  user_id: string
  modality: "text" | "voice" | "api" | "multimodal"
  status: SessionState
  started_at: timestamp
  last_activity: timestamp
  turn_count: number
  timeout_config: SessionConfig
  metadata: SessionMetadata
}
```

### SessionState

```typescript
SessionState = "active" | "idle" | "paused" | "ended"
```

### SessionConfig

```typescript
SessionConfig {
  idle_timeout_ms: number          // Default: 300000 (5 min)
  absolute_timeout_ms: number      // Default: 86400000 (24 hours)
  max_sessions_per_user: number    // Default: 10
  max_turns_per_session: number    // Default: 1000
}
```

### SessionMetadata

```typescript
SessionMetadata {
  user_preferences: UserPreferences
  device_info: {
    type: string                   // "desktop" | "mobile" | "tablet" | "voice_assistant"
    os: string
    browser?: string
    app_version?: string
    ip_address?: string
  }
  channel_info: {
    channel_id: string
    channel_type: string           // "web" | "mobile_app" | "cli" | "api" | "voice"
    integration?: string
  }
  session_tags: string[]
  custom_data: Record<string, unknown>
}
```

### SessionSummary

```typescript
SessionSummary {
  session_id: string
  turn_count: number
  duration: number                 // milliseconds
  topics_covered: string[]
  key_decisions: string[]
  outcome: "completed" | "timeout" | "abandoned" | "error"
}
```

### UserPreferences

```typescript
UserPreferences {
  formality: number                // 0.0â€“1.0
  verbosity: number                // 0.0â€“1.0
  preferred_modality: string
  timezone: string
  language: string
  accessibility: string[]          // e.g., "screen_reader", "high_contrast"
}
```

## Session Lifecycle

```
Create
   â”‚
   â–¼
 Active â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
   â”‚                             â”‚
   â”œâ”€â”€ idle timeout â”€â”€â–º Idle â”€â”€â”€â”€â”¤
   â”‚                  (input arrives)
   â”‚                             â”‚
   â”œâ”€â”€ user/Sou pause â”€â”€â–º Paused â”€â”€â–º Active
   â”‚                  (user/Sou resume)
   â”‚                             â”‚
   â””â”€â”€ user ends â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â–º Ended
       absolute timeout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â”‚
                                 â–¼
                              Archived
```

## Session State Transitions

| From | To | Condition |
|------|----|-----------|
| active | idle | No input received for `idle_timeout_ms` |
| active | paused | User calls `pauseSession()` or Sou calls `pauseSession()` |
| active | ended | User ends session, Sou ends session, or absolute timeout exceeded |
| idle | active | Input received (message, resume signal) |
| idle | ended | Absolute timeout exceeded |
| paused | active | User calls `resumeSession()` or Sou calls `resumeSession()` |
| paused | ended | Absolute timeout exceeded |
| ended | (none) | Terminal state â€” no transitions out |

### Transition Rules

- **active â†’ idle**: Session Manager timer fires after `idle_timeout_ms` of no `last_activity` update. Transition emits `CONV.SessionIdle`.
- **active â†’ paused**: Request from user or Sou. Reason is recorded in event. Turn count is frozen.
- **active â†’ ended**: User sends end signal, Sou triggers end, or `absolute_timeout_ms` fires. SessionSummary is generated before archival.
- **idle â†’ active**: Any user input re-activates the session. No loss of context. Turn count resumes.
- **idle â†’ ended**: Absolute timeout check on heartbeat or resume attempt. Cannot be resumed.
- **paused â†’ active**: Resume request from user or Sou. Session Manager validates session hasn't exceeded absolute timeout.
- **paused â†’ ended**: Absolute timeout check on heartbeat or resume attempt. Same as idle end.

## Timeout Management

### Idle Timeout

| Property | Value |
|----------|-------|
| Default duration | 300000 ms (5 minutes) |
| Configurable | Per-session via `timeout_config.idle_timeout_ms` |
| Effect | Session transitions to `idle` |
| Recovery | Input received â†’ back to `active` |
| Warning | Optional â€” emit `CONV.SessionTimeoutWarning` at 80% of timeout (240s) |

### Absolute Timeout

| Property | Value |
|----------|-------|
| Default duration | 86400000 ms (24 hours) |
| Configurable | Per-session via `timeout_config.absolute_timeout_ms` |
| Effect | Session transitions to `ended` |
| Recovery | Impossible â€” terminal state |
| Enforcement | Checked on resume and on periodic heartbeat |

### Timeout Warning Window

```
Timeout setup: idle_timeout_ms = 300000
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚                                                    â”‚
  â”‚  0ms          240000ms        300000ms              â”‚
  â”‚  â–²             â–²               â–²                    â”‚
  â”‚  â”‚             â”‚               â”‚                    â”‚
  â”‚  last_activity warning(80%)   idle transition       â”‚
  â”‚                                                    â”‚
  â”‚  Within warning window:                            â”‚
  â”‚  - Timer: CONV.SessionTimeoutWarning               â”‚
  â”‚  - Session Manager may notify user                 â”‚
  â”‚  - Warning is optional, enabled per-session         â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Timeout Decision Matrix

```
Input:
  - idle_timeout_ms: T_idle
  - absolute_timeout_ms: T_abs
  - started_at: t0
  - last_activity: t_last
  - current_time: t_now

Idle check (every heartbeat tick):
  if status == "active" and (t_now - t_last) >= T_idle:
    transition("active" â†’ "idle")

Absolute check (on resume or tick):
  if (t_now - t0) >= T_abs and status != "ended":
    transition(* â†’ "ended")
    archive()

Warning check:
  if status == "active" and (t_now - t_last) >= (T_idle * 0.8):
    emit(CONV.SessionTimeoutWarning)
```

## Session Persistence

### Storage Tiers

| Tier | Location | Purpose | Volatility |
|------|----------|---------|------------|
| Cache | Conversation OS (in-memory) | Fast access for active sessions | Lost on restart |
| Persistent | Memory OS â€” Episodic Memory | Long-term session storage | Durable |
| Archival | Memory OS â€” Episodic Memory | Summaries on session end | Durable |

### Persistence Flow

```
createSession()
  â†’ Store in Memory OS (Episodic Memory)
  â†’ Cache in Conversation OS (in-memory map)

updateSession()
  â†’ Update cache synchronously
  â†’ Persist to Memory OS asynchronously

getSession()
  â†’ Check cache â†’ hit â†’ return cache
  â†’ Cache miss â†’ restoreSession() from Memory OS
  â†’ Return restored session

endSession()
  â†’ Generate SessionSummary
  â†’ Archive summary in Memory OS
  â†’ Remove from cache
  â†’ Clear Working Memory for session
```

### Cache Strategy

| Property | Value |
|----------|-------|
| Cache type | In-memory `Map<session_id, ConversationSession>` |
| Eviction | LRU when cache exceeds 1000 sessions |
| Consistency | Write-through: update cache first, persist async |
| Restoration | On cache miss, rebuild from Memory OS Episodic Memory |

## Session Limits

| Limit | Default | Configurable | Enforcement |
|-------|---------|--------------|-------------|
| Max concurrent sessions per user | 10 | Via `SessionConfig.max_sessions_per_user` | Oldest idle session ended first |
| Max turns per session | 1000 | Via `SessionConfig.max_turns_per_session` | Turn Manager refuses new turns |
| Max session duration | 24 hours | Via `SessionConfig.absolute_timeout_ms` | Absolute timeout force-ends session |

### Limit Enforcement Algorithm

```
enforceLimits(user_id):
  sessions = getUserSessions(user_id)
  active_count = sessions.filter(s => s.status != "ended").length

  // Enforce max concurrent sessions
  if active_count > max_sessions_per_user:
    idle_sessions = sessions.filter(s => s.status == "idle")
                           .sortBy("last_activity")
    while active_count > max_sessions_per_user and idle_sessions.length > 0:
      oldest_idle = idle_sessions.shift()
      endSession(oldest_idle.session_id, reason="limit_enforcement")
      active_count--

  // Enforce max turns across all sessions for user (optional)
  for session in sessions:
    if session.turn_count >= max_turns_per_session and session.status == "active":
      endSession(session.session_id, reason="max_turns_exceeded")
```

## User Preferences

### Lifecycle

```
session.createSession(user_id, modality)
  â†’ User Profile Service loads preferences from Memory OS
  â†’ Preferences merged into session.metadata.user_preferences
  â†’ Defaults applied for missing fields

session.updatePreferences(session_id, updates)
  â†’ Merge updates into session metadata
  â†’ Persist to Memory OS (User Profile)
  â†’ Available to next session for same user
```

### Preference Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| formality | number (0.0â€“1.0) | 0.5 | Formality level of Sou's language |
| verbosity | number (0.0â€“1.0) | 0.5 | How detailed responses should be |
| preferred_modality | string | "text" | User's preferred communication channel |
| timezone | string | "UTC" | User's timezone for time-aware responses |
| language | string | "en" | ISO language code |
| accessibility | string[] | [] | Accessibility needs |

### Update Flow

```
updatePreferences(session_id, updates):
  1. Validate update fields against schema
  2. Merge updates into current metadata.user_preferences
  3. Update session in cache (synchronous)
  4. Persist preferences to Memory OS (asynchronous)
  5. Emit CONV.PreferencesUpdated event
  6. Return updated preferences
```

### Persistence Guarantee

Under CONV-005, user preferences are persistent across sessions. Preferences updated in one session are available in all subsequent sessions for that user (stored in Memory OS User Profile).

## Session Restoration Flow

```
User sends message with session_id
         â”‚
         â–¼
Session Manager.getSession(session_id)
         â”‚
         â”œâ”€â”€ Cache hit â”€â”€â–º Return cached session
         â”‚
         â””â”€â”€ Cache miss
                 â”‚
                 â–¼
         Query Memory OS (Episodic Memory)
                 â”‚
         â”Œâ”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”
         â–¼               â–¼
      Memory hit      Memory miss
         â”‚               â”‚
         â–¼               â–¼
  Rebuild session    Create new session
  in-memory cache    with new session_id
         â”‚               â”‚
         â–¼               â–¼
  Return session     Return new session
  to caller          to caller
```

### Restoration Details

```typescript
restoreSession(session_id: string): ConversationSession {
  // 1. Query Memory OS for session data
  const memoryData = await memoryOS.queryEpisodic({
    memory_type: "conversation_session",
    session_id: session_id
  });

  if (!memoryData) {
    // Memory miss â€” session not found
    return null;
  }

  // 2. Validate session hasn't exceeded absolute timeout
  const elapsed = Date.now() - memoryData.started_at;
  if (elapsed >= memoryData.timeout_config.absolute_timeout_ms) {
    // Absolute timeout exceeded â€” end session
    this.endSession(session_id, "absolute_timeout");
    return null;
  }

  // 3. Rebuild in-memory session state
  const session: ConversationSession = {
    ...memoryData,
    status: this.determineRestoreStatus(memoryData)
  };

  // 4. Load into cache
  this.cache.set(session_id, session);

  // 5. Emit restoration event
  this.events.emit("CONV.SessionRestored", {
    session_id,
    user_id: session.user_id,
    previous_status: memoryData.status
  });

  return session;
}

determineRestoreStatus(memoryData): SessionState {
  if (memoryData.status === "ended") return "ended";
  if (memoryData.status === "paused") return "paused";

  // Check idle timeout
  const idleMs = Date.now() - memoryData.last_activity;
  if (idleMs >= memoryData.timeout_config.idle_timeout_ms) {
    return "idle";
  }

  return "active";
}
```

## Internal Interface

```typescript
interface SessionManager {
  // Lifecycle
  createSession(user_id: string, modality: Modality, preferences?: Partial<UserPreferences>): ConversationSession
  getSession(session_id: string): ConversationSession | null
  updateSession(session_id: string, updates: Partial<ConversationSession>): ConversationSession
  pauseSession(session_id: string, reason?: string): void
  resumeSession(session_id: string): void
  endSession(session_id: string, reason?: string): SessionSummary

  // Timeout
  checkTimeouts(): TimedOutSession[]

  // Restoration & Persistence
  restoreSession(session_id: string): ConversationSession | null
  archiveSession(session_id: string): void

  // Query
  getUserSessions(user_id: string): ConversationSession[]

  // Preferences
  updatePreferences(session_id: string, updates: Partial<UserPreferences>): void

  // Limits
  enforceLimits(user_id: string): void
}
```

### TimedOutSession

```typescript
TimedOutSession {
  session_id: string
  timeout_type: "idle" | "absolute"
  from_status: SessionState
  to_status: SessionState
  idle_duration_ms?: number
  total_duration_ms?: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `CONV.SessionCreated` | session_id, user_id, modality, preferences | Conversation session started |
| `CONV.SessionEnded` | session_id, user_id, turn_count, duration, reason | Session terminated |
| `CONV.SessionPaused` | session_id, user_id, reason | Session paused by user or Sou |
| `CONV.SessionResumed` | session_id, user_id, idle_duration_ms | Session resumed from pause |
| `CONV.SessionIdle` | session_id, user_id, idle_duration_ms | Session transitioned to idle |
| `CONV.SessionRestored` | session_id, user_id, previous_status | Session rebuilt from Memory OS |
| `CONV.SessionArchived` | session_id, user_id, summary | Session summary archived |
| `CONV.SessionTimeoutWarning` | session_id, timeout_type, remaining_ms | Warning at 80% of idle timeout |
| `CONV.SessionAbsoluteTimeout` | session_id, total_duration_ms | Absolute timeout enforced |
| `CONV.SessionLimitEnforced` | user_id, ended_session_id, limit_type | Session ended due to limit enforcement |
| `CONV.PreferencesUpdated` | session_id, user_id, changed_fields | User preferences changed |
| `CONV.SessionCacheEvicted` | session_id, reason, age_ms | Session removed from in-memory cache |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CONV-004 | Conversation OS is stateless â€” sessions live in Memory OS | Architectural â€” cache is transient; Memory OS is source of truth |
| CONV-005 | User preferences are persistent across sessions | API-level â€” preferences stored in Memory OS User Profile |
| CONV-006 | Sessions auto-end after 24 hours | Algorithmic â€” Session Manager enforces absolute timeout |
| CONV-007 | A session in "ended" state cannot transition to any other state | Algorithmic â€” state machine rejects transitions out of "ended" |
| CONV-008 | Every session has exactly one owner (user_id) | Schema â€” `user_id` is required and immutable after creation |
| CONV-009 | Turn count is monotonic and never decreases within a session | Algorithmic â€” Turn Manager increments; Session Manager enforces no decrement |
| CONV-010 | A user cannot exceed `max_sessions_per_user` concurrent sessions | Algorithmic â€” `enforceLimits()` ends oldest idle session on overflow |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown session_id on get/update/pause/resume/end | `CONV_SESSION_NOT_FOUND` | Return null or error; suggest creating new session |
| Session already ended on operation request | `CONV_SESSION_ENDED` | Return error; session is terminal |
| Resume on non-paused session | `CONV_SESSION_NOT_PAUSED` | Return error; session is in unexpected state |
| Absolute timeout exceeded on resume attempt | `CONV_SESSION_EXPIRED` | Return error; session cannot be resumed |
| Session limit exceeded per user | `CONV_SESSION_LIMIT` | Auto-end oldest idle session; return new session |
| Max turns per session reached | `CONV_TURN_LIMIT_EXCEEDED` | Refuse new turns; suggest ending or starting new session |
| Invalid preference field or value | `CONV_INVALID_PREFERENCES` | Return error with validation details |
| Persistence write failure | `CONV_PERSISTENCE_FAILURE` | Retry with backoff; log critical error if retries exhausted |

## Usage Patterns

### Pattern 1: Normal Session Flow

```
1. User authenticates â†’ Conversation OS receives auth token
2. Conversation OS calls createSession(user_id, "text")
   â†’ Session created with status "active"
   â†’ Cache populated, Memory OS persisted
   â†’ CONV.SessionCreated emitted
3. User sends message â†’ Turn Manager processes within active session
4. Session Manager updates last_activity on each turn
5. User sends end signal â†’ endSession(session_id, "user_ended")
   â†’ SessionSummary generated
   â†’ Summary archived to Memory OS
   â†’ Cache cleared
   â†’ CONV.SessionEnded + CONV.SessionArchived emitted
```

### Pattern 2: Session Timeout and Recovery

```
1. User is in active session, walks away from device
2. After 5 minutes (idle_timeout_ms):
   â†’ Session Manager heartbeat tick fires
   â†’ checkTimeouts() detects idle
   â†’ CONV.SessionTimeoutWarning emitted at 80% (240s)
   â†’ At 300s: transition("active" â†’ "idle")
   â†’ CONV.SessionIdle emitted
3. User returns and sends message:
   â†’ getSession(session_id) â†’ cache hit â†’ status is "idle"
   â†’ Input received â†’ transition("idle" â†’ "active")
   â†’ Session restored to active, context preserved
4. User walks away for 25 hours:
   â†’ After 24 hours (absolute_timeout_ms):
   â†’ checkTimeouts() detects absolute timeout
   â†’ transition("idle" â†’ "ended")
   â†’ CONV.SessionAbsoluteTimeout + CONV.SessionEnded emitted
   â†’ Session archived
5. User attempts to resume:
   â†’ restoreSession(session_id)
   â†’ Memory hit, but elapsed > absolute_timeout_ms
   â†’ CONV_SESSION_EXPIRED error returned
   â†’ User must create new session
```

### Pattern 3: Limit Enforcement

```
1. User has 10 active sessions (max = 10)
2. User starts new conversation â†’ createSession()
3. Session Manager calls enforceLimits(user_id)
4. Finds active_count (11) > max_sessions_per_user (10)
5. Sorts idle sessions by last_activity (ascending)
6. Finds oldest idle session: session_id = "abc-123", idle for 30 min
7. Calls endSession("abc-123", "limit_enforcement")
   â†’ CONV.SessionLimitEnforced emitted
   â†’ Oldest idle session ended, summary archived
8. New session creation proceeds
   â†’ active_count now 10 (within limit)
   â†’ CONV.SessionCreated emitted
```

### Pattern 4: Multi-Device Session Continuation

```
1. User starts session on mobile app â†’ session_id = "sess-001"
2. Session persisted to Memory OS
3. User switches to desktop web browser
4. Desktop client sends message with session_id "sess-001"
5. Session Manager.getSession("sess-001"):
   â†’ Cache miss (different device, no cache replication)
   â†’ restoreSession("sess-001")
   â†’ Memory OS hit â†’ rebuild in-memory state
   â†’ Session restored with active status
   â†’ CONV.SessionRestored emitted
6. User continues conversation seamlessly across devices
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
| R1 â€” Modulsingularity | Session Management handles only session lifecycle â€” creation, state, timeout, persistence |
| R2 â€” Dependency Order | Depends on Memory OS (Episodic Memory, User Profile), Turn Manager; no upward deps |
| R3 â€” DRY | Session model defined once in Conversation OS data model |
| R4 â€” Builder Pattern | Session built by createSession â†’ preferences â†’ state initialization |
| R5 â€” Liskov Substitution | Any SessionManager implementation conforms to the interface |
| R6 â€” DI over Singletons | Timeout configs, limit policies, and persistence backends injected |
| R9 â€” Deterministic | Same session_id + same input produces same session state |
| R10 â€” Simpler Over Complex | Four-state model (active/idle/paused/ended) with clear transitions |
| R13 â€” Design for Failure | Absolute timeout ensures no session leaks; cache miss triggers restoration |
| R14 â€” Paved Path | All session operations flow through SessionManager interface |
| R15 â€” Open/Closed | New session states or transition rules added via config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Conversation/000-Overview.md | Session Management is a sub-component of Conversation OS |
| Conversation/002-Multi-Turn.md | Turn Manager operates within a session; session tracks turn_count |
| Conversation/005-Channel-Adaptation.md | Session captures modality; Modality Adapter uses it for I/O adaptation |
| Memory/000-Overview.md | Sessions persisted in Memory OS Episodic Memory |
| Memory/001-Working-Memory.md | Session lifecycle controls Working Memory lifecycle |
| Memory/002-Episodic-Memory.md | Session data and summaries stored as Episodic Memory records |
| Brain/Personality/000-Overview.md | User preferences include personality-related formality/verbosity |
| Brain/Sou/000-Overview.md | Sou consumes conversation sessions and produces responses |
| Brain/Context/000-Overview.md | Session context pushed to global context window |
| Bible/05-Platform/004-EVS.md | All session lifecycle events flow through Event System |
