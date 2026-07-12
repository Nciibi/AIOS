# AIOS Bible â€” Brain
## 002 â€” Episodic Memory

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Episodic Memory stores Sou's past experiences â€” conversation turns, mission outcomes, user interactions, system events, and notable occurrences. Unlike Working Memory (current state) or Semantic Memory (facts/knowledge), Episodic Memory is temporal and sequential: it records what happened, when it happened, and in what context.

Episodic Memory is the primary source for the Reflection Engine (Cognitive OS). When Sou reflects on past experiences, it queries Episodic Memory for relevant episodes.

## Data Model

### Episode

```typescript
Episode {
  episode_id: string
  session_id: string
  type: "conversation_turn" | "mission_record" | "user_interaction" |
        "system_event" | "decision" | "tool_invocation" | "reflection"
  timestamp: timestamp
  sequence_number: number        // Monotonically increasing within session
  content: EpisodeContent
  importance: number             // 0.0â€“1.0, computed or Sou-assigned
  tags: string[]
  context_hash: string           // Hash of context at episode time
  parent_episode?: string        // episode_id this is a response to
  related_episodes: string[]     // Episodes in the same chain
  metadata: {
    source: string
    token_count: number
    duration_ms?: number
    outcome?: "success" | "failure" | "partial" | "unknown"
    sentiment?: number            // -1.0 to 1.0
  }
  retention: {
    ttl_policy: "turns" | "duration" | "indefinite"
    ttl_value?: number            // Number of turns or milliseconds
    archived: boolean
    archived_at?: timestamp
    archived_summary?: string
  }
}

EpisodeContent {
  type: "text" | "structured" | "mixed"
  text?: string
  structured?: Record<string, unknown>
  attachments?: string[]          // References to stored artifacts
}
```

### EpisodeChain

```typescript
EpisodeChain {
  chain_id: string
  episodes: Episode[]
  topic: string
  started_at: timestamp
  last_activity: timestamp
  episode_count: number
  is_active: boolean             // Whether new episodes can be appended
}
```

## Retention Policies

Episodic Memory has graduated retention based on type and importance:

| Content | Default TTL | Retention | Archival Behavior |
|---------|-------------|-----------|-------------------|
| Conversation turns | 50 turns (sliding) | Sliding window | Summarized every 10 turns |
| User interactions | Indefinite | Full retention | Summarized monthly |
| Mission records | 30 days | Active + archive | Archived then summarized |
| Decisions | Indefinite | Full retention | Never archived |
| Tool invocations | 7 days | Active + archive | Summarized weekly |
| System events | 7 days | Auto-pruned | Deleted after TTL |
| Reflections | Indefinite | Full retention | Never archived |
| Sou-generated notes | 90 days | Active + archive | Summarized quarterly |

### Sliding Window (Conversation Turns)

```
Window: Last N turns
  N = 50 (configurable)
  On every new turn:
    - If turn_count > N, oldest turn is moved to archive
    - Archived turns are summarized into a compressed entry
    - Summary replaces the individual turns for context queries
    - Individual turns remain available for targeted recall
```

### Importance-Based Retention

Importance is computed on episode creation and adjusted over time:

| Condition | Importance Adjustment |
|-----------|---------------------|
| Episode accessed again | +0.1 |
| Episode referenced by Sou | +0.15 |
| Episode referenced by Reflection | +0.2 |
| Episode older than 30 days | -0.05 per month |
| Episode older than 90 days | -0.10 per month |
| Episode in a completed mission | +0.1 (final) |
| User explicitly mentions an episode | +0.3 |

Episodes below 0.2 importance are candidates for archival/pruning.

## Archival Process

### Turn Summarization

```
Every 10 conversation turns:
  1. Collect last 10 turns
  2. Generate summary via LLMOS (summarization request)
  3. Create EpisodicMemoryItem with:
       type: "conversation_summary"
       content: { summary: "...", turn_range: "101-110", key_points: [...] }
       importance: max of contained turns
  4. Original turns marked as archived
  5. Summary linked to original turns via related_episodes
```

### Long-Term Archival

```
Monthly archival cron:
  1. Query episodes older than 30 days with importance < 0.5
  2. Group by topic (using tags + semantic clustering)
  3. Generate monthly summary per topic via LLMOS
  4. Store summary episodes
  5. Archive (soft-delete) original episodes
  6. Emit MEM.EpisodesArchived event
```

## Query Patterns

### Time-Range Query

```typescript
{
  memory_types: ["episodic"],
  filters: {
    time_range: { start: "2026-06-01", end: "2026-06-30" },
    tags: ["mission", "auth-system"]
  }
}
```

### Sequential Replay

```typescript
{
  memory_types: ["episodic"],
  filters: {
    session_id: "session_123",
    tags: ["conversation_turn"]
  },
  order: "ascending",     // Chronological
  limit: 50
}
```

### Importance-Weighted Retrieval

```typescript
{
  memory_types: ["episodic"],
  filters: {
    importance_min: 0.5
  },
  limit: 20
}
```

### Semantic Search

```typescript
{
  memory_types: ["episodic"],
  text_query: "user complained about performance",
  limit: 10
}
```

## Pruning Strategy

### Soft Delete â†’ Hard Delete

```
1. Episode expires (TTL reached)
2. Episode marked as `archived = true`, `archived_at = now`
3. Episode remains available for 24 hours (recovery window)
4. After 24 hours, episode is hard-deleted
5. If episode was never summarized, generate final summary first
```

### Pruning Triggers

| Trigger | Behavior |
|---------|----------|
| TTL sweep (every 60s) | Check all episodes for TTL expiry |
| Session end | Archive low-importance conversation turns |
| Mission complete | Archive mission-related episodes if 30+ days old |
| Manual `prune()` call | Sou or Context triggers forced pruning |
| Storage threshold | If storage > 80%, prune lowest-importance episodes |

## Sou-Level Rollup

On session end, Episodic Memory performs a rollup to extract persistent knowledge:

```
Session End Rollup:
  1. Collect all episodes from the session
  2. Identify high-importance episodes (importance > 0.7)
  3. For each high-importance episode, check if content is:
     a. Already known (exists in Semantic Memory) â†’ skip
     b. Novel information â†’ propose to Semantic Memory
     c. Behavioral pattern â†’ propose to Procedural Memory
  4. Generate session summary via LLMOS
  5. Archive remaining episodes
```

## Internal Interfaces

```typescript
interface EpisodicMemoryStore {
  store(episode: Episode): Episode
  get(episode_id: string): Episode | null
  query(filter: EpisodicQuery): Episode[]
  update(episode_id: string, updates: Partial<Episode>): Episode
  delete(episode_id: string): void

  getChain(chain_id: string): EpisodeChain
  appendToChain(chain_id: string, episode: Episode): void

  archive(episode_id: string, summary?: string): void
  prune(config: PruneConfig): PruneReport
  rollupSession(session_id: string): RollupReport

  search(text: string, limit: number, min_score?: number): ScoredEpisode[]
}

interface EpisodicQuery {
  session_id?: string
  types?: string[]
  tags?: string[]
  time_range?: { start: timestamp, end: timestamp }
  importance_min?: number
  importance_max?: number
  outcome?: string
  text_search?: string
  limit: number
  offset?: number
  order: "ascending" | "descending" | "importance"
}

interface PruneConfig {
  older_than?: Duration
  importance_below?: number
  memory_type?: string
  limit?: number
}

interface PruneReport {
  episodes_archived: number
  episodes_deleted: number
  summaries_generated: number
  storage_freed_bytes: number
}

interface RollupReport {
  sessions_processed: number
  episodes_archived: number
  semantic_promotions: number
  procedural_promotions: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.MEMEvent |  episode_id, session_id, type, importance | Episode created |
| MEM.MEMEvent |  episode_id, updated_fields | Episode metadata changed |
| MEM.MEMEvent |  episode_id, summary_length | Episode moved to archive |
| MEM.MEMEvent |  episode_id, type, reason | Episode hard-deleted |
| MEM.MEMEvent |  episode_id, target_memory, target_id | Episode content moved to Semantic/Procedural |
| MEM.MEMEvent |  chain_id, topic, first_episode | Episode chain started |
| MEM.MEMEvent |  chain_id, episode_count | Episode appended to chain |
| MEM.MEMEvent |  session_id, turn_range, summary_length | Conversation turns summarized |
| MEM.MEMEvent |  archived_count, deleted_count, duration_ms | Pruning finished |
| MEM.MEMEvent |  session_id, promotions, archives | Session rollup finished |
| MEM.MEMEvent |  episode_id, old_importance, new_importance, reason | Importance score changed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| EP-001 | Every episode has a timestamp and sequence number | Schema â€” required fields |
| EP-002 | Episodes are immutable after storage (update creates new version) | Architectural â€” append-only log |
| EP-003 | Conversation turns are archived before hard deletion | Algorithmic â€” summary generated first |
| EP-004 | Deleted episodes have 24-hour recovery window | Algorithmic â€” soft-delete period |
| EP-005 | Importance scores are bounded [0.0, 1.0] | Schema â€” clamped on update |
| EP-006 | Sliding window always keeps the most recent N turns | Algorithmic â€” oldest evicted on insert |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Episode not found | `EP_EPISODE_NOT_FOUND` | Return null; not an error |
| Query matches no episodes | `EP_NO_MATCHES` | Return empty result |
| Archival of already-archived episode | `EP_ALREADY_ARCHIVED` | Idempotent; OK |
| Summarization fails (LLMOS error) | `EP_SUMMARIZATION_FAILED` | Skip summarization; archive raw |
| Prune with no candidates | `EP_NOTHING_TO_PRUNE` | Return empty report |
| Chain not found for append | `EP_CHAIN_NOT_FOUND` | Create new chain |


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
| R1 â€” Modulsingularity | Episodic Memory handles only temporal experience storage |
| R2 â€” Dependency Order | Depends on Memory OS core, LLMOS; no upward deps |
| R3 â€” DRY | Episode schema defined once in Data Model |
| R4 â€” Builder Pattern | Archive built by Summarization â†’ Soft Delete â†’ Hard Delete |
| R5 â€” Liskov Substitution | Any EpisodicMemoryStore implements the interface |
| R6 â€” DI over Singletons | Archival and pruning strategies injected |
| R9 â€” Deterministic | Same query returns same results (time-dependent) |
| R10 â€” Simpler Over Complex | Clear type-based retention with graduated archival |
| R13 â€” Design for Failure | Summarization failures don't block archival |
| R14 â€” Paved Path | All episodes flow through store/query/archive |
| R15 â€” Open/Closed | New episode types added via tags, not by modifying schema |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Episodic Memory is one of 4 memory types |
| Memory/001-Working-Memory.md | High-importance working items promoted here on session end |
| Memory/003-Semantic-Memory.md | Persistent knowledge extracted from episodes |
| Memory/004-Procedural-Memory.md | Behavioral patterns extracted from episodes |
| Brain/Cognitive/000-Overview.md | Reflection Engine consumes episodes for analysis |
| Brain/Conversation/000-Overview.md | Conversation turns are stored as episodes |
| Bible/02-Core/Academy/000-Overview.md | Academy consumes episodes for formal learning |
