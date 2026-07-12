# AIOS Bible â€” Brain
## 000 â€” Memory OS

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 5 â€” Law of Identity, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/004-Sessions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Memory OS is the persistence backbone of the Brain. Under BRAIN-007, all Brain services are stateless â€” every piece of data, every context window, every plan, every conversation turn, every personality trait is persisted through Memory OS. It is the single source of truth for all Brain state.

Memory OS manages four types of memory: working memory (active task state), episodic memory (conversation history, experiences), semantic memory (facts, knowledge), and procedural memory (learned patterns, skills). It provides the storage and retrieval APIs that every Brain service consumes.

## Architecture

```
Brain Services (Context, Planning, Decision, Tools, Attention, Personality, Conversation, Cognitive)
   â”‚           â”‚           â”‚           â”‚           â”‚           â”‚           â”‚           â”‚
   â–¼           â–¼           â–¼           â–¼           â–¼           â–¼           â–¼           â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                              Memory OS                                                     â”‚
â”‚                                                                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”        â”‚
â”‚  â”‚ Working   â”‚  â”‚  Episodic    â”‚  â”‚  Semantic    â”‚  â”‚  Procedural  â”‚  â”‚ Memory   â”‚        â”‚
â”‚  â”‚ Memory    â”‚â”€â–ºâ”‚  Memory      â”‚â”€â–ºâ”‚  Memory      â”‚â”€â–ºâ”‚  Memory      â”‚â”€â–ºâ”‚ Router   â”‚        â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜        â”‚
â”‚                                                                             â”‚              â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                          â”‚              â”‚
â”‚  â”‚ Index    â”‚  â”‚  Vector      â”‚  â”‚  TTL         â”‚                          â”‚              â”‚
â”‚  â”‚ Store    â”‚  â”‚  Store       â”‚  â”‚  Manager     â”‚                          â”‚              â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                          â”‚              â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                                                              â”‚
                                                                              â–¼
                                                                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                                                     â”‚  Event Store â”‚
                                                                     â”‚ (evidence)   â”‚
                                                                     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Memory OS sits at the foundation of the Brain. Every Brain service depends on it for persistence.

## Core Concepts

### Memory Model

```
MemoryItem {
  item_id: string
  memory_type: "working" | "episodic" | "semantic" | "procedural"
  content: unknown
  metadata: MemoryMetadata
  embedding?: number[]          // Vector embedding for similarity search
  created_at: timestamp
  updated_at: timestamp
  expires_at?: timestamp
}

MemoryMetadata {
  source: string                // Which Brain service created this item
  session_id?: string
  tags: string[]
  importance: number            // 0.0â€“1.0, influences retention priority
  access_count: number
  last_accessed: timestamp
  version: number
  parents: string[]             // item_ids this was derived from
  ttl_policy: "session" | "lifetime" | "indefinite"
}

MemoryQuery {
  query_id: string
  memory_types: MemoryType[]
  text_query?: string
  embedding?: number[]
  filters: {
    source?: string
    session_id?: string
    tags?: string[]
    time_range?: TimeRange
    importance_min?: number
  }
  limit: number
  min_score?: number            // Similarity threshold for vector search
}

MemoryQueryResult {
  items: MemoryItem[]
  total_count: number
  query_id: string
  latency_ms: number
}
```

### 1. Working Memory

Working memory holds the active state of the current session â€” what Sou is doing right now:

| Content | Example | TTL | Scope |
|---------|---------|-----|-------|
| Current goal | "Implement login feature" | Session | 1 per session |
| Active task state | "Writing authentication middleware" | Session | 1 per task |
| Pinned items | Important references Sou wants to keep | Session | User/Sou defined |
| Task stack | Nested sub-tasks | Session | LIFO stack |
| Recent decisions | Last 5 decisions made | 10 turns | Rolling buffer |

Working memory is the fastest memory tier. It is loaded on session start and persisted on every mutation.

Access pattern: Direct lookup by session_id + key. High throughput, low latency.

### 2. Episodic Memory

Episodic memory stores past experiences â€” conversation turns, mission outcomes, user interactions:

| Content | Example | TTL | Retention |
|---------|---------|-----|-----------|
| Conversation history | Recent message exchanges | 50 turns | Sliding window |
| Mission records | Past missions and results | 30 days | Archived then summarized |
| User interactions | Past user requests and responses | Indefinite | Summarized monthly |
| System events | Notable system occurrences | 7 days | Auto-pruned |

Episodic memory supports time-window queries and sequential replay. It is the primary source for Reflection Engine (Cognitive OS).

### 3. Semantic Memory

Semantic memory stores facts, knowledge, and concepts that Sou has learned:

| Content | Example | TTL | Source |
|---------|---------|-----|--------|
| User facts | "User prefers Python" | Indefinite | Extracted from conversation |
| Domain knowledge | "Trading domain requires ISO 20022" | Indefinite | Academy |
| Learned patterns | "User asks for code review after commits" | 90 days | Self-observed |
| Relationship data | "Org A collaborates with Org B" | Indefinite | Federation |

Semantic memory supports vector similarity search. Items are automatically embedded on creation. The Vector Store maintains embeddings for all semantic items.

### 4. Procedural Memory

Procedural memory stores learned procedures, skills, and behavioral patterns:

| Content | Example | TTL | Source |
|---------|---------|-----|--------|
| Skill patterns | "How to deploy a worker" | Indefinite | Repeated practice |
| Optimization tricks | "Common Docker issues and fixes" | Indefinite | Academy |
| Behavioral routines | "How to handle user complaints" | Indefinite | Constitutional + experience |
| Automation scripts | "Standard project scaffolding steps" | Indefinite | Template library |

Procedural memory is less structured than other types. Items may include freetext procedures, step-by-step guides, or references to playbooks.

### 5. Memory Router

The Memory Router determines which memory type(s) to query based on the request:

| Query Type | Primary Memory | Secondary Memory |
|------------|---------------|-----------------|
| "What am I doing?" | Working | â€” |
| "What happened before?" | Episodic | Working |
| "What do I know about X?" | Semantic | Episodic |
| "How do I do X?" | Procedural | Semantic |
| "What should I remember?" | All types | Importance scoring |

### 6. Index Store

The Index Store maintains indexes for efficient memory retrieval:

| Index Type | Key | Use Case |
|------------|-----|----------|
| Session index | session_id | Lookup all memories for a session |
| Source index | source service | Find memories created by a specific service |
| Tag index | tag | Tag-based retrieval |
| Time index | timestamp | Time-range queries |
| Importance index | importance score | Prioritized retrieval |

### 7. Vector Store

The Vector Store enables semantic similarity search across memory items:

| Property | Value |
|----------|-------|
| Embedding model | Configured via LLMOS |
| Dimensions | Configurable (default 1536) |
| Index type | HNSW (Hierarchical Navigable Small World) |
| Similarity metric | Cosine similarity |
| Auto-embed | Enabled for semantic and episodic memory |
| Re-index interval | Every 1000 new items |

### 8. TTL Manager

Manages memory item lifecycles:

| TTL Policy | Behavior | Enforcement |
|------------|----------|-------------|
| session | Deleted when session ends | Session Manager callback |
| lifetime | Persists across sessions | Manual deletion only |
| indefinite | Never deleted | Constitutional override required |
| fixed | Deleted after specified duration | TTL Manager sweeps every 60 seconds |

The TTL Manager performs periodic sweeps to identify and delete expired items. Expired items are soft-deleted (marked as expired) for 24 hours before hard deletion, allowing recovery.

## Interfaces

### Memory OS API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `store(item, memory_type)` | Any Brain Service | Store a memory item |
| `storeBatch(items)` | Any Brain Service | Batch store multiple items |
| `query(query)` | Any Brain Service | Query memory items |
| `get(item_id)` | Any Brain Service | Get single item by ID |
| `update(item_id, updates)` | Sou, Context | Update item fields |
| `delete(item_id)` | Sou, Context | Delete an item |
| `search(text, memory_types, limit)` | Any Brain Service | Semantic search |
| `getSessionMemory(session_id, memory_type?)` | Sou, Context | Get all session memories |
| `prune(memory_type, older_than)` | Sou, Context | Manually trigger pruning |
| `getStats()` | Sou only | Get memory usage statistics |

### Internal Interfaces

```
interface MemoryStore {
  read(key: string): Promise<MemoryItem | null>
  write(key: string, item: MemoryItem): Promise<void>
  delete(key: string): Promise<void>
  query(filter: MemoryQuery): Promise<MemoryQueryResult>
}

interface VectorIndex {
  search(embedding: number[], limit: number, min_score: number): Promise<ScoredItem[]>
  insert(item_id: string, embedding: number[]): Promise<void>
  remove(item_id: string): Promise<void>
}

interface TTLScanner {
  sweep(): Promise<ExpiredItem[]>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.ItemStored |  item_id, memory_type, source, importance | Memory item created |
| MEM.ItemUpdated |  item_id, memory_type, updated_fields | Item updated |
| MEM.ItemDeleted |  item_id, memory_type | Item deleted |
| MEM.ItemExpired |  item_id, memory_type, ttl_policy | Item TTL expired |
| MEM.QueryExecuted |  query_id, memory_types, result_count, latency | Query completed |
| MEM.SearchExecuted |  query_id, memory_types, result_count, avg_score | Semantic search completed |
| MEM.SessionMemoryCleared |  session_id, item_count | Session ended, memory pruned |
| MEM.TTLSweepCompleted |  expired_count, total_scanned | TTL sweep finished |
| MEM.ImportancePromoted |  item_id, old_importance, new_importance | Item importance auto-adjusted |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MEM-001 | All Brain state is persisted through Memory OS | Architectural â€” every Brain service depends on Memory OS |
| MEM-002 | Memory items are immutable after creation (update creates new version) | Architectural â€” append-only log |
| MEM-003 | Sou has read access to ALL memories; services have scoped access | API-level â€” authorization enforced per caller |
| MEM-004 | Expired items are soft-deleted before hard deletion | Algorithmic â€” 24-hour grace period |
| MEM-005 | Working memory is session-scoped and cleared on session end | Algorithmic â€” TTL policy enforcement |
| MEM-006 | Semantic memory items are automatically embedded | Architectural â€” Vector Store is mandatory |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Memory OS is a Brain Service; BRAIN-007 requires stateless services |
| Brain/Context/000-Overview.md | Context data persisted here |
| Brain/Planning/000-Overview.md | Plans persisted here |
| Brain/Personality/000-Overview.md | Personality profile persisted here |
| Brain/Conversation/000-Overview.md | Session state and preferences persisted here |
| Brain/Cognitive/000-Overview.md | Reasoning context retrieved from here |
| Brain/LLMOS/005-Memory-Injection.md | LLMOS retrieves memories for prompt injection |
| Brain/Sou/005-Knowledge.md | Sou delegates memory access to Memory OS |
| Bible/05-Platform/004-EVS.md | Event Store provides underlying persistence |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Memory type not found | `MEM_TYPE_NOT_FOUND` | Return error; list available types |
| Vector store query returns no results | `MEM_NO_MATCHES` | Return empty result; not an error |
| Storage backend unavailable | `MEM_STORE_UNAVAILABLE` | Return error; attempt failover |
| Item already exists (immutable violation) | `MEM_ITEM_EXISTS` | Return existing item_id; no overwrite |
| Batch store partial failure | `MEM_BATCH_PARTIAL` | Return success count and failure details |
| TTL sweep in progress | `MEM_SWEEP_IN_PROGRESS` | Queue write; complete after sweep |


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
| R1 â€” Modulsingularity | Memory OS does one thing: persistent storage for the Brain |
| R2 â€” Dependency Order | Depends on Event Store; no upward deps â€” all Brain services depend on Memory OS |
| R3 â€” DRY | Memory schema defined once in Memory Model |
| R4 â€” Builder Pattern | Query built by Router â†’ Index Lookup â†’ Vector Search |
| R5 â€” Liskov Substitution | Any MemoryStore implements the interface |
| R6 â€” DI over Singletons | Storage backends and index strategies injected |
| R9 â€” Deterministic | Same query produces same results (time-dependent data may vary) |
| R10 â€” Simpler Over Complex | Uses 4 clear memory types with defined access patterns |
| R13 â€” Design for Failure | Soft-delete with 24-hour recovery window |
| R14 â€” Paved Path | All persistence flows through `store` and `query` |
| R15 â€” Open/Closed | New memory types added via Registry, not by modifying core |
