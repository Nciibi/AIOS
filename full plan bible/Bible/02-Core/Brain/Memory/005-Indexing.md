# AIOS Bible — Brain
## 005 — Index Store

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-005 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Index Store provides the indexing infrastructure for all Memory OS types. It maintains secondary indexes — session, source, tag, time, and importance — that enable efficient memory retrieval across millions of items. Without the Index Store, every memory query would require a full scan of all stored items.

The Index Store is a supporting subsystem of Memory OS. It is not a memory type itself; it is the retrieval optimization layer that all four memory types (Working, Episodic, Semantic, Procedural) depend on.

## Architecture

```
Memory OS Query
    │
    ▼
┌─────────────────────────────┐
│       Index Store           │
│                             │
│  ┌────────┐ ┌────────┐     │
│  │ Session │ │ Source │     │
│  │ Index   │ │ Index  │     │
│  └────────┘ └────────┘     │
│  ┌────────┐ ┌────────┐     │
│  │ Tag     │ │ Time   │     │
│  │ Index   │ │ Index  │     │
│  └────────┘ └────────┘     │
│  ┌────────┐ ┌────────┐     │
│  │Importan │ │Memory  │     │
│  │ce Index│ │Type    │     │
│  └────────┘ └────────┘     │
└───────────────┬─────────────┘
                │
                ▼
        Primary Memory Store
        (actual item data)
```

## Index Types

### 1. Session Index

Maps session_id → all memory items belonging to that session.

```typescript
SessionIndex {
  type: "hash"                         // Hash map
  key: session_id: string
  value: Set<item_id>                  // All items in the session
  estimated_size_bytes: number
  
  operations: {
    addItem(session_id: string, item_id: string): void
    removeItem(session_id: string, item_id: string): void
    getItems(session_id: string): Set<string>  // O(1)
    clearSession(session_id: string): void
  }
}
```

| Property | Value |
|----------|-------|
| Lookup | O(1) |
| Memory per entry | ~40 bytes per item_id |
| Use case | "Get all memories for session X" |

### 2. Source Index

Maps source service → all items created by that service.

```typescript
SourceIndex {
  type: "hash"
  key: source: string                  // "sou" | "context" | "conversation" | etc.
  value: Set<item_id>
  
  operations: {
    addItem(source: string, item_id: string): void
    removeItem(source: string, item_id: string): void
    getItems(source: string): Set<string>
  }
}
```

| Property | Value |
|----------|-------|
| Lookup | O(1) |
| Memory per entry | ~40 bytes per item_id |
| Use case | "Find all items created by the Conversation OS" |

### 3. Tag Index

Inverted index mapping tags → items. An item can have multiple tags.

```typescript
TagIndex {
  type: "inverted"                    // Inverted index
  key: tag: string
  value: Set<item_id>
  
  operations: {
    addTags(item_id: string, tags: string[]): void
    removeTags(item_id: string, tags: string[]): void
    getItemsByTag(tag: string): Set<string>
    getItemsByAllTags(tags: string[]): Set<string>  // Intersection
    getItemsByAnyTag(tags: string[]): Set<string>    // Union
    getRelatedTags(tag: string, limit: number): TagCount[]
  }
}
```

| Property | Value |
|----------|-------|
| Lookup | O(1) per tag |
| Intersection | O(min(set_sizes)) |
| Union | O(sum(set_sizes)) |
| Memory per entry | ~50 bytes per (tag, item_id) pair |
| Use case | "Find items tagged with 'security' AND 'critical'" |

### 4. Time Index

B-tree index mapping timestamp → items. Enables efficient time-range queries.

```typescript
TimeIndex {
  type: "btree"                       // B-tree on timestamp
  key: created_at: timestamp (nanosecond precision)
  value: item_id
  
  operations: {
    insert(timestamp: timestamp, item_id: string): void
    remove(timestamp: timestamp, item_id: string): void
    queryRange(start: timestamp, end: timestamp): Iterator<item_id>
    queryBefore(timestamp: timestamp, limit: number): Iterator<item_id>
    queryAfter(timestamp: timestamp, limit: number): Iterator<item_id>
  }
}
```

| Property | Value |
|----------|-------|
| Lookup | O(log N) |
| Range query | O(log N + K) where K = results |
| Memory per entry | ~32 bytes per item_id |
| Use case | "Find items created in the last 24 hours" |

### 5. Importance Index

Sorted set mapping importance → items. Items with high importance are prioritized.

```typescript
ImportanceIndex {
  type: "sorted_set"                 // Skip list or B-tree on importance
  key: importance: number (0.0–1.0)
  value: Set<item_id>
  
  operations: {
    insert(importance: number, item_id: string): void
    update(old_importance: number, new_importance: number, item_id: string): void
    remove(importance: number, item_id: string): void
    getTopN(N: number): ScoredItem[]          // Highest importance items
    getAboveThreshold(threshold: number): ScoredItem[]
  }
}
```

| Property | Value |
|----------|-------|
| Insert | O(log N) |
| Get top N | O(log N + N) |
| Memory per entry | ~40 bytes per item_id |
| Use case | "Get the 10 most important items" |

### 6. Memory Type Index

Maps memory_type → items, enabling type-scoped queries.

```typescript
MemoryTypeIndex {
  type: "hash"
  key: memory_type: "working" | "episodic" | "semantic" | "procedural"
  value: Set<item_id>
  
  operations: {
    addItem(memory_type: string, item_id: string): void
    removeItem(memory_type: string, item_id: string): void
    getItems(memory_type: string): Set<string>
    countByType(): Record<string, number>
  }
}
```

## Composite Query Execution

When a memory query involves multiple filters, the Index Store executes a composite lookup:

```typescript
function executeCompositeQuery(query: MemoryQuery): string[] {
  // 1. Start with the most selective index
  let candidates: Set<string> | null = null
  
  // 2. Intersect each applicable index
  if (query.filters.session_id) {
    const sessionItems = sessionIndex.getItems(query.filters.session_id)
    candidates = intersect(candidates, sessionItems)
  }
  
  if (query.filters.source) {
    const sourceItems = sourceIndex.getItems(query.filters.source)
    candidates = intersect(candidates, sourceItems)
  }
  
  if (query.filters.tags && query.filters.tags.length > 0) {
    const tagItems = tagIndex.getItemsByAllTags(query.filters.tags)
    candidates = intersect(candidates, tagItems)
  }
  
  if (query.filters.time_range) {
    const timeItems = timeIndex.queryRange(
      query.filters.time_range.start,
      query.filters.time_range.end
    )
    candidates = intersect(candidates, new Set(timeItems))
  }
  
  if (query.filters.importance_min !== undefined) {
    const importanceItems = importanceIndex.getAboveThreshold(query.filters.importance_min)
    candidates = intersect(candidates, new Set(importanceItems))
  }
  
  // 3. Apply memory type filter
  if (query.memory_types && query.memory_types.length > 0) {
    const typeItems = new Set<string>()
    for (const mt of query.memory_types) {
      for (const id of memoryTypeIndex.getItems(mt)) {
        typeItems.add(id)
      }
    }
    candidates = intersect(candidates, typeItems)
  }
  
  // 4. Sort by importance (descending)
  const sorted = sortByImportance(Array.from(candidates || []))
  
  // 5. Apply limit
  return sorted.slice(0, query.limit)
}
```

## Index Maintenance

### Insert

```
On MemoryItem stored:
  1. sessionIndex.addItem(item.session_id, item.item_id)
  2. sourceIndex.addItem(item.metadata.source, item.item_id)
  3. tagIndex.addTags(item.item_id, item.metadata.tags)
  4. timeIndex.insert(item.created_at, item.item_id)
  5. importanceIndex.insert(item.metadata.importance, item.item_id)
  6. memoryTypeIndex.addItem(item.memory_type, item.item_id)
```

### Update

```
On MemoryItem metadata updated:
  1. If tags changed: tagIndex.removeTags(item_id, old_tags); tagIndex.addTags(item_id, new_tags)
  2. If importance changed: importanceIndex.update(old_importance, new_importance, item_id)
  3. Other indexes (session, source, time, type) are immutable for the item's lifetime
```

### Delete

```
On MemoryItem deleted:
  1. sessionIndex.removeItem(item.session_id, item.item_id)
  2. sourceIndex.removeItem(item.metadata.source, item.item_id)
  3. tagIndex.removeTags(item.item_id, item.metadata.tags)
  4. timeIndex.remove(item.created_at, item.item_id)
  5. importanceIndex.remove(item.metadata.importance, item.item_id)
  6. memoryTypeIndex.removeItem(item.memory_type, item.item_id)
```

### Rebuild

On system startup (or after corruption detection), all indexes can be rebuilt from the primary store:

```typescript
function rebuildIndexes(): RebuildReport {
  const startTime = Date.now()
  let itemsProcessed = 0
  
  // Clear all indexes
  clearAll()
  
  // Scan primary store
  for (const item of primaryStore.scanAll()) {
    insertToIndexes(item)
    itemsProcessed++
  }
  
  return {
    items_processed: itemsProcessed,
    duration_ms: Date.now() - startTime,
    indexes_rebuilt: 6
  }
}
```

## Performance Targets

| Operation | Target Latency | Target Throughput |
|-----------|---------------|-------------------|
| Single index lookup | < 10μs | 100,000/sec |
| Composite query (3 filters) | < 100μs | 10,000/sec |
| Composite query (5 filters) | < 500μs | 2,000/sec |
| Index insert | < 50μs | 20,000/sec |
| Index update (importance) | < 100μs | 10,000/sec |
| Index delete | < 50μs | 20,000/sec |
| Full rebuild (1M items) | < 10s | N/A |

## Memory Budget

| Index Type | Memory Per 1M Items |
|-----------|-------------------|
| Session Index | ~40 MB |
| Source Index | ~40 MB |
| Tag Index | ~100 MB (assuming 5 tags/item average) |
| Time Index | ~32 MB |
| Importance Index | ~40 MB |
| Memory Type Index | ~40 MB |
| **Total** | **~292 MB per 1M items** |

## Internal Interfaces

```typescript
interface IndexStore {
  // Session
  addToSessionIndex(session_id: string, item_id: string): void
  removeFromSessionIndex(session_id: string, item_id: string): void
  getSessionItemIds(session_id: string): Set<string>
  clearSessionIndex(session_id: string): void

  // Source
  addToSourceIndex(source: string, item_id: string): void
  removeFromSourceIndex(source: string, item_id: string): void
  getSourceItemIds(source: string): Set<string>

  // Tag
  addToTagIndex(item_id: string, tags: string[]): void
  removeFromTagIndex(item_id: string, tags: string[]): void
  getItemIdsByTag(tag: string): Set<string>
  getItemIdsByAllTags(tags: string[]): Set<string>
  getItemIdsByAnyTag(tags: string[]): Set<string>

  // Time
  insertTimeIndex(timestamp: timestamp, item_id: string): void
  removeTimeIndex(timestamp: timestamp, item_id: string): void
  queryTimeRange(start: timestamp, end: timestamp): Iterator<string>
  queryTimeBefore(timestamp: timestamp, limit: number): Iterator<string>
  queryTimeAfter(timestamp: timestamp, limit: number): Iterator<string>

  // Importance
  insertImportanceIndex(importance: number, item_id: string): void
  updateImportanceIndex(old_importance: number, new_importance: number, item_id: string): void
  removeImportanceIndex(importance: number, item_id: string): void
  getTopImportance(N: number): ScoredItem[]
  getImportanceAbove(threshold: number): ScoredItem[]

  // Memory Type
  addToTypeIndex(memory_type: string, item_id: string): void
  removeFromTypeIndex(memory_type: string, item_id: string): void
  getTypeItemIds(memory_type: string): Set<string>
  countByType(): Record<string, number>

  // Composite
  executeQuery(query: MemoryQuery): string[]

  // Lifecycle
  rebuild(): RebuildReport
  clear(): void
  health(): IndexHealth
}

interface IndexHealth {
  session_index_size: number
  source_index_size: number
  tag_index_size: number
  time_index_size: number
  importance_index_size: number
  type_index_size: number
  total_estimated_bytes: number
  last_rebuild: timestamp
  rebuild_count: number
}

interface RebuildReport {
  items_processed: number
  duration_ms: number
  indexes_rebuilt: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `MEM.IDX.ItemIndexed` | item_id, indexes_updated | Item added to all indexes |
| `MEM.IDX.IndexUpdated` | index_type, key, item_id | Single index entry updated |
| `MEM.IDX.IndexRemoved` | index_type, key, item_id | Single index entry removed |
| `MEM.IDX.QueryExecuted` | query_id, indexes_used, result_count, latency_ms | Composite query completed |
| `MEM.IDX.RebuildStarted` | reason | Full index rebuild initiated |
| `MEM.IDX.RebuildCompleted` | items_processed, duration_ms, indexes_rebuilt | Rebuild finished |
| `MEM.IDX.BudgetWarning` | current_bytes, budget_bytes, growth_rate | Index approaching memory budget |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IDX-001 | Every stored memory item exists in all applicable indexes | Algorithmic — insertToIndexes runs on every store |
| IDX-002 | Deleted memory items are removed from all indexes | Algorithmic — removeFromIndexes runs on every delete |
| IDX-003 | Index updates are atomic per item | Architectural — all-or-nothing index update |
| IDX-004 | The Index Store is rebuildable from the primary store | Architectural — full scan on rebuild |
| IDX-005 | Composite queries use the most selective index first | Algorithmic — query planner sorts by selectivity |
| IDX-006 | Time index uses nanosecond precision | Schema — prevents timestamp collisions |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Index rebuild in progress | `IDX_REBUILD_IN_PROGRESS` | Queue writes; fall back to full scan for reads |
| Composite query with no matches | `IDX_NO_MATCHES` | Return empty; not an error |
| Index corruption detected | `IDX_CORRUPTION_DETECTED` | Trigger automatic rebuild; log warning |
| Session index memory limit | `IDX_SESSION_LIMIT` | LRU evict oldest session |
| Tag too long (> 256 chars) | `IDX_TAG_TOO_LONG` | Truncate tag; log warning |
| Importance out of range | `IDX_IMPORTANCE_OUT_OF_RANGE` | Clamp to [0.0, 1.0] |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Index Store does one thing: efficient memory retrieval |
| R2 — Dependency Order | Depends on primary store for rebuild; no upward deps |
| R3 — DRY | Index schemas defined once per index type |
| R4 — Builder Pattern | Query built by Planner → Index Lookup → Intersection |
| R5 — Liskov Substitution | Any Index implementation follows the interface |
| R6 — DI over Singletons | Index implementations injected |
| R9 — Deterministic | Same query + same data = same results |
| R10 — Simpler Over Complex | 6 focused index types, each with one access pattern |
| R13 — Design for Failure | Rebuildable from primary store on corruption |
| R14 — Paved Path | All queries flow through executeQuery |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Index Store supports all memory types |
| Memory/001-Working-Memory.md | Working Memory queries use indexes |
| Memory/002-Episodic-Memory.md | Episodic queries use time + session indexes |
| Memory/003-Semantic-Memory.md | Semantic queries use tag + importance indexes |
| Memory/004-Procedural-Memory.md | Procedural queries use tag + source indexes |
| Memory/006-Compaction.md | Compaction updates indexes after data reorganization |
