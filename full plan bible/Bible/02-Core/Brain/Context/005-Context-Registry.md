# AIOS Bible â€” Brain
## 005 â€” Context Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Context |
| Document ID | AIOS-BBL-002-CTX-005 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Context Registry is the metadata authority for all items in the context window. It maintains a searchable index of every item's origin, type, priority, token cost, content hash, pin state, and eviction phase. Under CTX-003 the Context System is stateless â€” the Registry is an in-memory index that is rebuilt from Memory OS on session restore. The Registry enables deduplication (via content hash), source accountability, token accounting, and the filtered queries exposed through `getRegistry()`.

## Data Model

### RegistryEntry

```typescript
RegistryEntry {
  item_id: string
  session_id: string
  window_id: string
  source: string                    // Which service produced this item
  item_type: string                 // "user_input" | "memory" | "tool_result" | "system_signal"
  section_type: string              // Which section the item lives in
  content_hash: string              // SHA-256 of normalized content
  priority: number                  // 0.0â€“1.0 (live from Priority Manager)
  tier: string                      // Priority tier label
  token_count: number
  original_token_count: number      // Pre-compression count
  pinned: boolean
  pin_priority: number | null
  eviction_phase: "active" | "expired" | "recovery" | "purged"
  inserted_at: timestamp
  updated_at: timestamp
  last_accessed_at: timestamp
  access_count: number
  metadata: {
    source_service: string
    source_method: string
    tags: string[]
    compressed: boolean
    compressed_from: string[]
    duplicate_of: string | null
    summary_for: string[]
    ttl_record_id: string
  }
}
```

### RegistryIndex

```typescript
RegistryIndex {
  by_id: Map<string, RegistryEntry>
  by_session: Map<string, Set<string>>
  by_source: Map<string, Map<string, Set<string>>>
  by_content_hash: Map<string, string[]>
  by_eviction_phase: Map<string, Set<string>>
  by_section: Map<string, Map<string, Set<string>>>
  by_priority_range: IntervalIndex<number, string>
  by_time: SortedSet<timestamp, string>
}
```

### RegistrySnapshot

```typescript
RegistrySnapshot {
  session_id: string
  total_items: number
  total_tokens: number
  by_source: Record<string, number>
  by_type: Record<string, number>
  by_tier: Record<string, number>
  by_phase: Record<string, number>
  pinned_count: number
  compressed_count: number
  dedup_count: number
  taken_at: timestamp
}
```

## Registry Operations

### Register

When an item is pushed into the context window:

```typescript
register(item: ContextItem, session_id: string): RegistryEntry {
  contentHash = hashContent(item.content)

  entry: RegistryEntry = {
    item_id: item.itemId,
    session_id,
    window_id: item.windowId,
    source: item.source,
    item_type: item.itemType,
    section_type: item.sectionType,
    content_hash: contentHash,
    priority: item.priority,
    tier: classifyTier(item.priority),
    token_count: item.tokenCount,
    original_token_count: item.tokenCount,
    pinned: item.pinned,
    pin_priority: item.pinned ? item.priority : null,
    eviction_phase: "active",
    inserted_at: now,
    updated_at: now,
    last_accessed_at: now,
    access_count: 0,
    metadata: {
      source_service: extractServiceName(item.source),
      source_method: "pushItem",
      tags: extractTags(item),
      compressed: false,
      compressed_from: [],
      duplicate_of: null,
      summary_for: [],
      ttl_record_id: null
    }
  }

  indexes.byId.set(entry.itemId, entry)
  indexes.bySession.get(session_id).add(entry.itemId)
  indexes.bySource.get(entry.source).get(entry.itemType).add(entry.itemId)
  indexes.byEvictionPhase.get("active").add(entry.itemId)
  indexes.bySection.get(session_id).get(entry.sectionType).add(entry.itemId)
  indexes.byPriorityRange.insert(entry.priority, entry.itemId)
  indexes.byTime.insert(entry.insertedAt, entry.itemId)

  if !indexes.byContentHash.has(contentHash)
    indexes.byContentHash.set(contentHash, [])
  indexes.byContentHash.get(contentHash).push(entry.itemId)
  indexes.byContentHash.get(contentHash).sort(byPriorityDesc)

  return entry
}
```

### Update

```typescript
update(item_id: string, updates: Partial<RegistryEntry>): RegistryEntry {
  entry = indexes.byId.get(item_id)
  if !entry: throw CTX_ITEM_NOT_FOUND

  priorityChanged = updates.priority !== undefined
    && updates.priority !== entry.priority
  phaseChanged = updates.evictionPhase !== undefined
    && updates.evictionPhase !== entry.evictionPhase

  Object.assign(entry, updates, { updated_at: now })

  if (priorityChanged) {
    indexes.byPriorityRange.remove(entry.priority, item_id)
    indexes.byPriorityRange.insert(updates.priority, item_id)
    entry.tier = classifyTier(updates.priority)
  }

  if (phaseChanged) {
    const oldPhase = entry.evictionPhase
    const newPhase = updates.evictionPhase
    indexes.byEvictionPhase.get(oldPhase)?.delete(item_id)
    if (!indexes.byEvictionPhase.has(newPhase))
      indexes.byEvictionPhase.set(newPhase, new Set())
    indexes.byEvictionPhase.get(newPhase).add(item_id)
  }

  return entry
}
```

### FindByHash (Deduplication)

```typescript
findByHash(content_hash: string, session_id: string): RegistryEntry | null {
  candidates = indexes.byContentHash.get(content_hash) ?? []
  for itemId of candidates:
    entry = indexes.byId.get(itemId)
    if entry && entry.sessionId === session_id && entry.evictionPhase === "active"
      return entry
  return null
}
```

### Query

```typescript
query(session_id: string, filter?: RegistryFilter): RegistryEntry[] {
  if !filter: return [...indexes.bySession.get(session_id) ?? []]
    .map(id => indexes.byId.get(id))
    .filter(Boolean)

  let resultIds: Set<string> | null = null

  for constraint of buildConstraintSet(filter):
    candidates = matchConstraint(constraint, session_id)
    if resultIds === null
      resultIds = new Set(candidates)
    else
      resultIds = intersect(resultIds, new Set(candidates))

  return [...(resultIds ?? [])]
    .map(id => indexes.byId.get(id))
    .filter(Boolean)
    .sort(byPriorityDesc)
}
```

### RegistryFilter

```typescript
interface RegistryFilter {
  item_ids?: string[]
  source?: string | string[]
  item_type?: string | string[]
  section_type?: string | string[]
  priority_range?: { min?: number, max?: number }
  tier?: string | string[]
  eviction_phase?: string | string[]
  pinned?: boolean
  compressed?: boolean
  content_hash?: string
  tags?: string[]
  time_range?: { start?: timestamp, end?: timestamp }
  token_count_range?: { min?: number, max?: number }
  limit?: number
  offset?: number
  sort?: "priority_desc" | "priority_asc" | "newest" | "oldest" | "access_count"
}
```

## Content Hashing

```typescript
hashContent(content: unknown): string {
  normalized = normalizeContent(content)
  serialized = JSON.stringify(normalized, Object.keys(normalized).sort())
  return crypto.createHash("sha256").update(serialized).digest("hex")
}

normalizeContent(content: unknown): unknown {
  if typeof content === "string":
    return content.trim().toLowerCase()
  if content instanceof Object:
    const { insertedAt, ttlTurns, updatedAt, accessCount, ...semantic } = content
    return semantic
  return content
}
```

## Token Accounting

```typescript
getTotalTokens(session_id: string): number {
  return [...indexes.bySession.get(session_id) ?? []]
    .map(id => indexes.byId.get(id))
    .filter(e => e && e.evictionPhase === "active")
    .reduce((sum, e) => sum + e.tokenCount, 0)
}

getTokenBreakdown(session_id: string): TokenBreakdown {
  breakdown: TokenBreakdown = { by_source: {}, by_type: {}, by_section: {} }
  for entry of query(session_id):
    breakdown.bySource[entry.source] =
      (breakdown.bySource[entry.source] ?? 0) + entry.tokenCount
    breakdown.byType[entry.itemType] =
      (breakdown.byType[entry.itemType] ?? 0) + entry.tokenCount
    breakdown.bySection[entry.sectionType] =
      (breakdown.bySection[entry.sectionType] ?? 0) + entry.tokenCount
  return breakdown
}
```

## Deduplication Flow

```
pushItem -> Registry.register
   |
   +-- Compute content_hash
   +-- findByHash(content_hash, session_id)
   |
   +-- If duplicate found:
   |   +-- Compare priority of new vs existing
   |   +-- If new priority > existing:
   |   |   +-- Keep higher priority item
   |   |   +-- Mark lower priority as duplicate_of
   |   |   +-- Update eviction_phase to "recovery" for lower
   |   |   +-- Emit CTX.Deduplicated
   |   +-- If existing priority >= new:
   |   |   +-- Discard new item
   |   |   +-- Increment access_count on existing
   |   |   +-- Emit CTX.Deduplicated
   |   +-- Return the kept item_id
   |
   +-- If no duplicate -> proceed with normal register
```

## Registry Snapshot

```typescript
snapshot(session_id: string): RegistrySnapshot {
  entries = query(session_id)
  return {
    session_id,
    total_items: entries.length,
    total_tokens: getTotalTokens(session_id),
    by_source: countBy(entries, "source"),
    by_type: countBy(entries, "item_type"),
    by_tier: countBy(entries, "tier"),
    by_phase: countBy(entries, "evictionPhase"),
    pinned_count: entries.filter(e => e.pinned).length,
    compressed_count: entries.filter(e => e.metadata.compressed).length,
    dedup_count: entries.filter(e => e.metadata.duplicateOf !== null).length,
    taken_at: now
  }
}
```

## Session Lifecycle

| Event | Registry Action |
|-------|----------------|
| Session start | Rebuild indexes from Memory OS or create empty indexes |
| Item push | Register entry; update all indexes |
| Item update | Update entry; re-index if priority/phase changed |
| Item compress | Update entry with compressed flag, compressed_from, new token_count |
| Item expire | Update eviction_phase to "expired", then "recovery" on next sweep |
| Item restore | Update eviction_phase to "active"; reset expired flags |
| Item purge | Remove entry from all indexes; delete from by_id |
| Session end | Snapshot to Memory OS; clear all indexes |
| Window clear | Mark all entries as "purged"; remove from indexes |

## Internal Interfaces

```typescript
interface ContextRegistry {
  register(item: ContextItem, session_id: string): RegistryEntry
  update(item_id: string, updates: Partial<RegistryEntry>): RegistryEntry
  delete(item_id: string): void
  get(item_id: string): RegistryEntry | null
  getBySession(session_id: string): RegistryEntry[]
  findByHash(content_hash: string, session_id: string): RegistryEntry | null
  query(session_id: string, filter?: RegistryFilter): RegistryEntry[]
  snapshot(session_id: string): RegistrySnapshot
  tokenBreakdown(session_id: string): TokenBreakdown
  rebuild(session_id: string, entries: RegistryEntry[]): void
  clear(session_id: string): void
  getItemCount(session_id: string): number
  getTotalTokens(session_id: string): number
  getCountBySource(session_id: string): Record<string, number>
  getCountByType(session_id: string): Record<string, number>
  getCountByPhase(session_id: string): Record<string, number>
}

interface TokenBreakdown {
  by_source: Record<string, number>
  by_type: Record<string, number>
  by_section: Record<string, number>
}
```

## Usage Patterns

### Pattern 1: Source Accountability

```
1. Sou calls getRegistry(session_id, { source: "tools" })
2. Registry queries by_source index for "tools"
3. Returns all tool-result entries sorted by priority
4. Sou can audit tool results in context
5. Token breakdown shows: tools = 2400 tokens (29% of window)
6. Sou decides to reduce tool verbosity
```

### Pattern 2: Recovery Phase Query

```
1. Sou remembers a notification from earlier
2. Sou calls getRegistry(session_id, { eviction_phase: "recovery" })
3. Registry queries by_eviction_phase index for "recovery"
4. Returns all recoverable items
5. Sou finds the notification and calls restoreItem()
6. Item re-enters context window
```

### Pattern 3: Deduplication Prevention

```
1. Multiple services push the same mission state update
2. First push -> registered with content_hash = "abc123"
3. Second push -> same content_hash -> findByHash returns existing
4. Discard second; increment access_count on first
5. Registry reports dedup_count = 1
6. Savings: 150 tokens that would have been wasted
```

### Pattern 4: Token Budget Diagnostics

```
1. Compression engine reports high compression ratio
2. Sou calls registry.tokenBreakdown(session_id)
3. Results show:
   - conversation_history: 5000 tokens (61%)
   - tool_results: 2000 tokens (24%)
   - working_memory: 800 tokens (10%)
   - system_signals: 400 tokens (5%)
4. Sou identifies conversation_history as primary budget consumer
5. Sou requests smaller sliding window from Configuration
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `CTX.RegistryEntryCreated` | item_id, session_id, content_hash, source | Entry registered |
| `CTX.RegistryEntryUpdated` | item_id, updated_fields, changes | Entry metadata changed |
| `CTX.RegistryEntryDeleted` | item_id, session_id, reason | Entry removed from all indexes |
| `CTX.RegistryQueried` | session_id, filter_summary, result_count | Query executed |
| `CTX.RegistrySnapshotTaken` | session_id, total_items, total_tokens | Snapshot captured |
| `CTX.RegistryRebuilt` | session_id, entry_count, source | Indexes rebuilt from Memory OS |
| `CTX.RegistryCleared` | session_id, entries_removed | All entries for session removed |
| `CTX.RegistryDedupHit` | item_id, duplicate_of_id, content_hash | Deduplication triggered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| RG-001 | Every item in the context window has exactly one RegistryEntry | Architectural â€” register is required on push |
| RG-002 | Content hashes are unique within a session (for same content) | Algorithmic â€” findByHash enforces per-session dedup |
| RG-003 | Registry indexes are kept in sync with item state | Algorithmic â€” update re-indexes on priority/phase change |
| RG-004 | Token counts in Registry match the actual window total | Algorithmic â€” verified on every snapshot |
| RG-005 | Recovered items are re-indexed as active | Algorithmic â€” restoreItem updates phase index |
| RG-006 | Purged entries are removed from all indexes atomically | Algorithmic â€” delete removes from every index |
| RG-007 | Registry is scoped per session | Schema â€” all queries require session_id |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Register with existing item_id | `CTX_DUPLICATE_ENTRY` | Update existing entry; log warning |
| Query with no matching filter | `CTX_NO_MATCHES` | Return empty array |
| Update non-existent entry | `CTX_ENTRY_NOT_FOUND` | Return error; no such entry |
| Rebuild with partial data | `CTX_INCOMPLETE_REBUILD` | Accept partial rebuild; log warning |
| findByHash on closed session | `CTX_SESSION_NOT_FOUND` | Return null; session terminated |
| Snapshot on empty registry | `CTX_EMPTY_REGISTRY` | Return zeroed snapshot |
| Delete already-deleted entry | `CTX_ALREADY_DELETED` | Idempotent; skip |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Registry handles only metadata indexing and queries |
| R2 â€” Dependency Order | Depends on no other Context sub-system; used by all |
| R3 â€” DRY | RegistryEntry schema defined once in Data Model |
| R4 â€” Builder Pattern | Query results built by constraint intersection |
| R5 â€” Liskov Substitution | Any RegistryIndex implementation satisfies the interface |
| R6 â€” DI over Singletons | Index implementations injected |
| R9 â€” Deterministic | Same query on same state returns same results |
| R10 â€” Simpler Over Complex | Multiple specialized indexes over a single generic index |
| R13 â€” Design for Failure | Rebuild from Memory OS on session restore |
| R14 â€” Paved Path | All items flow through register -> update -> delete |
| R15 â€” Open/Closed | New filter dimensions added via new indexes, not by modifying query engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Context/000-Overview.md | Registry maintains the metadata model from CTX-000 |
| Context/001-Window-Management.md | Window Manager calls register on push, queries on pull |
| Context/002-Priority-Manager.md | Registry stores priority scores and tier labels |
| Context/003-Compression-Engine.md | Compression updates token_count and compressed flags |
| Context/004-TTL-Eviction.md | Eviction updates eviction_phase through the lifecycle |
| Brain/Memory/002-Episodic-Memory.md | Registry snapshots persisted on session end |
| Brain/Sou/000-Overview.md | Sou calls getRegistry for filtered queries |

