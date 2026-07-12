# AIOS Bible — Brain
## 005 — Context Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Context |
| Document ID | AIOS-BBL-002-CTX-005 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Context Registry is the metadata authority for all items in the context window. It maintains a searchable index of every item's origin, type, priority, token cost, content hash, pin state, and eviction phase. Under CTX-003 the Context System is stateless — the Registry is an in-memory index that is rebuilt from Memory OS on session restore. The Registry enables deduplication (via content hash), source accountability, token accounting, and the filtered queries exposed through `getRegistry()`.

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
  priority: number                  // 0.0–1.0 (live from Priority Manager)
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
