# AIOS Bible.Brain
## 005.Context Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible.Brain/Context |
| Document ID | AIOS-BBL-002-CTX-005 |
| Source Laws | Law 3.Law of Communication, Law 4.Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Context Registry is the metadata authority for all items in the context window. It maintains a searchable index of every item's origin, type, priority, token cost, content hash, pin state, and eviction phase. Under CTX-003 the Context System is stateless.the Registry is an in-memory index that is rebuilt from Memory OS on session restore. The Registry enables deduplication (via content hash), source accountability, token accounting, and the filtered queries exposed through getRegistry().

## Data Model

### RegistryEntry

RegistryEntry {
  item_id: string
  session_id: string
  window_id: string
  source: string
  item_type: string
  section_type: string
  content_hash: string
  priority: number
  tier: string
  token_count: number
  original_token_count: number
  pinned: boolean
  pin_priority: number or null
  eviction_phase: active or expired or recovery or purged
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
    duplicate_of: string or null
    summary_for: string[]
    ttl_record_id: string
  }
}