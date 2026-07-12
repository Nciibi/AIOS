# AIOS Bible â€” Brain
## 003 â€” Semantic Memory

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 5 â€” Law of Identity |
| Source Physics | Physics/005-Events.md, Physics/001-Identity.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Semantic Memory stores facts, knowledge, concepts, and relationships that Sou has learned and retained. Unlike Episodic Memory (temporal experiences), Semantic Memory is timeless â€” it holds "what Sou knows" rather than "what Sou experienced." Semantic Memory is the Brain's persistent knowledge base, supporting vector similarity search for context-aware retrieval.

Under MEM-006, all Semantic Memory items are automatically embedded for vector search on creation.

## Data Model

### SemanticFact

```typescript
SemanticFact {
  fact_id: string
  fact_type: "entity" | "relation" | "concept" | "property" | "rule" | "factoid"
  subject: string               // Main entity or concept
  predicate: string             // Relationship or attribute
  object: unknown               // Value, entity, or structure
  confidence: number            // 0.0â€“1.0
  source: string                // How this fact was acquired
  source_episode?: string       // Episode ID if derived from experience
  embedding: number[]           // Vector embedding for similarity search
  tags: string[]
  version: number
  created_at: timestamp
  updated_at: timestamp
  expires_at?: timestamp
  metadata: {
    importance: number
    access_count: number
    last_accessed: timestamp
    verified: boolean            // Has this fact been verified by Security Council?
    verification_ref?: string
    contradictions: string[]     // fact_ids that contradict this one
  }
}

SemanticRelation {
  relation_id: string
  source_fact_id: string
  target_fact_id: string
  relation_type: "is_a" | "part_of" | "related_to" | "causes" | "depends_on" |
                 "contradicts" | "supports" | "example_of"
  weight: number                // 0.0â€“1.0, strength of relation
  created_at: timestamp
}
```

### Fact Types

| Type | Description | Example |
|------|-------------|---------|
| entity | A named entity with attributes | `{ subject: "user_Alice", predicate: "preferred_language", object: "Python" }` |
| relation | Relationship between two entities | `{ subject: "Org_A", predicate: "collaborates_with", object: "Org_B" }` |
| concept | Abstract concept definition | `{ subject: "OAuth2", predicate: "is", object: "authorization_framework" }` |
| property | Attribute of an entity | `{ subject: "server_X", predicate: "has_uptime", object: "99.9%" }` |
| rule | If-then rule or heuristic | `{ subject: "deploy", predicate: "requires", object: "security_review" }` |
| factoid | Discrete piece of information | `{ subject: "AIOS", predicate: "version", object: "1.0" }` |

## Vector Store

### Embedding Configuration

| Property | Value |
|----------|-------|
| Model | Configured via LLMOS (default: text-embedding-3-large) |
| Dimensions | Configurable (default: 1536, range: 256â€“3072) |
| Index Type | HNSW (Hierarchical Navigable Small World) |
| Similarity Metric | Cosine similarity |
| Auto-embed | Enabled (all Semantic items embedded on creation) |
| Re-index Interval | Every 1000 new items or every 24 hours |

### HNSW Configuration

```typescript
HNSWConfig {
  M: 16                           // Connections per layer (higher = better recall, more memory)
  ef_construction: 200            // Dynamic candidate list at build time
  ef_search: 50                   // Dynamic candidate list at search time (configurable per query)
  dimensions: 1536
  max_elements: 1_000_000         // Max facts in index
}
```

### Embedding Pipeline

```
New SemanticFact
    â”‚
    â–¼
1. Generate embedding via LLMOS embedding endpoint
    â”‚
    â–¼
2. Store embedding in HNSW index
    â”‚
    â–¼
3. Store fact + embedding in primary store
    â”‚
    â–¼
4. Create/update relations
    â”‚
    â–¼
5. Emit MEM.SM.FactStored
```

## Ingestion Sources

| Source | How Facts Are Extracted | Confidence |
|--------|------------------------|------------|
| User conversation | Sou extracts facts from user statements | 0.7 (needs verification) |
| Academy | Formal knowledge from Academy KMS | 0.9+ |
| Episodic rollup | Session-end extraction from episodes | 0.6â€“0.8 |
| Reflection output | Insights from Cognitive OS reflection | 0.7â€“0.9 |
| Federation | Facts shared from other AIOS instances | 0.5â€“0.8 (source-dependent) |
| Manual | Sou or human explicitly stores a fact | 1.0 (if human-verified) |
| Tool results | Structured data from tool invocations | 0.8+ |

### Deduplication

Before storing a new fact, Semantic Memory checks for duplicates:

```typescript
function checkDuplicate(fact: SemanticFact): DuplicateCheck {
  // 1. Exact match on (subject, predicate, object)
  if (exactMatch(fact)) return { status: "duplicate", existing: match }

  // 2. Semantic similarity > 0.95
  if (semanticSimilarity(fact) > 0.95) return { status: "similar", existing: match, similarity }

  // 3. Contradiction detection
  if (contradicts(fact)) return { status: "contradiction", conflicting: matches }

  return { status: "new" }
}
```

On duplicate: increment `access_count`, update `last_accessed`, skip storage.
On contradiction: flag both facts, increment both contradiction lists, emit alert for Sou.

## Query Patterns

### Exact Fact Retrieval

```typescript
{
  memory_types: ["semantic"],
  filters: {
    subject: "user_Alice",
    predicate: "preferred_language"
  }
}
```

### Semantic Similarity Search

```typescript
{
  memory_types: ["semantic"],
  text_query: "What languages does Alice prefer?",
  limit: 5,
  min_score: 0.7
}
```

### Relation Traversal

```typescript
// Find all facts related to "user_Alice"
{
  memory_types: ["semantic"],
  filters: {
    subject: "user_Alice"
  },
  include_relations: true
}
```

### Confidence-Filtered Query

```typescript
{
  memory_types: ["semantic"],
  filters: {
    confidence_min: 0.8,
    verified: true
  }
}
```

## Fact Lifecycle

```
Creation
    â”‚
    â–¼
Unverified (confidence < 0.8, verified = false)
    â”‚
    â”œâ”€â”€ Sou verifies manually â†’ Verified (confidence = 1.0)
    â”œâ”€â”€ Corroborated by multiple sources â†’ Verified (confidence = avg)
    â”œâ”€â”€ Contradicted â†’ Flagged for review
    â””â”€â”€ Unaccessed for 90 days â†’ Low-importance, archival candidate
    â”‚
    â–¼
Verified (confidence â‰¥ 0.8, verified = true)
    â”‚
    â”œâ”€â”€ Accessed regularly â†’ Maintained
    â”œâ”€â”€ Contradicted by new evidence â†’ Downgraded to Unverified
    â””â”€â”€ Superseded by newer fact â†’ Deprecated
    â”‚
    â–¼
Deprecated
    â”‚
    â”œâ”€â”€ Still queryable but not returned by default
    â””â”€â”€ Hard-deleted after 1 year (unless referenced)
```

## Conflict Resolution

When two facts contradict:

```
1. Both facts are flagged with contradiction references
2. Contradiction is surfaced to Sou via Attention System
3. Sou investigates using Cognitive OS:
   a. Check source reliability of each fact
   b. Check recency (newer facts preferred)
   c. Check corroboration (facts supported by more sources)
4. Sou decides which fact to keep, which to deprecate
5. Deprecated fact is marked with superseeded_by reference
6. Decision is recorded as evidence
```

## Internal Interfaces

```typescript
interface SemanticMemoryStore {
  store(fact: SemanticFact): SemanticFact
  get(fact_id: string): SemanticFact | null
  query(filter: SemanticQuery): SemanticFact[]
  update(fact_id: string, updates: Partial<SemanticFact>): SemanticFact
  delete(fact_id: string): void

  search(text: string, limit: number, min_score?: number): ScoredFact[]
  searchByEmbedding(embedding: number[], limit: number, min_score?: number): ScoredFact[]

  getRelations(fact_id: string): SemanticRelation[]
  addRelation(relation: SemanticRelation): SemanticRelation
  removeRelation(relation_id: string): void

  checkDuplicate(fact: SemanticFact): DuplicateCheck
  resolveConflict(fact_a: string, fact_b: string, resolution: ConflictResolution): void

  reindex(): Promise<ReindexReport>
}

interface SemanticQuery {
  subject?: string
  predicate?: string
  object?: unknown
  fact_type?: string
  tags?: string[]
  confidence_min?: number
  verified?: boolean
  created_after?: timestamp
  created_before?: timestamp
  limit: number
  offset?: number
}

interface ScoredFact {
  fact: SemanticFact
  score: number
  matched_field?: string
}

interface DuplicateCheck {
  status: "new" | "duplicate" | "similar" | "contradiction"
  existing?: SemanticFact
  similarity?: number
  conflicting?: SemanticFact[]
}

interface ConflictResolution {
  survivor_id: string
  deprecated_id: string
  reason: string
  resolved_by: string
  evidence_ref: string
}

interface ReindexReport {
  facts_reindexed: number
  duration_ms: number
  index_size_bytes: number
  errors: string[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.MEMEvent |  fact_id, fact_type, subject, predicate, confidence | New fact created |
| MEM.MEMEvent |  fact_id, updated_fields, old_values | Fact metadata changed |
| MEM.MEMEvent |  fact_id, fact_type, reason | Fact removed |
| MEM.MEMEvent |  fact_id, previous_confidence, new_confidence | Fact verified |
| MEM.MEMEvent |  fact_id, superseeded_by, reason | Fact superseded |
| MEM.MEMEvent |  existing_id, incoming_id, similarity | Duplicate prevented |
| MEM.MEMEvent |  fact_a_id, fact_b_id, context | Conflicting facts flagged |
| MEM.MEMEvent |  survivor_id, deprecated_id, resolved_by | Conflict resolved |
| MEM.MEMEvent |  query_id, result_count, avg_score, latency | Semantic search completed |
| MEM.MEMEvent |  fact_id, old_confidence, new_confidence, reason | Confidence score changed |
| MEM.MEMEvent |  facts_reindexed, duration_ms, errors | HNSW index rebuilt |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SM-001 | Every Semantic Fact has exactly one embedding | Architectural â€” auto-embed on creation |
| SM-002 | Duplicate facts are not stored (detected before insert) | Algorithmic â€” checkDuplicate runs before store |
| SM-003 | Conflicting facts are always flagged to Sou | Architectural â€” contradiction event emitted |
| SM-004 | Confidence scores are bounded [0.0, 1.0] | Schema â€” clamped on update |
| SM-005 | Facts are immutable after creation (update creates new version) | Architectural â€” version number incremented |
| SM-006 | Semantic search always returns results ordered by similarity | Algorithmic â€” HNSW search ordering |
| SM-007 | Deprecated facts are excluded from default queries | Algorithmic â€” filter applied in query |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Embedding generation fails | `SM_EMBEDDING_FAILED` | Store fact without embedding; retry on schedule |
| HNSW index full | `SM_INDEX_FULL` | Trigger reindex with higher M; warn |
| Query matches no facts | `SM_NO_MATCHES` | Return empty result |
| Contradiction resolution with no survivor | `SM_INVALID_RESOLUTION` | Return error; both facts must exist |
| Reindex in progress | `SM_REINDEX_IN_PROGRESS` | Queue writes; service reads from old index |
| Vector search timeout | `SM_SEARCH_TIMEOUT` | Fall back to keyword search |


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
| R1 â€” Modulsingularity | Semantic Memory handles only persistent knowledge storage |
| R2 â€” Dependency Order | Depends on Memory OS core, LLMOS; no upward deps |
| R3 â€” DRY | Fact schema defined once; relations are separate |
| R4 â€” Builder Pattern | Knowledge built by Extraction â†’ Embedding â†’ Indexing |
| R5 â€” Liskov Substitution | Any SemanticMemoryStore implements the interface |
| R6 â€” DI over Singletons | Embedding model and index strategy injected |
| R9 â€” Deterministic | Same query returns same results (model-dependent) |
| R10 â€” Simpler Over Complex | Subject-predicate-object model with vector search |
| R13 â€” Design for Failure | Embedding failures don't block fact storage |
| R14 â€” Paved Path | All facts flow through store/search pattern |
| R15 â€” Open/Closed | New fact types added via fact_type field, not schema changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Semantic Memory is one of 4 memory types |
| Memory/002-Episodic-Memory.md | Persistent knowledge extracted from episodes |
| Memory/004-Procedural-Memory.md | Procedural patterns reference semantic facts |
| Brain/LLMOS/005-Memory-Injection.md | Semantic facts injected into LLMOS prompts |
| Brain/Cognitive/000-Overview.md | Cognitive OS queries semantic knowledge |
| Bible/02-Core/Academy/002-KMS.md | Academy Knowledge Management System sources here |
| Bible/02-Core/Academy/003-Knowledge-Graph.md | Knowledge Graph extends semantic relations |
