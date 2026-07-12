# AIOS Bible â€” Brain
## 006 â€” Memory Compaction

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Memory |
| Document ID | AIOS-BBL-002-MEM-006 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Memory Compaction is the maintenance subsystem of Memory OS. It reclaims storage space, reorganizes data for access efficiency, manages the archival lifecycle, and ensures the memory system operates within resource budgets. Compaction runs as a periodic background process that never blocks active memory operations.

## Compaction Operations

### 1. Storage Reclamation

Recovers space from deleted and expired memory items.

```typescript
ReclamationConfig {
  soft_delete_period: 24 hours      // How long items remain after deletion
  hard_delete_batch_size: 1000      // Items per compaction cycle
  min_free_bytes: 1 GB              // Trigger compaction when free space drops below this
  max_storage_ratio: 0.80           // Trigger when storage exceeds 80% capacity
}
```

| Phase | Action | Duration After Delete | Recoverable? |
|-------|--------|----------------------|--------------|
| 1. Soft delete | Item marked deleted, still in indexes | 0â€“24 hours | Yes |
| 2. Archival check | Check if item needs summarized first | 24 hours | Yes (from archive) |
| 3. Hard delete | Item removed from store + indexes | > 24 hours | No |

### 2. Data Reorganization

Defragments the primary store for better access locality.

```typescript
ReorganizationConfig {
  segment_size: 64 MB               // Data segment size for compaction
  rewrite_threshold: 0.30           // Rewrite segment if >30% is stale
  max_segments_per_pass: 10         // Segments to process per compaction cycle
}
```

Compaction reads each segment, keeps only live items, and writes a new segment. Old segments are deleted after all readers have drained.

### 3. Importance-Based Promotion

Automatically adjusts importance scores based on access patterns.

```typescript
PromotionConfig {
  access_promotion: +0.05           // Per access within observation window
  referral_promotion: +0.10         // Per referral from Cognitive OS
  decay_rate: -0.01                 // Per day without access
  promotion_window: 7 days          // Observation window for access counting
  min_importance: 0.0               // Floor
  max_importance: 1.0               // Ceiling
}
```

### 4. Cross-Memory Promotion

Items may be promoted between memory types as they demonstrate value.

```typescript
CrossMemoryPromotionConfig {
  // Working â†’ Episodic
  working_to_episodic_threshold: 0.7     // Importance threshold
  working_to_episodic_on_session_end: true

  // Episodic â†’ Semantic
  episodic_to_semantic_min_confidence: 0.8
  episodic_to_semantic_min_occurrences: 3   // Same pattern observed 3+ times
  episodic_to_semantic_types: [
    "user_preference", "domain_knowledge", "relationship", "rule"
  ]

  // Episodic â†’ Procedural
  episodic_to_procedural_min_successes: 3
  episodic_to_procedural_min_steps: 2         // Minimum action sequence length
  episodic_to_procedural_types: [
    "routine", "workflow", "playbook_sequence"
  ]
}
```

### 5. Eviction

Removes low-value items under resource pressure.

```typescript
EvictionConfig {
  priority_order: [
    // Evicted first:
    "expired_items",
    "archived_items_older_than_90_days",
    "unaccessed_working_memory_older_than_24h",
    "low_importance_episodic_older_than_30_days",
    "low_confidence_semantic_older_than_90_days",
    // Evicted last:
    "deprecated_procedural_older_than_1_year"
  ]
  min_retention_per_item: 24 hours
  max_eviction_per_cycle: 10000
}
```

### 6. Integrity Verification

Validates memory structure and detects corruption.

```typescript
VerificationConfig {
  verify_on_startup: true
  verify_every_n_cycles: 10
  sample_rate: 0.01                    // Verify 1% of items per cycle
  verify_checksums: true
  verify_index_consistency: true
  repair_on_corruption: true
}
```

## Compaction Scheduler

```typescript
CompactionScheduler {
  schedule: {
    reclamation: {
      interval: "every 5 minutes",
      priority: "high",
      max_duration_ms: 1000
    },
    reorganization: {
      interval: "every 1 hour",
      priority: "medium",
      max_duration_ms: 5000
    },
    promotion: {
      interval: "every 15 minutes",
      priority: "medium",
      max_duration_ms: 2000
    },
    cross_memory_promotion: {
      interval: "every 30 minutes",
      priority: "low",
      max_duration_ms: 5000
    },
    eviction: {
      interval: "on demand (triggered by storage threshold)",
      priority: "high",
      max_duration_ms: 3000
    },
    integrity_verification: {
      interval: "on startup + every 10 cycles",
      priority: "low",
      max_duration_ms: 10000
    }
  }
  backpressure: {
    // Delay compaction under load
    if (active_queries_per_second > 1000) delay_next_cycle: "1 minute"
    if (active_writes_per_second > 500) delay_next_cycle: "30 seconds"
  }
}
```

## Memory Budget Management

### Storage Budget

```typescript
StorageBudget {
  // Per memory type
  working: {
    max_items: 10000,
    max_bytes: 100 MB,
    current_usage: number
  },
  episodic: {
    max_items: 1000000,
    max_bytes: 10 GB,
    current_usage: number
  },
  semantic: {
    max_facts: 500000,
    max_bytes: 5 GB,
    current_usage: number
  },
  procedural: {
    max_procedures: 50000,
    max_bytes: 1 GB,
    current_usage: number
  },

  // Global
  total_max_bytes: 20 GB,
  emergency_threshold: 0.95,     // If >95% used, trigger emergency eviction
  archive_target_bytes: number   // Target freed per archival cycle
}
```

### Budget Enforcement

```
On storage threshold exceeded (80%):
  1. Trigger reclamation pass
  2. Trigger eviction pass (lowest importance first)
  3. Log budget warning event

On emergency threshold exceeded (95%):
  1. Immediate eviction of all expired items
  2. Eviction of lowest-importance episodic items (archived ones first)
  3. Block new writes with STORE_FULL error
  4. Emit EMERGENCY event to Sou via Attention System
```

## Compaction Phases

Each compaction cycle proceeds through configurable phases:

```
Phase 1: Reclamation
    â”œâ”€â”€ Scan for soft-deleted items past recovery window
    â”œâ”€â”€ Hard-delete in batches of 1000
    â””â”€â”€ Update all indexes
    â”‚
Phase 2: Reorganization (every N cycles)
    â”œâ”€â”€ Identify segments with high stale ratio
    â”œâ”€â”€ Read live items from stale segments
    â”œâ”€â”€ Write new compacted segments
    â””â”€â”€ Schedule old segments for deletion
    â”‚
Phase 3: Importance Adjustment
    â”œâ”€â”€ Query items with activity in promotion window
    â”œâ”€â”€ Apply access_promotion per access count
    â”œâ”€â”€ Apply decay for items without access
    â””â”€â”€ Emit promotion events for significant changes
    â”‚
Phase 4: Cross-Memory Promotion
    â”œâ”€â”€ Scan episodic for promotable patterns
    â”œâ”€â”€ For each candidate:
    â”‚   â”œâ”€â”€ Check minimum occurrences/confidence
    â”‚   â”œâ”€â”€ Generate Semantic Fact or Procedure
    â”‚   â”œâ”€â”€ Store in target memory type
    â”‚   â””â”€â”€ Record provenance link
    â””â”€â”€ Emit promotion events
    â”‚
Phase 5: Eviction (if triggered)
    â”œâ”€â”€ Sort eviction candidates by priority_order
    â”œâ”€â”€ Evict up to max_eviction_per_cycle
    â””â”€â”€ Update all indexes
    â”‚
Phase 6: Integrity Check (every N cycles)
    â”œâ”€â”€ Sample items from each memory type
    â”œâ”€â”€ Verify checksum against stored hash
    â”œâ”€â”€ Verify index consistency (every item in index exists in store)
    â””â”€â”€ Repair or report inconsistencies
```

## Performance Impact

Compaction is designed for minimal impact on active operations:

| Metric | Target | Mechanism |
|--------|--------|-----------|
| Read latency impact | < 5% increase | Read from old segments until compaction completes |
| Write latency impact | < 1% increase | Writes go to active segments; compaction works on cold data |
| CPU usage | < 10% of one core | Low-priority background thread |
| IO bandwidth | < 50 MB/s | Throttled per second |
| Memory overhead | < 200 MB | Fixed-size compaction buffer |

## Internal Interfaces

```typescript
interface CompactionEngine {
  // Main lifecycle
  initialize(config: CompactionConfig): void
  start(): void
  stop(): void
  triggerCycle(phase?: CompactionPhase): Promise<CompactionReport>
  
  // Phase execution
  runReclamation(): ReclamationReport
  runReorganization(): ReorganizationReport
  runPromotion(): PromotionReport
  runCrossMemoryPromotion(): CrossMemoryPromotionReport
  runEviction(): EvictionReport
  runIntegrityCheck(): IntegrityReport
  
  // Budget management
  getStorageBudget(): StorageBudget
  checkThresholds(): BudgetStatus
  emergencyEviction(): EmergencyReport
  
  // Status
  getStatus(): CompactionStatus
  isRunning(): boolean
}

interface CompactionConfig {
  reclamation: ReclamationConfig
  reorganization: ReorganizationConfig
  promotion: PromotionConfig
  cross_memory_promotion: CrossMemoryPromotionConfig
  eviction: EvictionConfig
  verification: VerificationConfig
  scheduler: CompactionScheduler
  budget: StorageBudget
}

interface CompactionReport {
  cycle_id: string
  phases_executed: CompactionPhase[]
  start_time: timestamp
  end_time: timestamp
  duration_ms: number
  reclamation?: ReclamationReport
  reorganization?: ReorganizationReport
  promotion?: PromotionReport
  cross_memory_promotion?: CrossMemoryPromotionReport
  eviction?: EvictionReport
  integrity?: IntegrityReport
  errors: string[]
}

interface ReclamationReport {
  items_hard_deleted: number
  bytes_reclaimed: number
  batches_processed: number
}

interface ReorganizationReport {
  segments_rewritten: number
  stale_bytes_reclaimed: number
  segments_deleted: number
}

interface PromotionReport {
  items_promoted: Record<string, number>  // Memory type â†’ count
  items_decayed: Record<string, number>
  importance_changes: number
}

interface CrossMemoryPromotionReport {
  episodic_to_semantic: number
  episodic_to_procedural: number
  working_to_episodic: number
}

interface EvictionReport {
  items_evicted: number
  bytes_freed: number
  eviction_reasons: Record<string, number>
}

interface IntegrityReport {
  items_verified: number
  items_corrupted: number
  items_repaired: number
  index_inconsistencies: number
  index_inconsistencies_repaired: number
}

interface EmergencyReport {
  items_evicted: number
  bytes_freed: number
  storage_after: number
  writes_blocked: boolean
}

interface CompactionStatus {
  running: boolean
  current_phase: CompactionPhase | null
  last_cycle: timestamp
  next_reclamation: timestamp
  next_reorganization: timestamp
  errors_last_cycle: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| MEM.MEMEvent |   cycle_id, phases_planned | Compaction cycle began |
| MEM.MEMEvent |   cycle_id, duration_ms, phases_executed | Cycle finished |
| MEM.MEMEvent |   items_deleted, bytes_reclaimed | Storage reclamation pass |
| MEM.MEMEvent |   segments_rewritten, stale_bytes | Data reorganization pass |
| MEM.MEMEvent |   items_promoted, items_decayed | Importance scores adjusted |
| MEM.MEMEvent |   type, count | Items promoted between memory types |
| MEM.MEMEvent |   items_evicted, reason | Storage pressure eviction |
| MEM.MEMEvent |   issue_type, item_id, details | Corruption or inconsistency detected |
| MEM.MEMEvent |   item_id, issue_type | Auto-repair applied |
| MEM.MEMEvent |   usage_ratio, total_bytes, free_bytes | Storage threshold exceeded |
| MEM.MEMEvent |   usage_ratio, actions_taken | Emergency eviction triggered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CMP-001 | Compaction never blocks active memory reads or writes | Architectural â€” concurrent access design |
| CMP-002 | Soft-deleted items are recoverable for 24 hours | Algorithmic â€” recovery window enforced |
| CMP-003 | Hard-deleted items are removed from all indexes | Algorithmic â€” index cleanup runs before delete |
| CMP-004 | Importance scores are bounded [0.0, 1.0] | Schema â€” clamped on every adjustment |
| CMP-005 | Cross-memory promotions preserve provenance | Schema â€” source_episode field required |
| CMP-006 | Emergency eviction always preserves Working and pinned items | Algorithmic â€” eviction order enforced |
| CMP-007 | Integrity checks never modify active data | Architectural â€” read-only verification |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
| BRAIN-008 | Sou has read access to ALL memories. Services have scoped access. | Constitutional - Sou's omniscience within Brain. Access control enforced by Memory OS. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Compaction already running | `CMP_ALREADY_RUNNING` | Skip cycle; log warning |
| Primary store unavailable | `CMP_STORE_UNAVAILABLE` | Skip compaction; retry next interval |
| Index rebuild needed | `CMP_INDEX_REBUILD_NEEDED` | Trigger index rebuild; delay compaction |
| Promotion candidate conflicts | `CMP_PROMOTION_CONFLICT` | Skip conflict; log for review |
| Eviction cannot free enough space | `CMP_EVICTION_INSUFFICIENT` | Report to Sou; escalate |
| Integrity check finds unrecoverable corruption | `CMP_CORRUPTION_UNRECOVERABLE` | Isolate corrupted segment; report to Sou |


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
| R1 â€” Modulsingularity | Compaction does one thing: memory maintenance |
| R2 â€” Dependency Order | Depends on Memory OS core, Index Store; no upward deps |
| R3 â€” DRY | Compaction config defined once; phases share common patterns |
| R4 â€” Builder Pattern | Report built by Phase Execution â†’ Aggregation |
| R5 â€” Liskov Substitution | Any CompactionStrategy implements the interface |
| R6 â€” DI over Singletons | Phase strategies injected via config |
| R9 â€” Deterministic | Same state produces same compaction outcome |
| R10 â€” Simpler Over Complex | Clear phase separation with graduated priority |
| R13 â€” Design for Failure | Emergency eviction as last resort |
| R14 â€” Paved Path | All maintenance flows through compaction cycles |
| R15 â€” Open/Closed | New phases added via CompactionPhase enum |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Memory/000-Overview.md | Compaction maintains all memory types |
| Memory/001-Working-Memory.md | Working Memory eviction part of compaction |
| Memory/002-Episodic-Memory.md | Episodic archival and pruning |
| Memory/003-Semantic-Memory.md | Semantic fact confidence decay |
| Memory/004-Procedural-Memory.md | Procedural success rate decay |
| Memory/005-Indexing.md | Indexes rebuilt/updated during compaction |
| Bible/05-Platform/004-EVS.md | Events emitted throughout compaction lifecycle |
