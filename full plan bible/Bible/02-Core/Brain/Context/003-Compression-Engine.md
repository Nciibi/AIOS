# AIOS Bible â€” Brain
## 003 â€” Compression Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Context |
| Document ID | AIOS-BBL-002-CTX-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Compression Engine reduces the context window's token count when it exceeds the budget set by LLMOS. It applies a ranked set of compression strategies â€” from least to most destructive â€” to bring the window within budget while preserving the maximum possible information value. Under CTX-004, compression never removes pinned items. The Compression Engine is stateless: it operates on window snapshots and returns compressed snapshots.

## Data Model

### CompressionRequest

```typescript
CompressionRequest {
  window_id: string
  session_id: string
  current_tokens: number
  target_tokens: number
  strategies: CompressionStrategy[]
  priority_thresholds: {
    always_include: number     // 0.7 â€” items above this are never compressed
    compress_eligible: number  // 0.4 â€” items below this are primary targets
    exclude_threshold: number  // 0.0 â€” background items excluded first
  }
  pinned_item_ids: string[]
  metadata: {
    reason: "turn_end" | "push_overflow" | "manual" | "emergency"
    requester: string
    requested_at: timestamp
  }
}
```

### CompressionResult

```typescript
CompressionResult {
  window_id: string
  session_id: string
  original_tokens: number
  compressed_tokens: number
  target_tokens: number
  compression_ratio: number
  within_budget: boolean
  strategies_applied: StrategyResult[]
  metadata: {
    items_dropped: number
    items_summarized: number
    items_deduplicated: number
    total_items_before: number
    total_items_after: number
    pinned_items_retained: number
    compressed_at: timestamp
    duration_ms: number
  }
}

StrategyResult {
  strategy_name: string
  tokens_saved: number
  items_affected: number
  quality_impact: "none" | "minimal" | "moderate" | "significant"
  order_applied: number
}
```

### CompressedItem

```typescript
CompressedItem {
  original_item_ids: string[]     // The items that were compressed
  item_type: "compressed_group"
  content: CompressedContent
  priority: number                // Max priority of original items
  token_count: number             // Post-compression token count
  original_token_count: number    // Pre-compression total
  pinned: boolean                 // true if any original was pinned
  source: string                  // "compression_engine"
  compression_metadata: {
    strategy: string
    original_items: number
    compression_savings: number
    summary_text?: string
  }
}

CompressedContent {
  type: "summary" | "deduped_reference" | "truncated" | "pruned"
  summary?: string                // For summarization strategy
  key_points?: string[]           // Extracted key information
  duplicate_of?: string           // For deduplication â€” item_id kept
  preserved_fields?: string[]     // Fields retained after structured pruning
}
```

## Compression Strategies

Strategies are applied in order from least to most destructive. Each strategy targets specific item types and priority ranges.

### Strategy 1: Background Exclusion

```
Target: Items with priority < 0.2 (Background tier)
Behavior: Remove all background-tier items from the window
Token Savings: 5â€“15%
Quality Impact: None â€” background items are not needed for normal operation
Execution:
  1. Scan all items with priority < 0.2
  2. Remove them from their sections
  3. Record in StrategyResult
```

### Strategy 2: Deduplication

```
Target: Items with identical content hash
Behavior: Remove duplicate items; keep the highest-priority instance
Token Savings: 5â€“15%
Quality Impact: None â€” no information lost
Execution:
  1. Group items by content hash
  2. For each group with count > 1:
     a. Keep item with highest priority
     b. For duplicates: if priority < kept item priority, drop;
        if priority equal, keep oldest
  3. Update Registry â€” link dropped items to kept item
```

### Strategy 3: Structured Pruning

```
Target: Items with verbose metadata fields
Behavior: Remove non-essential fields from items while preserving core content
Token Savings: 10â€“30%
Quality Impact: Minimal â€” core content preserved, metadata trimmed
Execution:
  1. For each eligible item (priority â‰¥ compress_eligible):
     a. Remove metadata fields not in PRESERVED_FIELDS
     b. Truncate messages > MAX_ITEM_TOKENS (default: 1024)
     c. Preserve: item_id, item_type, content.text, priority, source
     d. Remove: extended_metadata, raw_payload, debug_info
  2. Update token_count on affected items

PRESERVED_FIELDS = ["item_id", "item_type", "content", "priority", "source", "pinned"]
```

### Strategy 4: Conversation Summarization

```
Target: Conversation history turns (oldest first)
Behavior: Replace groups of N consecutive turns with a single summary item
Token Savings: 60â€“80% on affected turns
Quality Impact: Moderate â€” summaries lose detail but preserve key information
Execution:
  1. Identify oldest conversation turns in conversation_history section
  2. Group by N = 5 (configurable)
  3. For each group:
     a. Extract text from each turn
     b. Send to LLMOS for summarization (if available)
     c. On LLMOS success: replace N turns with one CompressedItem
     d. On LLMOS failure: use extractive summarization (key sentences)
  4. Set CompressedItem priority = max of original priorities
```

#### Extractive Fallback

When LLMOS summarization is unavailable or fails:

```
extractiveSummarize(turns, N):
  1. Score each sentence by TF-IDF against all turns
  2. Select top K sentences (K = N * 2)
  3. Order selected sentences chronologically
  4. Concatenate as summary text
  5. Set token_count = sum of selected sentence tokens
```

### Strategy 5: Sliding Window Truncation

```
Target: Conversation history (oldest turns)
Behavior: Drop oldest conversation turns beyond the sliding window limit
Token Savings: Fixed â€” depends on window size
Quality Impact: Moderate â€” oldest context lost
Execution:
  1. Calculate current conversation turn count
  2. If count > MAX_SLIDING_WINDOW (default: 50):
     a. Drop oldest (count - MAX_SLIDING_WINDOW) turns
     b. If any dropped turns were never summarized, emit event
  3. If still over budget after dropping, proceed to Strategy 6
```

### Strategy 6: Low-Priority Eviction

```
Target: Items with priority < compress_eligible (0.4)
Behavior: Drop items in ascending priority order
Token Savings: Variable
Quality Impact: Significant â€” low-value context lost
Execution:
  1. Collect all items with priority < compress_eligible, sorted ascending
  2. Drop items one at a time until budget is met or no more eligible items
  3. Skip: pinned items, Critical items (priority > always_include)
  4. Emit CTX.ItemEvicted for each dropped item
```

### Strategy 7: Emergency Compression

```
Target: Any item not pinned or Critical
Behavior: Aggressive sequential strategy â€” drop, summarize, and prune
Token Savings: Maximum
Quality Impact: Significant â€” may lose useful context
Execution:
  1. Remove all Background tier items
  2. Summarize all conversation turns (group by 10)
  3. Prune all non-critical fields
  4. Drop any item with priority < 0.4
  5. If still over budget: drop items with priority < 0.6
  6. If STILL over budget: return error â€” CTX_COMPRESSION_FAILED
```

## Strategy Selection

```
selectStrategies(request: CompressionRequest): CompressionStrategy[] {
  deficit = request.currentTokens - request.targetTokens
  ratio = deficit / request.currentTokens

  if request.metadata.reason === "emergency"
    return [EMERGENCY]

  strategies = [BACKGROUND_EXCLUSION, DEDUPLICATION]

  if deficit > request.currentTokens * 0.1
    strategies.push(STRUCTURED_PRUNING)

  if deficit > request.currentTokens * 0.2
    strategies.push(CONVERSATION_SUMMARIZATION)

  if deficit > request.currentTokens * 0.3
    strategies.push(SLIDING_WINDOW)

  if deficit > request.currentTokens * 0.4
    strategies.push(LOW_PRIORITY_EVICTION)

  return strategies
}
```

| Deficit Ratio | Strategies Applied | Expected Savings |
|---------------|-------------------|-----------------|
| < 10% | Background Exclusion + Deduplication | 5â€“15% |
| 10â€“20% | + Structured Pruning | 15â€“40% |
| 20â€“30% | + Conversation Summarization | 40â€“70% |
| 30â€“40% | + Sliding Window | 50â€“80% |
| > 40% | + Low-Priority Eviction | 60â€“95% |
| Emergency | Emergency Compression | 70â€“99% |

## Compression Pipeline

```
compressWindow(session_id, target_tokens):
  1. Get window
  2. Build CompressionRequest
     - current_tokens = window.totalTokens
     - target_tokens = min(target_tokens, window.maxTokens)
     - pinned_item_ids = findPinnedItems(window)
  3. Select strategies
  4. Initialize result accumulator
  5. For each strategy (in order):
     a. Check: have we met budget? If yes, break
     b. Apply strategy to window
     c. Record StrategyResult
     d. Update running token count
     e. If strategy fails (error): log, continue to next
  6. If after all strategies still over budget:
     - Emit CTX.CompressionFailed
     - Return result with within_budget = false
     - Window Manager will enforce hard limit
  7. Window Registry updated
  8. Update window.total_tokens
  9. Emit CTX.WindowCompressed
  10. Return CompressionResult
```

## Budget Verification

```typescript
verifyBudget(result: CompressionResult, request: CompressionRequest): boolean {
  if result.compressed_tokens <= request.target_tokens
    return true

  // If compression couldn't meet budget, enforce fallback
  enforceFallback(request)

  return false
}

enforceFallback(request: CompressionRequest): void {
  // Drop lowest-priority items unconditionally until under hard_limit
  window = getWindow(request.session_id)
  items = getAllItemsSortedByPriority(window)  // ascending

  for item in items:
    if item.pinned || item.priority >= PRIORITY_THRESHOLDS.always_include
      continue
    removeItem(window, item.item_id)
    emit CTX.ItemEvicted, {
      item_id: item.item_id,
      reason: "compression_fallback"
    }
    if window.total_tokens <= request.target_tokens * 1.1
      break
}
```

## Internal Interfaces

```typescript
interface CompressionEngine {
  compress(session_id: string, target_tokens: number): CompressionResult
  estimateSavings(session_id: string, strategy?: string): EstimationReport
  getStrategy(name: string): CompressionStrategy | null
  registerStrategy(strategy: CompressionStrategy): void
}

interface CompressionStrategy {
  name: string
  priority: number            // Application order (1 = first)
  canApply(window: ContextWindow, request: CompressionRequest): boolean
  apply(window: ContextWindow, request: CompressionRequest): StrategyResult
  estimateSavings(window: ContextWindow): number
  qualityImpact(severity: string): "none" | "minimal" | "moderate" | "significant"
}

interface EstimationReport {
  current_tokens: number
  target_tokens: number
  strategies: {
    name: string
    estimated_savings: number
    quality_impact: string
    items_affected: number
  }[]
  recommended_strategy: string
  estimated_final_tokens: number
}
```

## Usage Patterns

### Pattern 1: Turn-End Compression

```
1. Turn completes â†’ new items pushed (Sou response, tool results)
2. total_tokens = 7500, max_tokens = 8192
3. Usage = 91.5% â†’ compression_trigger exceeded
4. Compression called with target = 8192
5. Deficit = -692 (8.4% over) â†’ only Background Exclusion + Deduplication needed
6. Background items removed: saved 400 tokens
7. Deduplication removes 2 duplicate items: saved 300 tokens
8. Final: 6800 tokens (83% of budget)
9. CTX.WindowCompressed emitted
```

### Pattern 2: Deep Compression for Long Session

```
1. Session has been running for 100 turns
2. total_tokens = 24000, max_tokens = 8192
3. Deficit = 15808 (193% over budget)
4. All 6 strategies applied in sequence:
   - Background Exclusion: -1200 (22800)
   - Deduplication: -800 (22000)
   - Structured Pruning: -4000 (18000)
   - Conversation Summarization: -8000 (10000)
   - Sliding Window (50): -500 (9500)
   - Low-Priority Eviction: -1308 (8192)
5. Final: 8192 tokens â€” exactly at budget
6. Items summarized: 40 turns â†’ 8 summary items
7. Items dropped: 23 (background + low-priority + duplicates)
8. Pinned items retained: 5
```

### Pattern 3: Compression Failure Recovery

```
1. Emergency situation: window at 200% of hard_limit
2. Emergency Compression strategy applied
3. All non-pinned, non-critical items dropped
4. Remaining: 9011 tokens (hard_limit)
5. within_budget = true (hard limit met, even if max_tokens not)
6. If hard limit still exceeded: CTX_COMPRESSION_FAILED
7. Window Manager drops items from lowest priority regardless of tier
   until at or under hard_limit
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CTX.CompressionStarted |     session_id, original_tokens, target_tokens, reason | Compression beginning |
| CTX.WindowCompressed |     session_id, before_tokens, after_tokens, strategy_list | Compression completed |
| CTX.CompressionFailed |     session_id, before_tokens, target_tokens, reason | Could not meet budget |
| CTX.ItemSummarized |     item_ids, summary_item_id, token_savings | Turn group summarized |
| CTX.Deduplicated |     item_id, duplicate_of, token_savings | Duplicate item removed |
| CTX.ItemPruned |     item_id, field_removed, token_savings | Metadata field removed |
| CTX.ItemEvicted |     item_id, item_type, priority, reason | Item dropped from window |
| CTX.BackgroundExcluded |     item_ids, token_savings | Background items excluded |
| CTX.FallbackEviction |     item_ids, token_savings, emergency | Hard-limit fallback triggered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CP-001 | Pinned items are never compressed or removed | Algorithmic â€” verified before every strategy |
| CP-002 | Critical-tier items are never compressed or removed | Algorithmic â€” priority check in all strategies |
| CP-003 | Strategies are applied in deterministic order (leastâ†’most destructive) | Algorithmic â€” strategy.priority order enforced |
| CP-004 | Compression never increases token count | Algorithmic â€” verified on result |
| CP-005 | Deduplication preserves the highest-priority instance | Algorithmic â€” priority comparison |
| CP-006 | Emergency compression always produces a result (even if over budget) | Architectural â€” last resort always executes |
| CP-007 | Summarization failures fall back to extractive method | Algorithmic â€” fallback chain defined |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-006 | The Context System owns the global context window. Single authority for context. | Architectural - no other component may persist or modify global context. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| All strategies applied, still over budget | `CTX_COMPRESSION_FAILED` | Return result with within_budget = false; Window Manager enforces hard limit |
| LLMOS summarization unavailable | `CTX_SUMMARIZATION_FAILED` | Use extractive fallback; log warning |
| Empty window on compress | `CTX_EMPTY_WINDOW` | No-op; return success |
| No eligible items for any strategy | `CTX_NO_ELIGIBLE_ITEMS` | Return result with no strategies applied |
| target_tokens >= current_tokens | `CTX_NO_COMPRESSION_NEEDED` | No-op; return result with zero savings |
| Unknown strategy name | `CTX_UNKNOWN_STRATEGY` | Skip unknown strategy; log error |


## Cross-Cutting Concerns

### Security

Context System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Context System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Context System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Context System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Compression Engine handles only reducing token count |
| R2 â€” Dependency Order | Depends on Context Registry, LLMOS (optional); no upward deps |
| R3 â€” DRY | Compression strategies defined once in strategy registry |
| R4 â€” Builder Pattern | Result built by applying strategies in fixed order |
| R5 â€” Liskov Substitution | Any CompressionStrategy implements the interface |
| R6 â€” DI over Singletons | Strategy list and order injected at initialization |
| R9 â€” Deterministic | Same inputs produce same compression result |
| R10 â€” Simpler Over Complex | Clear strategy priority with graduated destructiveness |
| R13 â€” Design for Failure | Emergency compression always executes; LLMOS failure has fallback |
| R14 â€” Paved Path | All compression flows through compressWindow â†’ strategies |
| R15 â€” Open/Closed | New compression strategies implemented via CompressionStrategy interface |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Context/000-Overview.md | Compression Engine implements compression from CTX-000 |
| Context/001-Window-Management.md | Window Manager calls compress when budget exceeded |
| Context/002-Priority-Manager.md | Priority thresholds determine which items are eligible |
| Context/004-TTL-Eviction.md | Eviction removes items after compression fails |
| Context/005-Context-Registry.md | Registry tracks compressed items and dedup links |
| Brain/LLMOS/006-Token-Budget-Manager.md | Sets the max_tokens budget that compression targets |
| Brain/Memory/002-Episodic-Memory.md | Summarized turns may be persisted here |
