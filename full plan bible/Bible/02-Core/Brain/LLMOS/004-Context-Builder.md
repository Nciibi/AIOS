# AIOS Bible — Brain/LLMOS
## 004 — Context Builder

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-004 |
| Source Laws | Law 7 — Law of Capability Bounds (context window) |
| Source Physics | Physics/004-Sessions.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 8 — Context Building |

## Purpose

The Context Builder manages the model context window. It receives raw input (messages, context documents, system prompt) and produces a prioritized, truncated, and well-structured context payload that fits within the selected model's context window. It enforces token budgets for each content category and ensures critical information is never truncated.

## Architecture

```
Raw Input (messages + context + system prompt + memories)
         │
         ▼
┌─────────────────────────────────────────────┐
│          CONTEXT SIZER                      │
│  - Tokenize all content                     │
│  - Classify content by category             │
│  - Measure each category's token footprint  │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│          PRIORITY ASSIGNER                  │
│  - Assign priority tiers to each section    │
│  - Mark critical, high, normal, low, optional│
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│          WINDOW FITTER                      │
│  - Check total vs model context window      │
│  - Apply truncation strategies              │
│  - Allocate tokens per category             │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│          OVERFLOW HANDLER                   │
│  - Handle overflow gracefully               │
│  - Return truncated sections manifest       │
│  - Flag for caller feedback                 │
└─────────────────────────────────────────────┘
         │
         ▼
        ContextPayload (to Memory Injection Stage 9)
```

## Token Allocation Strategy

### Priority Tiers

| Tier | Color | Guarantee | Examples |
|------|-------|-----------|----------|
| critical | 🔴 | Always included — never truncated | System prompt, current user message |
| high | 🟠 | Included until 80% of window full | Direct instructions, required context |
| normal | 🟡 | Included until 90% of window full | Task-relevant context, recent history |
| low | 🟢 | Included if space permits, first to truncate | Retrieved documents, peripheral context |
| optional | ⚪ | Only included if window utilization < 60% | Reference material, verbose examples |

### Default Allocation

Assumes a 100K token context window:

| Category | Max Tokens | Priority | Truncation Strategy |
|----------|-----------|----------|---------------------|
| System Prompt | 4K | critical | Error if exceeded (config too large) |
| Current Message | 16K | critical | Truncate from center |
| Conversation History | 32K | high | Snippet from end — keep last N turns |
| Context Documents | 24K | normal | Remove lowest relevance documents first |
| Injected Memories | 12K | low | Remove lowest weight memories first |
| Tool Definitions | 8K | normal | Remove least-used tools first |
| Response Schema | 2K | normal | Error if exceeded (schema too large) |
| Reserve | 2K | — | Headroom for prompt formatting overhead |

Allocations are dynamic based on model context window size.

## Truncation Strategies

| Strategy | Description | Applied To |
|----------|-------------|------------|
| `snippet_end` | Keep only the last N tokens | Conversation history (most recent turns) |
| `snippet_start` | Keep only the first N tokens | Long documents |
| `center_trim` | Remove middle portion, keep start and end | Long user messages |
| `relevance_rank` | Rank and drop lowest scoring items | Context documents, memories |
| `summarize` | Replace verbose section with summary | Reserved for future use |
| `drop_optional` | Remove all optional-tier content | Peripheral reference material |
| `compress_tools` | Keep most-used N tools | Tool definitions |

## Context Budget

```typescript
interface ContextBudget {
  total_window: u64;                       // Model's context window
  reserved: u64;                           // Reserve for formatting overhead
  available: u64;                          // total_window - reserved
  allocations: Map<ContentCategory, CategoryBudget>;
}

interface CategoryBudget {
  max_tokens_explicit: u64;                // Configured maximum
  priority: PriorityTier;
  strategy: TruncationStrategy;
  actual_tokens: u64;                      // After truncation
  truncated: boolean;                      // Whether truncation occurred
  truncated_from: u64;                     // Original token count before truncation
}
```

## Overflow Handling

When total content exceeds available context:

```typescript
interface OverflowResult {
  fit: boolean;                            // Whether all content fit
  overflow_tokens: u64;                    // Excess tokens
  truncated_sections: TruncatedSection[];  // What was truncated
  suggestions: string[];                   // Suggestions for caller (e.g., "reduce context documents")
  estimated_cost_savings: f64;            // Estimated savings from truncation
}

interface TruncatedSection {
  category: ContentCategory;
  original_tokens: u64;
  final_tokens: u64;
  removed_items: u64;                      // Count of documents/memories removed
  strategy: TruncationStrategy;
}
```

## Invariants

- LLM-CTX-001: The total context payload never exceeds the model's context window minus 2K reserve.
- LLM-CTX-002: Critical-tier content is never truncated — if critical content exceeds its category max, the pipeline fails with LLM-0302.
- LLM-CTX-003: Every truncation decision is recorded in the `truncated_sections` manifest.
- LLM-CTX-004: Context Builder runs before Memory Injection — memories are treated as a content category within the budget.
- LLM-CTX-005: The same input produces the same context output (deterministic truncation).

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.ContextBuilt` | request_id, total_tokens, input_tokens, truncated_sections, allocations | After context building (Stage 8) |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/005-Memory-Injection.md | Memory is a content category within the context budget |
| LLMOS/003-Prompt-Compiler.md | Consumes the context payload produced by Context Builder |
| LLMOS/006-Token-Budget-Manager.md | Token budgets define per-entity context limits |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Critical content exceeds category max | LLM-0302 | Pipeline fails; return context overflow error |
| Requested context exceeds model window entirely | LLM-0302 | Pipeline fails; suggest larger context model |
| Token estimation fails | — | Use character-based estimation; log warning |
