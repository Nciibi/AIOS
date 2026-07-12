# AIOS Bible â€” Brain/LLMOS
## 004 â€” Context Builder

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-004 |
| Source Laws | Law 7 â€” Law of Capability Bounds (context window) |
| Source Physics | Physics/004-Sessions.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 8 â€” Context Building |

## Purpose

The Context Builder manages the model context window. It receives raw input (messages, context documents, system prompt) and produces a prioritized, truncated, and well-structured context payload that fits within the selected model's context window. It enforces token budgets for each content category and ensures critical information is never truncated.

## Architecture

```
Raw Input (messages + context + system prompt + memories)
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚          CONTEXT SIZER                      â”‚
â”‚  - Tokenize all content                     â”‚
â”‚  - Classify content by category             â”‚
â”‚  - Measure each category's token footprint  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚          PRIORITY ASSIGNER                  â”‚
â”‚  - Assign priority tiers to each section    â”‚
â”‚  - Mark critical, high, normal, low, optionalâ”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚          WINDOW FITTER                      â”‚
â”‚  - Check total vs model context window      â”‚
â”‚  - Apply truncation strategies              â”‚
â”‚  - Allocate tokens per category             â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚          OVERFLOW HANDLER                   â”‚
â”‚  - Handle overflow gracefully               â”‚
â”‚  - Return truncated sections manifest       â”‚
â”‚  - Flag for caller feedback                 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
        ContextPayload (to Memory Injection Stage 9)
```

## Token Allocation Strategy

### Priority Tiers

| Tier | Color | Guarantee | Examples |
|------|-------|-----------|----------|
| critical | ðŸ”´ | Always included â€” never truncated | System prompt, current user message |
| high | ðŸŸ  | Included until 80% of window full | Direct instructions, required context |
| normal | ðŸŸ¡ | Included until 90% of window full | Task-relevant context, recent history |
| low | ðŸŸ¢ | Included if space permits, first to truncate | Retrieved documents, peripheral context |
| optional | âšª | Only included if window utilization < 60% | Reference material, verbose examples |

### Default Allocation

Assumes a 100K token context window:

| Category | Max Tokens | Priority | Truncation Strategy |
|----------|-----------|----------|---------------------|
| System Prompt | 4K | critical | Error if exceeded (config too large) |
| Current Message | 16K | critical | Truncate from center |
| Conversation History | 32K | high | Snippet from end â€” keep last N turns |
| Context Documents | 24K | normal | Remove lowest relevance documents first |
| Injected Memories | 12K | low | Remove lowest weight memories first |
| Tool Definitions | 8K | normal | Remove least-used tools first |
| Response Schema | 2K | normal | Error if exceeded (schema too large) |
| Reserve | 2K | â€” | Headroom for prompt formatting overhead |

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

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-CTX-001 | The total context payload never exceeds the model's context window minus 2K reserve. | Algorithmic â€” window fitter enforces budget |
| LLM-CTX-002 | Critical-tier content is never truncated â€” if critical content exceeds its category max, the pipeline fails with LLM-0302. | Algorithmic â€” priority-based truncation |
| LLM-CTX-003 | Every truncation decision is recorded in the `truncated_sections` manifest. | Architectural â€” observability invariant |
| LLM-CTX-004 | Context Builder runs before Memory Injection â€” memories are treated as a content category within the budget. | Architectural â€” pipeline stage ordering |
| LLM-CTX-005 | The same input produces the same context output (deterministic truncation). | Algorithmic â€” deterministic truncation strategy |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.ContextBuilt |     request_id, total_tokens, input_tokens, truncated_sections, allocations | After context building (Stage 8) |


## Cross-Cutting Concerns

### Security

LLMOS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), LLMOS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), LLMOS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), LLMOS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Context Builder is the sole context window manager |
| R2 â€” Dependency Order | Context Builder precedes Memory Injection and Prompt Compiler |
| R3 â€” DRY | Truncation strategies defined once, applied consistently |
| R4 â€” Builder Pattern | ContextPayload built through staged pipeline architecture |
| R5 â€” Liskov Substitution | Content categories interchangeable within budget |
| R6 â€” DI over Singletons | ContextBuilder injected as pipeline service |
| R9 â€” Deterministic | Same input produces same truncation decisions |
| R10 â€” Simpler Over Complex | Priority tiers over complex allocation algorithms |
| R13 â€” Design for Failure | Overflow handled gracefully with truncated sections manifest |
| R14 â€” Paved Path | Default allocation provides safe baseline for all entities |
| R15 â€” Open/Closed | New content categories added without rebuilding pipeline |

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
| Token estimation fails | â€” | Use character-based estimation; log warning |
