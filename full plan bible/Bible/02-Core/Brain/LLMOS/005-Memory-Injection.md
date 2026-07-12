# AIOS Bible â€” Brain/LLMOS
## 005 â€” Memory Injection

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-005 |
| Source Laws | Law 3 â€” Law of Communication (conversation memory) |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 9 â€” Memory Injection |

## Purpose

Memory Injection retrieves relevant memories from the Memory OS and inserts them into the LLMOS context pipeline. This provides the AI model with conversation history, semantic memories, episodic memories, and working memory â€” all within the token budget allocated by Context Builder (Stage 8). The injection happens after context is built but before the prompt is compiled.

## Memory Sources

The Memory OS (Bible/02-Core/Brain/Memory/000-Overview.md) manages four types of memory:

| Source | Type | Description | Retrieval Method |
|--------|------|-------------|------------------|
| Working Memory | Short-term | Active task state, current goals, pinned items | Direct load by session_id |
| Conversation History | Episodic | Recent message exchanges | Time-window query by session_id |
| Semantic Memory | Long-term | Factual knowledge, learned patterns | Vector similarity search |
| Episodic Memory | Long-term | Past task executions and outcomes | Vector similarity + metadata filter |

## Retrieval Algorithm

```typescript
interface RetrievalConfig {
  sources: MemorySource[];
  session_id: UUIDv7;
  query: string;
  max_tokens: u64;
  recency_bias: f64;
  semantic_threshold: f64;
  episodic_threshold: f64;
  max_items_per_source: Map<MemorySource, u64>;
}
```

### Algorithm Steps

1. **Determine slot allocation** â€” split `max_tokens` across enabled sources based on `recency_bias`:
   - `recency_bias < 0.3`: bias toward conversation history (60%) over semantic (40%)
   - `recency_bias > 0.7`: bias toward semantic (60%) over conversation (40%)
   - Otherwise: equal split (50/50)
   - Working memory always gets a reserved minimum (5% of max_tokens)

2. **Query each source** in parallel:
   - Working Memory: Load current session state from Memory OS
   - Conversation History: Query recent messages within session
   - Semantic Memory: Vector search with requester query text, threshold check
   - Episodic Memory: Vector search + session/entity metadata filter, threshold check

3. **Rank and trim per source** â€” within each source's allocated token budget, rank by relevance score (vector similarity for semantic/episodic, recency for conversation), keep highest-ranked items until budget is consumed

4. **Merge into ordered block** â€” place memories in order: Working Memory â†’ Conversation History (most recent first) â†’ Episodic (highest relevance first) â†’ Semantic (highest relevance first)

## Memory Block Schema

```typescript
interface InjectedMemoryBlock {
  source: MemorySource;
  session_id: UUIDv7;
  items: MemoryItem[];
  total_tokens: u64;
}

interface MemoryItem {
  memory_id: UUIDv7;
  content: string;
  token_count: u64;
  relevance_score: f64;
  timestamp: DateTime;
  metadata: MemoryMetadata;
}

interface MemoryMetadata {
  type: MemoryItemType;
  source: string;
  importance: f64;
  tags: string[];
}
```

## Context Injection Format

Memories are injected as structured content blocks with semantic markers:

```
<memories>
  <working_memory>
    [Working memory content â€” current task state]
  </working_memory>

  <conversation_history>
    [Recent conversation turns, formatted as messages]
  </conversation_history>

  <episodic_memory>
    <episode relevance="0.92">
      [Past episode content]
    </episode>
  </episodic_memory>

  <semantic_memory>
    <fact relevance="0.87">
      [Semantic fact content]
    </fact>
  </semantic_memory>
</memories>
```

The XML structure is for semantic tagging â€” the Prompt Compiler (Stage 10) may reformat based on provider convention.

## Binding to ROS

Memory retrieval is a ROS-tracked operation:

```typescript
interface MemoryOperation {
  operation_id: UUIDv7;
  operation_type: "memory_retrieval";
  sources: MemorySource[];
  tokens_retrieved: u64;
  retrieval_duration_us: u64;
  entity_id: UUIDv7;
  session_id: UUIDv7;
}
```

- Each memory retrieval call is recorded as a ROS resource usage event
- Memory retrieval costs are attributed to the requesting entity's budget
- The Memory OS billable operation counter increments per retrieval

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-MEM-001 | Injected memory never exceeds the `max_memory_tokens` allocated by Context Builder. | Algorithmic â€” token budget enforcement |
| LLM-MEM-002 | Memory from a non-enabled source (according to `memory_config`) is never injected. | Schema â€” source enablement gating |
| LLM-MEM-003 | Working memory is always loaded â€” it is not subject to `recency_bias` for inclusion decisions. | Algorithmic â€” unconditional working memory load |
| LLM-MEM-004 | Conversation history maintains message ordering â€” oldest messages may be truncated but ordering is preserved. | Algorithmic â€” ordered merge logic |
| LLM-MEM-005 | Semantic and episodic memories below the similarity threshold are never injected. | Algorithmic â€” threshold-based filtering |
| LLM-MEM-006 | Memory retrieval is a side-effect-free read â€” it never mutates memory state. | Architectural â€” read-only operation |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.MemoryInjected |    request_id, sources_queried, sources_returned, total_memory_tokens, items_by_source, retrieval_duration_us | After injection (Stage 9) |


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
| R1 â€” Modulsingularity | Memory Injection is the sole memory retrieval point in the pipeline |
| R2 â€” Dependency Order | Memory Injection depends on Context Builder budget allocation |
| R3 â€” DRY | Retrieval logic centralized in single algorithm |
| R4 â€” Builder Pattern | InjectedMemoryBlock built through retrieval pipeline |
| R5 â€” Liskov Substitution | All memory sources interchangeable via MemorySource abstraction |
| R6 â€” DI over Singletons | MemoryOS injected as dependency |
| R9 â€” Deterministic | Same session produces same memory retrieval |
| R10 â€” Simpler Over Complex | Structured XML tagging over complex formatting |
| R13 â€” Design for Failure | Empty memory block on source failure |
| R14 â€” Paved Path | Default retrieval config for all sessions |
| R15 â€” Open/Closed | New memory sources added without pipeline changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/Memory/000-Overview.md | Memory OS provides the storage and retrieval APIs consumed by this component |
| LLMOS/004-Context-Builder.md | Defines the token budget that constrains memory injection |
| LLMOS/003-Prompt-Compiler.md | Consumes the injected memory blocks for prompt assembly |
| Bible/02-Core/ROS/000-Overview.md | Memory retrieval is tracked as a ROS resource usage |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Memory OS unavailable | â€” | Skip memory injection; produce warning in Events |
| Memory retrieval timeout (>5s) | â€” | Use whatever memories were retrieved within timeout |
| Session not found | â€” | Skip conversation history; log warning |
| All memory sources return empty | â€” | Inject empty memories block; continue normally |
