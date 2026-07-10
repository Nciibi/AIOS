# AIOS Bible — Execution/LLMOS
## 005 — Memory Injection

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/LLMOS |
| Document ID | AIOS-BBL-004-LLM-005 |
| Source Laws | Law 3 — Law of Communication (conversation memory) |
| Pipeline Stage | 9 — Memory Injection |

## Purpose

Memory Injection retrieves relevant memories from the Memory OS and inserts them into the LLMOS context pipeline. This provides the AI model with conversation history, semantic memories, episodic memories, and working memory — all within the token budget allocated by Context Builder (Stage 8). The injection happens after context is built but before the prompt is compiled.

## Memory Sources

The Memory OS (Bible/03-OS/Memory) manages four types of memory:

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

1. **Determine slot allocation** — split `max_tokens` across enabled sources based on `recency_bias`:
   - `recency_bias < 0.3`: bias toward conversation history (60%) over semantic (40%)
   - `recency_bias > 0.7`: bias toward semantic (60%) over conversation (40%)
   - Otherwise: equal split (50/50)
   - Working memory always gets a reserved minimum (5% of max_tokens)

2. **Query each source** in parallel:
   - Working Memory: Load current session state from Memory OS
   - Conversation History: Query recent messages within session
   - Semantic Memory: Vector search with requester query text, threshold check
   - Episodic Memory: Vector search + session/entity metadata filter, threshold check

3. **Rank and trim per source** — within each source's allocated token budget, rank by relevance score (vector similarity for semantic/episodic, recency for conversation), keep highest-ranked items until budget is consumed

4. **Merge into ordered block** — place memories in order: Working Memory → Conversation History (most recent first) → Episodic (highest relevance first) → Semantic (highest relevance first)

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
    [Working memory content — current task state]
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

The XML structure is for semantic tagging — the Prompt Compiler (Stage 10) may reformat based on provider convention.

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

- LLM-MEM-001: Injected memory never exceeds the `max_memory_tokens` allocated by Context Builder.
- LLM-MEM-002: Memory from a non-enabled source (according to `memory_config`) is never injected.
- LLM-MEM-003: Working memory is always loaded — it is not subject to `recency_bias` for inclusion decisions.
- LLM-MEM-004: Conversation history maintains message ordering — oldest messages may be truncated but ordering is preserved.
- LLM-MEM-005: Semantic and episodic memories below the similarity threshold are never injected.
- LLM-MEM-006: Memory retrieval is a side-effect-free read — it never mutates memory state.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.MemoryInjected` | request_id, sources_queried, sources_returned, total_memory_tokens, items_by_source, retrieval_duration_us | After injection (Stage 9) |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/03-OS/Memory/* | Memory OS provides the storage and retrieval APIs consumed by this component |
| LLMOS/004-Context-Builder.md | Defines the token budget that constrains memory injection |
| LLMOS/003-Prompt-Compiler.md | Consumes the injected memory blocks for prompt assembly |
| Bible/05-Platform/ROS/000-Overview.md | Memory retrieval is tracked as a ROS resource usage |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Memory OS unavailable | — | Skip memory injection; produce warning in Events |
| Memory retrieval timeout (>5s) | — | Use whatever memories were retrieved within timeout |
| Session not found | — | Skip conversation history; log warning |
| All memory sources return empty | — | Inject empty memories block; continue normally |
