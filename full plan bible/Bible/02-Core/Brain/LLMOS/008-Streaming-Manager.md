# AIOS Bible â€” Brain/LLMOS
## 008 â€” Streaming Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-008 |
| Source Laws | Law 3 â€” Law of Communication |
| Source Physics | Physics/004-Sessions.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 13 â€” Streaming |

## Purpose

The Streaming Manager handles streaming responses from AI providers. It receives a stream of tokens/chunks from the provider, assembles them into a coherent response, manages backpressure, handles mid-stream errors, and supports both real-time delivery (direct chunk forwarding) and buffered delivery (assemble-then-return).

## Stream Types

```typescript
type StreamMode = "direct" | "buffered" | "hybrid";
```

| Mode | Behavior | Latency | Use Case |
|------|----------|---------|----------|
| `direct` | Forward each chunk to caller immediately via ACF stream | Lowest | Interactive chat, real-time UX |
| `buffered` | Assemble full response in memory, return complete output | Highest | Background tasks, API responses |
| `hybrid` | Forward chunks AND assemble full response for validation | Medium | Interactive + validation required |

The mode is determined by:
- `stream=true` + no schema â†’ `direct`
- `stream=true` + schema â†’ `hybrid`
- `stream=false` â†’ `buffered`

## Chunk Schema

```typescript
interface LLMOSChunk {
  sequence: u64;
  request_id: UUIDv7;
  delta: string;
  finish_reason: "stop" | "length" | "content_filter" | "tool_use" | null;
  usage_snapshot: TokenUsage | null;
  metrics_snapshot: StreamMetrics | null;
  tool_call_batch: ToolCallChunk[] | null;
}

interface ToolCallChunk {
  index: u64;
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

interface StreamMetrics {
  tokens_per_second: f64;
  time_to_first_token_ms: u64;
  cumulative_latency_ms: u64;
  chunks_received: u64;
}
```

## Stream Assembly

For `buffered` and `hybrid` modes:

```typescript
interface AssembledResponse {
  request_id: UUIDv7;
  content: string;
  tool_calls: ToolCall[];
  usage: TokenUsage;
  finish_reason: string;
  chunks_received: u64;
  assembly_duration_us: u64;
  stream_metrics: StreamMetrics;
}
```

Assembly algorithm:
1. Concatenate all `delta` fields in sequence order
2. Accumulate tool call arguments (may arrive across multiple chunks)
3. Capture token usage from provider's final message
4. Track metrics: time-to-first-token, tokens-per-second

## Backpressure

```typescript
function handleBackpressure(
  providerStream: ReadableStream<ProviderChunk>,
  callerDemand: DemandSignal
): ControlledStream
```

- Measure caller consumption rate
- If caller rate < provider rate for > 1s: buffer up to 1000 chunks, then signal provider to slow
- If caller rate recovers: release buffered chunks, then resume normal flow
- If buffer exceeds 5000 chunks: drop oldest non-tool chunks, log warning
- Never drop tool call chunks

## Mid-Stream Error Handling

| Error | Position | Behavior |
|-------|----------|----------|
| Provider stream error | Mid-stream | Send error chunk; finalize with finish_reason = "error" |
| Provider timeout | Waiting for chunks | Retry from last confirmed chunk if supported; otherwise fail |
| Connection dropped | Mid-stream | Retry from start; include loss note in metrics |
| Token limit reached | Mid-stream | finish_reason = "length"; finalize normally |
| Content filter triggered | Mid-stream | finish_reason = "content_filter"; flag for guardrail audit |

## Stream Termination

Final chunk contains:
- `delta`: empty string
- `finish_reason`: termination reason
- `usage_snapshot`: final token usage
- `metrics_snapshot`: final stream metrics

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-STR-001 | Every chunk has a monotonically increasing sequence number starting at 1. | Algorithmic â€” sequence tracking |
| LLM-STR-002 | In `direct` mode, chunks are delivered to caller in order with no reordering. | Algorithmic â€” ordered delivery |
| LLM-STR-003 | In `buffered` mode, assembled response is equivalent to non-streamed response. | Algorithmic â€” deterministic assembly |
| LLM-STR-004 | Tool call arguments are accumulated correctly across chunks. | Algorithmic â€” partial tool call accumulation |
| LLM-STR-005 | Backpressure never causes data loss â€” only delays. | Algorithmic â€” buffer management |
| LLM-STR-006 | Every chunk delivered to caller passes through output guardrails (Stage 14) before delivery. | Architectural â€” pipeline stage ordering |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.StreamChunk |  request_id, sequence, delta_length, cumulative_tokens, streaming_latency_ms | Every 10th chunk emitted |
| LLM.StreamCompleted |  request_id, total_chunks, total_tokens, time_to_first_token_ms, tokens_per_second, finish_reason | Stream termination |
| LLM.StreamError |  request_id, sequence_at_error, error_code, was_resumed | Mid-stream error |


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
| R1 â€” Modulsingularity | Streaming Manager is the sole stream handler |
| R2 â€” Dependency Order | Streaming depends on Provider SDK for chunk delivery |
| R3 â€” DRY | Stream modes defined once (direct/buffered/hybrid) |
| R4 â€” Builder Pattern | AssembledResponse built through stream assembly |
| R5 â€” Liskov Substitution | All provider streams handled uniformly |
| R6 â€” DI over Singletons | StreamingManager injected into pipeline |
| R9 â€” Deterministic | Same chunks produce same assembled response |
| R10 â€” Simpler Over Complex | Simple delta concatenation over complex state machines |
| R13 â€” Design for Failure | Backpressure buffer prevents data loss |
| R14 â€” Paved Path | Direct mode provides default streaming behavior |
| R15 â€” Open/Closed | New provider stream formats added without manager changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/012-Response-Validator.md | In hybrid mode, assembled stream output is validated |
| LLMOS/009-Retry-Engine.md | Retry may restart stream from beginning |
| LLMOS/010-Guardrails.md | Output guardrails scan chunks before delivery |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Provider does not support streaming | â€” | Fall back to buffered mode |
| Backpressure buffer overflow | â€” | Drop oldest non-tool chunks |
| Mid-stream content filter trigger | â€” | Continue with finish_reason="content_filter" |
