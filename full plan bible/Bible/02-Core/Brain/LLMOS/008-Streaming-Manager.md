# AIOS Bible — Execution/LLMOS
## 008 — Streaming Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/LLMOS |
| Document ID | AIOS-BBL-004-LLM-008 |
| Source Laws | Law 3 — Law of Communication |
| Pipeline Stage | 13 — Streaming |

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
- `stream=true` + no schema → `direct`
- `stream=true` + schema → `hybrid`
- `stream=false` → `buffered`

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

- LLM-STR-001: Every chunk has a monotonically increasing sequence number starting at 1.
- LLM-STR-002: In `direct` mode, chunks are delivered to caller in order with no reordering.
- LLM-STR-003: In `buffered` mode, assembled response is equivalent to non-streamed response.
- LLM-STR-004: Tool call arguments are accumulated correctly across chunks.
- LLM-STR-005: Backpressure never causes data loss — only delays.
- LLM-STR-006: Every chunk delivered to caller passes through output guardrails (Stage 14 — `LLMOS.GuardrailChecked` with direction=output) before delivery.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.StreamChunk` | request_id, sequence, delta_length, cumulative_tokens, streaming_latency_ms | Every 10th chunk emitted |
| `LLMOS.StreamCompleted` | request_id, total_chunks, total_tokens, time_to_first_token_ms, tokens_per_second, finish_reason | Stream termination |
| `LLMOS.StreamError` | request_id, sequence_at_error, error_code, was_resumed | Mid-stream error |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/012-Response-Validator.md | In hybrid mode, assembled stream output is validated |
| LLMOS/009-Retry-Engine.md | Retry may restart stream from beginning |
| LLMOS/010-Guardrails.md | Output guardrails scan chunks before delivery |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Provider does not support streaming | — | Fall back to buffered mode |
| Backpressure buffer overflow | — | Drop oldest non-tool chunks |
| Mid-stream content filter trigger | — | Continue with finish_reason="content_filter" |
