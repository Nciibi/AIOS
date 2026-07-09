# AIOS Bible — Execution
## 002 — Anthropic Claude Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-002 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Claude Provider is an Execution Provider that executes model inference actions against Anthropic's Claude API (Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku). It receives verified execution tokens from the Runtime Manager, calls the Anthropic API within declared capability bounds, streams responses where requested, and produces execution Events.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.claude` |
| action_types | `model.inference`, `model.inference.stream` |
| max_parallelism | 50 concurrent executions |
| default_timeout_ms | 120000 (2 minutes) |
| supported_autonomy_levels | L0, L1, L2, L3, L4 |
| supported_models | claude-3-5-sonnet-latest, claude-3-opus-latest, claude-3-haiku-latest |

## Execution Flow

1. Runtime Manager dispatches a `model.inference` action to the Claude Provider with a validated execution token
2. Provider reads the action parameters: model name, system prompt, messages, temperature, max_tokens, stop_sequences
3. Provider resolves API credentials from the Runtime Manager's secret store (never stored in provider memory)
4. Provider checks rate limits against the token's capability bounds
5. Provider calls the Anthropic Messages API with the configured parameters
6. Provider monitors token consumption against the capability budget
7. If `action_type` is `model.inference.stream`, the provider returns a stream of `ExecutionChunk` objects
8. On completion, the provider produces an `ExecutionResult` with the model response and usage metrics

## Streaming Behavior

For streaming executions, the provider emits one chunk per content delta received from the SSE stream. Each chunk includes: the delta text, cumulative token counts, and the provider's estimated progress. The final chunk includes the full stop_reason and usage statistics.

## Token Budget Enforcement

The provider tracks input tokens (system prompt + messages) and output tokens (completion) separately. The capability bounds from the execution token specify `max_input_tokens`, `max_output_tokens`, and `max_total_tokens`. The provider enforces all three limits. If output generation approaches the limit (90%), the provider sends a warning chunk. At 100%, the provider terminates the stream and returns a `BoundsExceeded` error.

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| CLD-0001 | API key not configured or expired | Escalate to Security Council; deny execution |
| CLD-1001 | Rate limit exceeded | Back off and retry with exponential backoff (max 3 retries) |
| CLD-2001 | Model unavailable or overloaded | Return provider degradation status; fail over if secondary model configured |
| CLD-3001 | Content filter triggered | Return filtered response with filter_reason |
| CLD-4001 | Response exceeds max_output_tokens | Truncate response; return BoundsExceeded warning |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| api_endpoint | `https://api.anthropic.com/v1/messages` | Anthropic API endpoint |
| default_model | `claude-3-5-sonnet-latest` | Default model for inference |
| max_retries | 3 | Maximum retry attempts on rate limit or transient errors |
| retry_backoff_ms | 1000 | Initial backoff in milliseconds (doubles per retry) |
| connection_pool_size | 10 | Maximum concurrent HTTP connections to the Anthropic API |
| request_timeout_ms | 60000 | HTTP request timeout for individual API calls |
| secondary_model | None | Model to fail over to when primary is unavailable |

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Empty message list | Provider returns ValidationError before API call |
| System prompt exceeds max_input_tokens | Truncate system prompt; emit warning Event |
| Streaming connection interrupted mid-response | Return partial completion with interrupted status |
| Model returns unexpected stop_reason | Map to CLD-3002; log for analysis |
| API version mismatch | Negotiate API version; fail closed if incompatible |

## Integration Patterns

The Claude Provider is typically used as the primary model provider for Sou Reasoning and Worker Session execution. It integrates with the Knowledge Graph via embedding-capable Claude models to provide semantic search over Academy knowledge. For cost-sensitive operations, the provider supports automatic fallback from Claude Opus to Claude Sonnet or Claude Haiku based on token budget thresholds declared in the capability bounds.

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Claude.InferenceStarted` | execution_id, model, input_token_count, max_tokens |
| `Provider.Claude.InferenceChunk` | execution_id, sequence, delta_length, cumulative_tokens |
| `Provider.Claude.InferenceCompleted` | execution_id, model, output_token_count, stop_reason, duration_ms |
| `Provider.Claude.InferenceFailed` | execution_id, error_code, error_message, partial_output |

## Cross-Cutting Concerns

### Security

API credentials are resolved through the Runtime Manager's secret store at invocation time. Credentials are never cached in provider memory. All API calls use TLS 1.3. The provider validates that the requested model is within the entity's capability bounds before making any API call.

### Evidence

Every inference produces at minimum three Events: InferenceStarted, InferenceCompleted (or InferenceFailed), and per-chunk Events for streaming executions. Token consumption is recorded in every Event for cost accounting.

### Lifecycle

The provider maintains a persistent HTTP connection pool to the Anthropic API. On `initialize()`, it authenticates and validates API access. On `shutdown()`, it drains pending requests and closes all connections. Health checks verify API reachability and authentication status.

### Capability Bounds

The provider enforces token budgets (input, output, total), rate limits (requests per minute, tokens per minute), and model-specific constraints (max context window, supported capabilities). All bounds are declared in the capability declaration and enforced through the SDK middleware.

### Communication

The provider communicates with the Anthropic API over HTTPS. All provider-to-Runtime communication uses the SDK interface. The provider does not expose any network-accessible endpoints.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles only model inference — no tool execution, no data storage |
| R5 | Interchangeable with any model provider implementing the same action types |
| R10 | Inference path is linear: validate → resolve → call → return |
| R12 | All Claude API errors map to structured CLD-NNNN error codes |
| R13 | Rate limit retries with backoff; model unavailability triggers failover |
| R14 | Paved path: token → validate bounds → call API → produce Event → return |
| R15 | New Claude models are added via configuration, not code changes |

## Performance Characteristics

| Metric | Target | Notes |
|--------|--------|-------|
| Time to first token (non-streaming) | < 500ms | Dependent on Anthropic API latency |
| Time to first token (streaming) | < 300ms | SSE connection establishment overhead |
| Throughput per connection | 10 req/s | Limited by Anthropic rate limits |
| Token sampling overhead | < 5ms | SDK middleware processing per token |
| Connection reuse | Keep-alive pool | 10 pooled connections, 60s idle timeout |

## Autonomy Level Behavior

| Level | Behavior |
|-------|----------|
| L0 | Every inference requires explicit human approval of the prompt before API call |
| L1 | Inference proceeds autonomously; responses require human confirmation before delivery |
| L2 | Inference and response delivery are fully autonomous within token budget bounds |
| L3 | Provider may optimise model selection based on task complexity within capability bounds |
| L4 | Provider may initiate inference proactively based on entity's mission context |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Physics/010-Execution.md | Execution invariants for model inference |
| Physics/007-Capabilities.md | Capability bounds for token budgets |
