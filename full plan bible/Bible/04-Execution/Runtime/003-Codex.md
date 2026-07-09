# AIOS Bible — Execution
## 003 — OpenAI Codex Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-003 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Codex Provider executes model inference and code generation actions against OpenAI's API (GPT-4, GPT-4o, GPT-4o-mini, o-series reasoning models). It handles chat completions, structured output generation, and streaming inference within the constitutional bounds defined by the execution token.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.codex` |
| action_types | `model.inference`, `model.inference.stream`, `model.codegen` |
| max_parallelism | 100 concurrent executions |
| default_timeout_ms | 180000 (3 minutes) |
| supported_autonomy_levels | L0, L1, L2, L3, L4 |
| supported_models | gpt-4o, gpt-4o-mini, gpt-4-turbo, o1, o3-mini |

## Capabilities

### Chat Completions

The provider executes standard chat completion requests. Action parameters include: model, messages, temperature, top_p, max_completion_tokens, response_format (text, json_schema), tools, tool_choice, stop, and seed. The provider validates that the requested `response_format` is within the entity's declared capability scope.

### Code Generation

The `model.codegen` action type extends chat completions with code-specific parameters: language, max_lines, include_tests, and style_guide. The provider enforces code generation bounds — max lines per file, allowed languages, and prohibited patterns (eval, exec, unsafe operations) — as defined by the capability bounds in the execution token.

### Structured Output

When `response_format` is `json_schema`, the provider validates the schema against the entity's data handling capability. Schemas that request data beyond the entity's authorized scope are rejected at the provider level before any API call is made.

## Streaming Behavior

Streaming executions emit one chunk per content delta. For code generation actions, chunks correspond to token-level deltas. The provider includes cumulative token counts and estimated progress in each chunk.

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| CDX-0001 | API key invalid or quota exhausted | Escalate to Security Council; deny execution |
| CDX-1001 | Rate limited (HTTP 429) | Exponential backoff with jitter; max 5 retries |
| CDX-2001 | Model not found or deprecated | Return Unsupported error; trigger provider capability refresh |
| CDX-3001 | Content policy violation | Return filtered response with violation_category |
| CDX-4001 | Response exceeds model context window | Truncate input and retry; log context window warning |
| CDX-5001 | Unsupported response_format | Validate schema against action_type before API call |

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Codex.InferenceStarted` | execution_id, model, action_type, input_tokens |
| `Provider.Codex.InferenceChunk` | execution_id, sequence, delta_type, cumulative_tokens |
| `Provider.Codex.InferenceCompleted` | execution_id, model, output_tokens, finish_reason, duration_ms |
| `Provider.Codex.InferenceFailed` | execution_id, error_code, error_message, retry_count |

## Cross-Cutting Concerns

### Security

All API keys are managed through the Runtime Manager's secret store. The provider validates that the requested model's capabilities (vision, function calling, structured output) are within the entity's capability declaration before making API calls. Code generation outputs are scanned for prohibited patterns before return.

### Evidence

Every code generation action produces a CodeGenStarted, per-chunk (if streaming), and CodeGenCompleted/Failed Event chain. Generated code size and language are recorded in the completion Event for audit.

### Lifecycle

The provider maintains a connection pool to the OpenAI API. On `initialize()`, it validates API key permissions against the declared action types. Health checks verify API reachability and key validity.

### Capability Bounds

The provider enforces token budgets per execution, rate limits per entity, model-specific constraints (context window, supported features), and code generation bounds (max lines, allowed languages, prohibited patterns). All bounds are enforced through the SDK middleware.

### Communication

The provider communicates with the OpenAI REST API over HTTPS. Streaming uses server-sent events (SSE). Provider-to-Runtime communication uses the SDK interface only.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles inference and codegen — two closely related action types under one domain |
| R5 | Interchangeable with any model provider; `model.codegen` is unique to this provider |
| R10 | Execution path is linear with optional structured output validation step |
| R12 | All OpenAI API errors map to CDX-NNNN codes |
| R13 | Rate limit retries with jitter; model deprecation triggers capability refresh |
| R14 | Paved path: validate model → validate schema → call API → scan code → return |
| R15 | New models added through configuration in the provider's model registry |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Physics/010-Execution.md | Execution invariants for model inference |
| Physics/007-Capabilities.md | Capability bounds for token budgets and codegen scope |
