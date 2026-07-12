# AIOS Bible â€” Brain/LLMOS
## 000 â€” LLMOS: Large Language Model Operating System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-000 |
| Source Laws | Law 2 â€” Law of Non-Execution, Law 3 â€” Law of Communication, Law 7 â€” Law of Capability Bounds, Law 8 â€” Law of Verification-First |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Bible/04-Execution/LLMOS/000-Overview.md (moved to Brain) |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

LLMOS is the dedicated AI inference operating system within AIOS. Every request to an AI model â€” whether for reasoning, generation, embedding, or classification â€” routes through LLMOS. No Worker, Engine, or Service calls an AI provider directly. LLMOS owns model selection, prompt compilation, context management, memory injection, token budgeting, cost optimization, streaming, retry, guardrails, caching, and response validation.

LLMOS transforms AI inference from a direct provider call into a managed, observable, policy-governed subsystem with the same operational rigor as any other AIOS platform service.

## Architecture

```
Sou / Brain Service
         â”‚
         â–¼  (via ACF â€” acf://llmos/inference)
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        LLMOS GATEWAY                           â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚ Request   â”‚  â”‚ Security â”‚  â”‚ Rate     â”‚  â”‚ Token Budget  â”‚  â”‚
â”‚  â”‚ Receiver  â”‚  â”‚ Check    â”‚  â”‚ Limiter  â”‚  â”‚ Check         â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                      LLMOS PIPELINE                            â”‚
â”‚                                                               â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”               â”‚
â”‚  â”‚ MODEL    â”‚â”€â”€â”€â–ºâ”‚ COST     â”‚â”€â”€â”€â–ºâ”‚ ROUTER   â”‚               â”‚
â”‚  â”‚ REGISTRY â”‚    â”‚ OPTIMIZERâ”‚    â”‚          â”‚               â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜               â”‚
â”‚                                      â”‚                       â”‚
â”‚                                      â–¼                       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”               â”‚
â”‚  â”‚ CACHE    â”‚â”€â”€â”€â–ºâ”‚ CONTEXT  â”‚â”€â”€â”€â–ºâ”‚ MEMORY   â”‚               â”‚
â”‚  â”‚ (lookup) â”‚    â”‚ BUILDER  â”‚    â”‚ INJECTIONâ”‚               â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜               â”‚
â”‚       â”‚               â”‚               â”‚                       â”‚
â”‚       â–¼               â–¼               â–¼                       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”               â”‚
â”‚  â”‚ PROMPT   â”‚â”€â”€â”€â–ºâ”‚ GUARDRAILâ”‚â”€â”€â”€â–ºâ”‚ RETRY    â”‚               â”‚
â”‚  â”‚ COMPILER â”‚    â”‚  CHECK   â”‚    â”‚ ENGINE   â”‚               â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜               â”‚
â”‚                        â”‚            â”‚                        â”‚
â”‚                        â–¼            â–¼                        â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”               â”‚
â”‚  â”‚ STREAM   â”‚â”€â”€â”€â–ºâ”‚ GUARDRAILâ”‚â”€â”€â”€â–ºâ”‚ RESPONSE â”‚               â”‚
â”‚  â”‚ MANAGER  â”‚    â”‚ (output) â”‚    â”‚ VALIDATORâ”‚               â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜               â”‚
â”‚       â”‚                                      â”‚               â”‚
â”‚       â–¼                                      â–¼               â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”‚
â”‚  â”‚ PROVIDER â”‚                          â”‚ CACHE    â”‚         â”‚
â”‚  â”‚ SDK LAYERâ”‚                          â”‚ (store)  â”‚         â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚   â”‚
â”‚  â”‚  â”‚ Claude  â”‚ â”‚  Codex  â”‚ â”‚ Ollama  â”‚ â”‚ (future) â”‚  â”‚   â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚   â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚
         â–¼
  AI Provider API (Anthropic, OpenAI, Ollama, etc.)
```

## Pipeline Stages

Every inference request passes through LLMOS in order:

| Stage | Component | Responsibility | Produces Event |
|-------|-----------|----------------|----------------|
| 0 | Gateway | Receive request via ACF, authenticate, validate schema | `LLM.RequestReceived` |
| 1 | Security Check | Verify execution token against Security Council pipeline | `LLM.SecurityChecked` |
| 2 | Rate Limiter | Enforce per-entity rate limits | `LLM.RateChecked` |
| 3 | Token Budget Check | Verify entity has sufficient token budget | `LLM.BudgetChecked` |
| 4 | Model Registry | Resolve available models matching request requirements | `LLM.ModelsResolved` |
| 5 | Cost Optimizer | Estimate cost, apply cost optimization strategies for all candidates | `LLM.CostOptimized` |
| 6 | Router | Select optimal model using cost estimates + capability + latency scoring | `LLM.ModelSelected` |
| 7 | Cache Lookup | Check for cached response (exact or semantic match) | `LLM.CacheHit` / `LLM.CacheMiss` |
| 8 | Context Builder | Manage context window, truncate, prioritize content | `LLM.ContextBuilt` |
| 9 | Memory Injection | Retrieve and inject relevant memories | `LLM.MemoryInjected` |
| 10 | Prompt Compiler | Construct final prompt from template + context + memory | `LLM.PromptCompiled` |
| 11 | Guardrail Check | Scan prompt for policy violations | `LLM.GuardrailChecked` |
| 12 | Retry Engine | Send to provider, handle failures with retry/fallback | `LLM.ProviderCalled` |
| 13 | Streaming Manager | Manage streaming response, assemble chunks | `LLM.StreamChunk` |
| 14 | Guardrail Check (output) | Scan response for policy violations | `LLM.GuardrailChecked` (direction=output) |
| 15 | Response Validator | Validate structured output against schema | `LLM.ResponseValidated` |
| 16 | Cache Store | Store response in cache | `LLM.CacheStored` |
| 17 | Post-Processing | Update budgets, record metrics, produce final Event | `LLM.RequestCompleted` |

Stages 0-3 are gateway. Stages 4-11 are pre-processing. Stages 12-13 are execution. Stages 14-17 are post-processing.

## Request Schema

Every LLMOS request uses this envelope:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | UUIDv7 | Yes | Unique request identifier |
| `entity_id` | UUIDv7 | Yes | Requesting entity (Worker, Engine, Service) |
| `execution_token` | string | Yes | Validated token from Security Council pipeline |
| `model_requirements` | ModelRequirements | Yes | Capabilities, speed, cost constraints |
| `messages` | Message[] | Yes* | Conversation messages (alternative to prompt_template) |
| `prompt_template` | string | No* | Prompt template reference (alternative to messages) |
| `template_variables` | Map<string, any> | No | Variables for prompt template interpolation |
| `context` | RequestContext | No | Additional context, documents, references |
| `memory_config` | MemoryConfig | No | Memory retrieval configuration |
| `response_schema` | Schema | No | Expected output schema for structured generation |
| `stream` | boolean | No | Request streaming response (default: false) |
| `max_tokens` | u64 | No | Maximum output tokens (default: from capability bounds) |
| `temperature` | f64 | No | Generation temperature (default: from model config) |
| `stop_sequences` | string[] | No | Custom stop sequences |
| `cache_policy` | CachePolicy | No | Cache read/write behavior |
| `guardrail_overrides` | GuardrailOverride[] | No | Explicit guardrail configuration |
| `priority` | Priority | No | Request priority (default: normal) |

\* Exactly one of `messages` or `prompt_template` must be provided.

## Response Schema

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | UUIDv7 | Matching request identifier |
| `output` | Output | Generated content (text, structured data, or stream reference) |
| `model_used` | string | Model that served the request |
| `usage` | TokenUsage | Input tokens, output tokens, cached tokens |
| `cost` | CostBreakdown | Cost in credits and estimated USD |
| `latency_ms` | u64 | End-to-end latency |
| `cache_hit` | boolean | Whether response was served from cache |
| `guardrail_results` | GuardrailResult[] | Guardrails evaluated and their outcomes |
| `metrics` | LLMMetrics | Provider metrics, retry count, fallback chain |
| `error` | ErrorInfo | Present only on failure |

## Streaming Response

For streaming requests, LLMOS returns a stream of `LLMOSChunk` objects:

| Field | Type | Description |
|-------|------|-------------|
| `sequence` | u64 | Monotonic chunk sequence number |
| `request_id` | UUIDv7 | Matching request identifier |
| `delta` | string | Text delta for this chunk |
| `finish_reason` | string | Present only on final chunk â€” stop, length, content_filter |
| `usage` | TokenUsage | Cumulative token usage at this point |
| `metrics` | StreamMetrics | Cumulative latency, token rate |

The stream terminates with a final `LLMOSChunk` where `finish_reason` is set.

## Model Requirements

Requesters specify model requirements to constrain routing:

| Field | Type | Description |
|-------|------|-------------|
| `capabilities` | Capability[] | Required capabilities (vision, tools, structured_output, code, embedding, function_calling, multilingual) |
| `min_quality` | QualityTier | Minimum model quality tier (fast, balanced, high, premium) |
| `max_latency_ms` | u64 | Maximum acceptable latency |
| `max_cost` | CostLimit | Maximum acceptable cost per request |
| `allowed_providers` | string[] | Restrict to specific providers (e.g., ["claude", "ollama"]) |
| `blocked_providers` | string[] | Exclude specific providers |
| `allowed_models` | string[] | Restrict to specific models |
| `blocked_models` | string[] | Exclude specific models |
| `required_context_window` | u64 | Minimum context window size in tokens |
| `data_residency` | DataResidency | Data residency requirement (local, region, any) |

## Memory Config

Controls what memory LLMOS injects into the context:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | UUIDv7 | Active session for conversation memory |
| `include_working_memory` | boolean | Include current working memory |
| `include_conversation_history` | boolean | Include recent conversation turns |
| `include_semantic_memory` | boolean | Include semantically relevant memories |
| `include_episodic_memory` | boolean | Include task-relevant past episodes |
| `max_memory_tokens` | u64 | Maximum tokens for injected memory |
| `memory_recency_bias` | f64 | Preference for recent vs. relevant memory (0.0=recent, 1.0=relevant) |

## Events

| LLM.EventType |      Produced By | Fields |
|------------|-------------|--------|
| LLM.RequestReceived |      Gateway | request_id, entity_id, model_requirements_summary |
| LLM.SecurityChecked |      Gateway | request_id, entity_id, pipeline_result |
| LLM.RateChecked |      Gateway | request_id, entity_id, remaining, limit, reset_at |
| LLM.BudgetChecked |      Gateway | request_id, entity_id, budget_before, budget_after |
| LLM.BudgetReconciled |      Token Budget Manager | request_id, actual_tokens, estimated_tokens, difference, adjusted_cost |
| LLM.ModelsResolved |      Model Registry | request_id, matched_model_count, model_list |
| LLM.ModelSelected |      Router | request_id, model_selected, selection_reason, alternatives_considered |
| LLM.CostOptimized |      Cost Optimizer | request_id, estimated_cost, optimization_strategy, savings |
| LLM.CacheHit |      Cache | request_id, cache_key, age, similarity_score |
| LLM.CacheMiss |      Cache | request_id, cache_key, reason |
| LLM.CacheStored |      Cache | request_id, cache_key, ttl, storage_size_bytes |
| LLM.CacheEvicted |      Cache | cache_key, reason, age, access_count, saved_cost_total |
| LLM.ContextBuilt |      Context Builder | request_id, total_tokens, input_tokens, truncated_sections |
| LLM.MemoryInjected |      Memory Injection | request_id, memory_sources, total_memory_tokens, sources_count |
| LLM.PromptCompiled |      Prompt Compiler | request_id, template_used, compiled_length_tokens, compile_duration_us |
| LLM.GuardrailChecked |      Guardrails | request_id, direction(input/output), rules_evaluated, blocked, matched_rules |
| LLM.ModelRegistered |      Model Registry | model_id, provider, capabilities, quality_tier |
| LLM.ModelDeregistered |      Model Registry | model_id, provider, reason |
| LLM.ProviderRegistered |      Provider SDK | provider_name, version, model_count, registered_at |
| LLM.ProviderDeregistered |      Provider SDK | provider_name, reason, uptime_seconds |
| LLM.ProviderHealthChanged |      Model Registry | provider, old_state, new_state, reason, failure_count |
| LLM.ProviderCalled |      Retry Engine | request_id, provider, model, attempt, is_fallback, latency_ms, tokens_consumed |
| LLM.ProviderRetry |      Retry Engine | request_id, attempt, error, backoff_ms, fallback_activated |
| LLM.CircuitBreakerOpened |      Retry Engine | model_id, provider, failure_count, opened_at |
| LLM.CircuitBreakerClosed |      Retry Engine | model_id, provider, recovery_success_count, closed_at |
| LLM.StreamChunk |      Streaming Manager | request_id, sequence, cumulative_tokens, streaming_latency_ms |
| LLM.StreamCompleted |      Streaming Manager | request_id, total_chunks, total_tokens, time_to_first_token_ms, tokens_per_second |
| LLM.StreamError |      Streaming Manager | request_id, sequence_at_error, error_code, was_resumed |
| LLM.ResponseValidated |      Response Validator | request_id, schema_name, valid, errors |
| LLM.ResponseValidationFailed |      Response Validator | request_id, validation_types, errors, retry_strategy |
| LLM.ResponseValidationRetry |      Response Validator | request_id, retry_number, strategy, adjusted_parameters |
| LLM.RequestCompleted |      Pipeline | request_id, total_duration_ms, total_cost, total_tokens, cache_hit |
| LLM.RequestFailed |      Pipeline | request_id, stage, error_code, error_message, recovery_attempted |

## Error Codes

| Code | Stage | Condition | Recovery |
|------|-------|-----------|----------|
| LLM-0001 | Gateway | Invalid request schema | Return validation error to caller |
| LLM-0002 | Gateway | Expired or invalid execution token | Reject; caller must re-authenticate |
| LLM-0101 | Rate Limiter | Rate limit exceeded | Return Retry-After header; caller must wait |
| LLM-0102 | Budget Check | Token budget exhausted | Return budget exceeded; caller must request top-up |
| LLM-0201 | Model Registry | No models match requirements | Return unsupported; caller must relax requirements |
| LLM-0202 | Router | Selected model unavailable | Trigger fallback; return degraded status |
| LLM-0301 | Prompt Compiler | Template not found | Return template error |
| LLM-0302 | Context Builder | Context exceeds max context window | Return context overflow; caller must reduce input |
| LLM-0401 | Guardrails | Input blocked by guardrail | Return blocked with matched rule details |
| LLM-0402 | Guardrails | Output blocked by guardrail | Return blocked with matched rule details |
| LLM-0501 | Retry Engine | All retries exhausted | Return provider unavailable; include last error |
| LLM-0502 | Retry Engine | All fallbacks exhausted | Return all providers unavailable |
| LLM-0601 | Response Validator | Output failed schema validation | Return validation error with details |
| LLM-0602 | Response Validator | Structured output parse failure | Return parse error; request retry with relaxed schema |
| LLM-0701 | Provider | Provider returned error | Return provider error with details |
| LLM-0702 | Provider | Provider timeout | Return timeout; suggest smaller model |
| LLM-9999 | Any | Internal LLMOS error | Return internal error; escalate to operator |

## Pipeline Invariants

- LLM-INV-001: Every request produces exactly one terminal Event (Completed or Failed).
- LLM-INV-002: Pipeline stages execute in order; no stage may be skipped.
- LLM-INV-003: No Worker or Engine calls an AI provider directly â€” all AI traffic passes through LLMOS.
- LLM-INV-004: Gate stages (0-3) run before any model selection occurs.
- LLM-INV-005: Guardrails run twice â€” on input (Stage 11) and on output (Stage 14).
- LLM-INV-006: Cache is checked before provider call; cache is written after response validation.
- LLM-INV-007: Cost optimization never selects a model that violates the requester's constraints.
- LLM-INV-008: Memory injection never exceeds the configured `max_memory_tokens`.
- LLM-INV-009: All token usage is tracked and reported regardless of cache hit or failure.


## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |

## Cross-Cutting Concerns

### Security

Every LLMOS request carries an execution token validated by the Security Council pipeline (7-stage). LLMOS itself authenticates to ACF with its own identity. Provider API credentials are managed by SSM and resolved at invocation time â€” never stored in LLMOS memory between requests. All provider communication uses TLS 1.3. LLMOS enforces data residency constraints when routing to cloud providers.

### Evidence

Every pipeline stage produces at least one Event. The terminal Event (Completed/Failed) contains the complete cost and usage breakdown for audit and billing. Cache hits are still recorded as Events with the original cost basis preserved.

### Lifecycle

LLMOS has no persistent state â€” it is stateless across requests. The Model Registry is rebuilt on startup from provider health checks. The Cache is backed by EVS for persistence. Per-entity token budgets are managed by ROS and consulted at Stage 3.

### Capability Bounds

LLMOS enforces capability bounds at two levels: (1) the execution token from the Security Council constrains which models, token budgets, and capabilities the entity may access; (2) LLMOS's own rate limiter and budget tracker provide a second layer of enforcement.

### Communication

Workers and Engines communicate with LLMOS over ACF using the `acf://llmos/inference` endpoint. LLMOS communicates with AI providers through their native APIs wrapped by the Provider SDK. LLMOS does not expose any direct network-accessible endpoints.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 â€” Modulsingularity | LLMOS does one thing: manage AI model inference through a standardized pipeline. |
| R2 â€” Dependency Order | LLMOS depends on ACF (communication), EVS (events), SSM (secrets), ROS (budgets). No cycles. |
| R3 â€” DRY | Model selection, prompt compilation, guardrails, caching are in LLMOS â€” not duplicated across providers or Workers. |
| R4 â€” Builder Pattern | The final provider request is built incrementally through Context Builder, Memory Injection, and Prompt Compiler. |
| R5 â€” Liskov Substitution | Every Model Provider implements the same `ModelProvider` interface. Providers are drop-in replaceable. |
| R6 â€” DI over Singletons | Model Provider dependencies (API keys, endpoints) are injected through the SDK's `initialize()` method. |
| R7 â€” Tests Exist | Every pipeline component has unit tests. Integration tests route through a mock Provider SDK. |
| R8 â€” Fast Tests | Pipeline tests complete in < 100ms using in-memory mock providers and cache backends. |
| R9 â€” Deterministic | Model selection is deterministic for the same inputs. Provider nondeterminism is contained in Stage 12. |
| R10 â€” Simpler Over Complex | The pipeline is sequential and linear. No branching except for streaming vs. non-streaming. |
| R11 â€” Refactor over Rewrite | New pipeline stages can be inserted without modifying existing stages. New providers implement existing interfaces. |
| R12 â€” Embrace Errors | Every error has a unique LLM-NNNN code with stage, condition, and recovery path. |
| R13 â€” Design for Failure | Retry Engine handles provider failures. Fallback chains handle model unavailability. Cache provides degradation path. |
| R14 â€” Paved Path | The paved path is Stages 0-17 in order. No alternative pipeline flow. |
| R15 â€” Open/Closed | New AI providers implement the `ModelProvider` interface without modifying the LLMOS pipeline. |

## Relationship to Runtime SDK

The existing Runtime SDK (`Bible/04-Execution/Runtime/001-SDK.md`) defines the `ExecutionProvider` interface for runtime execution. LLMOS introduces a new `ModelProvider` interface (see `013-Provider-SDK.md`) specifically for AI model providers. The two coexist:

- **Execution Providers** (Browser, Trading, Robotics) implement `ExecutionProvider` and are called through the Runtime Manager.
- **Model Providers** (Claude, Codex, Ollama) implement `ModelProvider` and are called through LLMOS.
- **Dual-implementation providers** (Claude, Codex, Ollama) implement both interfaces for backward compatibility during migration. The LLMOS path is the canonical path; the direct Runtime path is deprecated.

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/LLMOS/001-Model-Registry.md | Model registration and discovery |
| Bible/02-Core/Brain/LLMOS/002-Router.md | Request routing and model selection |
| Bible/02-Core/Brain/LLMOS/003-Prompt-Compiler.md | Prompt construction from templates |
| Bible/02-Core/Brain/LLMOS/004-Context-Builder.md | Context window management |
| Bible/02-Core/Brain/LLMOS/005-Memory-Injection.md | Memory retrieval and injection |
| Bible/02-Core/Brain/LLMOS/006-Token-Budget-Manager.md | Token budget tracking and enforcement |
| Bible/02-Core/Brain/LLMOS/007-Cost-Optimizer.md | Cost estimation and optimization |
| Bible/02-Core/Brain/LLMOS/008-Streaming-Manager.md | Streaming response management |
| Bible/02-Core/Brain/LLMOS/009-Retry-Engine.md | Retry logic and fallback chains |
| Bible/02-Core/Brain/LLMOS/010-Guardrails.md | Content filtering and constitutional bounds |
| Bible/02-Core/Brain/LLMOS/011-Cache.md | Response caching |
| Bible/02-Core/Brain/LLMOS/012-Response-Validator.md | Structured output validation |
| Bible/02-Core/Brain/LLMOS/013-Provider-SDK.md | Model provider implementation interface |
| Bible/04-Execution/Runtime/001-SDK.md | Existing Execution Provider SDK (dual-interface providers) |
| Bible/04-Execution/Runtime/002-Claude.md | Claude provider (LLMOS model provider) |
| Bible/04-Execution/Runtime/004-Ollama.md | Ollama provider (LLMOS model provider) |
| Bible/06-Services/ACF/000-Overview.md | Communication substrate for LLMOS requests |
| Bible/05-Platform/004-EVS.md | Event Store for LLMOS pipeline events |
| Bible/04-Execution/Security/SSM/000-SSM.md | Secret management for provider API keys |
| Physics/010-Execution.md | Execution invariants for model inference |
| Physics/007-Capabilities.md | Capability bounds for token budgets and model selection |
