# AIOS Bible â€” Brain/LLMOS
## 001 â€” Model Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-001 |
| Source Laws | Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 4 â€” Model Resolution |

## Purpose

The Model Registry maintains a real-time inventory of all available AI models across all configured providers. It resolves model requirements against available models and produces a ranked list of candidates for the Router (Stage 5). The Registry is rebuilt whenever a provider connects, disconnects, or reports a health change.

## Data Model

### ModelEntry

| Field | Type | Description |
|-------|------|-------------|
| `model_id` | string | Unique identifier (e.g., "claude.sonnet:4.0", "ollama.llama3:70b") |
| `provider` | string | Provider name (e.g., "claude", "codex", "ollama") |
| `display_name` | string | Human-readable name (e.g., "Claude Sonnet 4.0") |
| `capabilities` | CapabilitySet | Bitmask of supported capabilities |
| `quality_tier` | QualityTier | Fidelity/capability tier (fast, balanced, high, premium) |
| `context_window` | u64 | Maximum context window size in tokens |
| `max_output_tokens` | u64 | Maximum output tokens |
| `pricing` | PricingModel | Cost structure |
| `pricing. per_input_token` | f64 | Cost per input token |
| `pricing. per_output_token` | f64 | Cost per output token |
| `pricing. per_cached_input_token` | f64 | Cost per cached input token |
| `pricing. per_request` | f64 | Fixed cost per request (if any) |
| `pricing.currency` | string | Currency (e.g., "credits", "usd") |
| `latency_p50` | u64 | P50 latency in ms (rolling window) |
| `latency_p95` | u64 | P95 latency in ms (rolling window) |
| `latency_p99` | u64 | P99 latency in ms (rolling window) |
| `health` | HealthStatus | Current health |
| `health.status` | HealthState | online, degraded, offline, maintenance |
| `health.last_check` | DateTime | Last health check timestamp |
| `health.failure_count` | u64 | Consecutive health check failures |
| `features` | FeatureFlags | Enabled features |
| `features.streaming` | boolean | Supports streaming |
| `features.structured_output` | boolean | Supports structured/JSON output |
| `features.tool_use` | boolean | Supports tool/function calling |
| `features.vision` | boolean | Supports image input |
| `features.code` | boolean | Optimized for code generation |
| `features.multilingual` | boolean | Supports multiple languages natively |
| `features.parallel` | boolean | Supports parallel tool calls |
| `data_residency` | DataResidency[] | Supported data residency regions |
| `max_rate` | u64 | Maximum requests per minute for this model |

### CapabilitySet (bitmask)

```
BIT_VISION            = 1 << 0
BIT_TOOL_USE          = 1 << 1
BIT_STRUCTURED_OUTPUT = 1 << 2
BIT_CODE              = 1 << 3
BIT_EMBEDDING         = 1 << 4
BIT_FUNCTION_CALLING  = 1 << 5
BIT_MULTILINGUAL      = 1 << 6
BIT_STREAMING         = 1 << 7
BIT_PARALLEL_TOOLS    = 1 << 8
BIT_IMAGE_GENERATION  = 1 << 9
BIT_AUDIO             = 1 << 10
BIT_VIDEO             = 1 << 11
BIT_FILE_UPLOAD       = 1 << 12
```

### QualityTier enum

| Value | Description | Example Models |
|-------|-------------|----------------|
| `fast` | Quick responses, lower quality | Ollama TinyLlama, Claude Haiku |
| `balanced` | Good balance of speed and quality | Claude Sonnet, Ollama Llama 3 70B |
| `high` | High quality, higher latency | Claude Opus, GPT-4 |
| `premium` | Maximum quality, highest cost | Claude Opus 4.5, specialized models |

## Operations

### Register (provider â†’ registry)

Called when a Model Provider initializes or a new model is added:

```typescript
async function registerModel(entry: ModelEntry): Promise<void>
```

Validates the entry against schema, checks for duplicate `model_id`, adds to registry, produces `LLMOS.ModelRegistered(model_id, provider, capabilities)` Event.

### Update (provider â†’ registry)

Called when a provider's health or metrics change:

```typescript
async function updateModel(model_id: string, update: Partial<ModelEntry>): Promise<void>
```

Only specific fields are mutable post-registration: `health`, `latency_p50`, `latency_p95`, `latency_p99`. All other fields require deregister + re-register.

### Deregister (provider â†’ registry)

Called when a provider disconnects or a model is removed:

```typescript
async function deregisterModel(model_id: string, reason: string): Promise<void>
```

Produces `LLMOS.ModelDeregistered(model_id, reason)` Event.

### Resolve (pipeline â†’ registry)

The primary pipeline operation â€” resolves requirements to candidates:

```typescript
async function resolveModels(requirements: ModelRequirements): Promise<ModelResolveResult>
```

Algorithm:
1. Filter by capabilities: model must have ALL required capabilities
2. Filter by quality: model tier >= min_quality
3. Filter by data_residency: model supports at least one required region
4. Filter by allow/block lists
5. Filter by health: only online models (degraded models are included but flagged)
6. Filter by context window: context_window >= required_context_window
7. Apply preliminary sort: [cost_efficiency, latency, quality_tier] â€” this is a heuristic pre-sort to limit candidate count; the Router (Stage 6) performs the final composite scoring with entity-specific weights
8. Return top N (default 10) candidates

Returns `ModelResolveResult`:

| Field | Type | Description |
|-------|------|-------------|
| `candidates` | CandidateModel[] | Ranked candidate list (max N) |
| `total_matched` | u64 | Total models matching requirements |
| `filtered_by_capability` | u64 | Count filtered out by capability mismatch |
| `filtered_by_quality` | u64 | Count filtered out by quality tier |
| `filtered_by_residency` | u64 | Count filtered out by data residency |
| `filtered_by_context` | u64 | Count filtered out by context window |
| `filtered_by_allowlist` | u64 | Count filtered out by allow/block lists |
| `filtered_by_health` | u64 | Count filtered out by health status |

### CandidateModel

| Field | Type | Description |
|-------|------|-------------|
| `entry` | ModelEntry | The full model entry |
| `composite_score` | f64 | Composite score for ranking |
| `estimated_cost` | f64 | Cost estimate for this request |
| `estimated_latency` | f64 | Latency estimate based on request size |
| `is_degraded` | boolean | True if health is degraded (not offline) |

## Health Monitoring

The Registry maintains a health check loop for every registered provider:

```typescript
async function performHealthCheck(provider: string): Promise<void>
```

- Checks are performed every 30 seconds per provider
- A provider is marked `degraded` after 3 consecutive failures
- A provider is marked `offline` after 10 consecutive failures
- A provider is marked `maintenance` explicitly via deregister
- Recovery: 1 successful check restores to `online` from any state
- Produces `LLMOS.ProviderHealthChanged(provider, old_state, new_state, reason)` Event

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-REG-001 | Every model in the registry has a unique `model_id` across all providers. | Schema â€” enforced at registration |
| LLM-REG-002 | The registry always contains at least one model for every connected provider. | Architectural â€” lifecycle management |
| LLM-REG-003 | A model cannot be registered without at least one capability. | Schema â€” CapabilitySet validation |
| LLM-REG-004 | Health checks run for every registered provider regardless of usage. | Algorithmic â€” health check loop |
| LLM-REG-005 | Resolve never returns an empty list if at least one model matches requirements. | Algorithmic â€” resolve logic guarantees |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.ModelRegistered |      model_id, provider, capabilities, quality_tier | Provider initialization |
| LLM.ModelDeregistered |      model_id, provider, reason | Provider disconnect or removal |
| LLM.ModelUpdated |      model_id, changed_fields, old_values, new_values | Health/metrics change |
| LLM.ProviderHealthChanged |      provider, old_state, new_state, reason, failure_count | Health check transition |
| LLM.ModelsResolved |      request_id, total_matched, filtered_by_*, candidates_summary | Pipeline Stage 4 |


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
| R1 â€” Modulsingularity | Registry is the sole source of model inventory across all providers |
| R2 â€” Dependency Order | Registry precedes Router and Cost Optimizer in pipeline order |
| R3 â€” DRY | Single ModelEntry schema used across all components |
| R4 â€” Builder Pattern | ModelEntry constructed via builder for validation |
| R5 â€” Liskov Substitution | All providers produce ModelEntry uniformly |
| R6 â€” DI over Singletons | Registry injected into pipeline stages |
| R9 â€” Deterministic | Resolve produces deterministic candidate list for identical input |
| R10 â€” Simpler Over Complex | Bitmask capabilities over complex type system |
| R13 â€” Design for Failure | Health monitoring with degraded/offline states |
| R14 â€” Paved Path | Standardized model registration flow for all providers |
| R15 â€” Open/Closed | New providers add entries without changing registry implementation |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/002-Router.md | Consumes ModelRegistry::resolve() output for model selection |
| LLMOS/013-Provider-SDK.md | Providers implement health check callback consumed by Registry |
| LLMOS/007-Cost-Optimizer.md | Cost optimizer uses pricing data from ModelEntry |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No models match requirements | LLM-0201 | Return empty candidates; caller receives unsupported error |
| All matching models offline | LLM-0202 | Return candidates flagging all as offline; Router handles fallback |
| Provider health check timeout | â€” | Count as failure, move toward degraded/offline thresholds |
