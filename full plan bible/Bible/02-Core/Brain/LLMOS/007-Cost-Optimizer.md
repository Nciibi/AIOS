# AIOS Bible â€” Brain/LLMOS
## 007 â€” Cost Optimizer

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-007 |
| Source Laws | Law 7 â€” Law of Capability Bounds (cost constraints) |
| Source Physics | Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 5 â€” Cost Optimization |

## Purpose

The Cost Optimizer estimates request cost across candidate models and applies cost-optimization strategies. It runs after the Model Registry resolves candidates (Stage 4) and before the Router selects a model (Stage 6). The optimizer produces per-model cost estimates that feed directly into the Router's scoring function, enabling cost-aware routing decisions.

## Cost Estimation

```typescript
interface CostEstimate {
  request_id: UUIDv7;
  model_id: string;
  provider: string;
  estimated_input_tokens: u64;
  estimated_output_tokens: u64;
  estimated_cached_input_tokens: u64;
  estimated_cached_output_tokens: u64;
  input_cost: f64;
  cached_input_cost: f64;
  output_cost: f64;
  cached_output_cost: f64;
  fixed_cost: f64;
  total_cost: f64;
  provider_discount: f64;
  effective_cost: f64;
  cost_score: f64;
  confidence: f64;
}

function estimateCost(
  request: InferenceRequest,
  model: ModelEntry,
  entity_id: UUIDv7
): CostEstimate
```

### Estimation Algorithm

1. **Token count estimation**: Use Token Budget Manager's estimator to get input token count. Output token count uses `request.max_tokens` or model's default max.

2. **Cache estimation**: If request has cache_policy enabled, estimate what fraction of input tokens will be cached based on:
   - What percentage of the prompt is system prompt + conversation prefix (likely cached)
   - Historical cache hit rate for this entity + model combination
   - Default assumption: 30% cacheable for first request, 60% for subsequent requests in same session

3. **Raw cost calculation**: Multiply token estimates by model pricing from ModelEntry.

4. **Discount application**: Apply entity-specific provider discounts from ROS billing profile.

5. **Score normalization**: `cost_score = 1.0 - (effective_cost / max(cost_of_all_candidates))`

## Optimization Strategies

| Strategy | Description | When Applied |
|----------|-------------|--------------|
| `prompt_slimming` | Suggest removing low-value context/docs to reduce token count | Candidate cost > entity cost sensitivity threshold |
| `model_downgrade` | Suggest a lower-tier model if requirements allow | Cost savings > 40% and quality impact minimal |
| `batching` | Suggest entity batch multiple requests for shared prefix caching | Consecutive requests from same entity within 60s |
| `caching_hint` | Suggest enabling cache if cost savings potential > 10% | Cache disabled and entity has cache_policy allowing hints |
| `time_shift` | Suggest deferring non-urgent requests to off-peak window | Provider has off-peak pricing (future) |

### Strategy Application

```typescript
interface CostOptimizationResult {
  request_id: UUIDv7;
  estimates: CostEstimate[];
  selected_strategy: OptimizationStrategy | null;
  strategy_results: StrategyResult[];
  savings: f64;
  recommended_model: string | null;
}
```

Strategies are advisory â€” the Router may accept or reject the recommendation based on its own scoring.

## Provider-Specific Pricing

```typescript
interface ProviderPricing {
  provider: string;
  base_rates: ModelPricing[];
  entity_rates: Array<{
    entity_id: UUIDv7;
    discounts: ModelDiscount[];
  }>;
  effective_date: DateTime;
  source: "published" | "negotiated" | "estimated";
}

interface ModelPricing {
  model_id: string;
  per_input_token: f64;
  per_output_token: f64;
  per_cached_input_token: f64;
  per_cached_output_token: f64;
  per_request: f64;
  currency: string;
  effective_date: DateTime;
}

interface ModelDiscount {
  model_id: string | null;
  discount_rate: f64;
  reason: string;
}
```

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-CST-001 | Cost estimation is never the sole routing criterion â€” it contributes to Router scoring. | Architectural â€” scoring composition |
| LLM-CST-002 | Cost optimization never suggests a model that violates request model_requirements. | Algorithmic â€” requirement filtering |
| LLM-CST-003 | Entity discounts are never exposed to the calling entity (internal only). | Governance â€” data privacy policy |
| LLM-CST-004 | Cost estimates are recorded in Events even for cache hits (to preserve cost basis). | Architectural â€” event logging invariant |
| LLM-CST-005 | Provider pricing is updated from a central source (ROS billing configuration) â€” never hardcoded. | Governance â€” centralized configuration |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.CostOptimized |   request_id, model_estimates_summary, selected_strategy, strategy_results, estimated_savings, recommended_model | After optimization (Stage 6) |


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
| R1 â€” Modulsingularity | Cost Optimizer is the sole cost estimation authority |
| R2 â€” Dependency Order | Optimizer depends on Registry pricing data |
| R3 â€” DRY | Single estimation algorithm avoids duplication |
| R4 â€” Builder Pattern | CostEstimate built through estimation pipeline |
| R5 â€” Liskov Substitution | All models cost-estimated uniformly |
| R6 â€” DI over Singletons | CostOptimizer injected into pipeline |
| R9 â€” Deterministic | Same request produces same cost estimates |
| R10 â€” Simpler Over Complex | Linear cost scoring over complex financial models |
| R13 â€” Design for Failure | Default pricing when provider data unavailable |
| R14 â€” Paved Path | Standard optimization strategies for all entities |
| R15 â€” Open/Closed | New strategies added without changing core estimation |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/002-Router.md | Router consumes cost scores from Cost Optimizer |
| LLMOS/001-Model-Registry.md | Model pricing data comes from ModelEntry records |
| LLMOS/006-Token-Budget-Manager.md | Token estimator and entity budgets are shared |
| Bible/02-Core/ROS/000-Overview.md | Billing profiles, entity discounts, and pricing sources are managed by ROS |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Pricing data unavailable for model | â€” | Use estimated pricing based on provider average; log warning |
| Entity discount source unreachable | â€” | Apply no discount; return estimate with confidence=0.5 |
| Token estimate uncertain (>20% variance) | â€” | Return estimate with reduced confidence |
