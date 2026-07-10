# AIOS Bible — Execution/LLMOS
## 007 — Cost Optimizer

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/LLMOS |
| Document ID | AIOS-BBL-004-LLM-007 |
| Source Laws | Law 7 — Law of Capability Bounds (cost constraints) |
| Pipeline Stage | 5 — Cost Optimization |

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

Strategies are advisory — the Router may accept or reject the recommendation based on its own scoring.

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

- LLM-CST-001: Cost estimation is never the sole routing criterion — it contributes to Router scoring.
- LLM-CST-002: Cost optimization never suggests a model that violates request model_requirements.
- LLM-CST-003: Entity discounts are never exposed to the calling entity (internal only).
- LLM-CST-004: Cost estimates are recorded in Events even for cache hits (to preserve cost basis).
- LLM-CST-005: Provider pricing is updated from a central source (ROS billing configuration) — never hardcoded.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.CostOptimized` | request_id, model_estimates_summary, selected_strategy, strategy_results, estimated_savings, recommended_model | After optimization (Stage 6) |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/002-Router.md | Router consumes cost scores from Cost Optimizer |
| LLMOS/001-Model-Registry.md | Model pricing data comes from ModelEntry records |
| LLMOS/006-Token-Budget-Manager.md | Token estimator and entity budgets are shared |
| Bible/05-Platform/ROS/000-Overview.md | Billing profiles, entity discounts, and pricing sources are managed by ROS |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Pricing data unavailable for model | — | Use estimated pricing based on provider average; log warning |
| Entity discount source unreachable | — | Apply no discount; return estimate with confidence=0.5 |
| Token estimate uncertain (>20% variance) | — | Return estimate with reduced confidence |
