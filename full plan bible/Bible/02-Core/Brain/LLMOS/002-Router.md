# AIOS Bible â€” Brain/LLMOS
## 002 â€” Router

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-002 |
| Source Laws | Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 6 â€” Model Selection |

## Purpose

The Router selects the optimal model for a given request from the candidate list produced by the Model Registry (Stage 4) with cost estimates from the Cost Optimizer (Stage 5). Selection decisions balance cost, latency, capability, and entity-specific preferences. The Router is the central intelligence for model routing â€” it is the only component that decides which model serves which request.

## Selection Algorithm

The Router uses a weighted scoring function across four dimensions:

```typescript
interface SelectionConfig {
  cost_weight: f64;      // default 0.35
  latency_weight: f64;   // default 0.25
  quality_weight: f64;   // default 0.30
  reliability_weight: f64; // default 0.10
  entity_overrides: Map<EntityID, SelectionConfig>;
}

function computeScore(candidate: CandidateModel, request: InferenceRequest, config: SelectionConfig): f64 {
  let cost_score = normalizeCost(candidate, request);
  let latency_score = normalizeLatency(candidate, request);
  let quality_score = candidate.entry.quality_tier.numericValue();
  let reliability_score = normalizeReliability(candidate);

  return config.cost_weight * cost_score
       + config.latency_weight * latency_score
       + config.quality_weight * quality_score
       + config.reliability_weight * reliability_score;
}
```

### Normalization

Each raw metric is normalized to [0.0, 1.0] where 1.0 is best:

- **Cost**: `1.0 - (estimated_cost / max_cost_in_candidates)` â€” cheapest model scores 1.0
- **Latency**: `1.0 - (estimated_latency / max_latency_in_candidates)` â€” fastest model scores 1.0
- **Quality**: Numeric mapping of QualityTier: fast=0.25, balanced=0.50, high=0.75, premium=1.0
- **Reliability**: `1.0 - (failure_count_in_window / max_acceptable_failures)` â€” health score based on recent failure rate

### Entity-Specific Overrides

Entities can override weights via their Security Council-verified profile:

```typescript
interface EntityModelProfile {
  entity_id: UUIDv7;
  preferred_providers: string[];          // boost these providers
  blocked_providers: string[];            // block these providers
  preferred_models: string[];             // exact model IDs preferred
  cost_sensitivity: CostSensitivity;      // low, normal, high
  latency_sensitivity: LatencySensitivity; // low, normal, high
  quality_floor: QualityTier;             // never route below this tier
  custom_weights: Partial<SelectionConfig>;
}
```

## Routing Modes

| Mode | Behavior | When Used |
|------|----------|-----------|
| `auto` | Full scoring, selects highest score | Default for Workers without explicit model choice |
| `cost_optimized` | Cost weight = 0.8, latency = 0.1, quality = 0.05, reliability = 0.05 | Batch processing, non-critical tasks |
| `latency_optimized` | Latency weight = 0.7, cost = 0.1, quality = 0.1, reliability = 0.1 | Interactive, real-time requests |
| `quality_optimized` | Quality weight = 0.6, cost = 0.1, latency = 0.1, reliability = 0.2 | Critical reasoning, complex tasks |
| `manual` | Entity specifies exact model_id; no scoring | Debugging, testing, explicit pinning |

## Decision Trace

Every routing decision produces a trace record:

```typescript
interface RoutingDecision {
  request_id: UUIDv7;
  selected_model: string;
  selection_reason: string;  // e.g., "highest composite score (0.87)"
  composite_score: f64;
  all_candidates: Array<{
    model_id: string;
    score: f64;
    cost_contribution: f64;
    latency_contribution: f64;
    quality_contribution: f64;
    reliability_contribution: f64;
    estimated_cost: f64;
    estimated_latency_ms: u64;
  }>;
  mode: RoutingMode;
  entity_overrides_applied: string[];
  timestamp: DateTime;
}
```

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-RTR-001 | Every request produces exactly one routing decision. | Architectural â€” one decision per request |
| LLM-RTR-002 | Router never selects a model from outside the Model Registry candidate list. | API-level â€” candidate list enforced at boundary |
| LLM-RTR-003 | Router never selects a blocked model or provider regardless of score. | Algorithmic â€” allow/block list filtering |
| LLM-RTR-004 | Manual routing bypasses scoring but enforces allow/block lists. | Algorithmic â€” mode-specific routing logic |
| LLM-RTR-005 | Router selection is deterministic for identical input (mode, candidates, config). | Algorithmic â€” deterministic scoring function |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.ModelSelected` | request_id, model_selected, selection_reason, composite_score, mode, alternatives_considered | After selection (Stage 5) |


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
| R1 â€” Modulsingularity | Router is the sole decision-maker for model selection |
| R2 â€” Dependency Order | Router depends on Registry candidates and Cost Optimizer estimates |
| R3 â€” DRY | Scoring logic centralized in Router, not duplicated across consumers |
| R4 â€” Builder Pattern | SelectionConfig built via builder with entity overrides |
| R5 â€” Liskov Substitution | All models interchangeable via normalized scoring |
| R6 â€” DI over Singletons | Router injected as service into pipeline |
| R9 â€” Deterministic | Scoring produces identical results for identical inputs |
| R10 â€” Simpler Over Complex | Weighted linear scoring over complex ML-based routing |
| R13 â€” Design for Failure | Fallback to first candidate when all score 0.0 |
| R14 â€” Paved Path | Predefined routing modes cover common patterns |
| R15 â€” Open/Closed | Entity overrides extend routing without modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/001-Model-Registry.md | Provides candidate list for routing |
| LLMOS/007-Cost-Optimizer.md | Cost estimation feeds into scoring |
| LLMOS/013-Provider-SDK.md | Provider initialization updates health metrics used in reliability scoring |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No candidates provided | â€” | Internal error; pipeline fails with LLM-9999 |
| Manual route to unknown model | LLM-0202 | Return model unavailable; suggest available alternatives |
| All candidates score 0.0 | â€” | Select first candidate as fallback; log warning |
