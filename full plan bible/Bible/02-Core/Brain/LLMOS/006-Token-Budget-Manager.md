# AIOS Bible â€” Brain/LLMOS
## 006 â€” Token Budget Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-006 |
| Source Laws | Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 3 â€” Budget Check (gateway) + continuous tracking |

## Purpose

The Token Budget Manager enforces per-entity token usage limits. It is consulted at Stage 3 (gateway) to verify the requesting entity has sufficient token budget before processing begins, and it tracks token consumption throughout the pipeline. It reports final usage to ROS for billing and audit.

## Token Budget Model

```typescript
interface EntityTokenBudget {
  entity_id: UUIDv7;
  budgets: TokenBudgetWindow[];
  utilization: TokenUtilization;
  overrides: BudgetOverride[];
}

interface TokenBudgetWindow {
  window_type: "daily" | "hourly" | "per_request";
  limit: u64;
  current_usage: u64;
  reset_at: DateTime;
}

interface TokenUtilization {
  total_input_tokens: u64;
  total_output_tokens: u64;
  total_cached_tokens: u64;
  total_cost_credits: f64;
  current_window_input: u64;
  current_window_output: u64;
  current_window_cost: f64;
}

interface BudgetOverride {
  model_id: string | null;
  multiplier: f64;
  reason: string;
  expires_at: DateTime | null;
}
```

## Pre-Request Check (Stage 3)

```typescript
async function checkBudget(entity_id: UUIDv7, requirements: ModelRequirements): Promise<BudgetCheckResult>

interface BudgetCheckResult {
  approved: boolean;
  denial_reason: string | null;
  estimated_cost: f64;
  budget_remaining: u64;
  budget_before: u64;
  budget_limit: u64;
  overrides_applied: BudgetOverride[];
}
```

### Pre-Check Algorithm

1. Load entity token budget from ROS
2. Estimate tokens for this request based on `messages`/`prompt_template` size
3. Apply budget overrides (e.g., double-count tokens on expensive models)
4. Check each window:
   - If `current_usage + estimated_tokens > limit`: deny with `budget_exceeded` for this window
5. If all windows pass: approve and reserve estimated tokens (optimistic reservation)
6. Reserve estimated tokens in an in-memory pending ledger (not persisted to ROS) â€” this prevents concurrent requests from the same entity from over-subscribing within the same process. The persistent ROS record is only updated at reconciliation (Stage 17).

## Post-Request Reconciliation (Stage 17)

```typescript
async function reconcileBudget(entity_id: UUIDv7, usage: TokenUsage): Promise<void>
```

1. Load the optimistic reservation made at Stage 3
2. Replace with actual token counts from `usage`
3. Adjust entity's budget to reflect actual counts
4. If actual > estimated: deduct the difference
5. If actual < estimated: refund the over-reserved tokens
6. Report to ROS for billing ledger

## Budget Exhaustion Handling

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Daily window exhausted | LLM-0102 | Deny request; return budget_exceeded with reset_at timestamp |
| Hourly window exhausted | LLM-0102 | Deny request; return budget_exceeded with reset_at timestamp |
| Per-request limit exceeded | LLM-0102 | Deny request; suggest reducing input size |
| Entity has no budget configured | â€” | Apply default budget (1M tokens/day, unlimited hourly) |

## Token Estimation

```typescript
function estimateTokens(content: string | Message[], model: string): u64 {
  // Use model-specific tokenizer if available
  // Fall back to 4 characters per token estimation
  // Cache tokenizer results per (model, content_hash)
}
```

- Model-specific tokenizers are preferred (e.g., Anthropic's tokenizer for Claude models)
- Fallback: `content.length / 4` characters-per-token estimation
- Tokenizer results are cached by `(model_id, content_hash)` with LRU eviction
- Cache size: 10,000 entries, TTL: 5 minutes

## Credit-Based Budgeting

```typescript
interface CreditBudget {
  entity_id: UUIDv7;
  total_credits: u64;
  used_credits: u64;
  reset_policy: ResetPolicy;
  credit_rate: Map<string, f64>;
}
```

- Each model has a credit rate (credits per 1K tokens)
- Models with higher cost-per-token consume credits proportionally faster
- Credit rates are published by the Cost Optimizer and synchronized with ROS

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-BGT-001 | Every request passes budget check before entering the pipeline (Stage 3). | Architectural â€” gateway stage enforcement |
| LLM-BGT-002 | Budget check is performed against at least one window (daily or hourly). | Algorithmic â€” multi-window check |
| LLM-BGT-003 | Token estimation never returns 0 â€” minimum estimate is 1 token. | Algorithmic â€” floor applied |
| LLM-BGT-004 | Reconciliation always runs after request completion (Stage 17). | Architectural â€” post-request stage enforcement |
| LLM-BGT-005 | Budget overrides are multiplicative â€” applied to token counts before comparison with limits. | Algorithmic â€” override calculation |
| LLM-BGT-006 | Credit budgets and token budgets are mutually exclusive â€” an entity uses one or the other. | Schema â€” budget type exclusivity |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.BudgetChecked |     request_id, entity_id, budget_type, budget_before, budget_after, estimated_cost, overrides_applied, approved | Stage 3 check |
| LLM.BudgetReconciled |     request_id, actual_tokens, estimated_tokens, difference, adjusted_cost | Stage 17 reconciliation |


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
| R1 â€” Modulsingularity | Token Budget Manager is the sole budget authority |
| R2 â€” Dependency Order | Budget check precedes all pipeline processing (Stage 3) |
| R3 â€” DRY | Single budgeting model applied across all entities |
| R4 â€” Builder Pattern | Token budgets configured through builder patterns |
| R5 â€” Liskov Substitution | All entity budgets handled uniformly |
| R6 â€” DI over Singletons | BudgetManager injected into pipeline stages |
| R9 â€” Deterministic | Same request gets same budget decision |
| R10 â€” Simpler Over Complex | Window-based budgets over complex rate-limiting |
| R13 â€” Design for Failure | Default budget applied when entity config missing |
| R14 â€” Paved Path | Standard budget windows defined for all entities |
| R15 â€” Open/Closed | New budget windows added without pipeline changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/ROS/000-Overview.md | Token budgets are stored and tracked by ROS |
| LLMOS/007-Cost-Optimizer.md | Cost optimizer produces credit rates consumed by this manager |
| LLMOS/000-Overview.md | TokenBudget Check is Stage 3 of the pipeline |
| Physics/007-Capabilities.md | Capability Bounds define token budget constraints |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| ROS unreachable for budget load | â€” | Allow request with warning; log for operator |
| Entity budget not found | â€” | Apply default budget; log for operator |
| Tokenizer cache miss + slow tokenization | â€” | Use fallback estimation; continue |
| Reconciliation fails | â€” | Queue reconciliation job for retry; do not block pipeline |
