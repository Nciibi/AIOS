# AIOS Bible — Brain/LLMOS
## 006 — Token Budget Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-006 |
| Source Laws | Law 7 — Law of Capability Bounds |
| Pipeline Stage | 3 — Budget Check (gateway) + continuous tracking |

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
6. Reserve estimated tokens in an in-memory pending ledger (not persisted to ROS) — this prevents concurrent requests from the same entity from over-subscribing within the same process. The persistent ROS record is only updated at reconciliation (Stage 17).

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
| Entity has no budget configured | — | Apply default budget (1M tokens/day, unlimited hourly) |

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

- LLM-BGT-001: Every request passes budget check before entering the pipeline (Stage 3).
- LLM-BGT-002: Budget check is performed against at least one window (daily or hourly).
- LLM-BGT-003: Token estimation never returns 0 — minimum estimate is 1 token.
- LLM-BGT-004: Reconciliation always runs after request completion (Stage 17).
- LLM-BGT-005: Budget overrides are multiplicative — applied to token counts before comparison with limits.
- LLM-BGT-006: Credit budgets and token budgets are mutually exclusive — an entity uses one or the other.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.BudgetChecked` | request_id, entity_id, budget_type, budget_before, budget_after, estimated_cost, overrides_applied, approved | Stage 3 check |
| `LLMOS.BudgetReconciled` | request_id, actual_tokens, estimated_tokens, difference, adjusted_cost | Stage 17 reconciliation |

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
| ROS unreachable for budget load | — | Allow request with warning; log for operator |
| Entity budget not found | — | Apply default budget; log for operator |
| Tokenizer cache miss + slow tokenization | — | Use fallback estimation; continue |
| Reconciliation fails | — | Queue reconciliation job for retry; do not block pipeline |
