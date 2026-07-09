# AIOS Bible — Core
## 005 — Resource Budget

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-005 |
| Source Laws | Law 8 — Law of Proportionality |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Budget defines per-entity, per-Mission, and per-Organization resource entitlements. Every allocation is checked against the entity's budget. Budgets are the primary mechanism for fair resource distribution across AIOS entities.

## Budget Structure

```
Budget {
    budget_id: UUID
    entity_id: UUID
    scope_type: Enum (entity, mission, organization)
    scope_id: UUID
    resource_type: ResourceType
    total_budget: Quantity           // Total resources allocated for the period
    used: Quantity                    // Resources consumed so far
    remaining: Quantity               // total_budget - used
    period_start: Timestamp           // Budget period start
    period_end: Timestamp             // Budget period end
    budget_type: BudgetType           // fixed, elastic, burst
    burst_remaining: Quantity         // For burst budgets: remaining burst capacity
    burst_recovery_rate: Float        // For burst budgets: recovery per hour
    metadata: Map<String, String>
}
```

## Budget Types

### Fixed (Hard Cap)

A fixed budget has a hard upper bound that cannot be exceeded under any circumstance.

| Property | Value |
|----------|-------|
| Maximum allocation | total_budget - used |
| Override allowed | Only by Security Council |
| Default period | Monthly |
| Typical use | Entity token budgets, storage limits |

### Elastic (Can Grow Within Limits)

An elastic budget can grow beyond its initial total_budget, up to a configured maximum. Growth is approved by the organization or Security Council.

| Property | Value |
|----------|-------|
| Maximum allocation | min(max_budget - used, total_budget - used + growth_approved) |
| Growth approval | Organization admin or policy-based auto-approval |
| Default period | Monthly |
| Typical use | Organization compute budgets, Mission budgets |

### Burst (Short-Term Overage with Recovery)

A burst budget allows short-term overage up to a burst limit. The overage must be recovered within the recovery period.

| Property | Value |
|----------|-------|
| Burst limit | total_budget × burst_multiplier (default: 1.5×) |
| Recovery period | Configurable (default: 24 hours) |
| Recovery rate | burst_recovery_rate per hour |
| During recovery | New allocations limited until budget recovers |
| Typical use | LLM token bursts during peak reasoning, temporary compute spikes |

**Burst behavior**:
```
effective_budget = total_budget + burst_remaining
if used > effective_budget:
    allocation denied (budget exhausted, no burst available)
if used > total_budget and burst_remaining > 0:
    burst_remaining -= (used - total_budget)
    burst starts recovery timer
```

## Budget Operations

### setBudget

Creates or replaces a budget for an entity, mission, or organization.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, mission, organization |
| `scope_id` | UUID | Scope identifier |
| `resource_type` | ResourceType | Resource this budget applies to |
| `total_budget` | Quantity | Budget amount |
| `budget_type` | BudgetType | fixed, elastic, burst |
| `period_end` | Timestamp | Budget period end (default: end of month) |
| `burst_multiplier` | Float (optional) | For burst budgets |
| `burst_recovery_rate` | Float (optional) | For burst budgets |

**Event produced**: `BudgetSet { budget_id, scope_id, scope_type, resource_type, total_budget, budget_type, timestamp }`

### adjustBudget

Adjusts an existing budget (increase or decrease).

| Parameter | Type | Description |
|-----------|------|-------------|
| `budget_id` | UUID | Budget to adjust |
| `new_total` | Quantity | New total budget amount |
| `reason` | String | Reason for adjustment |

**Event produced**: `BudgetAdjusted { budget_id, old_total, new_total, reason, timestamp }`

### getBudget

Retrieves the current budget for a scope and resource type.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, mission, organization |
| `scope_id` | UUID | Scope identifier |
| `resource_type` | ResourceType | Resource type |

**Returns**: Budget with current usage and remaining amounts.

### getUsage

Retrieves current usage breakdown for a budget.

| Parameter | Type | Description |
|-----------|------|-------------|
| `budget_id` | UUID | Budget identifier |

**Returns**: Usage breakdown (allocated, consumed, reserved, available).

## Budget Enforcement

The Allocator (003-Allocator) checks budget before every allocation:

```
function checkBudget(entity_id, resource_type, requested_quantity):
    budget = getBudget(entity, resource_type)
    if budget == null:
        deny (no budget configured)
    if budget.used + requested_quantity > budget.effective_total:
        deny (budget exhausted)
    if budget.used + requested_quantity > budget.soft_warning_threshold:
        produce BudgetWarning Event
    allow
```

| Check | Fixed | Elastic | Burst |
|-------|-------|---------|-------|
| Hard limit | total_budget | max_budget | total_budget + burst_remaining |
| Warning threshold | 80% of total | 80% of max | 80% of total |
| Deny when | used + request > total | used + request > max | used + request > total + burst_remaining |

## Budget Period

| Period | Default | Configuration |
|--------|---------|---------------|
| Entity | Monthly | Per entity |
| Mission | Mission duration | Set at mission creation |
| Organization | Monthly | Per organization |
| System-wide | Annual | Set by Security Council |

At period end:
1. Remaining budget is reset to total_budget
2. Burst capacity is fully restored
3. Unused budget does not roll over (unless policy specifies rollover)
4. `BudgetPeriodReset` Event produced

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| BudgetSet | setBudget | budget_id, scope_id, scope_type, resource_type, total_budget, budget_type, timestamp |
| BudgetAdjusted | adjustBudget | budget_id, old_total, new_total, reason, timestamp |
| BudgetExhausted | Allocation denied due to budget | entity_id, resource_type, requested, remaining, timestamp |
| BudgetWarning | Usage exceeds 80% threshold | budget_id, usage_pct, timestamp |
| BudgetPeriodReset | Period end | budget_id, new_period_start, new_period_end, timestamp |
| BurstStarted | Burst budget activated | budget_id, burst_amount, recovery_period, timestamp |
| BurstRecovered | Burst budget fully recovered | budget_id, timestamp |

## Cross-Cutting Concerns

### Security

Budget changes require authorization. Only Organization administrators may adjust Organization budgets. Only the Security Council may adjust system-wide budgets.

### Evidence

All budget operations produce Events. Budget history is fully auditable.

### Lifecycle

Budgets are created when an entity is created and archived when the entity is terminated. Mission budgets are tied to Mission lifecycle.

### Capability Bounds

A budget cannot exceed the capability bounds of the entity's template. Budgets are capped by capability resource limits per CPR-006.

### Communication

Budget queries use the read-replica pattern for scalability. Budget updates go through the active ROS node for consistency.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Budget handles only resource entitlement and tracking. |
| R9 — Deterministic | Budget calculations are deterministic. |
| R10 — Simpler Over Complex | Three budget types cover all use cases. No complex dynamic budgeting. |
| R13 — Design for Failure | Budget enforcement in the Allocator prevents runaway consumption even if other systems fail. |
| R14 — Paved Path | The paved path is: Set Budget → Use Resources → Check Budget → Track Usage → Reset. |
| R15 — Open/Closed | New budget types can be added via the budget type registry. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Allocator checks budget before every allocation |
| ROS/006-Quota.md | Quota enforces additional limits beyond budget |
| ROS/010-Cost.md | Cost tracks actual usage against budget |
| ROS/013-Observability.md | Budget exhaustion alerting |
| Physics/007-Capabilities.md | Budget is bounded by capability limits |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization budget lifecycle |
