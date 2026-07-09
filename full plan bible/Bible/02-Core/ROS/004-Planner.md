# AIOS Bible — Core
## 004 — Resource Planner

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-004 |
| Source Laws | Law 8 — Law of Proportionality |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Planner provides resource forecasting and planning for Missions, Organizations, and the overall AIOS instance. Plans are advisory — the Allocator (003-Allocator) makes real-time decisions within plan guidance. The Planner ensures that resource consumption is predictable and that capacity demands are visible before they become critical.

## Planning Horizons

| Horizon | Time Range | Update Frequency | Used By |
|---------|-----------|------------------|---------|
| Immediate | Next 0–60 seconds | Real-time | Allocator burst planning |
| Short-term | Next 1–24 hours | Hourly | Mission resource planning |
| Medium-term | Next 1–30 days | Daily | Organization budget planning |
| Long-term | Next 1–12 weeks | Weekly | Infrastructure capacity planning |

## Planner Operations

### createPlan

Creates a resource plan for a Mission, Organization, or the entire AIOS instance.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_id` | UUID | ID of the scope (Mission, Organization, or instance root) |
| `scope_type` | Enum | mission, organization, instance |
| `horizon` | Enum | immediate, short_term, medium_term, long_term |
| `resource_projections` | Map<ResourceType, Quantity> | Projected resource needs per type |
| `confidence` | Float | Confidence level in projections (0.0–1.0) |

**Process**:
1. Validate scope exists and is active
2. Analyze historical usage from Cost (010-Cost)
3. Apply growth/contraction trends from mission plan or organization growth
4. Generate forecast with confidence intervals
5. Compare against current capacity from Registry (002-Registry)
6. Return plan with recommendations

**Event produced**: `PlanCreated { plan_id, scope_id, scope_type, horizon, timestamp }`

### adjustPlan

Adjusts an existing plan based on new information (mission changes, capacity changes, actual usage divergence).

| Parameter | Type | Description |
|-----------|------|-------------|
| `plan_id` | UUID | Plan to adjust |
| `adjustments` | Map<ResourceType, Quantity> | Resource projection adjustments |
| `reason` | String | Reason for adjustment |

**Event produced**: `PlanAdjusted { plan_id, adjustments, reason, timestamp }`

### getForecast

Retrieves the resource forecast for a scope at a given horizon.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_id` | UUID | Scope to forecast for |
| `scope_type` | Enum | mission, organization, instance |
| `horizon` | Enum | Desired forecast horizon |

**Returns**: Forecast with projected usage, confidence intervals, and capacity gap analysis.

### compareActualToPlan

Compares actual resource consumption (from Cost) to planned projections.

| Parameter | Type | Description |
|-----------|------|-------------|
| `plan_id` | UUID | Plan to compare against |

**Returns**: Variance analysis with positive/negative deviations per resource type.

**Event produced**: `PlanComparisonCompleted { plan_id, variances, timestamp }`

## Forecasting Model

The Planner uses a weighted combination of:

1. **Historical usage patterns** (70% weight): Exponential moving average of past N periods of usage data from Cost (010-Cost).
2. **Mission plans** (20% weight): Projected resource needs from Mission definitions.
3. **Organization growth** (10% weight): Entity count growth rates from OSYS.

For each resource type, the forecast is:

```
forecast = 0.7 × historical_avg + 0.2 × mission_projection + 0.1 × growth_projection
```

Confidence intervals widen with horizon length:
- Immediate: ±5%
- Short-term: ±15%
- Medium-term: ±30%
- Long-term: ±50%

## Plan Advisory Model

Plans are advisory, not binding:

| Aspect | Plan Role | Allocator Role |
|--------|-----------|----------------|
| Resource quantity | Recommends expected demand | Allocates what is actually requested and available |
| Timeline | Projects when resources are needed | Allocates when requests arrive |
| Priority | Suggests priority levels | Applies actual entity priorities |
| Provider | May suggest provider types | Selects best provider at time of allocation |

If actual usage diverges from the plan by more than 20% for 3 consecutive periods, the Planner produces an alert via Observability (013-Observability) and may trigger plan review.

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| PlanCreated | createPlan | plan_id, scope_id, scope_type, horizon, timestamp |
| PlanAdjusted | adjustPlan | plan_id, adjustments, reason, timestamp |
| PlanComparisonCompleted | compareActualToPlan | plan_id, variances, timestamp |
| PlanAlertRaised | Significant divergence | plan_id, divergence_pct, resource_type, timestamp |

## Cross-Cutting Concerns

### Security

Plan creation and adjustment require authorization. Plans for Organizations may only be created by Organization administrators or the Security Council.

### Evidence

All planning operations produce Events. Plan history is fully auditable via the Event Store.

### Lifecycle

Plans are tied to scope lifecycle. When a Mission completes or an Organization dissolves, associated plans are archived.

### Capability Bounds

Plans cannot recommend resource consumption beyond the total capacity registered in the Registry. Forecasts that exceed capacity are flagged as capacity gaps.

### Communication

The Planner reads historical data from Cost (010-Cost) and current capacity from Registry (002-Registry). It outputs plans via ACF to requesting entities.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | The Planner handles only resource forecasting and planning. |
| R9 — Deterministic | Forecast model is deterministic per R9. Same historical data always produces same forecast. |
| R10 — Simpler Over Complex | Forecasting uses a simple weighted average model. No complex ML or simulation. |
| R14 — Paved Path | The paved path is: Historical Data → Forecast → Plan → Monitor → Adjust. No other path. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Plans guide but do not bind allocation |
| ROS/002-Registry.md | Capacity data source for forecasts |
| ROS/010-Cost.md | Historical usage data for forecasts |
| ROS/013-Observability.md | Plan divergence alerting |
| Bible/02-Core/OSYS | Organization growth projections |
| Bible/02-Core/Sou/003-Missions.md | Mission resource projections |
