# AIOS Bible — Core
## 010 — Resource Cost

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-010 |
| Source Laws | Law 8 — Law of Proportionality |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Cost tracks and accounts for resource consumption across all entities, missions, organizations, and time periods. Cost data feeds budget planning, resource optimization, organization billing, and observability. Every resource allocation is recorded as a cost line item.

## Cost Model

```
cost = resource_type × usage_amount × cost_rate
```

Where:
- `resource_type`: Type of resource consumed (compute, memory, storage, tokens, energy)
- `usage_amount`: Quantity consumed (core-hours, GB-hours, tokens, watt-hours)
- `cost_rate`: Configurable rate per unit, set per provider

### Cost Rate Configuration

| Resource Type | Default Rate | Unit | Configurable Per |
|---------------|-------------|------|------------------|
| compute (cpu) | 10 credits/core-hour | core-hour | Provider, Organization |
| compute (gpu) | 100 credits/core-hour | core-hour | Provider, Organization |
| memory (ram) | 1 credit/GB-hour | GB-hour | Provider, Organization |
| memory (vram) | 10 credits/GB-hour | GB-hour | Provider, Organization |
| storage (disk) | 0.1 credit/GB-hour | GB-hour | Provider, Organization |
| storage (ssd) | 1 credit/GB-hour | GB-hour | Provider, Organization |
| storage (object) | 0.05 credit/GB-month | GB-month | Provider, Organization |
| tokens (input) | 0.01 credit/token | token | Provider |
| tokens (output) | 0.03 credit/token | token | Provider |
| energy | 0.5 credit/watt-hour | watt-hour | Provider, Organization |

## Cost Operations

### recordUsage

Records resource usage for an entity.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | UUID | Entity that consumed resources |
| `allocation_id` | UUID | Associated allocation |
| `resource_type` | ResourceType | Type of resource consumed |
| `amount` | Quantity | Amount consumed |
| `duration` | Duration | Duration of consumption |
| `provider_id` | UUID | Provider that supplied the resource |
| `cost_rate` | Float (optional) | Actual cost rate applied |

**Process**:
1. Calculate cost: `cost = amount × duration_hours × cost_rate`
2. Record usage entry
3. Update entity's accumulated cost
4. Update organization's accumulated cost (if applicable)
5. Update mission's accumulated cost (if applicable)
6. Produce Event

**Event produced**: `UsageRecorded { usage_id, entity_id, allocation_id, resource_type, amount, duration, cost, timestamp }`

### calculateCost

Calculates the cost for a usage record or projected usage.

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_type` | ResourceType | Resource type |
| `amount` | Quantity | Resource amount |
| `duration` | Duration | Expected duration |
| `provider_id` | UUID (optional) | Specific provider |
| `cost_rate` | Float (optional) | Override cost rate |

**Returns**: Calculated cost with rate breakdown.

### getCostReport

Generates a cost report for a scope over a time period.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, mission, organization, system |
| `scope_id` | UUID | Scope identifier |
| `start_time` | Timestamp | Report start |
| `end_time` | Timestamp | Report end |
| `group_by` | Enum (optional) | resource_type, time_period, provider |

**Returns**: Cost report with totals, breakdowns, and trends.

**Event produced**: `CostReportGenerated { report_id, scope_type, scope_id, start_time, end_time, total_cost, timestamp }`

### setCostRate

Sets or updates the cost rate for a resource type on a provider or organization scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | provider, organization, system |
| `scope_id` | UUID | Scope identifier |
| `resource_type` | ResourceType | Resource type |
| `cost_rate` | Float | New cost rate |

**Event produced**: `CostRateSet { scope_type, scope_id, resource_type, old_rate, new_rate, timestamp }`

## Cost Reports

### Per-Entity Report

```
Cost Report: Entity {entity_id}
Period: 2026-06-01 to 2026-06-30

Resource Type    | Usage           | Rate      | Cost
-----------------|-----------------|-----------|-------
compute (cpu)    | 120 core-hours  | 10/hr     | 1,200
memory (ram)     | 480 GB-hours    | 1/hr      | 480
tokens (input)   | 50,000 tokens   | 0.01/tk   | 500
tokens (output)  | 15,000 tokens   | 0.03/tk   | 450
----------------------------------------------
Total: 2,630 credits
```

### Per-Mission Report

```
Cost Report: Mission {mission_id}
Period: 2026-06-01 to 2026-06-30

Entity          | Total Cost | % of Mission
----------------|------------|-------------
entity-001      | 1,200      | 45.6%
entity-002      | 850        | 32.3%
entity-003      | 580        | 22.1%
----------------------------------------------
Mission Total: 2,630 credits
```

### Per-Organization Report

```
Cost Report: Organization {org_id}
Period: 2026-06-01 to 2026-06-30

Mission         | Total Cost | % of Org
----------------|------------|----------
mission-001     | 10,500     | 42.0%
mission-002     | 8,200      | 32.8%
mission-003     | 6,300      | 25.2%
----------------------------------------------
Organization Total: 25,000 credits
```

## Usage Data Retention

| Time Period | Retention | Granularity |
|-------------|-----------|-------------|
| Current month | Full detail | Per-allocation |
| Previous 12 months | Aggregated daily | Per-day totals per entity |
| Older than 12 months | Aggregated monthly | Per-month totals per organization |
| Older than 36 months | Archived | Summary only |

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| UsageRecorded | recordUsage | usage_id, entity_id, allocation_id, resource_type, amount, duration, cost, timestamp |
| CostReportGenerated | getCostReport | report_id, scope_type, scope_id, start_time, end_time, total_cost, timestamp |
| CostRateSet | setCostRate | scope_type, scope_id, resource_type, old_rate, new_rate, timestamp |
| CostThresholdReached | Cost exceeds configured threshold | entity_id, current_cost, threshold, resource_type, timestamp |

## Cross-Cutting Concerns

### Security

Cost reports are scoped to the requesting entity's authorization. Entities may view their own cost. Organization admins may view organization cost. Only Security Council may view system-wide cost.

### Evidence

Every usage record is an immutable Event. Cost data is derived entirely from Events per the Observability via Events pattern (Foundations/005-Architectural-Patterns.md).

### Lifecycle

Cost data is retained per entity lifecycle. When an entity is terminated, its cost data is retained for audit but the entity is marked as inactive.

### Capability Bounds

Cost is a post-hoc accounting of capability resource consumption. It does not enforce bounds (that is Budget and Quota's role) but informs budget planning.

### Communication

Cost reports are generated on demand and served via the read-replica pattern. Usage recording is synchronous with allocation.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Cost handles only accounting and reporting. Separate from allocation and budget enforcement. |
| R3 — DRY | Cost data is derived from allocation Events. No duplicate data store. |
| R9 — Deterministic | Cost calculation is deterministic — same usage × same rate always produces same cost. |
| R10 — Simpler Over Complex | Simple linear cost model: resource × amount × rate. No complex pricing tiers. |
| R13 — Design for Failure | Cost recording is non-blocking. Allocation succeeds even if cost recording is temporarily unavailable (cost records are queued and replayed). |
| R14 — Paved Path | The paved path is: Record Usage → Calculate Cost → Generate Report. No other path. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Allocator triggers usage recording |
| ROS/005-Budget.md | Budget is planned based on cost data |
| ROS/013-Observability.md | Cost metrics and dashboards |
| ROS/004-Planner.md | Planner uses historical cost data for forecasts |
| Foundations/005-Architectural-Patterns.md | Observability via Events pattern |
