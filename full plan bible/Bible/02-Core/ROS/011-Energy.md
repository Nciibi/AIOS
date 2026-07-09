# AIOS Bible — Core
## 011 — Energy-Aware Resource Scheduling

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-011 |
| Source Laws | Law 7 — Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Energy-aware resource scheduling enables AIOS to optimize resource allocation for energy efficiency without compromising reliability. Energy optimization is optional per PHI-009 (Simpler Over Complex) and is never applied at the cost of system reliability or capability execution guarantees.

## Energy Model

### Per-Provider Energy Consumption

Each provider reports its energy consumption characteristics:

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | UUID | Provider identifier |
| `resource_type` | ResourceType | Resource type |
| `base_power` | Float | Base power draw in watts (idle) |
| `per_unit_power` | Float | Additional power draw per allocated unit |
| `max_power` | Float | Maximum power draw at full capacity |
| `current_power` | Float | Current power draw |
| `energy_source` | Enum | grid, solar, battery, hybrid |
| `carbon_intensity` | Float | gCO₂eq/kWh (if available) |
| `last_updated` | Timestamp | When energy data was last reported |

### Energy Consumption Calculation

```
energy_consumed (Wh) = (base_power + per_unit_power × units_allocated) × duration_hours
```

### Energy Cap

Per-entity and per-organization energy caps limit power consumption:

| Scope | Cap Type | Default |
|-------|----------|---------|
| Entity | Maximum instantaneous power (watts) | 1000 W |
| Entity | Maximum daily energy (watt-hours) | 10,000 Wh |
| Organization | Maximum instantaneous power (watts) | 50,000 W |
| Organization | Maximum daily energy (watt-hours) | 500,000 Wh |
| System | Maximum instantaneous power (watts) | Set by Security Council |

When an entity reaches its energy cap, new allocations are directed to lower-energy providers or denied if no low-energy option is available.

## Energy-Aware Allocation

### Provider Selection

When multiple providers have equivalent capability for a requested resource, the Allocator (003-Allocator) may select the lower-energy option:

```
function selectProvider(providers, request):
    if energy_optimization_enabled(request.entity):
        return select_lowest_energy_provider(providers)
    else:
        return select_least_loaded_provider(providers)
```

Energy optimization is enabled per entity type via RMP (007-RMP) policies:

```
Example Policy:
  entity_type: "org.batch.*"
  resource_type: "compute"
  conditions: [time_range("22:00", "06:00")]
  actions: [energy_optimize(enabled: true)]
```

### Low-Energy Period Scheduling

The Energy component tracks periods of low energy demand:

| Period | Typical Time | Description |
|--------|-------------|-------------|
| Off-peak | 22:00–06:00 | Lowest energy demand and cost |
| Shoulder | 06:00–09:00, 17:00–22:00 | Moderate energy demand |
| Peak | 09:00–17:00 | Highest energy demand |

Non-urgent workloads may be scheduled during off-peak periods. The Planner (004-Planner) factors energy periods into resource forecasts.

### Workload Aggregation

To improve energy efficiency, compatible workloads may be aggregated:

| Aggregation Pattern | Description | Energy Benefit |
|---------------------|-------------|----------------|
| Temporal batching | Group similar short tasks together | Reduced idle power between tasks |
| Spatial packing | Place workloads on same physical hardware | Better utilization, lower per-task energy |
| Load smoothing | Spread demand evenly over time | Avoid power spikes |

Aggregation is only applied when it does not violate latency or throughput requirements.

## Energy Operations

### getEnergyStatus

Returns current energy status for a provider or scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | provider, entity, organization, system |
| `scope_id` | UUID | Scope identifier |

**Returns**: Current power consumption, energy cap, remaining energy budget, carbon intensity (if available).

### setEnergyCap

Sets an energy cap for a scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, organization, system |
| `scope_id` | UUID | Scope identifier |
| `power_cap_watts` | Float | Maximum instantaneous power |
| `energy_cap_wh` | Float | Maximum daily energy |

**Event produced**: `EnergyCapSet { scope_type, scope_id, power_cap, energy_cap, timestamp }`

### reportEnergyConsumption

Providers report their energy consumption to ROS.

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider_id` | UUID | Provider identifier |
| `current_power` | Float | Current power draw in watts |
| `energy_since_last_report` | Float | Energy consumed since last report (Wh) |
| `duration` | Duration | Time since last report |

**Event produced**: `EnergyConsumed { provider_id, current_power, energy_delta, duration, timestamp }`

## Energy Optimization Guidelines

Per PHI-009 (Simpler Over Complex):

1. **Energy optimization is optional**: The default allocation strategy does not consider energy. Energy-aware allocation is enabled only via explicit RMP policy.
2. **Reliability first**: Energy optimization never reduces reliability. If the only energy-efficient provider has lower reliability, ROS prefers reliability.
3. **Transparency**: When energy optimization affects allocation, the entity is informed via allocation metadata.
4. **No performance degradation**: Energy optimization does not reduce allocated resources or increase latency beyond configured thresholds.
5. **Provider neutrality**: Energy optimization does not exclude providers; it prefers lower-energy options among equivalent providers.

## Energy Data Structures

```
EnergyReport {
    provider_id: UUID
    resource_type: ResourceType
    base_power_watts: Float
    per_unit_power_watts: Float
    current_power_watts: Float
    energy_consumed_wh: Float
    carbon_intensity: Float (optional)
    energy_source: Enum (grid, solar, battery, hybrid)
    measured_at: Timestamp
}

EnergyBudget {
    scope_type: Enum (entity, organization, system)
    scope_id: UUID
    power_cap_watts: Float
    energy_cap_wh_daily: Float
    current_power_watts: Float
    current_energy_wh: Float
    energy_remaining_wh: Float
    cap_reset_at: Timestamp
}

EnergyOptimizationDecision {
    allocation_id: UUID
    entity_id: UUID
    selected_provider: UUID
    alternative_providers: List<UUID>
    energy_saved_wh: Float
    cost_impact: Float
    reason: String
}
```

## Energy Monitoring

Energy monitoring tracks consumption at multiple levels:

| Level | Metrics | Update Frequency |
|-------|---------|------------------|
| Provider | Instantaneous power, cumulative energy, carbon intensity | Every 30 seconds |
| Entity | Power draw, daily energy, energy cap utilization | Every 60 seconds |
| Organization | Aggregate power, total daily energy, organization efficiency | Every 5 minutes |
| System | Total power draw, grid vs renewable ratio, carbon footprint | Every 15 minutes |

Energy monitoring data is exposed via Observability (013-Observability) dashboards and alerting.

## Energy Optimization Strategies

### Provider Preference

When energy optimization is enabled, providers are ranked by energy preference:

```
provider_energy_score = current_power_watts / total_capacity
                       × carbon_intensity_factor
                       × time_of_day_factor
```

| Factor | Description | Range |
|--------|-------------|-------|
| Efficiency | Power per unit of capacity | 0–1 (lower is better) |
| Carbon intensity | Carbon emissions per kWh | 0–1 (lower is better) |
| Time of day | Peak vs off-peak factor | 0.5–1.5 (lower during off-peak) |

### Workload Scheduling

Energy-aware scheduling can defer non-urgent workloads:

| Workload Type | Scheduling Behavior |
|---------------|---------------------|
| Interactive | Always immediate (no deferral) |
| Batch | May be deferred to off-peak (max 1 hour delay) |
| Background | May be deferred to off-peak (max 8 hours delay) |
| Maintenance | Scheduled during minimum energy cost period |

### Provider Power Management

When a provider has no active allocations for more than 5 minutes, ROS may:

1. Notify the provider to enter low-power state
2. Consolidate remaining workloads to fewer providers
3. Power down idle providers (if supported by provider type)

Power management is always optional per-provider. Providers opt in during registration.

## Energy and Carbon Reporting

Periodic energy and carbon reports are generated:

| Report Type | Audience | Content |
|-------------|----------|---------|
| Entity energy report | Entity supervisor | Power draw, energy consumed, carbon footprint |
| Organization energy report | Organization admin | Aggregate power, energy efficiency, optimization opportunities |
| System sustainability report | Security Council | Total energy, renewable percentage, carbon offset recommendations |
| Provider energy report | Provider operator | Provider efficiency, utilization vs energy consumption |

Reports are generated monthly by default and retained for 36 months.

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| EnergyConsumed | reportEnergyConsumption | provider_id, current_power, energy_delta, duration, timestamp |
| EnergyCapSet | setEnergyCap | scope_type, scope_id, power_cap, energy_cap, timestamp |
| EnergyCapReached | Entity reaches energy cap | entity_id, current_consumption, cap, timestamp |
| EnergyOptimizationApplied | Allocator used energy-aware selection | allocation_id, selected_provider, energy_saved, timestamp |

## Cross-Cutting Concerns

### Security

Energy cap changes require authorization. Only Security Council may set system-wide energy caps.

### Evidence

All energy operations produce Events. Energy consumption is auditable per provider, entity, and organization.

### Lifecycle

Energy data is maintained per entity lifecycle. When an entity terminates, its energy records are retained for audit.

### Capability Bounds

Energy optimization does not override capability resource bounds. A capability's resource envelope is always respected.

### Communication

Energy data is reported by providers via ACF. Energy status queries use read replicas.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Energy handles only energy-aware scheduling. Separate from general allocation. |
| R9 — Deterministic | Energy-aware provider selection is deterministic — same providers with same consumption always produce same selection. |
| R10 — Simpler Over Complex | Energy optimization is optional and uses simple preference logic. No complex optimization algorithms. |
| R13 — Design for Failure | If energy data is unavailable, ROS falls back to the default allocation strategy. Energy optimization never blocks allocation. |
| R14 — Paved Path | The paved path for allocation ignores energy. Energy-aware selection is an optional branch enabled by explicit policy. |
| PHI-009 (Simpler Over Complex) | Energy optimization is never applied at the cost of reliability. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Energy-aware provider selection in allocation |
| ROS/007-RMP.md | Energy optimization enabled via RMP policies |
| ROS/004-Planner.md | Energy periods factored into resource planning |
| ROS/010-Cost.md | Energy cost tracked alongside other resource costs |
| Foundations/001-AIOS-Philosophy.md | PHI-009 — Simpler Over Complex |
| Physics/007-Capabilities.md | Capability bounds not affected by energy optimization |
