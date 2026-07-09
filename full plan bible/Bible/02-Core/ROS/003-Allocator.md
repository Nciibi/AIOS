# AIOS Bible — Core
## 003 — Resource Allocator

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-003 |
| Source Laws | Law 7 — Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Allocator is the core decision engine of ROS. It determines which entity receives which resources, in what quantity, and for how long. Every allocation is a function of entity priority, budget remaining, resource availability, entity autonomy level, and current demand. The Allocator is deterministic per R9 — same inputs always produce the same allocation.

## Allocation Function

```
Allocation = f(entity_priority, budget_remaining, resource_availability, autonomy_level, demand)
```

Where:
- `entity_priority`: Priority level assigned to the entity (1=highest, 5=lowest)
- `budget_remaining`: Remaining budget for the requested resource type
- `resource_availability`: Currently available capacity from providers
- `autonomy_level`: Entity autonomy level (L0–L4, per PHI-003)
- `demand`: Requested resource quantity

## Allocation Strategies

### Proportional (Fair Share)

Resources are divided proportionally among requesting entities based on their priority weight:

```
entity_allocation = (entity_weight / sum(all_entity_weights)) × available_capacity
```

Used for: General-purpose allocation, balanced workloads.

### Priority-Based

Higher-priority entities receive resources first. Lower-priority entities receive remaining resources.

```
sorted_entities = sort(entities, by: priority ASC)
for entity in sorted_entities:
    allocate(entity, min(entity.demand, available))
```

Used for: Time-sensitive operations, Security Council actions, critical missions.

### Reservation-Based

Resources are pre-reserved for specific entities or capabilities. Reserved resources are excluded from general allocation pools.

```
if entity has active reservation:
    allocate(reservation.quantity)
    mark reservation as consumed
else:
    fall back to strategy based on RMP
```

Used for: Execution authorization (Stage 7), guaranteed capability execution.

### Best-Effort

Resources are allocated on a first-come, first-served basis with no guarantees. Best-effort allocations may be preempted.

Used for: Background tasks, non-critical operations, learning workloads.

## Allocation Operations

### allocate

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | UUID | Requesting entity |
| `capability_id` | UUID | Capability being executed |
| `resource_requests` | Map<ResourceType, Quantity> | Requested resources |
| `strategy` | Enum (optional) | Allocation strategy override |
| `priority` | Int (optional) | Priority override (must be within entity's range) |

**Process**:
1. Validate entity identity
2. Check budget (005-Budget) — fail if insufficient
3. Check quota (006-Quota) — fail if hard quota exceeded
4. Evaluate RMP policies (007-RMP) — apply policy overrides
5. Query Registry (002-Registry) for provider availability
6. Select provider(s) based on strategy, energy optimization (011-Energy), and cost
7. Execute allocation on selected provider(s)
8. Record usage in Cost (010-Cost)
9. Produce Event

**Event produced**: `ResourcesAllocated { allocation_id, entity_id, capability_id, resources, provider_id, strategy, timestamp }`

### deallocate

| Parameter | Type | Description |
|-----------|------|-------------|
| `allocation_id` | UUID | Allocation to release |
| `reason` | Enum | normal, preempted, failure, recovery |

**Event produced**: `ResourcesDeallocated { allocation_id, entity_id, reason, timestamp }`

### reserve

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | UUID | Entity making reservation |
| `capability_id` | UUID | Capability to reserve for |
| `resources` | Map<ResourceType, Quantity> | Resources to reserve |
| `ttl` | Duration | Reservation time-to-live |

**Event produced**: `ResourcesReserved { reservation_id, entity_id, capability_id, resources, ttl, timestamp }`

### release

Releases a reservation without consuming it (e.g., capability evaluation failed before execution).

| Parameter | Type | Description |
|-----------|------|-------------|
| `reservation_id` | UUID | Reservation to release |

**Event produced**: `ReservationReleased { reservation_id, entity_id, timestamp }`

## Preemption

Lower-priority allocations may be preempted when higher-priority entities require resources:

| Condition | Action |
|-----------|--------|
| Higher-priority entity needs resources, none available | Preempt lowest-priority allocation |
| Mission-critical capability requires guaranteed resources | Preempt best-effort allocations first |
| Entity autonomy violation detected | Preempt all allocations from violating entity |

Preemption flow:
1. Identify preemptable allocation(s) by priority order
2. Issue preemption notice to affected entity
3. Allow grace period for graceful shutdown (configurable, default 30 seconds)
4. Force-deallocate if entity does not release within grace period
5. Produce `AllocationPreempted` Event

**Event produced**: `AllocationPreempted { allocation_id, entity_id, preempting_entity_id, grace_period, timestamp }`

## Determinism Guarantee

The Allocator is deterministic per R9 and ROS-002:

1. **Same allocation inputs** (entity_priority, budget_remaining, resource_availability, autonomy_level, demand) **always produce the same allocation output**.
2. **Strategy selection is deterministic**: given the same RMP policies and resource availability, the same strategy is chosen.
3. **Provider selection is deterministic**: given the same provider list and selection criteria, the same provider is chosen.
4. **Tie-breaking is deterministic**: ties are broken by entity_id (lexicographic order).

Nondeterminism is explicitly bounded to: allocation_id generation (random UUID suffix).

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| ResourcesAllocated | allocate | allocation_id, entity_id, capability_id, resources, provider_id, strategy, timestamp |
| ResourcesDeallocated | deallocate | allocation_id, entity_id, reason, timestamp |
| ResourcesReserved | reserve | reservation_id, entity_id, capability_id, resources, ttl, timestamp |
| ReservationReleased | release | reservation_id, entity_id, timestamp |
| AllocationPreempted | Preemption | allocation_id, entity_id, preempting_entity_id, grace_period, timestamp |

## Cross-Cutting Concerns

### Security

All allocation requests require entity authentication. Preemption requires higher priority authorization. The Allocator verifies entity identity via IDS before processing any request.

### Evidence

Every allocation, deallocation, reservation, and preemption produces an Event. The full allocation history is available for audit.

### Lifecycle

Allocations are tied to entity lifecycle. When an entity terminates, all its allocations are deallocated via Recovery (012-Recovery).

### Capability Bounds

The Allocator enforces capability resource bounds. A capability's template defines maximum resource consumption, and the Allocator never allocates beyond that bound.

### Communication

The Allocator communicates with Registry, Budget, Quota, RMP, Cost, and Providers via ACF. Internal calls are synchronous; external provider calls have configurable timeouts.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | The Allocator handles only resource allocation decisions. |
| R9 — Deterministic | All allocation logic is deterministic per ROS-002. |
| R10 — Simpler Over Complex | Allocation strategies are linear and predictable. No complex optimization heuristics. |
| R13 — Design for Failure | Allocator assumes providers may fail; grace periods prevent cascading failures. |
| R14 — Paved Path | The paved path is: Request → Budget Check → Quota Check → Policy Eval → Allocate → Record. |
| R15 — Open/Closed | New allocation strategies implement the strategy interface without modifying the core allocator. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/002-Registry.md | Provider availability queries |
| ROS/005-Budget.md | Budget checking before allocation |
| ROS/006-Quota.md | Quota enforcement during allocation |
| ROS/007-RMP.md | Policy evaluation during allocation |
| ROS/009-Reservation.md | Reservation-based allocation |
| ROS/010-Cost.md | Usage recording after allocation |
| ROS/011-Energy.md | Energy-aware provider selection |
| Physics/010-Execution.md | Stage 7 reservation integration |
