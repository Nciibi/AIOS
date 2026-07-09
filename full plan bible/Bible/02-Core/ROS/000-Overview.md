# AIOS Bible — Core
## 000 — ROS Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-000 |
| Source Laws | Law 8 — Law of Proportionality, Law 12 — Law of Bounded Capability |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md, Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Resource Orchestration Service (ROS) is the constitutional authority on resource availability within AIOS. Every computational resource — tokens, memory, compute, storage, energy — is registered, allocated, tracked, and accounted for by ROS. No capability executes without ROS verifying resource availability. No entity consumes resources without ROS recording the usage.

ROS owns the Resources concern per CPR-001 (Separation of Concerns). It provides the resource management layer that all other systems depend on for bounded, fair, and auditable resource consumption.

## ROS Resource Model

```
Resource Provider → Resource Pool → Budget → Allocation → Usage → Accounting
```

| Stage | Description | Owner Document |
|-------|-------------|----------------|
| Provider | Abstracts a resource source (machine, cloud, API) | 002-Registry |
| Pool | Aggregated capacity from providers | 002-Registry |
| Budget | Per-entity resource entitlement | 005-Budget |
| Allocation | Assigned resources for a specific operation | 003-Allocator |
| Usage | Actual consumption tracked in real-time | 010-Cost |
| Accounting | Historical record for planning and billing | 010-Cost |

## Relationship to Physics

| Physics Document | Relationship |
|-----------------|--------------|
| Physics/007-Capabilities.md | ROS enforces resource bounds on every capability. A capability's resource budget is checked before execution. |
| Physics/010-Execution.md | ROS performs resource pre-reservation during Stage 7 (Execution Authorization) of the verification pipeline. No execution token is issued without confirmed resource availability. |
| Physics/006-Lifecycles.md | ROS releases all resources when an entity's lifecycle terminates. Recovery (012-Recovery) handles failure cases. |
| Physics/005-Events.md | Every resource operation produces an Event. All ROS metrics derive from Events (Observability via Events pattern). |

## Invariants

Stable identifiers: ROS-001 through ROS-005.

1. **ROS-001 — Resource Availability**: Every allocation is backed by confirmed available capacity. ROS never over-commits resources beyond what providers have reported.
2. **ROS-002 — Deterministic Allocation**: Given the same allocation inputs (entity priority, budget remaining, resource availability, autonomy level, demand), the Allocator always produces the same allocation. Complies with R9 (Deterministic) and CPR-003.
3. **ROS-003 — Budget Enforcement**: No allocation may exceed the entity's current budget. The Allocator checks budget before every allocation. Budget violations escalate to the Security Council.
4. **ROS-004 — Auditability**: Every resource operation (registration, allocation, release, reservation, budget change, quota change) produces an Event. ROS is fully auditable via the Event Store.
5. **ROS-005 — Liveness**: All reservations and allocations are time-bound. No resource is held indefinitely. Expired reservations are automatically released (deadlock prevention per R13 Design for Failure).

## Structure

| # | Document | Content | Reading Order |
|---|----------|---------|---------------|
| 000 | Overview (this file) | ROS architecture overview, resource model, invariants | 1 |
| 001 | Architecture | Component diagram, data flow, clustering, provider model | 2 |
| 002 | Registry | Resource provider registry, provider types, health checking | 3 |
| 003 | Allocator | Allocation algorithm, strategies, preemption | 4 |
| 004 | Planner | Resource planning, forecasting, horizon-based planning | 5 |
| 005 | Budget | Per-entity budgeting, budget types, enforcement | 6 |
| 006 | Quota | Hard/soft limits, quota enforcement, violation escalation | 7 |
| 007 | RMP | Resource Management Policies, policy evaluation | 8 |
| 008 | Provider SDK | SDK for building resource providers | 9 |
| 009 | Reservation | Resource reservation for execution authorization | 10 |
| 010 | Cost | Cost tracking, accounting, cost reports | 11 |
| 011 | Energy | Energy-aware resource scheduling, optimization | 12 |
| 012 | Recovery | Resource recovery on entity failure | 13 |
| 013 | Observability | Metrics, monitoring, alerting | 14 |
| 014 | RXP | Resource Exchange Protocol for cross-instance sharing | 15 |

## ROS in the Verification Pipeline

ROS participates in Stage 7 (Execution Authorization) of the 7-stage verification pipeline:

| Stage | Name | ROS Role |
|-------|------|----------|
| 1 | Identity Verification | None (handled by IDS) |
| 2 | Authentication | None (handled by ATS) |
| 3 | Authorization | None (handled by AZS) |
| 4 | Policy Evaluation | RMP policies (007-RMP) are evaluated here but applied by ROS |
| 5 | Capability Check | ROS checks capability resource bounds |
| 6 | Risk Assessment | None (handled by Risk Engine) |
| 7 | Execution Authorization | ROS reserves resources (009-Reservation) and issues execution token |

If ROS cannot confirm resource availability at Stage 7, the execution is denied. This is a fail-closed behavior per R13.

## Resource Lifecycle

Every resource in ROS follows a defined lifecycle:

```
Available ──→ Reserved ──→ Allocated ──→ Consumed ──→ Released
    │            │              │              │
    │            ▼              ▼              ▼
    │         Expired       Preempted       Failed
    │            │              │              │
    └────────────┴──────────────┴──────────────┘
                  (returned to available pool)
```

| State | Description | Transitions |
|-------|-------------|-------------|
| Available | Resource is in the provider pool, unassigned | → Reserved |
| Reserved | Resource is held for a specific entity (time-bound) | → Allocated, → Expired, → Available |
| Allocated | Resource is assigned to an entity for active use | → Consumed, → Preempted |
| Consumed | Resource has been used and released normally | → Available |
| Released | Resource returned to pool after use | → Available |
| Expired | Reservation TTL expired without consumption | → Available |
| Preempted | Allocation terminated for higher-priority use | → Available |
| Failed | Resource released due to error or crash | → Available |

## Resource Conflicts

Resource conflicts occur when demand exceeds supply. ROS resolves conflicts using a deterministic hierarchy:

| Conflict Type | Resolution | Document |
|---------------|-----------|----------|
| Budget exhaustion vs demand | Deny allocation, produce BudgetExhausted Event | 005-Budget |
| Quota limit vs request | Deny allocation, produce QuotaViolated Event | 006-Quota |
| Provider capacity vs demand | Preempt lower-priority allocations | 003-Allocator |
| Cross-entity priority conflict | Higher priority entity gets resources first | 003-Allocator |
| Reservation vs allocation | Reservations take priority over new allocations | 009-Reservation |

## Performance Characteristics

ROS is designed for predictable performance under load:

| Operation | Latency Target | Throughput | Consistency |
|-----------|---------------|------------|-------------|
| Resource allocation | < 50 ms | 10,000/s | Strong (active node) |
| Budget query | < 10 ms | 100,000/s | Eventual (read replica) |
| Provider registration | < 100 ms | 100/s | Strong |
| Heartbeat processing | < 5 ms | 10,000/s | Strong |
| Quota check | < 10 ms | 10,000/s | Strong (active node) |
| Cost recording | < 20 ms | 10,000/s | Eventual |
| Plan generation | < 5 seconds | On demand | Strong |

## Cross-Cutting Concerns

### Security

ROS enforces that no entity may allocate resources without authorization. All resource operations require a valid entity identity (PHI-002) and are subject to quota enforcement (006-Quota). Resource allocation is gated by the verification pipeline (Stage 7).

### Evidence

Every ROS operation produces an Event per ROS-004. Events are stored in the Event Store and are immutable per CPR-004. Resource allocation decisions are auditable from request through fulfillment.

### Lifecycle

ROS integrates with LMS (Physics/006-Lifecycles). Resources are allocated when an entity activates and released when the entity terminates. Recovery (012-Recovery) handles abnormal termination.

### Capability Bounds

ROS enforces the resource bounds defined in capability templates. A capability's resource budget is a constitutional bound per CPR-006 — an entity cannot exceed its capability's resource envelope regardless of available budget.

### Communication

ROS communicates internally via ACF. Cross-instance resource sharing (014-RXP) uses the inter-instance ACF bridge. Budget and quota queries use a read-replica pattern for scalability.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Each ROS document addresses exactly one concern (overview, architecture, registry, allocator, planner, budget, quota, policy, provider SDK, reservation, cost, energy, recovery, observability, RXP). No document covers more than one. |
| R5 — Liskov Substitution | Resource providers implement the `ResourceProvider` interface and are interchangeable per 008-Provider-SDK. |
| R9 — Deterministic | Allocator is deterministic per ROS-002. Same inputs always produce same allocation. |
| R10 — Simpler Over Complex | Energy optimization (011-Energy) is optional per PHI-009. Allocation strategies are linear and predictable. |
| R13 — Design for Failure | Every provider assumes failure (heartbeat, automatic deregistration, reservation expiry). ROS fails closed — if resources cannot be confirmed, the allocation is denied. |
| R14 — Paved Path | The paved path is: Provider → Pool → Budget → Allocation → Usage → Accounting. No other path exists. |
| R15 — Open/Closed | New provider types implement the `ResourceProvider` interface without modifying ROS core. New allocation strategies extend the strategy registry without modifying the allocator. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Foundations/003-Core-Principles.md | CPR-001 (Separation of Concerns) — ROS owns Resources |
| Foundations/002-Design-DNA.md | R1, R5, R9, R10, R13, R14, R15 compliance |
| Physics/007-Capabilities.md | ROS enforces capability resource bounds |
| Physics/010-Execution.md | ROS pre-reservation in Stage 7 of verification pipeline |
| Physics/006-Lifecycles.md | Lifecycle-integrated resource allocation and recovery |
| Physics/005-Events.md | Event sourcing for all resource operations |
| Bible/02-Core/OSYS | Organization lifecycle integration with resource budgeting |
| Bible/02-Core/Sou | Sou decisions may trigger ROS planning |
| Bible/04-Execution/Security/IDS | Entity identity required for all resource operations |
