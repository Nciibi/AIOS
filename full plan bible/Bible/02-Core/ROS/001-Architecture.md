# AIOS Bible — Core
## 001 — ROS Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-001 |
| Source Laws | Law 7 — Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Defines the component architecture of ROS, the data flow through the resource management pipeline, the clustering model for high availability, and the abstract provider model that enables extensible resource backends.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      Resource Orchestration Service               │
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Registry │  │Allocator │  │ Planner  │  │ Budget   │       │
│  │(002)     │  │(003)     │  │(004)     │  │(005)     │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │              │
│  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐       │
│  │  Quota   │  │  RMP     │  │  Cost    │  │ Energy   │       │
│  │ (006)    │  │ (007)    │  │ (010)    │  │ (011)    │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │              │
│  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐       │
│  │Recovery  │  │Reservtn  │  │Observblty│  │   RXP    │       │
│  │ (012)    │  │ (009)    │  │ (013)    │  │ (014)    │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Provider Abstraction Layer                     │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ Compute  │ │  Memory  │ │ Storage  │ │  Tokens  │   │   │
│  │  │ Provider │ │ Provider │ │ Provider │ │ Provider │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  │  ┌──────────┐ ┌──────────┐                               │   │
│  │  │  Energy  │ │  Custom  │                               │   │
│  │  │ Provider │ │ Provider │                               │   │
│  │  └──────────┘ └──────────┘                               │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
1. Provider Registration ──→ Registry (provider registers capabilities)
2. Budget Assignment ──────→ Budget (entity receives resource budget)
3. Allocation Request ─────→ Allocator (entity requests resources)
     │
     ├──→ Registry (check provider availability)
     ├──→ Budget (check remaining budget)
     ├──→ Quota (check hard limits)
     ├──→ RMP (evaluate allocation policies)
     └──→ Cost (record usage for accounting)
     │
     ▼
4. Allocation Result ──────→ Entity (resources assigned)
     │
     └──→ Observability (metrics updated)
5. Usage Tracking ─────────→ Cost (actual consumption recorded)
6. Periodic Accounting ────→ Cost (billing, reports)
7. Release ────────────────→ Allocator → Registry (resources returned)
```

## ROS Clustering

ROS operates in an active-passive high-availability configuration:

| Node Role | Function | Count |
|-----------|----------|-------|
| Active | Writes (allocation, registration, budget changes) | 1 |
| Passive Standby | Takes over on active failure | 1 |
| Read Replicas | Budget queries, cost reports, observability dashboards | N (scalable) |

**Failure handling**: On active node failure, the passive standby promotes to active within 5 seconds. Read replicas continue serving queries uninterrupted. All allocation operations pause during promotion and resume once the new active is confirmed.

**Consistency model**: Read replicas may serve stale budget/quota data (eventual consistency, < 1 second lag). Allocation operations always read from the active node for consistency.

## Provider Model

Every resource provider implements the abstract `ResourceProvider` interface (R5 Liskov Substitution):

| Method | Signature | Description |
|--------|-----------|-------------|
| `getCapacity` | `() → Capacity` | Reports current available capacity |
| `allocate` | `(AllocationRequest) → AllocationResult` | Allocates resources |
| `release` | `(AllocationId) → ReleaseResult` | Releases allocated resources |
| `health` | `() → HealthStatus` | Returns provider health |

### Concrete Provider Types

| Provider | Resource Types | Backend Examples |
|----------|---------------|------------------|
| Compute | CPU cores, GPU cores, CPU time | Local machine, cloud VM, Kubernetes pod |
| Memory | RAM, VRAM | System memory, GPU memory |
| Storage | Disk, SSD, Object storage | Local filesystem, S3, NFS |
| Tokens | LLM tokens (input/output) | OpenAI API, local LLM, Anthropic API |
| Energy | Power budget, watt-hours | Power meter, cloud energy API |

## Provider Registration Lifecycle

```
Provider Created ──→ Registered (active) ──→ Deregistered (inactive)
                         │
                         ├──→ Health Check Failed (marked degraded)
                         ├──→ Heartbeat Missed (marked suspected)
                         └──→ Automatic Deregistration (removed after N failures)
```

Compliant with R13 (Design for Failure): providers that fail health checks are automatically deregistered. ROS never allocates to a provider with unknown health status.

## Component Responsibilities

| Component | Primary Responsibility | Dependencies | Consumed By |
|-----------|----------------------|--------------|-------------|
| Registry | Provider registration, capacity reporting, health tracking | Providers (via SDK) | Allocator, Planner, Observability |
| Allocator | Resource allocation decisions, strategy selection, preemption | Registry, Budget, Quota, RMP, Cost | Execution pipeline, entities |
| Planner | Resource forecasting, plan creation, variance analysis | Registry, Cost, OSYS, Sou/Missions | Organization admins, Security Council |
| Budget | Per-entity budget management, burst tracking | Cost (for usage data) | Allocator, entities, Observability |
| Quota | Hard/soft limit enforcement, violation escalation | Registry (for capacity) | Allocator, Security Council |
| RMP | Policy management, policy evaluation | None (self-contained store) | Allocator, Security Council, Organizations |
| Cost | Usage recording, cost calculation, report generation | Allocator (for allocation data) | Budget, Planner, Organization admins |
| Energy | Energy consumption tracking, energy-aware provider selection | Registry, Providers | Allocator (via policy) |
| Recovery | Resource cleanup on entity/scope termination | Allocator, Registry, Providers | LMS, Security Council |
| Reservation | Resource holding for execution authorization | Allocator, Registry, Budget | Verification pipeline (Stage 7) |
| Observability | Metrics, monitoring, alerting | Event Store (all components) | Security Council, Organization admins |
| RXP | Cross-instance resource sharing | ACF Bridge, Registry | Instance operators, Federation partners |

## Request Routing

Allocation requests follow a defined routing path through ROS:

```
Request arrives at ROS Gateway
    │
    ├──→ Read-only request? (budget query, cost report, plan view)
    │       └──→ Route to read replica
    │
    └──→ Write request? (allocation, registration, budget change)
            └──→ Route to active node
                    │
                    ├──→ Allocator path (allocation, reservation)
                    ├──→ Registry path (provider registration, deregistration)
                    ├──→ Budget path (budget set, adjust)
                    ├──→ Quota path (quota set, check)
                    └──→ RXP path (cross-instance request)
```

## Service Level Objectives

| SLO | Target | Measurement |
|-----|--------|-------------|
| Allocation availability | 99.99% uptime | Monthly allocation success rate |
| Allocation latency P99 | < 100 ms | End-to-end allocation latency |
| Budget query latency P99 | < 20 ms | Budget read query latency |
| Data consistency | < 1 second lag | Read replica staleness |
| Provider heartbeat processing | < 5 ms per heartbeat | Heartbeat processing latency |
| Recovery completion | < 60 seconds | Time from trigger to completion |
| RXP transfer completion | < 30 seconds | Time from accept to transfer complete |

## Cross-Cutting Concerns

### Security

The Registry validates provider identity before registration. Only authenticated providers may register resources. Allocation requests include entity identity verified by IDS.

### Evidence

All component operations produce Events: `ProviderRegistered`, `AllocationCompleted`, `BudgetUpdated`, `QuotaViolated`.

### Lifecycle

Provider lifecycle is monitored via health checks and heartbeats. Entity lifecycle termination triggers resource recovery (012-Recovery).

### Capability Bounds

Provider capacity reporting is the source of truth for capability bounds. If a provider reports zero capacity, no capability requiring that resource can execute.

### Communication

ROS components communicate via ACF. Internal ROS calls use private ACF channels. External calls (to providers, to the verification pipeline) use public ACF channels.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Each ROS component has exactly one responsibility. |
| R5 — Liskov Substitution | All providers implement the same interface and are interchangeable. |
| R6 — DI over Singletons | Components receive dependencies (Registry, Allocator, Budget) via constructor injection. |
| R9 — Deterministic | Allocation logic is deterministic per ROS-002. |
| R13 — Design for Failure | Active-passive clustering, automatic failover, provider health monitoring. |
| R14 — Paved Path | The data flow is the paved path: Registration → Budget → Allocation → Usage → Accounting. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/000-Overview.md | ROS architecture overview and invariants |
| ROS/002-Registry.md | Provider registration and capability discovery |
| ROS/003-Allocator.md | Allocation algorithm within the architecture |
| ROS/005-Budget.md | Budget component and enforcement |
| ROS/006-Quota.md | Quota component and enforcement |
| ROS/008-Provider-SDK.md | Provider interface implementation SDK |
| Physics/010-Execution.md | Integration with verification pipeline |
| Physics/006-Lifecycles.md | Lifecycle-driven resource management |
