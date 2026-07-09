# AIOS Bible — Platform
## 003 — Platform Service Access Point (PSAP)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Platform |
| Document ID | AIOS-BBL-005-PSAP-000 |
| Source Laws | Law 2 — Law of Non-Execution/Autonomy, Law 3 — Law of Capability Bounds |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

PSAP is the service addressing and routing layer within the Platform. It maps service names to ACF endpoints and provides load balancing, health checking, and failover. PSAP ensures that every service is discoverable, reachable, and healthy. No service communicates directly by address — all communication goes through PSAP resolution.

## Service Registry

Every service in the Platform registers with PSAP. The registry contains:

| Field | Description |
|-------|-------------|
| **service_name** | Canonical name (e.g., `lms`, `evs`, `aus`) |
| **endpoint** | ACF endpoint for the service instance |
| **health_status** | Current health: healthy, degraded, unhealthy |
| **load** | Current load metric (0.0 – 1.0) |
| **version** | Service version string |
| **capabilities** | List of capability identifiers the service provides |
| **tags** | Metadata labels for routing |

## PSAP Operations

```
registerService(service_name, endpoint, capabilities) → registration_id
deregisterService(registration_id) → void
resolveService(service_name, capabilities?) → endpoint
getServiceHealth(service_name) → HealthStatus
listServices(filter?) → ServiceInfo[]
getServiceMetrics(service_name) → Metrics
```

### Resolution Flow

```
1. Client requests resolveService("lms")
2. PSAP queries registry for all "lms" instances
3. Filters by health_status == "healthy"
4. Applies load balancing strategy to select instance
5. Returns endpoint to client
6. Client sends message to resolved endpoint via ACF
```

## Health Checking

PSAP pings every registered service every 5 seconds. Health check results:

| Status | Meaning | Traffic? |
|--------|---------|----------|
| **healthy** | Service responded within threshold | Yes |
| **degraded** | Service responded but with latency > threshold | Yes (reduced weight) |
| **unhealthy** | Service did not respond within 2 attempts | No |
| **unknown** | Service registration incomplete or initial check pending | No |

Unhealthy services are removed from the routing table. Traffic is diverted to remaining healthy instances. When all instances of a service are unhealthy, PSAP returns a ServiceUnavailable error.

## Load Balancing Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **round-robin** | Distribute evenly across instances | General-purpose |
| **least-connections** | Route to instance with fewest active connections | Long-running operations |
| **weighted** | Distribute by instance capacity | Heterogeneous instances |
| **random** | Random selection | Stateless services |
| **sticky** | Route same client to same instance | Stateful services |

## Service Discovery

PSAP supports dynamic service discovery:

- **Startup registration**: Service registers on startup with health check callback
- **Heartbeat**: Service sends periodic heartbeats (default 15s)
- **Graceful deregistration**: Service deregisters on shutdown
- **Forced deregistration**: PSAP removes unresponsive services after 3 missed heartbeats

## PSAP Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `PSAP.ServiceRegistered` | A service registers | service_name, endpoint, version, capabilities |
| `PSAP.ServiceDeregistered` | A service deregisters | service_name, endpoint, reason |
| `PSAP.ServiceHealthChanged` | A service health status changes | service_name, endpoint, old_status, new_status |
| `PSAP.ServiceUnavailable` | All instances of a service are unhealthy | service_name, instance_count, last_healthy |
| `PSAP.RoutingUpdated` | Routing table is modified | service_name, strategy, instance_count |

## Cross-Cutting Concerns

### Security

Service registration requires authentication. Only authorized Platform services may register. Deregistration is verified to prevent impersonation. Health check responses are signed. PSAP itself authenticates to ACF.

### Evidence

Every service registration, deregistration, and health change produces an Event. Service availability metrics are recorded. All routing changes are auditable.

### Lifecycle

PSAP follows standard Platform service lifecycle: Created → Registered → Active → Degraded → Unhealthy → Deregistered. Service lifecycle is managed by LMS.

### Capability Bounds

PSAP only handles service addressing and health. It does not perform message routing (ACF does), does not authenticate messages (Security Council does), and does not store service data. PSAP has no authority over service behaviour.

### Communication

PSAP communicates through ACF. Service resolution requests arrive via ACF. Health check results are published to ACF streams. PSAP does not expose external endpoints.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | PSAP does one thing: service addressing and health |
| R2 — Dependency Order | PSAP depends on ACF; no circular dependencies |
| R3 — DRY | Service registry is the single source of truth for endpoints |
| R4 — Builder Pattern | Service registration records are built by ServiceBuilder |
| R5 — Liskov | All health check providers implement the same interface |
| R6 — DI over Singletons | PSAP receives ACF as an injected dependency |
| R7 — Tests Exist | Every load balancing strategy has unit tests |
| R8 — Tests Fast | Resolution completes in <5ms |
| R9 — Deterministic | Same registry + same strategy produces same resolution |
| R10 — Simpler Over Complex | Round-robin is default; advanced strategies are explicit |
| R11 — Refactor Over Rewrite | Registry schema evolves via versioned migrations |
| R12 — Embrace Errors | Every resolution failure has a unique error code |
| R13 — Design for Failure | Unhealthy services are removed; PSAP itself is redundant |
| R14 — Paved Path | PSAP is the only path for service resolution |
| R15 — Open/Closed | New load balancing strategies extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 06-Services/ACF/003-Routing.md | ACF routing uses PSAP for service resolution |
| 06-Services/ACF/001-Architecture.md | ACF architecture — PSAP integrates with message broker |
| Physics/009-Interaction.md | Interaction patterns — service discovery |
| Standards/004-PSAP.md | PSAP addressing standards |
| Foundations/007-Naming-Conventions.md | Service naming conventions |
