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

| Field | Type | Description |
|-------|------|-------------|
| service_name | string | Canonical name (e.g., `lms`, `evs`, `aus`) |
| instance_id | UUID | Unique instance identifier |
| endpoint | ACF Address | ACF endpoint for the service instance |
| health_status | enum | healthy, degraded, unhealthy, unknown |
| load | float | Current load metric (0.0 – 1.0) |
| version | string | Service version string |
| capabilities | string[] | Capability identifiers the service provides |
| tags | map<string, string> | Metadata labels for routing and filtering |
| registered_at | timestamp | When the service registered |
| last_heartbeat | timestamp | Last successful heartbeat |

## PSAP Operations

```
registerService(service_name, endpoint, capabilities, config) → registration_id
deregisterService(registration_id) → void
resolveService(service_name, capabilities?, filter?) → endpoint
resolveServiceBatch(service_name, count) → endpoint[]
getServiceHealth(service_name) → HealthStatus[]
getServiceHealthByInstance(registration_id) → HealthStatus
listServices(filter?) → ServiceInfo[]
getServiceMetrics(registration_id) → Metrics
updateServiceCapabilities(registration_id, capabilities) → void
updateServiceLoad(registration_id, load) → void
```

### RegisterService

| Parameter | Description |
|-----------|-------------|
| service_name | Canonical service name |
| endpoint | ACF address for this instance |
| capabilities | List of provided capabilities |
| config | Health check config (interval, timeout, threshold) |

Services must authenticate before registration. Registration produces a PSAP.ServiceRegistered Event.

### ResolveService

Resolution algorithm:

```
1. Query all instances matching service_name
2. If capabilities filter provided, filter by capabilities
3. Filter by health_status == "healthy" (or "degraded" if no healthy)
4. Sort by load (ascending)
5. Apply load balancing strategy to select instance
6. Return selected endpoint
7. If no instances match, return ServiceUnavailable error
```

## Health Checking

PSAP pings every registered service on a configurable interval:

| Parameter | Default | Description |
|-----------|---------|-------------|
| ping_interval | 5s | Time between health checks |
| ping_timeout | 2s | Timeout per health check |
| unhealthy_threshold | 2 | Consecutive failures before marking unhealthy |
| degraded_threshold | 500ms | Latency above this = degraded |
| recovery_threshold | 1 | Consecutive successes to restore |

### Health Status Transitions

```
Initial → Unknown → Healthy ↔ Degraded → Unhealthy
```

| Status | Traffic | Action |
|--------|---------|--------|
| **healthy** | Yes | Normal routing |
| **degraded** | Yes (reduced weight) | Service is slow but functional |
| **unhealthy** | No | Removed from routing, alert generated |
| **unknown** | No | Initial state, pending first check |

### Health Check Protocol

PSAP sends a `PSAP.HealthCheck` message to the service's ACF endpoint. The service must respond within the ping_timeout. The health check response includes:

```
HealthCheckResponse {
  status: "healthy" | "degraded",
  load: float,           // 0.0 – 1.0
  version: string,
  uptime_seconds: int,
  capabilities: string[]
}
```

## Load Balancing Strategies

| Strategy | Algorithm | Use Case |
|----------|-----------|----------|
| **round-robin** | Sequential distribution | General-purpose stateless |
| **least-connections** | Route to instance with fewest active connections | Long-running operations |
| **weighted** | Distribute by instance weight | Heterogeneous instances |
| **random** | Random selection | Stateless services |
| **sticky** | Hash sender → instance | Stateful services |

### Strategy Configuration

```
LBConfig {
  strategy: LBStrategy,
  weights?: map<instance_id, float>,    // for weighted strategy
  stickiness_ttl?: duration,            // for sticky strategy
  fallback_strategy?: LBStrategy        // if primary fails
}
```

## Service Discovery Mechanisms

| Mechanism | Description |
|-----------|-------------|
| **Startup registration** | Service registers on startup with health check callback |
| **Heartbeat** | Service sends periodic heartbeats (default 15s interval) |
| **Graceful deregistration** | Service deregisters on shutdown via PSAP.Deregister |
| **Forced deregistration** | PSAP removes after 3 consecutive missed heartbeats |
| **Health check probe** | PSAP initiates health checks on registered services |

## Metrics and Monitoring

PSAP collects per-service metrics:

| Metric | Description |
|--------|-------------|
| service_health_status | Current health status |
| service_load | Current load (0.0 – 1.0) |
| service_resolution_count | Number of resolutions per interval |
| service_resolution_latency | Time to resolve (P50, P95, P99) |
| service_instance_count | Number of instances per service |
| unhealthy_instances | Count of unhealthy instances |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| PSAP-001 | ServiceNotFound | No service with the given name |
| PSAP-002 | NoHealthyInstances | All instances are unhealthy |
| PSAP-003 | InstanceNotFound | Registration ID not found |
| PSAP-004 | RegistrationFailed | Service could not authenticate |
| PSAP-005 | DuplicateRegistration | Instance already registered |
| PSAP-006 | HeartbeatMissed | Instance missed heartbeat threshold |

## PSAP Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `PSAP.ServiceRegistered` | Service registers | service_name, instance_id, endpoint, version, capabilities |
| `PSAP.ServiceDeregistered` | Service deregisters | service_name, instance_id, reason, uptime_seconds |
| `PSAP.ServiceHealthChanged` | Health status changes | service_name, instance_id, old_status, new_status, reason |
| `PSAP.ServiceUnavailable` | All instances unhealthy | service_name, instance_count, last_healthy_timestamp |
| `PSAP.HeartbeatReceived` | Heartbeat from service | service_name, instance_id, load, timestamp |
| `PSAP.RoutingUpdated` | Routing table modified | service_name, strategy, instance_count, change_type |
| `PSAP.LoadBalanced` | Load balancing decision | service_name, instance_id, strategy, sender |

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
