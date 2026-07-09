# AIOS Bible — Services
## ACF 003 — Routing

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Services (ACF) |
| Document ID | AIOS-BBL-006-ACF-003 |
| Source Laws | Law 4 — Law of Evidence, Law 5 — Law of Identity |
| Source Physics | Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Routing rules and service discovery for ACF messages. The Router determines the delivery path for every message based on the target address, routing table, load balancing strategy, and health checks. Routing ensures that every message reaches the correct entity or entities.

## Routing Table

The routing table maps target patterns to endpoints:

```
RoutingEntry {
  id: UUID,
  target_pattern: string,    // glob pattern matching ACF addresses
  endpoints: Endpoint[],     // eligible delivery targets
  strategy: LBStrategy,      // load balancing strategy
  health_check: HealthCheck, // health check configuration
  timeout: duration,         // delivery timeout
  retry: RetryPolicy,        // retry configuration
  filter: MessageFilter?     // optional message filter
}

Endpoint {
  address: Address,
  weight: float,             // for weighted load balancing
  capabilities: string[],    // endpoint capabilities
  status: EndpointStatus
}
```

## Routing Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| **Direct** | Route to a specific entity | `aios:engine:sec:lms:001` |
| **Type-based** | Route to all entities of a type | `aios:engine:sec:lms:*` |
| **Hierarchy-based** | Route to parent/child in org tree | `aios:org:001:*` |
| **Anycast** | Route to one of many (first healthy) | `aios:engine:sec:verifier:*` |
| **Multicast** | Route to a specific group | `aios:group:auditors:001` |

## Load Balancing Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **round-robin** | Distribute evenly across endpoints | General-purpose stateless |
| **least-connections** | Route to least-loaded endpoint | Long-running stateful ops |
| **weighted** | Distribute by endpoint weight | Heterogeneous capacity |
| **random** | Random selection | Stateless, no affinity needed |
| **sticky** | Same sender → same endpoint | Session affinity |

## Routing Operations

```
defineRoute(target_pattern, endpoints, config) → route_id
updateRoute(route_id, updates) → void
removeRoute(route_id) → void
resolveRoute(target) → Endpoint
getRoute(route_id) → RoutingEntry
listRoutes(filter?) → RoutingEntry[]
testRoute(target, message) → RouteTestResult
```

### Resolution Flow

```
1. Receive message with target address
2. Match target against routing table patterns
3. If multiple patterns match, most specific pattern wins
4. Filter endpoints by health status (healthy only)
5. Apply load balancing strategy to select endpoint
6. If no healthy endpoints, return ServiceUnavailable
7. Return selected endpoint for delivery
```

## Service Discovery

ACF integrates with PSAP (05-Platform/003-PSAP.md) for service discovery:

1. Services register with PSAP on startup
2. PSAP provides health status for all services
3. ACF routing table is updated from PSAP registry
4. Unhealthy services are removed from routing
5. New service instances are automatically added

### Dynamic Endpoint Updates

- **Added**: New service instance registered → routing table updated
- **Removed**: Service instance deregistered → routing table updated
- **Unhealthy**: Service fails health check → removed from active endpoints
- **Restored**: Service passes health check again → added to active endpoints

## ACF Routing Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.RouteDefined` | A new route is created | route_id, target_pattern, strategy, endpoint_count |
| `ACF.RouteUpdated` | A route is modified | route_id, changes |
| `ACF.RouteRemoved` | A route is deleted | route_id, removed_by |
| `ACF.MessageRouted` | A message is routed to an endpoint | message_id, route_id, endpoint, lb_strategy |
| `ACF.EndpointUnavailable` | An endpoint becomes unhealthy | route_id, endpoint, reason |
| `ACF.EndpointRestored` | An endpoint becomes healthy again | route_id, endpoint |
| `ACF.RouteUnresolvable` | No route matches target | message_id, target, reason |

## Cross-Cutting Concerns

### Security

Route definitions require Security Council authorization. Route patterns are validated to prevent address spoofing. Endpoints must authenticate with PSAP before being added to routing tables.

### Evidence

Every route definition, update, and removal produces an Event. Every routing decision produces a MessageRouted Event. Route failures are recorded.

### Lifecycle

Routes follow: Defined → Active → Updated → Suspended → Removed. Endpoint lifecycle follows PSAP service lifecycle. Routing table schema is versioned.

### Capability Bounds

ACF Routing only determines delivery paths. It does not interpret message content, does not authenticate (ACF Gateway does), and does not store messages (Broker does). Routing capabilities are limited to: pattern matching, endpoint selection, and load distribution.

### Communication

Routing communicates internally with PSAP for service discovery. All routing decisions are made within the ACF cluster. Routing table updates are replicated through Raft consensus.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Routing does one thing: message delivery path selection |
| R2 — Dependency Order | Routing depends on PSAP; no upward deps |
| R3 — DRY | Routing table is the single source for delivery paths |
| R4 — Builder Pattern | Routing entries are built by RouteBuilders |
| R5 — Liskov | All load balancing strategies implement the same LB interface |
| R6 — DI over Singletons | Router receives PSAP as injected dependency |
| R7 — Tests Exist | Every routing pattern and LB strategy has tests |
| R8 — Tests Fast | Route resolution completes in <2ms |
| R9 — Deterministic | Same routing table + same target always produces same resolution |
| R10 — Simpler Over Complex | Pattern matching is explicit; no fuzzy routing |
| R11 — Refactor Over Rewrite | Routing table evolves via PSAP updates |
| R12 — Embrace Errors | Every routing failure has a unique error code |
| R13 — Design for Failure | Unhealthy endpoints are bypassed; routing fails to safe |
| R14 — Paved Path | ACF Routing is the only path for message delivery |
| R15 — Open/Closed | New LB strategies and patterns extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Architecture.md | ACF architecture — Router component |
| 002-Messages.md | Message target is resolved by Router |
| 05-Platform/003-PSAP.md | PSAP provides service discovery |
| 006-Reliability.md | Route retry policy |
| Physics/009-Interaction.md | Interaction model |
