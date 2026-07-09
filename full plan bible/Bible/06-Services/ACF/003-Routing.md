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
  name: string,
  target_pattern: string,    // glob pattern matching ACF addresses
  endpoints: Endpoint[],     // eligible delivery targets
  strategy: LBStrategy,      // load balancing strategy
  health_check: HealthCheckConfig,
  timeout: duration,
  retry: RetryPolicy,
  filter: MessageFilter?
}

Endpoint {
  address: Address,
  weight: float,             // for weighted load balancing
  capabilities: string[],
  status: EndpointStatus,    // healthy, degraded, unhealthy, draining
  last_health_check: timestamp
}

HealthCheckConfig {
  interval: duration,        // default 5s
  timeout: duration,         // default 2s
  unhealthy_threshold: int,  // default 2
  degraded_threshold: duration // latency above this = degraded
}
```

## Routing Patterns

| Pattern | Syntax | Description | Example |
|---------|--------|-------------|---------|
| **Direct** | Exact address match | Route to specific entity | `aios:engine:sec:lms:001` |
| **Type-based** | Wildcard sub-type | Route to all entities of a type | `aios:engine:sec:lms:*` |
| **Hierarchy** | Prefix pattern | Route to org hierarchy | `aios:org:001:*` |
| **Anycast** | First healthy match | Route to one of many | `aios:engine:sec:verifier:*` |
| **Multicast** | Group address | Route to group members | `aios:group:auditors:001` |
| **Broadcast** | Type wildcard | Route to all matching | `aios:engine:**` |

### Pattern Matching

Pattern matching follows these rules:

1. Exact match has highest priority (direct)
2. Wildcard `*` matches exactly one segment
3. Wildcard `**` matches zero or more segments
4. Most specific pattern wins among multiple matches
5. If patterns have equal specificity, longest match wins
6. If still tied, round-robin between matched routes

## Load Balancing Strategies

| Strategy | Algorithm | When to Use |
|----------|-----------|-------------|
| **round-robin** | Sequential distribution | General-purpose stateless |
| **least-connections** | Route to least-loaded | Long-running stateful |
| **weighted** | Distribute by weight | Heterogeneous capacity |
| **random** | Random selection | Stateless, no affinity |
| **sticky** | Hash sender → endpoint | Session affinity |

### Sticky Strategy

Sticky routing hashes the sender address to select an endpoint:

```
endpoint_index = hash(sender) % endpoint_count
```

Stickiness is preserved across sender restarts (hash-based, not state-based). If the selected endpoint becomes unhealthy, a new endpoint is selected and the stickiness is updated.

## Routing Operations

```
defineRoute(target_pattern, endpoints, config) → route_id
updateRoute(route_id, updates) → void
removeRoute(route_id) → void
resolveRoute(target, sender?) → Endpoint
getRoute(route_id) → RoutingEntry
listRoutes(filter?) → RoutingEntry[]
testRoute(target, message?) → RouteTestResult
```

### Resolution Flow

```
1. Receive message with target address
2. Query routing table for matching patterns
3. If multiple patterns match, select most specific
4. Filter endpoints: remove unhealthy, sort by load
5. If no healthy endpoints, return ServiceUnavailable
6. Apply load balancing strategy to select endpoint
7. Return selected endpoint for delivery
8. Produce ACF.MessageRouted Event
```

## Service Discovery

ACF integrates with PSAP (05-Platform/003-PSAP.md) for service discovery:

| Event | PSAP Action | Routing Impact |
|-------|-------------|----------------|
| Service registered | Add to PSAP registry | Route added to routing table |
| Service deregistered | Remove from PSAP | Route removed from routing table |
| Health change to unhealthy | Mark unhealthy | Endpoint removed from active pool |
| Health change to healthy | Mark healthy | Endpoint added to active pool |
| Heartbeat missed | Mark unknown | Endpoint quarantined |

### Dynamic Endpoint Updates

The routing table is updated dynamically without service interruption:

```
1. PSAP publishes ServiceHealthChanged Event
2. Router subscribes to PSAP events
3. On event, router updates the relevant routing entry
4. New messages use the updated routing table
5. In-flight messages complete with their original endpoint
```

## Routing Table Replication

The routing table is replicated across the ACF cluster via Raft:

| Operation | Propagation | Latency |
|-----------|-------------|---------|
| Route defined | Raft commit | <100ms |
| Route updated | Raft commit | <100ms |
| Route removed | Raft commit | <100ms |
| Endpoint unhealthy | Direct update | <5s (health check interval) |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| ACF-RT-001 | RouteNotFound | No route matches the target address |
| ACF-RT-002 | NoHealthyEndpoints | All endpoints are unhealthy |
| ACF-RT-003 | EndpointUnavailable | Selected endpoint became unavailable |
| ACF-RT-004 | InvalidPattern | Route pattern syntax is invalid |
| ACF-RT-005 | DuplicateRoute | Route with same pattern already exists |
| ACF-RT-006 | CapacityExceeded | All endpoints at capacity |

## ACF Routing Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ACF.RouteDefined` | New route created | route_id, target_pattern, strategy, endpoint_count, created_by |
| `ACF.RouteUpdated` | Route modified | route_id, changes, updated_by, reason |
| `ACF.RouteRemoved` | Route deleted | route_id, removed_by, reason |
| `ACF.MessageRouted` | Message routed to endpoint | message_id, route_id, endpoint, lb_strategy, resolution_time_us |
| `ACF.EndpointUnavailable` | Endpoint becomes unhealthy | route_id, endpoint, reason, last_healthy_latency |
| `ACF.EndpointRestored` | Endpoint becomes healthy | route_id, endpoint, degraded_duration |
| `ACF.RouteUnresolvable` | No route matches | message_id, target, sender, route_attempts |
| `ACF.RoutingTableSynced` | Routing table synchronized | route_count, endpoint_count, sync_source |

## Cross-Cutting Concerns

### Security

Route definitions require Security Council authorization. Route patterns are validated to prevent address spoofing. Endpoints must authenticate with PSAP before being added to routing tables.

### Evidence

Every route definition, update, and removal produces an Event. Every routing decision produces a MessageRouted Event. Route failures are recorded.

### Lifecycle

Routes follow: Defined → Active → Updated → Suspended → Removed. Endpoint lifecycle follows PSAP service lifecycle. Routing table schema is versioned.

### Capability Bounds

ACF Routing only determines delivery paths. It does not interpret message content, does not authenticate (ACF Gateway does), and does not store messages (Broker does).

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
