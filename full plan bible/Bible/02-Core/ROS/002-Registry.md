# AIOS Bible — Core
## 002 — Resource Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-002 |
| Source Laws | Law 12 — Law of Bounded Capability |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Registry is the authoritative catalog of all resource providers and their capabilities within an AIOS instance. Every provider registers here, reports capacity, and is discovered by the Allocator. The Registry is the source of truth for "what resources are available."

## Provider Registration

Every provider must register before it can supply resources. The registration record contains:

| Field | Type | Description |
|-------|------|-------------|
| `provider_id` | UUID | Unique provider identifier (UUIDv4) |
| `resource_type` | Enum | Type of resource (compute, memory, storage, tokens, energy) |
| `capacity` | ResourceCapacity | Total and available capacity |
| `availability` | Float | Provider availability (0.0–1.0, for planning) |
| `location` | String | Physical or logical location (node, region, cluster) |
| `cost_model` | CostModel | Pricing structure for this provider |
| `status` | Enum | active, degraded, suspected, inactive |
| `heartbeat_interval` | Duration | Expected heartbeat interval in seconds |
| `last_heartbeat` | Timestamp | Most recent heartbeat timestamp |
| `metadata` | Map | Provider-specific metadata (architecture, GPU type, etc.) |

### Resource Types

| Resource Type | Sub-types | Unit | Description |
|---------------|-----------|------|-------------|
| compute | cpu, gpu | cores, TFLOPS | Computational processing power |
| memory | ram, vram | MB, GB | Volatile memory |
| storage | disk, ssd, object | GB, TB | Non-volatile storage |
| tokens | input, output | tokens | LLM token budget |
| energy | power | watts, watt-hours | Power consumption budget |

## Registry Operations

### registerProvider

Registers a new resource provider with the Registry.

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider_id` | UUID | Unique provider identifier |
| `resource_type` | Enum | Type of resource |
| `capacity` | ResourceCapacity | Initial capacity report |
| `location` | String | Provider location |
| `cost_model` | CostModel | Pricing structure |
| `heartbeat_interval` | Duration | Expected heartbeat interval |

**Event produced**: `ProviderRegistered { provider_id, resource_type, capacity, location, timestamp }`

### deregisterProvider

Removes a provider from the Registry. All outstanding allocations from this provider must be released first.

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider_id` | UUID | Provider to deregister |
| `reason` | Enum | voluntary, failure, administrative |

**Event produced**: `ProviderDeregistered { provider_id, reason, timestamp }`

### updateCapacity

Updates the capacity report for a registered provider.

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider_id` | UUID | Provider identifier |
| `capacity` | ResourceCapacity | New capacity data |

**Event produced**: `ProviderCapacityUpdated { provider_id, old_capacity, new_capacity, timestamp }`

### queryProviders

Queries providers matching specified criteria.

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_type` | Enum (optional) | Filter by resource type |
| `location` | String (optional) | Filter by location |
| `status` | Enum (optional) | Filter by status |
| `min_availability` | Float (optional) | Minimum availability threshold |

**Returns**: List of matching providers with current capacity and status.

### listResources

Lists all available resources across all providers, aggregated by type.

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_type` | Enum (optional) | Filter by resource type |

**Returns**: Aggregated resource availability across all providers.

## Health Checking

Providers must send heartbeats at their configured interval. The Registry tracks heartbeat health:

| Heartbeat State | Condition | Action |
|----------------|-----------|--------|
| Healthy | Heartbeat received within interval | Normal operation |
| Missed | Heartbeat overdue by 1 interval | Mark status as suspected |
| Degraded | Heartbeat overdue by 2 intervals | Mark status as degraded, notify Allocator |
| Failed | Heartbeat overdue by 3 intervals | Mark status as inactive, trigger automatic deregistration |

**Heartbeat operation**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider_id` | UUID | Provider identifier |
| `capacity` | ResourceCapacity | Updated capacity (may be same as previous) |

**Event produced**: `ProviderHeartbeatReceived { provider_id, capacity, timestamp }`

**Automatic deregistration on failure** (R13 Design for Failure): After 3 missed heartbeats, the Registry automatically marks the provider as inactive and produces `ProviderDeregistered` with reason `heartbeat_timeout`. The Allocator stops sending allocation requests to this provider.

## Registry Data Structures

```
ResourceCapacity {
    total: Map<ResourceSubType, Quantity>
    available: Map<ResourceSubType, Quantity>
    allocated: Map<ResourceSubType, Quantity>
}

CostModel {
    base_rate: Float
    per_unit_rate: Float
    unit: String (e.g., "per_core_hour", "per_gb_hour", "per_token")
    currency: String (default: "credits")
}

ProviderRecord {
    provider_id: UUID
    resource_type: ResourceType
    capacity: ResourceCapacity
    availability: Float
    location: String
    cost_model: CostModel
    status: ProviderStatus
    heartbeat_interval: Duration
    last_heartbeat: Timestamp
    registered_at: Timestamp
    metadata: Map<String, String>
}
```

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| ProviderRegistered | registerProvider | provider_id, resource_type, capacity, location, timestamp |
| ProviderDeregistered | deregisterProvider | provider_id, reason, timestamp |
| ProviderCapacityUpdated | updateCapacity | provider_id, old_capacity, new_capacity, timestamp |
| ProviderHeartbeatReceived | Heartbeat | provider_id, capacity, timestamp |
| ProviderStatusChanged | Health check state transition | provider_id, old_status, new_status, timestamp |

## Cross-Cutting Concerns

### Security

Provider registration requires authentication. Only authorized provider binaries may register. The Registry validates provider identity before accepting any operation.

### Evidence

Every registry operation produces an Event per ROS-004. Provider history is fully auditable.

### Lifecycle

Provider lifecycle (registration → heartbeat → deregistration) mirrors entity lifecycle. Providers that outlive their expected lifespan without heartbeats are automatically removed.

### Capability Bounds

The Registry is the source of truth for capability bounds. Capability templates reference resource types, and the Registry determines whether those resources are available.

### Communication

The Registry communicates with providers via ACF. Providers use the Provider SDK (008-Provider-SDK) to handle ACF integration.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | The Registry handles only provider registration and capacity reporting. |
| R5 — Liskov Substitution | All provider types store identical record structures. |
| R9 — Deterministic | Same query inputs always produce the same provider list. |
| R13 — Design for Failure | Automatic deregistration on heartbeat failure. ROS never allocates to unconfirmed providers. |
| R14 — Paved Path | The paved path for provider lifecycle is: Register → Heartbeat → Deregister. |
| R15 — Open/Closed | New resource types can be added to the enum without modifying registry internals. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/001-Architecture.md | Registry is the first component in the ROS data flow |
| ROS/003-Allocator.md | Allocator queries the Registry for provider availability |
| ROS/008-Provider-SDK.md | SDK handles heartbeat and registration for providers |
| ROS/013-Observability.md | Provider health metrics are exposed for monitoring |
| Physics/007-Capabilities.md | Provider capacity defines capability resource bounds |
| Physics/005-Events.md | Event sourcing for registry operations |
