# AIOS Bible — Core
## 008 — Provider SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-008 |
| Source Laws | Law 12 — Law of Bounded Capability |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Provider SDK enables building new resource providers that integrate with ROS. It handles all ROS integration concerns: ACF communication, heartbeat reporting, capacity reporting, error handling, and metrics. Provider authors implement only the resource-specific logic; the SDK provides the constitutional plumbing.

## Provider Interface

The SDK exposes the `ResourceProvider` interface that all providers must implement:

```rust
trait ResourceProvider {
    /// Returns current available and total capacity
    fn getCapacity(&self) -> Result<Capacity, ProviderError>;
    
    /// Allocates resources for a request
    fn allocate(&self, request: AllocationRequest) -> Result<AllocationResult, ProviderError>;
    
    /// Releases previously allocated resources
    fn release(&self, allocation_id: AllocationId) -> Result<ReleaseResult, ProviderError>;
    
    /// Returns provider health status
    fn health(&self) -> Result<HealthStatus, ProviderError>;
}
```

### getCapacity

| Return Field | Type | Description |
|-------------|------|-------------|
| `total` | Map<ResourceSubType, Quantity> | Total capacity per sub-type |
| `available` | Map<ResourceSubType, Quantity> | Currently available capacity |
| `allocated` | Map<ResourceSubType, Quantity> | Currently allocated capacity |
| `timestamp` | Timestamp | When this capacity snapshot was taken |

### allocate

| Parameter | Type | Description |
|-----------|------|-------------|
| `allocation_id` | UUID | Unique allocation identifier (assigned by ROS) |
| `entity_id` | UUID | Entity receiving the allocation |
| `resources` | Map<ResourceSubType, Quantity> | Resources to allocate |
| `constraints` | Map<String, String> | Provider-specific constraints |

| Return Field | Type | Description |
|-------------|------|-------------|
| `success` | Boolean | Whether allocation succeeded |
| `allocated_resources` | Map<ResourceSubType, Quantity> | Actually allocated resources |
| `provider_metadata` | Map<String, String> | Provider-specific allocation details |
| `error` | ProviderError (optional) | Error details if failed |

### release

| Parameter | Type | Description |
|-----------|------|-------------|
| `allocation_id` | UUID | Allocation to release |
| `entity_id` | UUID | Entity that owned the allocation |

| Return Field | Type | Description |
|-------------|------|-------------|
| `success` | Boolean | Whether release succeeded |
| `released_resources` | Map<ResourceSubType, Quantity> | Resources returned to pool |
| `error` | ProviderError (optional) | Error details if failed |

### health

| Return Field | Type | Description |
|-------------|------|-------------|
| `status` | Enum | healthy, degraded, unhealthy |
| `message` | String | Human-readable health description |
| `last_check` | Timestamp | When health was last verified |
| `latency_ms` | Int | Response latency in milliseconds |

## SDK Responsibilities

### ACF Integration

The SDK manages all ACF (Agent Communication Framework) connectivity:

| Concern | SDK Handling |
|---------|-------------|
| Channel setup | SDK creates and manages ACF channel to ROS Registry |
| Message serialization | SDK handles serialization/deserialization of requests and responses |
| Authentication | SDK injects provider credentials into every message |
| Retry logic | SDK retries failed messages with exponential backoff (max 3 retries) |
| Timeouts | SDK enforces request timeouts (default: 5 seconds) |

### Heartbeat Management

The SDK automatically sends heartbeats at the configured interval:

| Feature | Description |
|---------|-------------|
| Interval | Configured during registration (default: 30 seconds) |
| Capacity | Latest capacity snapshot included in every heartbeat |
| Jitter | ±10% random jitter to prevent thundering herd |
| Failure handling | SDK retries heartbeat 3 times before reporting failure |

### Capacity Reporting

The SDK manages capacity reporting:

| Trigger | Action |
|---------|--------|
| On registration | Reports initial capacity |
| Every heartbeat | Reports current capacity |
| On significant change | Reports delta immediately (change > 10% of total) |
| On allocation/release | Updates internal tracking, reports on next heartbeat |

### Error Handling

The SDK handles errors according to constitutional standards (R12 — Embrace Errors):

| Error Type | SDK Behavior |
|-----------|-------------|
| Allocation failure | Returns error to ROS with error code + context |
| Provider unavailable | Returns ProviderUnavailable error, marks health as degraded |
| Capacity exceeded | Returns CapacityExceeded error |
| Authentication failure | Returns AuthFailure error |
| Timeout | Returns Timeout error after 5 seconds |
| Network error | Retries up to 3 times, then returns NetworkError |

### Metrics

The SDK exposes standard metrics:

| Metric | Type | Description |
|--------|------|-------------|
| allocation_count | Counter | Total allocations performed |
| allocation_latency_ms | Histogram | Allocation latency distribution |
| release_count | Counter | Total releases performed |
| capacity_total | Gauge | Total capacity per sub-type |
| capacity_available | Gauge | Available capacity per sub-type |
| health_status | Gauge | Current health status (1=healthy, 0=degraded, -1=unhealthy) |
| heartbeat_latency_ms | Histogram | Heartbeat round-trip latency |

## Provider Registration

Providers use the SDK to register with ROS:

```rust
let provider = MyCustomProvider::new(config);
let sdk = ProviderSDK::new(provider, ProviderConfig {
    provider_id: "my-provider-001",
    resource_type: ResourceType::Compute,
    location: "node-01",
    heartbeat_interval: Duration::from_secs(30),
    credentials: auth_credentials,
});

sdk.register().await?;
// Provider is now registered and heartbeating automatically
sdk.run().await?; // Blocks until shutdown
```

## Shipped Provider Types

### LocalMachine Provider

Manages local machine resources (CPU, RAM, disk).

| Property | Value |
|----------|-------|
| Resource types | compute (cpu), memory (ram), storage (disk) |
| Auto-detection | Detects available cores, memory, disk space |
| Isolation | Process-level isolation via OS cgroups |
| Constraints | max_cores_per_allocation, max_memory_per_allocation |

### CloudVM Provider

Manages cloud VM resources via cloud provider API.

| Property | Value |
|----------|-------|
| Resource types | compute (cpu), memory (ram), storage (ssd) |
| Backends | AWS EC2, Azure VM, GCP Compute |
| Auto-scaling | Can provision/deprovision VMs based on demand |
| Constraints | instance_type, region, availability_zone |

### KubernetesPod Provider

Manages Kubernetes pod resources.

| Property | Value |
|----------|-------|
| Resource types | compute (cpu), memory (ram) |
| Namespace isolation | Each allocation creates a pod in a dedicated namespace |
| Auto-scaling | Leverages K8s cluster autoscaler |
| Constraints | node_selector, tolerations, resource_limits |

### ExternalAPI Provider

Manages token-based resources from external APIs (LLM providers).

| Property | Value |
|----------|-------|
| Resource types | tokens (input, output) |
| Backends | OpenAI, Anthropic, local LLM |
| Rate limiting | SDK handles API rate limits with queueing |
| Constraints | model, max_tokens, temperature (passed as allocation constraints) |

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| ProviderSDKInitialized | SDK created | provider_id, sdk_version, timestamp |
| ProviderRegistered | Registration complete | provider_id, resource_type, timestamp |
| ProviderHeartbeatSent | Heartbeat sent | provider_id, capacity, timestamp |
| ProviderAllocationCompleted | Allocation | provider_id, allocation_id, success, latency_ms, timestamp |
| ProviderReleaseCompleted | Release | provider_id, allocation_id, success, timestamp |
| ProviderError | SDK error | provider_id, error_code, error_context, timestamp |

## Cross-Cutting Concerns

### Security

Provider credentials are injected at SDK initialization. The SDK never logs credentials. Provider identity is verified by ROS Registry during registration.

### Evidence

Every SDK operation produces an Event. Provider metrics are exposed to ROS Observability.

### Lifecycle

The SDK manages the provider lifecycle: registration → heartbeat → allocation → release → deregistration. On SDK shutdown, all outstanding allocations are released gracefully.

### Capability Bounds

The SDK enforces that reported capacity never exceeds the provider's actual capability. Providers cannot report fake capacity.

### Communication

All provider-ROS communication uses ACF. The SDK handles encryption, authentication, and serialization.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | The SDK handles only ROS integration concerns. Provider authors write only resource logic. |
| R5 — Liskov Substitution | All providers implement the same `ResourceProvider` interface and are interchangeable. |
| R6 — DI over Singletons | Providers are injected into the SDK, not accessed globally. |
| R12 — Embrace Errors | Every error has a unique code, context, and handling path. |
| R13 — Design for Failure | SDK retries failed operations with exponential backoff. If ROS is unreachable, SDK buffers events and replays on reconnection. |
| R15 — Open/Closed | New provider types implement `ResourceProvider` without modifying the SDK. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/002-Registry.md | Providers register with the Registry via SDK |
| ROS/003-Allocator.md | Allocator calls provider allocate/release via SDK |
| ROS/013-Observability.md | SDK metrics feed into ROS observability |
| Physics/007-Capabilities.md | Provider capacity defines capability resource bounds |
| Bible/08-Interfaces/ACF | SDK uses ACF for all communication |
