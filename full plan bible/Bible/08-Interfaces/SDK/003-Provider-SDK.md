# AIOS Bible â€” Interfaces
## SDK â€” 003: Provider SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-SDK-003 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Provider SDK provides the standard interface for building resource providers that register with ROS (Resource Orchestration Service) and offer capabilities to AIOS. A resource provider is any external system or service that AIOS can consume â€” compute clusters, LLM APIs, storage backends, network services, hardware devices, or any other resource type.

The Provider SDK is the extension mechanism of AIOS. While the Runtime SDK defines how Workers execute, and the Knowledge SDK defines how knowledge is managed, the Provider SDK defines how *anything else* connects to AIOS. It enables Organizations, partners, and the open-source community to add new resource types without modifying AIOS core.

## Provider Interface

Every resource provider must implement the `ResourceProvider` interface:

```
interface ResourceProvider {
  // Registration
  register(registration: ProviderRegistration): RegistrationReceipt
  deregister(providerId: ProviderID): void
  updateCapabilities(providerId: ProviderID, capabilities: Capability[]): void

  // Lifecycle
  initialize(config: ProviderConfig): void
  shutdown(): void
  healthCheck(): HealthStatus

  // Resource Management
  discover(): ResourceDiscovery
  allocate(request: AllocationRequest): AllocationReceipt
  release(allocationId: AllocationID): void
  queryAvailability(filter: AvailabilityFilter): AvailabilityReport

  // Capability Execution
  executeCapability(capabilityId: CapabilityID, params: ExecutionParams): ExecutionResult
  cancelExecution(executionId: ExecutionID): void

  // Monitoring
  streamMetrics(): MetricStream
  reportUsage(): UsageReport
  getStatus(): ProviderStatus

  // Evidence
  produceEvent(event: ProviderEvent): void
  getEventLog(filter: EventFilter): Event[]
}
```

| Method | Description | Latency SLO |
|--------|-------------|-------------|
| `register` | Register provider with ROS | < 2 seconds |
| `deregister` | Remove provider from ROS registry | < 2 seconds |
| `updateCapabilities` | Update advertised capabilities | < 1 second |
| `initialize` | Initialize provider with configuration | < 30 seconds |
| `shutdown` | Gracefully shut down provider | < 10 seconds |
| `healthCheck` | Report provider health status | < 500 ms |
| `discover` | Discover available resources | < 5 seconds |
| `allocate` | Allocate a resource from the provider | < 2 seconds |
| `release` | Release an allocated resource | < 1 second |
| `queryAvailability` | Query resource availability | < 1 second |
| `executeCapability` | Execute a capability on the provider | Varies |
| `cancelExecution` | Cancel a running capability | < 1 second |
| `streamMetrics` | Stream real-time metrics | Real-time |
| `reportUsage` | Report resource consumption | < 1 second |
| `produceEvent` | Emit a provider-specific Event | < 100 ms |
| `getEventLog` | Query provider's Event log | < 1 second |

## Provider Registration

Providers register with ROS through a structured registration:

```
{
  "provider_id": "uuid-v7 (assigned by ROS)",
  "provider_type": "compute | storage | llm | network | hardware | custom",
  "provider_name": "string (human-readable)",
  "version": "1.0.0",
  "capabilities": [
    {
      "id": "capability-uuid",
      "name": "CapabilityName",
      "parameters": { ... },
      "resource_profile": {
        "tokens_per_second": 1000,
        "compute_units": 16,
        "memory_mb": 8192,
        "storage_gb": 100
      }
    }
  ],
  "endpoints": {
    "primary": "acf://provider-id/primary",
    "metrics": "acf://provider-id/metrics",
    "events": "acf://provider-id/events"
  },
  "authentication": {
    "method": "mTLS | token | api_key",
    "credential_ref": "kms://key-id"
  }
}
```

Registration is validated by ROS. Providers with invalid capability schemas or missing required endpoints are rejected.

## Provider Lifecycle

Providers follow this lifecycle within ROS:

```
Discovered â†’ Registered â†’ Initialized â†’ Active â†” Degraded â†’ Offline â†’ Deregistered
```

| State | Description | Resource Availability |
|-------|-------------|----------------------|
| Discovered | Provider detected but not yet registered | None |
| Registered | Registration accepted, configuration pending | None |
| Initialized | Provider initialized with configuration | None |
| Active | Provider fully operational | Resources available for allocation |
| Degraded | Provider operating with reduced capacity | Limited availability |
| Offline | Provider not reachable | No resources available |
| Deregistered | Provider removed from ROS registry | None |

Health checks drive state transitions. A provider that fails consecutive health checks transitions to Degraded then Offline.

## Provider Capability Lifecycle

Provider capabilities follow a defined lifecycle:

```
Registered â†’ Active â†’ Deprecated â†’ Removed
```

| State | Description | Allocation Possible? |
|-------|-------------|---------------------|
| Registered | Capability is registered but not yet verified | No |
| Active | Capability is available for allocation | Yes |
| Deprecated | Capability is scheduled for removal | Yes (existing consumers) |
| Removed | Capability is no longer available | No |

Capability deprecation requires a minimum 30-day notice. Deprecated capabilities remain available for existing consumers but are not advertised to new consumers.

## Resource Types

The Provider SDK supports these built-in resource types, with extension points for custom types:

| Resource Type | Provider Examples | Allocation Units | ROS Accounting |
|--------------|-------------------|-----------------|----------------|
| `compute` | AWS EC2, Kubernetes, local Docker | CPU-seconds, GPU-seconds | Usage-based |
| `storage` | S3, local FS, NFS | GB-months | Reservation-based |
| `llm` | Claude API, Ollama, vLLM | Tokens (input/output) | Usage-based |
| `network` | VPN, CDN, load balancer | Bandwidth (GB) | Usage-based |
| `hardware` | JTAG probe, serial device, GPIO | Session-based | Reservation-based |
| `custom` | User-defined provider types | Per-provider schema | Per-provider schema |

## Provider Performance Requirements

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Registration processing | < 1 second | 5 seconds |
| Health check response | < 200ms | 1 second |
| Resource allocation | < 500ms | 2 seconds |
| Resource release | < 200ms | 1 second |
| Capability execution (sync) | < 1 second | 5 seconds |
| Capability execution (async) | Varies by capability | Varies by capability |
| Metric stream latency | < 100ms | 500ms |
| Usage report processing | < 200ms | 1 second |

## Events

| SDK.EventType | Produced When | Fields |
|-----------|--------------|--------|
| `SDK.ProviderRegistered` | Provider registers with ROS | provider_id, provider_type, capabilities_hash, version |
| `SDK.ProviderHealthChanged` | Provider health status transitions | provider_id, from_status, to_status, reason, consecutive_checks |
| `SDK.ProviderResourceAllocated` | Resource is allocated | allocation_id, provider_id, resource_type, quantity, consumer_entity_id |
| `SDK.ProviderResourceReleased` | Resource is released | allocation_id, provider_id, usage_summary, duration_seconds |
| `SDK.ProviderCapabilityExecuted` | Capability execution completes | execution_id, provider_id, capability, result_summary, duration_ms |
| `SDK.ProviderCapabilityDeprecated` | Capability is deprecated | provider_id, capability_id, deprecation_date, replacement |
| `SDK.ProviderDeregistered` | Provider is removed from registry | provider_id, reason, final_metrics, total_uptime_hours |

## Cross-Cutting Concerns

### Security

Resource providers authenticate with ROS via mTLS. Provider credentials are managed by KMS â€” never stored in provider configuration files. All provider communication is encrypted. Providers are isolated â€” one provider cannot access another provider's allocations. Capability execution is authorized by ROS based on the requesting entity's permissions. (Physics/008-Security.md)

### Evidence

Every provider operation produces an Event â€” registration, health changes, resource allocation, capability execution, and deregistration. Provider Events feed into ROS accounting, DTS trust scoring, and Academy learning. Providers that fail to produce Events are marked as Degraded. (PHI-008)

### Lifecycle

Providers follow the lifecycle defined in the Provider SDK. Resource allocations within a provider follow the resource lifecycle (Reserved â†’ Allocated â†’ Consumed â†’ Released). Provider versions follow semantic versioning. Deprecated provider capabilities have a minimum support window. (Physics/006-Lifecycles.md)

### Capability Bounds

Providers can only offer capabilities they registered. The resources a provider can allocate are bounded by its advertised capacity. ROS enforces that no provider may over-allocate beyond discovered capacity. Custom provider types must define their capability bounds explicitly in the registration schema. (Physics/007-Capabilities.md)

### Communication

All Provider SDK communication flows through ACF. Provider endpoints use ACF topics for capability requests, metrics streaming, and event production. Cross-provider communication is not supported â€” all inter-provider data must flow through AIOS core. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Provider SDK covers only resource provision â€” no runtime or knowledge concerns |
| R5 (Liskov) | All providers implement the same ResourceProvider interface â€” interchangeable |
| R6 (DI) | Providers are injected into ROS â€” no hard coupling between provider types |
| R9 (Deterministic) | Same allocation request to the same provider produces identical allocation |
| R10 (Simpler Over Complex) | Provider capabilities are flat-listed â€” no capability hierarchies |
| R13 (Design for Failure) | Providers report Degraded health before failing; ROS fails allocation to Degraded providers |
| R14 (Paved Path) | Paved path: register â†’ initialize â†’ allocate â†’ execute â†’ release â†’ deregister |
| R15 (Open/Closed) | New provider types implement the ResourceProvider interface without modifying ROS core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence â€” Provider SDK operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” Provider capabilities define resource bounds |
| Bible/08-Interfaces/API/000-Specifications.md | API â€” Provider SDK uses ACF API contracts |
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Runtime SDK â€” Runtime providers implement Provider SDK |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” Provider SDK integrates with ROS for resource management |
| Bible/02-Core/ROS/002-Registry.md | ROS Registry â€” Provider registration and health tracking |
| Bible/02-Core/ROS/008-Provider-SDK.md | ROS Provider SDK â€” Detailed provider SDK specification |
| Bible/06-Services/Cryptography/KMS/000-KMS.md | KMS â€” Provider credential management |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” Provider communication transport |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA â€” R1â€“R15 compliance for providers |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
