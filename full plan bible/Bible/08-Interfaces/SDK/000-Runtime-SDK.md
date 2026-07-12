# AIOS Bible â€” Interfaces
## SDK â€” 000: Runtime SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-SDK-000 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Runtime SDK provides the standard interface for runtime execution providers to integrate with AIOS. A runtime execution provider is any backend that can instantiate and run AIOS Workers â€” examples include LLM inference engines (Claude Code, Codex, Ollama), code execution sandboxes (container runtimes, WASM), and general compute environments (VM, bare metal).

The Runtime SDK defines the contract that every runtime provider must implement to be compatible with AIOS. It covers session lifecycle, capability invocation, resource accounting, evidence capture, and communication with the AIOS core.

## Runtime Provider Interface

Every runtime provider must implement the `RuntimeProvider` interface:

```
interface RuntimeProvider {
  // Lifecycle
  createSession(genome: Genome, allocation: ResourceAllocation): Session
  startSession(sessionId: SessionID): void
  pauseSession(sessionId: SessionID): void
  resumeSession(sessionId: SessionID): void
  terminateSession(sessionId: SessionID): TerminationResult

  // Execution
  invokeCapability(sessionId: SessionID, capability: Capability, input: Payload): CapabilityResult
  cancelInvocation(sessionId: SessionID, invocationId: InvocationID): void

  // Monitoring
  getSessionStatus(sessionId: SessionID): SessionStatus
  streamMetrics(sessionId: SessionID): MetricStream
  healthCheck(): HealthStatus

  // Resource Accounting
  reportUsage(sessionId: SessionID): UsageReport
}
```

| Method | Description | Latency SLO |
|--------|-------------|-------------|
| `createSession` | Instantiate a new Worker session from a Genome | < 5 seconds |
| `startSession` | Transition session to Running state | < 1 second |
| `pauseSession` | Suspend session execution, preserve state | < 2 seconds |
| `resumeSession` | Restore session from paused state | < 2 seconds |
| `terminateSession` | End session, release all resources | < 3 seconds |
| `invokeCapability` | Execute a capability within the session | Varies by capability |
| `cancelInvocation` | Cancel a running capability invocation | < 1 second |
| `getSessionStatus` | Query current session state | < 100 ms |
| `streamMetrics` | Subscribe to real-time session metrics | Real-time stream |
| `healthCheck` | Report runtime provider health | < 500 ms |
| `reportUsage` | Report resource consumption for accounting | < 1 second |

## Session Lifecycle (Runtime View)

From the Runtime SDK perspective, a session follows this lifecycle:

```
Created â†’ Starting â†’ Running â†” Paused â†’ Terminating â†’ Terminated
     â””â”€â”€â”€â”€â†’ Failed
```

| State | Description | Expected By |
|-------|-------------|-------------|
| Created | Session record allocated, no process yet | LMS |
| Starting | Genome loaded, dependencies initialized, sandbox prepared | Runtime Provider |
| Running | Session is executing capabilities | LMS, Invokers |
| Paused | Execution suspended, state preserved | LMS, Supervisor |
| Terminating | Cleanup in progress â€” final events, resource release | Runtime Provider |
| Terminated | Session fully stopped, resources released | LMS |
| Failed | Unexpected termination â€” error state | Security Council, LMS |

The Runtime SDK must emit lifecycle Events for every transition.

## Capability Invocation Protocol

Capability invocation follows a defined protocol:

```
1. Invoker sends invokeCapability request via ACF
2. Runtime SDK validates:
   â””â”€ Session is in Running state
   â””â”€ Capability is authorized in session Genome
   â””â”€ Resource budget is sufficient
3. Runtime SDK allocates resources for this invocation
4. Runtime SDK executes the capability in the session context
5. Runtime SDK streams intermediate events (if streaming capability)
6. On completion, Runtime SDK returns CapabilityResult
7. Runtime SDK records usage evidence
8. Resource accounting updated
```

Each invocation receives a unique `InvocationID` for tracing, cancellation, and audit.

## Runtime Provider Registration

Runtime providers register with AIOS through a structured registration:

```
{
  "provider_id": "uuid-v7",
  "runtime_type": "llm | sandbox | container | vm | wasm",
  "provider_name": "string",
  "version": "1.0.0",
  "capabilities": ["capability_id", ...],
  "max_sessions": 100,
  "supported_genome_types": ["Worker", "Engine"],
  "resource_limits": {
    "max_tokens_per_session": 100000,
    "max_compute_per_session": 3600,
    "max_memory_per_session_mb": 8192
  },
  "endpoints": {
    "control": "acf://runtime-provider-id/control",
    "metrics": "acf://runtime-provider-id/metrics",
    "events": "acf://runtime-provider-id/events"
  }
}
```

Registration is validated by the Execution runtime. Providers with invalid capability references or missing endpoints are rejected.

## Session Isolation Model

Runtime providers must implement session isolation at these levels:

| Isolation Level | Guarantee | Provider Types |
|----------------|-----------|----------------|
| L1 â€” Logical | Separate process space, shared kernel | WASM, LLM (stateless) |
| L2 â€” Container | Separate container per session | Container runtimes |
| L3 â€” VM | Separate virtual machine per session | VM providers |
| L4 â€” Hardware | Separate physical hardware | Bare metal, HSM |

The minimum isolation level for a session is determined by the session's Genome security requirements. L1 is the default. L3 or L4 is required for sessions handling sensitive data or operating at high autonomy levels.

## Resource Accounting

Runtime providers must report resource consumption for every session:

| Metric | Unit | Reporting Frequency | Audit Use |
|--------|------|---------------------|-----------|
| Token Usage (Input) | tokens | Per invocation | Cost allocation, DTS confidence |
| Token Usage (Output) | tokens | Per invocation | Cost allocation |
| Compute Time | CPU-seconds | Continuous (stream) | Budget enforcement |
| Memory Usage | MB | Continuous (stream) | Budget enforcement |
| Wall Clock Time | seconds | Per invocation | Performance monitoring |
| Network Egress | bytes | Per invocation | Security audit |
| Storage Used | MB | Per session | Budget enforcement |

Usage is reported via the `reportUsage` method and consumed by ROS for budget tracking.

## Provider Health Model

Runtime providers report health through a three-tier model:

| Status | Description | Action |
|--------|-------------|--------|
| Healthy | Provider operating normally | New sessions assigned |
| Degraded | Provider experiencing issues (high latency, partial capacity) | Existing sessions continue; new sessions deprioritized |
| Unhealthy | Provider cannot accept or run sessions | All sessions terminated; provider removed from rotation |

Health checks occur every 30 seconds. A provider that reports Unhealthy for 3 consecutive checks triggers an alert to the Execution runtime.

## Events

| SDK.EventType | Produced When | Fields |
|-----------|--------------|--------|
| `SDK.RuntimeSessionCreated` | Runtime session is created | session_id, runtime_type, provider_id, genome_hash, isolation_level |
| `SDK.RuntimeSessionStarted` | Session transitions to Running | session_id, started_at, initial_metrics, provider_health |
| `SDK.RuntimeSessionPaused` | Session is paused | session_id, pause_reason, suspended_state_ref, memory_preserved_bytes |
| `SDK.RuntimeSessionTerminated` | Session terminates | session_id, reason, final_usage_report, total_duration_seconds |
| `SDK.RuntimeInvocationCompleted` | Capability invocation finishes | invocation_id, session_id, capability, duration_ms, usage_metrics, outcome |
| `SDK.RuntimeHealthChanged` | Runtime provider health status changes | provider_id, previous_status, new_status, details, consecutive_failures |
| `SDK.RuntimeUsageReported` | Resource usage is reported | session_id, report_period, usage_metrics, budget_remaining |

## Cross-Cutting Concerns

### Security

Runtime sessions are sandboxed â€” no session may access another session's resources. Runtime providers authenticate with AIOS via mTLS. All capability invocations are authorized by the session's Genome. Resource reporting is cryptographically signed to prevent tampering. (Physics/008-Security.md)

### Evidence

Every Runtime SDK operation produces an Event â€” session lifecycle transitions, capability invocations, resource usage reports. The complete execution history of every session is recorded in the Event Store for audit and analysis. (PHI-008)

### Lifecycle

Sessions follow the lifecycle defined in the SDK interface. The Runtime SDK implements the session management portion of the broader entity lifecycle (Physics/006-Lifecycles.md). Runtime providers have their own operational lifecycle (Registered â†’ Active â†’ Degraded â†’ Offline). (Physics/006-Lifecycles.md)

### Capability Bounds

Runtime providers can only execute capabilities defined in the session's Genome. Resource consumption is bounded by the allocation provided at session creation. Providers enforce resource limits at the OS/container level â€” a session exceeding its allocation is terminated. (Physics/007-Capabilities.md)

### Communication

All Runtime SDK communication with AIOS core flows through ACF. Runtime providers communicate with their sessions through provider-specific channels (not through ACF). Cross-provider communication is not supported â€” all inter-session communication must go through ACF. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Runtime SDK covers only runtime execution â€” no knowledge or audit concerns |
| R5 (Liskov) | All runtime providers implement the same RuntimeProvider interface â€” interchangeable |
| R6 (DI) | Runtime providers are injected into sessions â€” no hard coupling |
| R9 (Deterministic) | Same Genome and allocation produces identical session initialization |
| R10 (Simpler Over Complex) | Session lifecycle is linear â€” no branching state machines |
| R13 (Design for Failure) | Sessions fail closed â€” terminate on unhandled error, preserve evidence |
| R14 (Paved Path) | Paved path: create session â†’ start â†’ invoke â†’ monitor â†’ terminate |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence â€” Runtime SDK operations produce Events |
| Physics/010-Execution.md | Execution â€” Runtime SDK implements the execution model |
| Bible/08-Interfaces/API/000-Specifications.md | API â€” Runtime SDK consumes ACF API contracts |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” Session genomes define runtime requirements |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” Resource allocation and accounting for sessions |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime â€” Execution runtime architecture |
| Bible/03-Institutions/Workers/000-Overview.md | Workers â€” Sessions are Worker instances |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA â€” R1â€“R15 compliance |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
