# AIOS Bible — Brain
## 005 — Tool Sandboxing

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-005 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Tool Sandboxing constrains tool execution within resource limits to protect the system from runaway processes, excessive resource consumption, and unintended side effects. The Sandbox Manager enforces CPU, memory, network, and filesystem limits, imposes timeouts, caps output sizes, and validates capability bounds during execution. It ensures that no tool can exceed its declared capability scope or consume more resources than allocated.

Under Law 7 (Capability Bounds), each tool's sandbox profile is derived from its capability declaration. Under Law 13 (Design for Failure), sandbox violations are caught gracefully with clear error reporting.

## Data Model

### SandboxProfile

```typescript
SandboxProfile {
  tool_id: string
  capabilities: string[]
  resource_limits: ResourceLimits
  execution_constraints: ExecutionConstraints
  network_policy: NetworkPolicy
  filesystem_policy: FilesystemPolicy
  isolation_level: "process" | "container" | "thread" | "none"
}
```

### ResourceLimits

```typescript
ResourceLimits {
  cpu: {
    max_ms: number                  // Maximum CPU time
    max_percent?: number            // Maximum CPU percentage
  }
  memory: {
    max_bytes: number               // Maximum memory allocation
    max_swap_bytes?: number
  }
  network: {
    max_bytes_tx: number            // Maximum bytes transmitted
    max_bytes_rx: number            // Maximum bytes received
    max_requests: number            // Maximum outbound requests
    allowed_endpoints?: string[]    // Whitelist of allowed endpoints
    blocked_endpoints?: string[]    // Blacklist of blocked endpoints
  }
  filesystem: {
    max_write_bytes: number         // Maximum bytes written
    max_read_bytes: number          // Maximum bytes read
    allowed_paths?: string[]        // Whitelist of accessible paths
    allowed_tmp_size?: number       // Maximum temp storage
    read_only: boolean              // If true, writes are denied
  }
  output: {
    max_bytes: number               // Maximum result size
    max_lines?: number              // Maximum line count for text output
    max_items?: number              // Maximum array items
  }
}
```

### ExecutionConstraints

```typescript
ExecutionConstraints {
  max_duration_ms: number
  max_concurrency: number
  allow_subprocess: boolean
  allow_network: boolean
  allow_filesystem_write: boolean
  allow_filesystem_read: boolean
  allow_environment_variables: boolean
}
```

### NetworkPolicy

```typescript
NetworkPolicy {
  egress: "allowed" | "restricted" | "denied"
  ingress: "allowed" | "restricted" | "denied"
  allowed_domains?: string[]
  blocked_domains?: string[]
  allowed_ports?: number[]
  require_tls: boolean
}
```

### FilesystemPolicy

```typescript
FilesystemPolicy {
  mode: "isolated" | "restricted" | "full"
  sandbox_root?: string             // Virtual filesystem root for isolated mode
  allowed_read_paths: string[]
  allowed_write_paths: string[]
  denied_paths: string[]
  max_file_size_bytes: number
}
```

### SandboxExecution

```typescript
SandboxExecution {
  execution_id: string
  invocation_id: string
  tool_id: string
  status: "pending" | "running" | "completed" | "violated" | "timeout" | "killed"
  resource_usage: ResourceUsage
  violation?: SandboxViolation
  started_at: timestamp
  completed_at?: timestamp
}
```

### ResourceUsage

```typescript
ResourceUsage {
  cpu_ms: number
  memory_bytes: number
  memory_peak_bytes: number
  network_tx_bytes: number
  network_rx_bytes: number
  filesystem_read_bytes: number
  filesystem_write_bytes: number
  output_bytes: number
  duration_ms: number
}
```

### SandboxViolation

```typescript
SandboxViolation {
  type: "cpu_exceeded" | "memory_exceeded" | "network_exceeded" |
        "filesystem_denied" | "output_exceeded" | "timeout" |
        "subprocess_denied" | "capability_exceeded" | "isolation_breach"
  limit: number
  actual: number
  details?: string
}
```

## Core Concepts

### Sandbox Profile Derivation

Each tool's sandbox profile is derived from its ToolDefinition and capability declaration:

```
ToolDefinition
    │
    ├── execution_type → max_duration_ms (sync=30s, async=5min, stream=10min)
    ├── category → default resource profile (read=low, compute=high, etc.)
    ├── capability_bounds → network/filesystem policies
    └── rate_limits → concurrency constraint
    │
    ▼
SandboxProfile (merged from defaults + tool-specific overrides)
```

### Resource Limit Enforcement

| Resource | Enforcement Point | Violation Behavior |
|----------|-------------------|-------------------|
| CPU time | Continuous monitoring during execution | Kill execution; emit violation event |
| Memory | Allocation tracking | Kill execution; emit violation event |
| Network TX/RX | Per-request monitoring | Block request; emit violation event |
| Filesystem access | Path check on every I/O | Deny access; emit violation event |
| Output size | Post-execution check | Truncate output; emit violation event |
| Duration | Deadline timer | Kill execution; emit timeout event |

### Isolation Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `none` | No isolation, runs in-process | Trusted system tools |
| `thread` | Separate thread with resource monitoring | Read/compute tools |
| `process` | Separate OS process | Write tools, file operations |
| `container` | Full container isolation | Untrusted tools, network-accessible tools |

The Sandbox Manager selects the isolation level based on the tool's capability_bounds and category. Tools with `communicate` or `write` categories default to at least `process` isolation.

### Output Size Limiting

Output size limits prevent tools from flooding the context window:

```
On result reception:
  If result.data exceeds max_bytes:
    Truncate to max_bytes
    Set result.truncated = true
    Emit TLS.SandboxOutputTruncated event
  
  If result is array and exceeds max_items:
    Truncate array to max_items
    Set result.truncated = true
    Add note to result metadata
```

### Enforcement Modes

| Mode | Behavior | Configuration |
|------|----------|---------------|
| Enforce | Hard limits; violations kill execution | Default for external tools |
| Warn | Soft limits; log violations but continue | Default for internal tools |
| Monitor | Track usage but no enforcement | Debug/development mode |

## Operations

### ExecuteInSandbox

```typescript
executeInSandbox(
  invocation_id: string,
  tool_id: string,
  profile: SandboxProfile,
  execute: () => Promise<unknown>
): Promise<SandboxExecution>
```

- Creates sandbox execution context
- Applies resource limits and isolation
- Monitors execution for violations
- Returns SandboxExecution with final status and resource usage

### GetResourceUsage

```typescript
getResourceUsage(execution_id: string): ResourceUsage | null
```

- Returns current resource consumption for a running execution
- Includes cumulative counters for all tracked resources
- Returns null if execution_id unknown

### EnforceLimits

```typescript
enforceLimits(execution_id: string, profile: SandboxProfile): void
```

- Called periodically during execution
- Checks all resource limits against current usage
- Kills execution if any hard limit is exceeded
- Emits violation events

### SetProfile

```typescript
setProfile(tool_id: string, profile: SandboxProfile): void
```

- Sets or updates the sandbox profile for a tool
- Applied to all subsequent invocations
- Emits TLS.SandboxProfileUpdated event

### GetProfile

```typescript
getProfile(tool_id: string): SandboxProfile | null
```

- Returns the active sandbox profile for a tool
- Returns system default if no tool-specific profile set

## Internal Interface

```typescript
interface SandboxManager {
  executeInSandbox(
    invocation_id: string,
    tool_id: string,
    profile: SandboxProfile,
    execute: () => Promise<unknown>
  ): Promise<SandboxExecution>

  getResourceUsage(execution_id: string): ResourceUsage | null

  enforceLimits(execution_id: string, profile: SandboxProfile): void

  setProfile(tool_id: string, profile: SandboxProfile): void
  getProfile(tool_id: string): SandboxProfile | null

  deriveProfile(tool: ToolDefinition, defaults?: Partial<SandboxProfile>): SandboxProfile

  getViolationHistory(tool_id?: string): SandboxViolation[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `TLS.SandboxCreated` | execution_id, invocation_id, tool_id, isolation_level | Sandbox execution context created |
| `TLS.SandboxCompleted` | execution_id, resource_usage, duration_ms | Sandbox execution completed successfully |
| `TLS.SandboxViolation` | execution_id, type, limit, actual, details | Resource limit violated |
| `TLS.SandboxTimeout` | execution_id, deadline, actual_duration | Execution exceeded time limit |
| `TLS.SandboxKilled` | execution_id, reason, resource_usage | Execution forcibly terminated |
| `TLS.SandboxOutputTruncated` | execution_id, original_bytes, max_bytes | Output truncated to size limit |
| `TLS.SandboxProfileDerived` | tool_id, isolation_level, resource_limits_summary | Sandbox profile derived from tool definition |
| `TLS.SandboxProfileUpdated` | tool_id, updated_limits, reason | Sandbox profile changed |
| `TLS.SandboxIsolationBreach` | execution_id, breach_type, details | Isolation boundary crossed |
| `TLS.SandboxMetrics` | total_executions, violations_count, avg_resource_usage | Aggregated sandbox metrics |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SAN-001 | No tool execution exceeds its resource limits | Algorithmic — limits enforced at runtime |
| SAN-002 | Tool output never exceeds output size limits | Algorithmic — truncation applied post-execution |
| SAN-003 | Network-denied tools never make network requests | Algorithmic — network policy checked per request |
| SAN-004 | Filesystem-read-only tools never write to disk | Algorithmic — filesystem policy enforced on every I/O |
| SAN-005 | Sandbox profiles are derived deterministically from tool definitions | Algorithmic — deriveProfile is a pure function |
| SAN-006 | Every sandbox execution has a timeout | API-level — max_duration_ms is required |
| SAN-007 | Resource usage tracking is monotonic (counters only increase) | Algorithmic — cumulative counters |
| SAN-008 | Violation events always include the limit and actual values | Schema — SandboxViolation requires limit and actual |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| CPU limit exceeded | `SAN_CPU_EXCEEDED` | Kill execution; return error |
| Memory limit exceeded | `SAN_MEMORY_EXCEEDED` | Kill execution; return error |
| Network request denied | `SAN_NETWORK_DENIED` | Block request; continue execution |
| Filesystem write denied | `SAN_FILESYSTEM_DENIED` | Deny write; return partial error |
| Output size exceeded | `SAN_OUTPUT_EXCEEDED` | Truncate output; return with truncated flag |
| Execution timeout | `SAN_TIMEOUT` | Kill execution; return timeout error |
| Subprocess creation denied | `SAN_SUBPROCESS_DENIED` | Return error; subprocess not allowed |
| Isolation breach detected | `SAN_ISOLATION_BREACH` | Kill execution; escalate security alert |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Sandbox Manager handles only execution constraints |
| R2 — Dependency Order | Depends on Tool Registry for tool definitions; no upward deps |
| R3 — DRY | Sandbox profiles derived from tool definitions, not duplicated |
| R4 — Builder Pattern | Profile built by Derivation → Limit Setup → Execution → Monitoring |
| R5 — Liskov Substitution | Any SandboxManager implements the interface |
| R6 — DI over Singletons | Resource monitors and isolation strategies injected |
| R9 — Deterministic | Same profile and execution produce same constraint behavior |
| R10 — Simpler Over Complex | Clear limit/resource/violation model with three enforcement modes |
| R13 — Design for Failure | Violations caught gracefully; execution killed cleanly |
| R14 — Paved Path | All sandboxed execution flows through executeInSandbox() |
| R15 — Open/Closed | New resource types added via monitor plugins |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Sandboxing constrains all tool execution |
| Brain/Tools/001-Registry.md | Tool definitions provide capability bounds for profile derivation |
| Brain/Tools/003-Invocation.md | Sandbox wraps the execution step of the invocation pipeline |
| Brain/Tools/004-Validation.md | Validated parameters passed into sandboxed execution |
| Brain/Tools/006-Lifecycle.md | Violation history feeds health tracking |
| Bible/04-Execution/Runtime/001-SDK.md | Runtime SDK executes within sandbox constraints |
| Bible/05-Platform/004-EVS.md | Events emitted for all sandbox violations and completions |
