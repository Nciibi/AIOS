# AIOS Bible â€” Brain
## 003 â€” Invocation Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-003 |
| Source Laws | Law 7 â€” Law of Capability Bounds, Law 3 â€” Law of Communication |
| Source Physics | Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Invocation Manager orchestrates the full lifecycle of a tool call â€” from parameter validation through capability and rate-limit checking, Security Council routing, Runtime SDK execution, and result parsing. It supports three execution types (sync, async, stream), provides invocation tracking with status queries and cancellation, enforces rate limits and timeouts, and ensures every invocation is observable through events.

Under TLS-000, the Invocation Manager is the sole entry point for tool execution. No tool is invoked without passing through its pipeline.

## Data Model

### InvocationRequest

```typescript
InvocationRequest {
  invocation_id: string
  tool_id: string
  parameters: Record<string, unknown>
  execution_type: "sync" | "async" | "stream"
  context: {
    session_id: string
    sou_identity: string
    capability_token: string
    deadline: timestamp
    parent_invocation_id?: string  // For nested invocations
  }
  metadata: {
    source: string
    priority: "low" | "normal" | "high"
    retry_count: number
    max_retries: number
  }
}
```

### InvocationRecord

```typescript
InvocationRecord {
  invocation_id: string
  tool_id: string
  tool_name: string
  status: "pending" | "validating" | "checking_capabilities" |
          "checking_rate_limits" | "routing_security" |
          "executing" | "parsing" | "completed" |
          "failed" | "timeout" | "cancelled"
  parameters: Record<string, unknown>
  context: InvocationRequest["context"]
  execution_type: "sync" | "async" | "stream"
  result?: ToolResult
  error?: {
    code: string
    message: string
    stage: string
    details?: unknown
  }
  timeline: {
    created_at: timestamp
    started_at?: timestamp
    validated_at?: timestamp
    dispatched_at?: timestamp
    completed_at?: timestamp
  }
  rate_limit_info?: {
    tokens_consumed: number
    remaining_budget: number
  }
}
```

### InvocationResult

```typescript
InvocationResult {
  invocation_id: string
  status: "pending" | "running" | "completed" | "failed" | "cancelled"
  result?: ToolResult
  events: InvocationEvent[]
}

InvocationEvent {
  event_type: string
  timestamp: timestamp
  stage: string
  data?: unknown
}
```

### RateLimitState

```typescript
RateLimitState {
  tool_id: string
  window_start: timestamp
  calls_this_window: number
  concurrent_calls: number
  tokens_consumed_this_window: number
  max_calls_per_minute: number
  max_concurrent: number
  max_tokens_per_window?: number
}
```

## Core Concepts

### Invocation Lifecycle

```
InvocationRequest
    â”‚
    â–¼
[1] Validate Parameters â”€â”€â”€â”€ Failure â†’ Return error
    â”‚
    â–¼
[2] Check Capability Bounds â”€â”€ Denied â†’ Return TLS_CAPABILITY_DENIED
    â”‚
    â–¼
[3] Check Rate Limits â”€â”€â”€â”€ Exceeded â†’ Return TLS_RATE_LIMITED
    â”‚
    â–¼
[4] Route through Security Council â”€â”€ Denied â†’ Ret urn security error
    â”‚
    â–¼
[5] Execute via Runtime SDK
    â”‚
    â”œâ”€â”€ Sync: Wait for result
    â”œâ”€â”€ Async: Return invocation_id, poll later
    â””â”€â”€ Stream: Return async iterator
    â”‚
    â–¼
[6] Parse Result
    â”‚
    â–¼
InvocationResult
```

### Execution Types

| Type | Behavior | Use Case |
|------|----------|----------|
| Sync | Block until result received | Quick operations (read, compute) |
| Async | Return immediately with invocation_id, poll for result | Long-running operations (queries, API calls) |
| Stream | Return async iterator of result chunks | Large data, real-time updates |

### Rate Limiting

Rate limits are enforced per-tool across all sessions:

```
On each invocation:
  1. Increment calls_this_window
  2. If calls_this_window > max_calls_per_minute: DENY
  3. If concurrent_calls >= max_concurrent: QUEUE or DENY
  4. If tokens_consumed_this_window + estimated_tokens > max_tokens: DENY

On completion:
  1. Decrement concurrent_calls
  2. Record actual token cost

Window resets every 60 seconds
```

### Timeout Handling

| Deadline Source | Default | Behavior |
|----------------|---------|----------|
| Tool definition | Max 30s for sync, 5min for async | Abort execution if exceeded |
| Caller context | Per-invocation override | Takes precedence over tool default |
| No deadline | System default (30s) | Applied automatically |

When a timeout occurs:
1. Cancel the execution on the provider side
2. Emit TLS.ToolTimeout event
3. Return timeout result with error code TLS_INVOCATION_TIMEOUT

### Cancellation

An invocation can be cancelled at any stage before completion:

| Stage | Cancellation Behavior |
|-------|----------------------|
| Pending/Validating | Mark cancelled, never dispatched |
| Checking limits | Mark cancelled, stop processing |
| Executing | Send cancel signal to Runtime SDK / provider |
| Completed/Failed | Cancellation ignored (already terminal) |

## Operations

### Invoke

```typescript
invoke(
  tool_id: string,
  parameters: Record<string, unknown>,
  context: InvocationRequest["context"],
  execution_type?: "sync" | "async" | "stream",
  options?: {
    priority?: string
    max_retries?: number
    deadline?: timestamp
  }
): InvocationResult
```

- Creates invocation_id (UUID v4)
- Runs the full lifecycle pipeline
- Returns InvocationResult with final status

### GetResult

```typescript
getResult(invocation_id: string): InvocationResult | null
```

- Returns current state of an invocation
- For async invocations, call periodically to check completion
- Returns null if invocation_id unknown

### CancelInvocation

```typescript
cancelInvocation(invocation_id: string): void
```

- Cancels an in-progress invocation
- No-op if invocation already in terminal state
- Emits TLS.InvocationCancelled event

### GetStatus

```typescript
getStatus(invocation_id: string): {
  status: InvocationRecord["status"]
  stage: string
  elapsed_ms?: number
  estimated_remaining_ms?: number
}
```

- Lightweight status check (cheaper than getResult)
- Returns current pipeline stage and timing estimates

### GetActiveInvocations

```typescript
getActiveInvocations(options?: {
  session_id?: string
  tool_id?: string
}): InvocationRecord[]
```

- Returns all non-terminal invocations
- Filterable by session_id or tool_id

## Internal Interface

```typescript
interface InvocationManager {
  invoke(
    tool_id: string,
    parameters: Record<string, unknown>,
    context: InvocationRequest["context"],
    execution_type?: "sync" | "async" | "stream",
    options?: {
      priority?: string
      max_retries?: number
      deadline?: timestamp
    }
  ): InvocationResult

  getResult(invocation_id: string): InvocationResult | null

  cancelInvocation(invocation_id: string): void

  getStatus(invocation_id: string): {
    status: InvocationRecord["status"]
    stage: string
    elapsed_ms?: number
    estimated_remaining_ms?: number
  }

  getActiveInvocations(options?: {
    session_id?: string
    tool_id?: string
  }): InvocationRecord[]

  getRateLimitState(tool_id: string): RateLimitState
  resetRateLimits(tool_id: string): void
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| TOL.InvocationCreated |  invocation_id, tool_id, execution_type, source | Invocation request created |
| TOL.InvocationValidated |  invocation_id, validation_result | Parameter validation passed |
| TOL.InvocationDispatched |  invocation_id, tool_id, endpoint, deadline | Invocation sent to Runtime SDK |
| TOL.InvocationCompleted |  invocation_id, status, duration_ms, token_cost | Invocation finished successfully |
| TOL.InvocationFailed |  invocation_id, error_code, stage, error_message | Invocation failed at a stage |
| TOL.InvocationTimeout |  invocation_id, deadline, elapsed_ms | Invocation exceeded deadline |
| TOL.InvocationCancelled |  invocation_id, stage, reason | Invocation cancelled by caller |
| TOL.InvocationRetrying |  invocation_id, attempt, max_retries, delay_ms | Retrying failed invocation |
| TOL.InvocationQueued |  invocation_id, reason, queue_position | Invocation queued due to rate limit |
| TOL.RateLimitExceeded |  tool_id, current_usage, limit, reset_in_ms | Rate limit hit for a tool |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| INV-001 | Every invocation has a unique invocation_id | Algorithmic â€” UUID v4 generation |
| INV-002 | Every invocation passes through all pipeline stages | Architectural â€” pipeline is sequential |
| INV-003 | Rate limits are enforced before execution begins | Algorithmic â€” checked before dispatch |
| INV-004 | No invocation can be cancelled after terminal state | Algorithmic â€” terminal check on cancel |
| INV-005 | Every invocation has a deadline; none execute indefinitely | API-level â€” deadline required in context |
| INV-006 | Sync invocations block until completion or timeout | Algorithmic â€” synchronous wait with timeout |
| INV-007 | Capability bounds are checked before rate limits | Pipeline-ordering â€” stage sequence enforced |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown tool_id | `TLS_TOOL_NOT_FOUND` | Return error; invocation not created |
| Invalid parameters | `TLS_PARAMETER_INVALID` | Return validation errors per field; invocation failed |
| Rate limit exceeded | `TLS_RATE_LIMITED` | Return error with retry-after in seconds |
| Capability denied | `TLS_CAPABILITY_DENIED` | Deny invocation; log security event |
| Invocation timeout | `TLS_INVOCATION_TIMEOUT` | Return timeout result; cancel on provider |
| Provider unreachable | `TLS_PROVIDER_UNREACHABLE` | Return error; mark tool degraded |
| Security Council denied | `TLS_SECURITY_DENIED` | Deny invocation; log security event with details |
| Concurrent invocations exhausted | `TLS_CONCURRENT_LIMIT` | Return error; suggest retry after current invocations complete |


## Cross-Cutting Concerns

### Security

Tool System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Tool System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Tool System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Tool System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Invocation Manager handles only tool execution lifecycle |
| R2 â€” Dependency Order | Depends on Registry, Validator, Security Council, Runtime SDK |
| R3 â€” DRY | Invocation pipeline steps defined once in ordered stages |
| R4 â€” Builder Pattern | Invocation built by Pipeline Stages â†’ Execution â†’ Result |
| R5 â€” Liskov Substitution | Any InvocationManager implements the interface |
| R6 â€” DI over Singletons | Pipeline stages, validators, and rate limiters injected |
| R9 â€” Deterministic | Same inputs and registry state produce same result |
| R10 â€” Simpler Over Complex | Three clear execution types with explicit lifecycle |
| R13 â€” Design for Failure | Timeouts, retries, cancellation, and fallbacks at every stage |
| R14 â€” Paved Path | All invocations flow through invoke() |
| R15 â€” Open/Closed | New execution types added via strategy injection |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Invocation Manager is the execution orchestrator |
| Brain/Tools/001-Registry.md | Reads tool definitions and rate limits from Registry |
| Brain/Tools/004-Validation.md | Schema Validator runs as pipeline stage 1 |
| Brain/Tools/005-Sandboxing.md | Sandbox Manager enforces execution constraints |
| Brain/Tools/006-Lifecycle.md | Health tracking monitors invocation success/failure |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | Invocations route through Security Council pipeline |
| Bible/04-Execution/Runtime/001-SDK.md | Runtime SDK executes the actual tool call |
| Bible/05-Platform/004-EVS.md | Events emitted throughout invocation lifecycle |
