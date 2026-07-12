# AIOS Bible â€” Brain
## 006 â€” Tool Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-006 |
| Source Laws | Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Tool Lifecycle Manager governs the full lifespan of every tool in the system â€” from registration through active use, deprecation, and eventual removal. It implements health monitoring via a heartbeat mechanism, tracks provider health transitions, automatically deregisters tools when their provider fails, and manages tool versioning. The Lifecycle Manager ensures that the Tool Registry always reflects the true operational state of every tool.

Under Law 6 (Lifecycle), every tool has a defined lifecycle with explicit transitions. No tool skips from registered to removed without passing through the appropriate intermediate states.

## Data Model

### ToolLifecycleState

```typescript
ToolLifecycleState {
  tool_id: string
  stage: LifecycleStage
  version: string
  previous_stage?: LifecycleStage
  entered_stage_at: timestamp
  stage_duration_ms: number
  transition_count: number
  metadata: {
    reason?: string                 // Why the transition occurred
    initiated_by: string            // "system" | "provider" | "admin"
    approved_by?: string            // For deprecation/removal requiring approval
    deprecation_notice?: string     // Message shown to Sou on use
    sunset_date?: timestamp         // Date of automatic removal
  }
}
```

### LifecycleStage

```typescript
LifecycleStage =
  | "registered"
  | "active"
  | "deprecated"
  | "removed"
```

### HealthRecord

```typescript
HealthRecord {
  tool_id: string
  current_status: "healthy" | "degraded" | "unavailable"
  last_heartbeat: timestamp
  heartbeat_interval_ms: number
  missed_heartbeats: number
  max_missed_heartbeats: number    // Threshold for unavailable
  consecutive_failures: number
  last_error?: string
  status_history: HealthTransition[]
  uptime_percentage: number
}
```

### HealthTransition

```typescript
HealthTransition {
  from: "healthy" | "degraded" | "unavailable"
  to: "healthy" | "degraded" | "unavailable"
  timestamp: timestamp
  reason: string
}
```

### HeartbeatSignal

```typescript
HeartbeatSignal {
  tool_id: string
  provider: string
  timestamp: timestamp
  status: "healthy" | "degraded" | "unavailable"
  metrics?: {
    cpu_load: number
    memory_usage: number
    response_time_ms: number
    error_rate: number
  }
}
```

### VersionInfo

```typescript
VersionInfo {
  tool_id: string
  current_version: string
  previous_versions: string[]
  changelog: VersionChange[]
  breaking_versions: string[]      // Versions that broke backward compatibility
}

VersionChange {
  version: string
  released_at: timestamp
  changes: string[]
  is_breaking: boolean
}
```

## Core Concepts

### Lifecycle Stages

```
Registered
    â”‚
    â”‚  (health check passed)
    â–¼
Active â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
    â”‚                                         â”‚
    â”‚  (deprecation notice)                   â”‚
    â–¼                                         â”‚
Deprecated â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
    â”‚                                      â”‚   â”‚
    â”‚  (sunset date reached / manual)      â”‚   â”‚
    â–¼                                      â–¼   â–¼
Removed                               (provider failure â†’ auto-removed)
```

| Stage | Meaning | Discovery | Invocation |
|-------|---------|-----------|------------|
| `registered` | Tool cataloged, provider not yet verified | Hidden | Blocked |
| `active` | Tool operational, fully available | Visible | Allowed |
| `deprecated` | Tool scheduled for removal, still functional | Visible with warning | Allowed with warning |
| `removed` | Tool no longer available | Hidden | Blocked |

### Health Monitoring

The Lifecycle Manager tracks tool health through periodic heartbeats:

```
Heartbeat Cycle:
  1. Provider sends HeartbeatSignal at configured interval
  2. Lifecycle Manager updates HealthRecord
  3. If heartbeat received:
      - Reset missed_heartbeats counter
      - Update status to healthy (if was degraded/unavailable)
      - Update last_heartbeat timestamp
  4. If heartbeat MISSED:
      - Increment missed_heartbeats counter
      - If missed_heartbeats >= max_missed_heartbeats:
          Transition to "unavailable"
          Emit TLS.ToolHealthChanged
      - If missed_heartbeats >= max_missed_heartbeats * 2:
          Trigger auto-deregistration
```

| Health Status | Heartbeat Condition | Invocation Behavior |
|---------------|--------------------|---------------------|
| healthy | Heartbeat received within interval | Normal invocation |
| degraded | Heartbeat delayed (>1.5x interval) | Invocation allowed, warning logged |
| unavailable | Heartbeat missed (>= max_missed) | Invocation blocked, fallback suggested |

### Automatic Deregistration

When a provider fails completely (prolonged unavailable state), the Lifecycle Manager:

1. Marks all tools from that provider as unavailable
2. Waits for grace period (configurable, default 5 minutes)
3. If no heartbeat received during grace period:
   - Deregisters all tools from that provider
   - Emits TLS.ProviderFailed and TLS.ToolDeregistered for each tool
4. If provider recovers during grace period:
   - Restores tools to active state

### Version Management

Tool versions follow semantic versioning (MAJOR.MINOR.PATCH):

| Version Change | Effect | Lifecycle Action |
|----------------|--------|------------------|
| PATCH bump | Bug fix, no schema change | Automatic, no lifecycle transition |
| MINOR bump | New feature, backward-compatible | Automatic, no lifecycle transition |
| MAJOR bump | Breaking change | New ToolDefinition required; old version deprecated |

When a new version is registered:
- Previous version enters deprecated stage
- New version starts in experimental stage (unless configured otherwise)
- Sou is directed to the new version during discovery

### Provider Health Transitions

```
Provider sends heartbeat â”€â”€â–º healthy
    â”‚
    â”œâ”€â”€ Intermittent failures (3+ in 5 min) â”€â”€â–º degraded
    â”œâ”€â”€ Heartbeat delayed (>1.5x interval) â”€â”€â–º degraded
    â”œâ”€â”€ No heartbeat (> max_missed threshold) â”€â”€â–º unavailable
    â””â”€â”€ Grace period expired â”€â”€â–º auto-deregistration
```

## Operations

### RegisterTool

```typescript
registerTool(
  definition: ToolDefinition,
  provider: string,
  provider_endpoint: string,
  options?: {
    initial_stage?: "registered" | "experimental"
    health_check_on_register?: boolean
  }
): ToolLifecycleState
```

- Registers tool in the Registry
- Creates lifecycle state in "registered" stage
- If health_check_on_register, performs initial health check
- Transitions to "active" if health check passes

### DeprecateTool

```typescript
deprecateTool(
  tool_id: string,
  options: {
    reason: string
    deprecation_notice: string
    sunset_date?: timestamp
    replacement_tool_id?: string
  }
): ToolLifecycleState
```

- Transitions tool from active to deprecated
- Sets deprecation_notice shown on invocation
- Optionally sets sunset_date for automatic removal
- Optionally links to replacement tool

### RemoveTool

```typescript
removeTool(tool_id: string, options?: {
  reason?: string
  force?: boolean                    // Skip grace period
}): void
```

- Removes tool from active Registry
- Retains tombstone for audit
- If force=true, skips grace period for healthy tools

### HealthCheck

```typescript
healthCheck(tool_id: string): HealthRecord
```

- Performs immediate health check on tool
- Updates health status based on response
- Returns full HealthRecord

### GetLifecycleState

```typescript
getLifecycleState(tool_id: string): ToolLifecycleState | null
```

- Returns current lifecycle stage and metadata
- Returns null for unknown tools or tombstoned tools after retention period

### ProcessHeartbeat

```typescript
processHeartbeat(signal: HeartbeatSignal): void
```

- Processes incoming heartbeat from provider
- Updates health record and status
- May trigger lifecycle transitions

### ReinstateTool

```typescript
reinstateTool(
  tool_id: string,
  options?: { reason?: string }
): ToolLifecycleState
```

- Restores a removed tool to active status
- Used when a provider recovers after auto-deregistration
- Creates new ToolLifecycleState

## Internal Interface

```typescript
interface ToolLifecycleManager {
  registerTool(
    definition: ToolDefinition,
    provider: string,
    provider_endpoint: string,
    options?: {
      initial_stage?: "registered" | "experimental"
      health_check_on_register?: boolean
    }
  ): ToolLifecycleState

  deprecateTool(
    tool_id: string,
    options: {
      reason: string
      deprecation_notice: string
      sunset_date?: timestamp
      replacement_tool_id?: string
    }
  ): ToolLifecycleState

  removeTool(
    tool_id: string,
    options?: {
      reason?: string
      force?: boolean
    }
  ): void

  healthCheck(tool_id: string): HealthRecord

  getLifecycleState(tool_id: string): ToolLifecycleState | null

  processHeartbeat(signal: HeartbeatSignal): void

  reinstateTool(
    tool_id: string,
    options?: { reason?: string }
  ): ToolLifecycleState

  getHealthRecord(tool_id: string): HealthRecord | null
  getToolsByStage(stage: LifecycleStage): ToolLifecycleState[]
  getToolsByProvider(provider: string): ToolLifecycleState[]
  listDeprecatedTools(): ToolLifecycleState[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| TOL.ToolRegistered |      tool_id, name, provider, initial_stage, version | Tool registered in the system |
| TOL.ToolActivated |      tool_id, previous_stage, health_status | Tool transitioned to active |
| TOL.ToolDeprecated |      tool_id, reason, sunset_date, replacement_tool_id | Tool marked as deprecated |
| TOL.ToolRemoved |      tool_id, reason, stage_duration_days | Tool removed from system |
| TOL.ToolReinstated |      tool_id, reason, previous_stage | Tool restored after removal |
| TOL.ToolHealthChanged |      tool_id, old_status, new_status, reason | Health status transition |
| TOL.ToolHeartbeatReceived |      tool_id, status, response_time_ms | Heartbeat signal processed |
| TOL.ToolHeartbeatMissed |      tool_id, missed_count, max_threshold | Heartbeat timeout detected |
| TOL.ProviderFailed |      provider, affected_tools, reason | All tools from provider marked unavailable |
| TOL.ToolVersionChanged |      tool_id, old_version, new_version, is_breaking | Tool version updated |
| TOL.ToolSunsetReached |      tool_id, version, sunset_date | Auto-removal triggered by sunset date |
| TOL.ToolAutoDeregistered |      tool_id, provider, missed_heartbeats, duration | Tool removed due to provider failure |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LIF-001 | Every tool transitions through lifecycle stages in order (registered â†’ active â†’ deprecated â†’ removed) | Algorithmic â€” state machine enforces ordering |
| LIF-002 | No tool can be invoked before it reaches the active stage | Application-level â€” Invocation Manager checks lifecycle stage |
| LIF-003 | A deprecated tool can still be invoked but Sou receives a deprecation notice | Algorithmic â€” deprecation_notice appended to result |
| LIF-004 | Health status transitions are monotonic within a degradation period | Algorithmic â€” status can only worsen until heartbeat recovered |
| LIF-005 | Every deregistered tool retains a tombstone for audit (minimum 30 days) | Database â€” tombstone retention enforced |
| LIF-006 | A tool removed due to provider failure cannot be reinstated without a new provider heartbeat | Algorithmic â€” reinstateTool requires recent heartbeat |
| LIF-007 | Version strings follow semantic versioning (MAJOR.MINOR.PATCH) | Schema â€” validated on registration |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Invalid lifecycle transition | `LIF_INVALID_TRANSITION` | Return error; show valid next stages |
| Cannot deprecate already removed tool | `LIF_ALREADY_REMOVED` | Return error; tool no longer exists |
| Provider failure triggers cascade | `LIF_PROVIDER_CASCADE` | Automatically degrade all provider tools |
| Heartbeat from unknown tool | `LIF_UNKNOWN_TOOL` | Return error; register tool first |
| Sunset date in the past | `LIF_PAST_SUNSET_DATE` | Return error; provide future date |
| Cannot remove active tool (force=false) | `LIF_ACTIVE_TOOL` | Return error; deprecate first or use force |
| Version downgrade detected | `LIF_VERSION_DOWNGRADE` | Return error; versions must increase monotonically |


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
| R1 â€” Modulsingularity | Lifecycle Manager handles only tool lifespan and health |
| R2 â€” Dependency Order | Depends on Tool Registry; no upward deps |
| R3 â€” DRY | Lifecycle stages defined once in state machine |
| R4 â€” Builder Pattern | Lifecycle built by Register â†’ Health â†’ Stage Transitions |
| R5 â€” Liskov Substitution | Any ToolLifecycleManager implements the interface |
| R6 â€” DI over Singletons | Health checkers, heartbeat handlers, auto-removal strategies injected |
| R9 â€” Deterministic | Same heartbeats and transitions produce same lifecycle state |
| R10 â€” Simpler Over Complex | Four clear stages with explicit transition rules |
| R13 â€” Design for Failure | Auto-deregistration and grace period protect against provider failure |
| R14 â€” Paved Path | All lifecycle flows through registerTool() â†’ deprecateTool() â†’ removeTool() |
| R15 â€” Open/Closed | New lifecycle stages added via state machine config |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Lifecycle Manager governs tool lifespan in the Tool System |
| Brain/Tools/001-Registry.md | Lifecycle Manager updates Registry health and status |
| Brain/Tools/002-Discovery.md | Lifecycle stage affects tool visibility in discovery |
| Brain/Tools/003-Invocation.md | Lifecycle stage checked before invocation is allowed |
| Brain/Tools/005-Sandboxing.md | Violation history feeds health tracking |
| Physics/006-Lifecycles.md | Lifecycle stages follow the general Lifecycle Physics |
| Bible/05-Platform/004-EVS.md | Events emitted for every lifecycle transition |
