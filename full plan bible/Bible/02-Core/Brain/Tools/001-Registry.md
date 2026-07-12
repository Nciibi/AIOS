# AIOS Bible â€” Brain
## 001 â€” Tool Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-001 |
| Source Laws | Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Tool Registry is the authoritative catalog of all tools available to Sou. It stores `ToolDefinition` and `ToolRegistration` records, tracks tool health, manages tool categories (read/write/compute/communicate/system), and enforces the tool status lifecycle (active/deprecated/experimental). All tool discovery, validation, and invocation flows depend on the Registry as the single source of truth for what tools exist and what state they are in.

Under TLS-000, every tool has exactly one provider. The Registry verifies this on registration and ensures no duplicate tool_id can exist.

## Data Model

### ToolDefinition

```typescript
ToolDefinition {
  tool_id: string
  name: string
  description: string
  category: "read" | "write" | "compute" | "communicate" | "system"
  capability_bounds: string[]
  parameters: ParameterSchema
  returns: ReturnSchema
  execution_type: "sync" | "async" | "stream"
  rate_limits: {
    max_calls_per_minute: number
    max_concurrent: number
    max_tokens_per_call?: number
  }
  cost: {
    tokens_per_call: number
    credits_per_call?: number
  }
  status: "active" | "deprecated" | "experimental"
  version: string
  tags: string[]
}
```

### ToolRegistration

```typescript
ToolRegistration {
  tool: ToolDefinition
  provider: string
  provider_endpoint: string
  health_status: "healthy" | "degraded" | "unavailable"
  health_metadata: {
    last_heartbeat: timestamp
    consecutive_failures: number
    last_error?: string
    uptime_percentage: number
  }
  registered_at: timestamp
  updated_at: timestamp
}
```

### CategoryIndex

```typescript
CategoryIndex {
  read: string[]
  write: string[]
  compute: string[]
  communicate: string[]
  system: string[]
}
```

### RegistrySnapshot

```typescript
RegistrySnapshot {
  total_tools: number
  by_category: Record<string, number>
  by_status: Record<string, number>
  healthy_count: number
  degraded_count: number
  unavailable_count: number
  taken_at: timestamp
}
```

## Core Concepts

### Tool Categories

| Category | Examples | Capability Required |
|----------|----------|---------------------|
| Read | `read_file`, `query_database`, `search_web` | `tool.read.*` |
| Write | `write_file`, `create_record`, `send_message` | `tool.write.*` |
| Compute | `execute_code`, `run_query`, `calculate` | `tool.compute.*` |
| Communicate | `send_email`, `post_message`, `notify` | `tool.communicate.*` |
| System | `list_files`, `get_metrics`, `check_health` | `tool.system.*` |

Categories are disjoint â€” every tool belongs to exactly one category. The capability_bounds field may specify sub-capabilities within the category (e.g., `tool.read.file` for a more granular permission).

### Tool Status Lifecycle

```
Registration
    â”‚
    â–¼
Experimental â”€â”€â–º Active â”€â”€â–º Deprecated â”€â”€â–º Deregistered
    â”‚               â”‚
    â–¼               â–¼
(removed)      (removed)
```

| Status | Description | Discovery Visibility |
|--------|-------------|---------------------|
| `experimental` | Tool under testing, may change without notice | Visible only with explicit flag |
| `active` | Fully supported, stable interface | Visible in all queries |
| `deprecated` | Scheduled for removal, still usable | Visible with warning flag |

### Health Tracking

Each registered tool has a health status updated by the Tool Lifecycle Manager:

- **healthy** â€” Tool responding normally, heartbeat received within window
- **degraded** â€” Intermittent failures or slow responses, heartbeat delayed
- **unavailable** â€” Tool not responding, heartbeat missed threshold

Health transitions trigger events and may affect discovery results (unavailable tools are hidden by default).

## Operations

### Register

```typescript
register(
  definition: ToolDefinition,
  provider: string,
  provider_endpoint: string
): ToolRegistration
```

- Validates no tool_id collision
- Validates category is one of the five defined categories
- Sets initial health_status to "healthy"
- Sets registered_at and updated_at timestamps
- Emits TLS.ToolRegistered event

### Deregister

```typescript
deregister(tool_id: string): void
```

- Removes tool from all category indices
- Emits TLS.ToolDeregistered event
- Fails if tool_id does not exist

### Get

```typescript
get(tool_id: string): ToolRegistration | null
```

- Direct lookup by tool_id
- Returns full ToolRegistration including health metadata

### List

```typescript
list(options?: {
  category?: string
  status?: string
  health?: string
  include_experimental?: boolean
}): ToolRegistration[]
```

- Filters by category, status, or health if provided
- Excludes experimental tools unless include_experimental is true
- Excludes unavailable tools by default

### Search

```typescript
search(query: string): ToolRegistration[]
```

- Text search across tool name, description, and tags
- Returns ranked results based on text relevance

### UpdateHealth

```typescript
updateHealth(
  tool_id: string,
  health_status: "healthy" | "degraded" | "unavailable",
  metadata?: Partial<ToolRegistration["health_metadata"]>
): ToolRegistration
```

- Updates health_status and health_metadata
- Emits TLS.ToolHealthChanged on transition
- Triggers auto-deregistration logic if appropriate

### Snapshot

```typescript
snapshot(): RegistrySnapshot
```

- Returns aggregate counts of registry state
- Used for monitoring and diagnostics

## Internal Interface

```typescript
interface ToolRegistry {
  register(
    definition: ToolDefinition,
    provider: string,
    provider_endpoint: string
  ): ToolRegistration

  deregister(tool_id: string): void

  get(tool_id: string): ToolRegistration | null

  list(options?: {
    category?: string
    status?: string
    health?: string
    include_experimental?: boolean
  }): ToolRegistration[]

  search(query: string): ToolRegistration[]

  updateHealth(
    tool_id: string,
    health_status: "healthy" | "degraded" | "unavailable",
    metadata?: Partial<ToolRegistration["health_metadata"]>
  ): ToolRegistration

  snapshot(): RegistrySnapshot

  getByCategory(category: string): ToolRegistration[]
  getByStatus(status: string): ToolRegistration[]
  getByProvider(provider: string): ToolRegistration[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| TOL.ToolRegistered |      tool_id, name, category, provider, version | Tool registered in the catalog |
| TOL.ToolDeregistered |      tool_id, provider, category, reason | Tool removed from registry |
| TOL.ToolHealthChanged |      tool_id, old_status, new_status, consecutive_failures | Tool health transition detected |
| TOL.ToolStatusChanged |      tool_id, old_status, new_status, version | Tool status lifecycle transition |
| TOL.ToolUpdated |      tool_id, provider, updated_fields, version | Tool definition modified |
| TOL.ToolCategoryChanged |      tool_id, old_category, new_category | Tool category reassigned |
| TOL.RegistryQuery |      query_type, filters, result_count | Registry queried by Sou or system |
| TOL.RegistrySnapshotTaken |      total_tools, healthy, degraded, unavailable | Registry snapshot generated |
| TOL.ProviderToolsListed |      provider, tool_ids, count | All tools for a provider listed |
| TOL.RegistryIntegrityCheck |      total_tools, inconsistencies_found | Periodic registry integrity verified |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| REG-001 | Every tool_id in the Registry is unique | Algorithmic â€” collision check on register |
| REG-002 | Every tool belongs to exactly one category | Schema â€” category is required, not an array |
| REG-003 | Every tool has exactly one provider | Registry â€” verified on registration |
| REG-004 | A tool's capability_bounds must be a subset of its provider's capabilities | Application-level â€” validated at registration time |
| REG-005 | Deregistered tool_ids are never reassigned | Registry â€” tombstone retained for audit |
| REG-006 | Health status transitions follow valid paths (healthyâ†”degradedâ†”unavailable) | Algorithmic â€” state machine enforced |
| REG-007 | Experimental tools are invisible to Sou unless explicitly requested | API-level â€” list() filters by default |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Duplicate tool_id | `REG_DUPLICATE_TOOL_ID` | Return error; suggest unique ID |
| Unknown category | `REG_INVALID_CATEGORY` | Return error; show valid categories |
| Missing provider | `REG_MISSING_PROVIDER` | Return error; provider required |
| Tool not found | `REG_TOOL_NOT_FOUND` | Return null; no error |
| Invalid health transition | `REG_INVALID_HEALTH_TRANSITION` | Return error; valid transitions listed |
| Provider mismatch | `REG_PROVIDER_MISMATCH` | Return error; tool belongs to different provider |
| Invalid status transition | `REG_INVALID_STATUS_TRANSITION` | Return error; valid transitions listed |


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
| R1 â€” Modulsingularity | Registry handles only tool catalog storage and queries |
| R2 â€” Dependency Order | Depends on Tool Lifecycle Manager for health; no upward deps |
| R3 â€” DRY | Tool definitions stored once, referenced by ID everywhere |
| R4 â€” Builder Pattern | Registration built by Definition â†’ Provider â†’ Health Init |
| R5 â€” Liskov Substitution | Any ToolRegistry implements the interface |
| R6 â€” DI over Singletons | Index implementations and query strategies injected |
| R9 â€” Deterministic | Same registry state produces same query results |
| R10 â€” Simpler Over Complex | Flat key-value catalog with category indices |
| R13 â€” Design for Failure | Health tracking enables automatic recovery or removal |
| R14 â€” Paved Path | All tool discovery flows through list() or get() |
| R15 â€” Open/Closed | New categories added via config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Registry is the authoritative catalog in the Tool System |
| Brain/Tools/002-Discovery.md | Discovery Engine queries the Registry |
| Brain/Tools/003-Invocation.md | Invocation Manager reads tool definitions from Registry |
| Brain/Tools/006-Lifecycle.md | Lifecycle Manager updates health and status in Registry |
| Brain/Tools/004-Validation.md | Parameter schemas stored in Registry ToolDefinitions |
| Bible/04-Execution/Runtime/001-SDK.md | Runtime SDK registers tools via the Registry |
| Bible/05-Platform/004-EVS.md | Events emitted throughout Registry operations |
