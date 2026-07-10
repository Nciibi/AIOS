# AIOS Bible — Brain
## 000 — Tool System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Tools |
| Document ID | AIOS-BBL-002-TLS-000 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 3 — Law of Communication |
| Source Physics | Physics/007-Capabilities.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Tool System manages the registry, discovery, and invocation of tools available to Sou. Tools are the mechanism by which Sou interacts with the external world — reading files, querying databases, executing code, making API calls, and performing any action that goes beyond reasoning and language generation.

Under Law 7 (Capability Bounds), every tool has a declared capability scope. The Tool System enforces that Sou only invokes tools within its capability bounds, and that tool results are properly validated and returned to the context window.

## Architecture

```
Sou (discovers and invokes tools)
   ▲
   │
   ▼
┌────────────────────────────────────────────┐
│           Tool System                       │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Tool     │  │ Discovery│  │ Invocation│ │
│  │ Registry │─►│ Engine   │─►│  Manager  │ │
│  └──────────┘  └──────────┘  └────┬─────┘ │
│                                    │       │
│  ┌──────────┐  ┌──────────┐       │       │
│  │ Schema   │  │ Result   │       │       │
│  │ Validator│  │ Parser   │       │       │
│  └──────────┘  └──────────┘       │       │
└────────────────────────────────────┼───────┘
                                     │
                                     ▼
                            ┌──────────────┐
                            │  Runtime SDK │
                            │ (execution)  │
                            └──────────────┘
```

The Tool System does not execute tools directly. Execution is delegated to the Runtime SDK via the Security Council verification pipeline. The Tool System handles discovery, validation, and result processing — not execution.

## Core Concepts

### Tool Model

```
ToolDefinition {
  tool_id: string
  name: string
  description: string
  category: string            // "read" | "write" | "compute" | "communicate" | "system"
  capability_bounds: string[] // Required capabilities for invocation
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
}

ParameterSchema {
  type: "object"
  properties: Record<string, ParameterProperty>
  required: string[]
}

ParameterProperty {
  type: string               // "string" | "number" | "boolean" | "array" | "object"
  description: string
  enum?: string[]            // Allowed values
  default?: unknown
  constraints?: {
    min?: number
    max?: number
    pattern?: string         // Regex validation
    format?: string          // "date" | "email" | "uri" | etc.
  }
}

ReturnSchema {
  type: string               // "string" | "number" | "boolean" | "array" | "object" | "binary"
  description: string
  is_stream: boolean
}

ToolResult {
  tool_id: string
  invocation_id: string
  status: "success" | "error" | "timeout" | "cancelled"
  data: unknown              // Parsed result data
  error?: {
    code: string
    message: string
    details?: unknown
  }
  metadata: {
    duration_ms: number
    token_cost: number
    resource_usage: {
      cpu_ms?: number
      memory_bytes?: number
      network_bytes?: number
    }
  }
}
```

### 1. Tool Registry

The Tool Registry is the authoritative catalog of all tools available to Sou:

| Tool Category | Examples | Capability Required |
|---------------|----------|---------------------|
| Read | `read_file`, `query_database`, `search_web` | `tool.read.*` |
| Write | `write_file`, `create_record`, `send_message` | `tool.write.*` |
| Compute | `execute_code`, `run_query`, `calculate` | `tool.compute.*` |
| Communicate | `send_email`, `post_message`, `notify` | `tool.communicate.*` |
| System | `list_files`, `get_metrics`, `check_health` | `tool.system.*` |

Tools are discovered at startup and registered through the Registry. External tools can be added via the Tool SDK (planned).

```
ToolRegistration {
  tool: ToolDefinition
  provider: string           // Which Engine/Service provides this tool
  provider_endpoint: string  // ACF endpoint for invocation
  health_status: "healthy" | "degraded" | "unavailable"
  last_heartbeat: timestamp
}
```

### 2. Discovery Engine

Sou can query available tools based on capability, category, or natural language description:

| Discovery Mode | Behavior | Use Case |
|----------------|----------|----------|
| List all | Return all active tools | Sou exploring available capabilities |
| Filter by capability | Return tools matching capability | Sou needs a specific capability |
| Filter by category | Return tools in a category | Sou wants read/write/compute tools |
| Semantic search | Find tools by description | "Find me a tool that can search the web" |
| Recommend | Suggest tools for a goal | Sou has a goal but doesn't know which tool |

### 3. Invocation Manager

When Sou decides to use a tool, the Invocation Manager:

1. Validates parameters against the schema
2. Checks Sou has the required capability bounds
3. Verifies rate limits are not exceeded
4. Routes the invocation through the Security Council pipeline
5. Delegates execution to the Runtime SDK
6. Receives the result and parses it
7. Returns the parsed result to Sou

```
InvocationRequest {
  invocation_id: string
  tool_id: string
  parameters: Record<string, unknown>
  context: {
    session_id: string
    sou_identity: string
    capability_token: string
    deadline: timestamp
  }
}

InvocationResult {
  invocation_id: string
  status: "pending" | "running" | "completed" | "failed" | "cancelled"
  result?: ToolResult
  events: {
    event_type: string
    timestamp: timestamp
    data?: unknown
  }[]
}
```

### 4. Schema Validation

Every tool invocation is validated against its parameter schema before execution:

| Validation | Behavior on Failure |
|------------|-------------------|
| Required fields | Return error; no execution |
| Type checking | Return error with type mismatch details |
| Enum values | Return error; show allowed values |
| Range constraints | Clamp to valid range OR return error (configurable) |
| Pattern matching | Return error; show expected pattern |

### 5. Result Parsing

Raw execution results are parsed into structured `ToolResult` objects:

| Result Type | Parser Behavior |
|-------------|-----------------|
| Structured (JSON) | Parse into typed data |
| Text | Return as string with metadata |
| Binary | Return as base64-encoded blob |
| Stream | Return as async iterator of chunks |
| Error | Return with error code, message, and details |

## Interfaces

### Tool System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `listTools(category?, capability?)` | Sou only | List available tools matching filter |
| `getTool(tool_id)` | Sou only | Get tool definition by ID |
| `searchTools(query)` | Sou only | Semantic search for tools |
| `invokeTool(tool_id, parameters)` | Sou only | Invoke a tool (goes through Security Council) |
| `getInvocationResult(invocation_id)` | Sou only | Poll for result (async invocations) |
| `cancelInvocation(invocation_id)` | Sou only | Cancel a running invocation |
| `registerTool(definition, provider)` | Runtime SDK | Register a new tool |
| `deregisterTool(tool_id)` | Runtime SDK | Remove a tool from registry |
| `reportToolHealth(tool_id, status)` | Runtime SDK | Update tool health status |

### Internal Interfaces

```
interface SchemaValidator {
  validate(parameters: Record<string, unknown>, schema: ParameterSchema): ValidationResult
}

interface ResultParser {
  parse(raw: unknown, return_schema: ReturnSchema): ToolResult
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `TLS.ToolInvoked` | invocation_id, tool_id, parameter_summary | Tool invocation started |
| `TLS.ToolCompleted` | invocation_id, status, duration_ms | Tool execution completed |
| `TLS.ToolFailed` | invocation_id, error_code, error_message | Tool execution failed |
| `TLS.ToolTimeout` | invocation_id, deadline | Tool exceeded deadline |
| `TLS.ToolRegistered` | tool_id, provider, category | New tool registered |
| `TLS.ToolDeregistered` | tool_id, provider | Tool removed from registry |
| `TLS.ToolHealthChanged` | tool_id, old_status, new_status | Tool health transitioned |
| `TLS.ValidationFailed` | invocation_id, field, reason | Parameter validation failed |
| `TLS.CapabilityDenied` | invocation_id, tool_id, required_cap | Sou lacks required capability |
| `TLS.RateLimitExceeded` | tool_id, current_usage, limit | Tool rate limit hit |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| TLS-001 | All tool invocations pass through the Security Council pipeline | Architectural — Invocation Manager routes through SC |
| TLS-002 | Sou only invokes tools within its capability bounds | API-level — checked before invocation |
| TLS-003 | Tools are stateless — all state lives in caller | Architectural — tools are pure functions |
| TLS-004 | Tool parameters are validated before execution | Algorithmic — Schema Validator runs before dispatch |
| TLS-005 | Tool results are always returned to Context System | Architectural — result pushed to Context Window |
| TLS-006 | Every tool has exactly one provider | Registry — verified on registration |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Tool System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou discovers and invokes tools |
| Brain/Context/000-Overview.md | Tool results are pushed to the Context Window |
| Brain/Decision/000-Overview.md | Tool selection is a decision the Decision System supports |
| Brain/Planning/000-Overview.md | Plan milestones may require specific tools |
| Security/Execution-Auth/000-EAS.md | Tool invocations pass through the 7-stage pipeline |
| Runtime/001-SDK.md | Runtime SDK executes tool calls |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown tool_id | `TLS_TOOL_NOT_FOUND` | Return error; suggest similar tools |
| Invalid parameters | `TLS_PARAMETER_INVALID` | Return validation errors per field |
| Rate limit exceeded | `TLS_RATE_LIMITED` | Return error with retry-after |
| Capability denied | `TLS_CAPABILITY_DENIED` | Deny invocation; log security event |
| Tool unhealthy | `TLS_TOOL_UNAVAILABLE` | Return error; suggest alternatives |
| Invocation timeout | `TLS_INVOCATION_TIMEOUT` | Return timeout result; cancel on provider |
| Provider unreachable | `TLS_PROVIDER_UNREACHABLE` | Return error; mark tool degraded |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Tool System does one thing: manage tool lifecycle and invocation |
| R2 — Dependency Order | Depends on Runtime SDK, Security Council; no upward deps |
| R3 — DRY | Tool definitions stored once in Registry |
| R4 — Builder Pattern | Invocation built by Validator → Capability Check → Dispatch |
| R5 — Liskov Substitution | Any ResultParser implements the interface |
| R6 — DI over Singletons | Validators and parsers injected |
| R9 — Deterministic | Same inputs produce same result (tools may vary) |
| R10 — Simpler Over Complex | Tools are simple input → output mappings |
| R13 — Design for Failure | All invocations have deadlines, retries, and fallbacks |
| R14 — Paved Path | All tool usage flows through `invokeTool` |
| R15 — Open/Closed | New tool categories added via Registry, not by modifying core |