# AIOS Bible — Execution
## 000 — Runtime Engine Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-000 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Runtime Engine is the constitutional execution substrate of AIOS. It is the environment in which verified, authorized actions are carried out — model inference, tool invocation, code execution, data processing, and domain-specific operations. The Runtime Engine does not decide what to execute; it receives authorized execution tokens from the Security Kernel and executes them within declared capability bounds.

The Runtime is strictly an executor. It has no strategic authority, no governance role, no decision-making capacity. It is bound by Law 2 (Non-Execution) in the inverse — it executes but does not decide. Law 8 (Verification-First) ensures every action executed by the Runtime has passed the full verification pipeline. Law 7 (Capability Bounds) ensures every execution stays within its declared resource and scope limits.

## Architecture

The Runtime Engine is a provider-based architecture. A central Runtime Manager brokers execution requests to registered Execution Providers, each of which implements a specific execution domain.

```
Execution Request (with Verification Token)
    │
    ▼
┌─────────────────────────────────────┐
│        Runtime Manager                │
│  ┌──────────┐  ┌──────────┐          │
│  │ Provider │  │ Token    │          │
│  │ Registry │  │ Validator│          │
│  └──────────┘  └──────────┘          │
│  ┌──────────┐  ┌──────────┐          │
│  │ Resource │  │ Lifecycle│          │
│  │ Monitor  │  │ Manager  │          │
│  └──────────┘  └──────────┘          │
│  ┌──────────┐  ┌──────────┐          │
│  │ Event    │  │ Quarantine│         │
│  │ Producer │  │ Handler  │          │
│  └──────────┘  └──────────┘          │
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│     Execution Provider Interface      │
│  ┌────────┐ ┌──────┐ ┌──────────┐    │
│  │ Claude │ │Codex │ │  Ollama  │ ... │
│  │ Prov.  │ │Prov. │ │  Prov.   │    │
│  └────────┘ └──────┘ └──────────┘    │
│  ┌────────┐ ┌────────┐ ┌──────────┐  │
│  │Browser │ │Trading │ │ Robotics │  │
│  │ Prov.  │ │ Prov.  │ │  Prov.   │  │
│  └────────┘ └────────┘ └──────────┘  │
└─────────────────────────────────────┘
```

### Runtime Manager

The Runtime Manager is the central orchestrator. It receives execution requests, validates the verification token, selects an appropriate provider, dispatches execution, monitors resource consumption, and produces execution Events.

| Function | Description |
|----------|-------------|
| Token Validation | Verifies the execution token's signature, expiry, and scope before any provider is invoked |
| Provider Selection | Routes execution to the correct provider based on the execution type declared in the token |
| Resource Monitoring | Tracks token consumption, compute, memory, and duration against the capability budget |
| Lifecycle Management | Manages execution state: Requested → Authorized → Executing → Completed/Failed |
| Event Production | Produces execution Events for every state transition, resource sample, and outcome |
| Quarantine | Isolates misbehaving providers or executions; terminates executions that exceed bounds |

### Execution Providers

Execution Providers are pluggable modules that implement the `ExecutionProvider` interface. Each provider encapsulates the domain-specific logic for executing a class of actions. Providers are registered with the Runtime Manager at startup and are discoverable via the Provider Registry.

Providers are bounded by Law 7 — they declare their capability requirements (resource consumption, scope, supported action types) at registration. The Runtime Manager enforces these bounds during execution.

## Execution Flow

```
1. Entity receives verified execution token from Security Kernel
2. Entity submits token + action to Runtime Manager via ACF
3. Runtime Manager validates token (signature, expiry, scope)
4. Runtime Manager selects Execution Provider based on action type
5. Runtime Manager checks resource availability against ROS
6. Provider executes the action within declared bounds
7. Runtime Manager monitors execution (resources, duration, health)
8. Provider returns result or error
9. Runtime Manager produces Execution Event
10. Runtime Manager releases resources and updates ROS
11. Result returned to requesting entity via ACF
```

## Provider Registration

Every Execution Provider must register with the Runtime Manager before accepting executions. Registration includes:

| Field | Description | Required |
|-------|-------------|----------|
| provider_id | Unique provider identifier | Yes |
| name | Human-readable provider name | Yes |
| version | Provider implementation version | Yes |
| action_types | Array of supported action type identifiers | Yes |
| capability_declaration | Resource requirements, autonomy level, scope | Yes |
| health_endpoint | Endpoint for liveness/readiness probes | Yes |
| max_concurrent | Maximum concurrent executions | Yes |
| timeout_default | Default execution timeout | Yes |

## Invariants

1. **RTM-001 — Token-Bound Execution**: Every execution is authorized by a verified token. No execution occurs without token validation.
2. **RTM-002 — Bounded Execution**: Every execution operates within the capability bounds declared at provider registration and token issuance. Bounds are enforced by the Runtime Manager.
3. **RTM-003 — Isolated Execution**: Every execution is isolated at the provider level. No execution interferes with another. Cross-execution communication flows through ACF.
4. **RTM-004 — Observable Execution**: Every execution produces Events at start, progress checkpoints, resource consumption samples, and completion or failure.
5. **RTM-005 — Provider Neutrality**: The Runtime Manager treats all providers equally under the same interface. No provider receives preferential scheduling or resource allocation.
6. **RTM-006 — Fail-Closed**: If the Runtime Manager cannot validate a token, select a provider, or verify resource availability, execution is denied.

## Execution Lifecycle

```
Requested ──→ TokenValidated ──→ ProviderSelected ──→ Executing ──→ Completed
                    │                    │                  │
                    ▼                    ▼                  ▼
                Denied              Unsupported        Failed
```

| State | Description |
|-------|-------------|
| Requested | Execution request received by Runtime Manager |
| TokenValidated | Verification token is valid and in scope |
| ProviderSelected | Appropriate provider identified and available |
| Executing | Provider is executing the action |
| Completed | Execution succeeded; result ready for return |
| Failed | Execution failed; error details captured |
| Denied | Token validation failed or resource unavailable |
| Unsupported | No provider registered for the requested action type |

## Events

| Event Type | Produced When | Fields |
|------------|---------------|--------|
| `Runtime.ExecutionRequested` | Execution request received | execution_id, entity_id, action_type, token_id |
| `Runtime.TokenValidated` | Token validation succeeded | execution_id, token_id, expiry, scope |
| `Runtime.ProviderSelected` | Provider assigned to execution | execution_id, provider_id, action_type |
| `Runtime.ExecutionStarted` | Provider begins execution | execution_id, provider_id, timestamp |
| `Runtime.ResourceSample` | Periodic resource consumption data | execution_id, token_consumed, memory_mb, cpu_ms |
| `Runtime.ExecutionCompleted` | Execution succeeded | execution_id, result_summary, duration_ms |
| `Runtime.ExecutionFailed` | Execution failed | execution_id, error_code, error_message, partial_state |
| `Runtime.ExecutionDenied` | Token validation or resource check failed | execution_id, reason, deny_stage |
| `Runtime.ProviderHealthChanged` | Provider health status changes | provider_id, previous_status, new_status |

## Cross-Cutting Concerns

### Security

The Runtime Engine enforces the security boundary between verification and execution. It does not re-verify identity, authentication, or authorization — it validates the execution token issued by the Security Kernel. Token forgery or replay is detected through cryptographic signature verification. Each execution runs in an isolated context scoped to the token's declared bounds. The quarantine handler terminates any execution that attempts to exceed its bounds or access resources outside its scope.

### Evidence

Every execution produces a complete Event stream. Events are immutable after production and are stored in the Event Store. The Event chain — from execution request through token validation, provider selection, resource sampling, and outcome — provides a full audit trail. Law 4 (Law of Evidence) is satisfied by the Runtime's Event production at every lifecycle transition.

### Lifecycle

The Runtime Engine follows the execution lifecycle defined in Physics/010-Execution.md. Each execution transitions through Requested → TokenValidated → ProviderSelected → Executing → Completed/Failed. The Runtime Manager enforces timeout bounds — executions that exceed their maximum duration are terminated and recorded as Failed.

### Capability Bounds

Providers declare their capability requirements at registration. The Runtime Manager checks each execution against the provider's declared bounds and the execution token's issued bounds. If an execution's resource consumption approaches its budget limit (90%), a warning Event is produced. If the hard limit is reached, execution is terminated. ROS integration ensures resource budgets are enforced in real-time.

### Communication

All execution requests arrive via ACF. All execution results are returned via ACF. Providers do not communicate directly with entities — all communication flows through the Runtime Manager, which enforces the ACF contract. Law 3 (Law of Communication) is satisfied through this architecture.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 — Modulsingularity | The Runtime Engine does one thing: execute verified actions within bounds. It does not decide, verify, or govern. |
| R2 — Dependency Order | Runtime depends on Security Kernel (tokens), ROS (resources), ACF (communication). No reverse dependencies. |
| R3 — DRY | Execution logic is defined once per provider. Provider capabilities are declared once at registration. |
| R4 — Builder Pattern | Execution tokens are built by the Security Kernel. The Runtime receives pre-built, validated tokens. |
| R5 — Liskov Substitution | All Execution Providers implement the same `ExecutionProvider` interface. Providers are interchangeable. |
| R6 — DI over Singletons | Runtime Manager receives its dependencies (Provider Registry, ROS client, ACF client) through injection. |
| R7 — Tests Exist | Every provider has unit tests for its execution logic and integration tests for token validation and bounds enforcement. |
| R8 — Fast Tests | Unit tests complete in < 100ms. Integration tests complete in < 5s. Provider integration tests use mock backends. |
| R9 — Deterministic | Given the same token and action, the Runtime Manager produces the same lifecycle sequence. Provider outputs may vary by nature. |
| R10 — Simpler Over Complex | The execution pipeline is linear: validate → select → execute → record. No branching, no parallel execution paths. |
| R11 — Refactor over Rewrite | Providers evolve through interface versioning. The Runtime Manager core is stable; providers are pluggable. |
| R12 — Embrace Errors | Every error has a unique code (RTM-ERR-NNN). Error codes include actional context and escalation path. |
| R13 — Design for Failure | If a provider is unhealthy, the Runtime Manager fails over to a secondary provider or denies execution. Fail-closed. |
| R14 — Paved Path | The paved path for execution is: Token → Validate → Select → Execute → Monitor → Record → Return. No alternative paths exist. |
| R15 — Open/Closed | New providers implement `ExecutionProvider` without modifying the Runtime Manager. New action types extend the registry. |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/010-Execution.md | Execution invariants — the Runtime Engine is the concrete implementation of these invariants |
| Physics/007-Capabilities.md | Capability bounds — enforced by the Runtime Manager during execution |
| Physics/005-Events.md | Event production — the Runtime Engine produces Events at every lifecycle transition |
| Physics/008-Security.md | Security invariants — token validation is the Runtime's security boundary |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK — how to build Execution Providers |
| Bible/04-Execution/Runtime/002-Claude.md | Anthropic Claude provider specification |
| Bible/04-Execution/Runtime/003-Codex.md | OpenAI Codex provider specification |
| Bible/04-Execution/Runtime/004-Ollama.md | Ollama provider specification |
| Bible/04-Execution/Runtime/005-Browser.md | Browser automation provider specification |
| Bible/04-Execution/Runtime/006-Trading.md | Trading execution provider specification |
| Bible/04-Execution/Runtime/007-Robotics.md | Robotics execution provider specification |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA R1-R15 compliance framework |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001 (Separation of Concerns) — Runtime owns execution |
