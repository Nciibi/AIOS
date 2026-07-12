# AIOS Bible â€” Brain/LLMOS
## 013 â€” Provider SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-013 |
| Source Laws | Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | Provider Abstraction Layer |

## Purpose

The Provider SDK defines the contract that every AI model provider must implement to integrate with LLMOS. Any provider implementing the `ModelProvider` interface is a drop-in replacement â€” the LLMOS pipeline operates identically regardless of which provider is behind the interface. This document specifies the interface, lifecycle, error model, and implementation requirements.

## ModelProvider Interface

```typescript
interface ModelProvider {
  // Identity
  readonly provider_name: string;
  readonly version: string;
  
  // Lifecycle
  initialize(config: ProviderConfig): Promise<void>;
  healthCheck(): Promise<HealthStatus>;
  shutdown(): Promise<void>;
  
  // Model Management
  listModels(): Promise<ModelEntry[]>;
  getModel(model_id: string): Promise<ModelEntry | null>;
  
  // Core Inference
  execute(request: ProviderRequest): Promise<ProviderResponse>;
  executeStream(request: ProviderRequest): AsyncIterable<ProviderChunk>;
  
  // Embeddings (if supported)
  embed(inputs: string[], model: string): Promise<EmbeddingResult>;
  
  // Tokenization
  countTokens(content: string, model: string): Promise<u64>;
}
```

## ProviderConfig

```typescript
interface ProviderConfig {
  provider_name: string;
  
  // Authentication (resolved from SSM at runtime)
  credentials: CredentialResolution;
  
  // Endpoints
  base_url: string;
  api_version: string;
  
  // Provider-specific options
  options: Map<string, any>;
  
  // Network
  timeout_ms: u64;
  max_connections: u64;
  retry_config: RetryConfig;
  
  // LLMOS integration
  event_bus: EventBus;              // For emitting provider Events
  metrics_collector: MetricsCollector;
  logger: Logger;
}
```

### Credential Resolution

API keys and secrets are never stored in provider config. They are resolved from SSM at `initialize()`:

```typescript
interface CredentialResolution {
  type: "ssm" | "env" | "file" | "inline";  // inline only for local dev
  ssm_path: string | null;                   // e.g., "/aios/providers/claude/api_key"
  env_var: string | null;                    // e.g., "ANTHROPIC_API_KEY"
  file_path: string | null;                  // e.g., "/etc/aios/secrets/claude.key"
  resolved_value: string | null;             // Populated at initialization â€” never serialized
}
```

## ProviderRequest (Provider SDK version)

```typescript
interface ProviderRequest {
  model: string;
  system: string | null;
  messages: ProviderMessage[];
  max_tokens: u64;
  temperature: f64;
  top_p: f64;
  stop_sequences: string[];
  tools: ToolDefinition[] | null;
  tool_choice: ToolChoice | null;
  response_format: ResponseFormat | null;
  stream: boolean;
  metadata: Map<string, string>;
  // Provider-specific extensions
  extensions: Map<string, any>;
}

interface ProviderMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | ContentBlock[];
  name: string | null;
  tool_call_id: string | null;
  tool_calls: ToolCall[] | null;
}

type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; source: ImageSource }
  | { type: "tool_use"; id: string; name: string; input: any }
  | { type: "tool_result"; tool_use_id: string; content: string }
  | { type: "document"; source: DocumentSource };
```

## ProviderResponse

```typescript
interface ProviderResponse {
  id: string;                        // Provider's response ID
  model: string;                     // Model that generated the response
  content: string;
  tool_calls: ToolCall[] | null;
  finish_reason: "stop" | "length" | "content_filter" | "tool_use" | "error";
  
  // Usage
  usage: {
    input_tokens: u64;
    output_tokens: u64;
    cached_input_tokens: u64;
    total_tokens: u64;
  };
  
  // Provider-specific metadata
  provider_metadata: Map<string, any>;
  
  // Timing
  time_to_first_token_ms: u64;
  total_duration_ms: u64;
}
```

## Streaming

```typescript
interface ProviderChunk {
  index: u64;
  delta: {
    content: string | null;
    tool_calls: PartialToolCall[] | null;
  };
  finish_reason: string | null;
  usage: {
    input_tokens: u64;
    output_tokens: u64;
    cached_input_tokens: u64;
  } | null;
}

interface PartialToolCall {
  index: u64;
  id: string | null;                 // May be null on first chunk
  function: {
    name: string | null;             // May be null on first chunk
    arguments: string;               // May be partial JSON
  };
}
```

The provider returns an `AsyncIterable<ProviderChunk>`. The Streaming Manager (LLMOS Stage 13) wraps this into `LLMOSChunk` objects for the caller.

## Embeddings

```typescript
interface EmbeddingResult {
  model: string;
  embeddings: f64[][];               // [n_inputs][embedding_dimension]
  usage: {
    tokens: u64;
  };
  dimensions: u64;
}
```

Embeddings are optional â€” providers that don't support them return an empty result with `usage.tokens = 0`.

## Token Counting

```typescript
async function countTokens(content: string, model: string): Promise<u64>
```

- Returns the exact token count for the given content on the given model
- Should use the provider's native tokenizer when available
- Providers without a native tokenizer should implement a character-based estimate (`content.length / 4`)

## Health Check

```typescript
interface HealthStatus {
  provider: string;
  status: "online" | "degraded" | "offline";
  checked_at: DateTime;
  latency_ms: u64;
  models_available: u64;
  error: string | null;              // Present only if degraded or offline
  details: Map<string, any>;         // Provider-specific health data
}
```

```typescript
async function healthCheck(): Promise<HealthStatus> {
  // 1. Attempt lightweight API call (e.g., list models or simple completion)
  // 2. Measure response time
  // 3. Return status: online if successful, degraded if slow, offline if failed
  // 4. LLMOS Registry consumes this status for model availability
}
```

## Lifecycle

### Initialization Sequence

1. LLMOS Gateway calls `provider.initialize(config)` for each configured provider
2. Provider resolves credentials from SSM (`config.credentials.ssm_path`)
3. Provider opens connection pool to API endpoint
4. Provider calls `healthCheck()` to verify connectivity
5. Provider calls `listModels()` to populate the Model Registry
6. Provider registers itself with the Registry (Stage 4)
7. LLMOS Gateway produces `LLMOS.ProviderRegistered(provider_name, model_count)` Event

### Shutdown Sequence

1. LLMOS Gateway calls `provider.shutdown()` for each active provider
2. Provider closes connection pool
3. Provider deregisters from Model Registry
4. Provider flushes any pending metrics
5. LLMOS produces `LLMOS.ProviderDeregistered(provider_name)` Event

### Error Handling

```typescript
class ProviderError extends Error {
  constructor(
    public readonly code: ProviderErrorCode,
    public readonly message: string,
    public readonly provider: string,
    public readonly model: string,
    public readonly retryable: boolean,
    public readonly retry_after_ms: u64 | null,
    public readonly cause: Error | null
  ) {
    super(`[${provider}:${code}] ${message}`);
  }
}

type ProviderErrorCode =
  | "AUTH_ERROR"              // 401, 403 â€” not retryable
  | "RATE_LIMITED"            // 429 â€” retryable with retry_after
  | "TIMEOUT"                 // Connection or read timeout â€” retryable
  | "UNAVAILABLE"             // 502, 503 â€” retryable
  | "OVERLOADED"              // 529 â€” retryable
  | "INVALID_REQUEST"         // 400, 422 â€” not retryable
  | "CONTENT_FILTERED"        // Content blocked â€” not retryable
  | "MODEL_NOT_FOUND"         // Model does not exist â€” not retryable
  | "CONTEXT_TOO_LARGE"       // Context exceeds limit â€” not retryable
  | "INTERNAL_ERROR"          // 500 â€” retryable
  | "NETWORK_ERROR"           // DNS, TLS, connection â€” retryable
  | "UNKNOWN";                // Fallback
```

All provider errors must use `ProviderError` with the correct code, retryable flag, and retry_after_ms (if applicable). The Retry Engine (LLMOS Stage 12) uses this information for retry/fallback decisions.

## Implementation Requirements

### Required

Every `ModelProvider` implementation MUST:

1. Implement ALL methods in the `ModelProvider` interface (embed may be empty)
2. Handle credential resolution through SSM (env var fallback for local dev)
3. Use TLS 1.3 for all API communications
4. Implement proper error mapping â†’ `ProviderError` codes
5. Support both `execute` and `executeStream` (stream may fall back to buffered)
6. Provide accurate token counting via `countTokens`
7. Implement `healthCheck` that completes in < 5s
8. Emit metrics for every call: latency, tokens, errors

### Testing Requirements

Each provider implementation MUST include:

| Test Type | Coverage | Purpose |
|-----------|----------|---------|
| Unit tests | 100% of non-network logic | Credential resolution, error mapping, request building |
| Integration tests | All API paths | Happy path, rate limiting, auth failure, timeout |
| Mock tests | All error codes | Every ProviderError code produced correctly |
| Streaming tests | Stream assembly | Chunks assembled correctly, tool calls accumulated |
| Tokenizer tests | Accuracy | Token counts match provider's own tokenizer within 5% |

### Provider Registration

```typescript
// In LLMOS initialization:
interface ProviderFactory {
  provider_name: string;
  create(config: ProviderConfig): ModelProvider;
}

// Registered providers:
const PROVIDER_FACTORIES: Map<string, ProviderFactory> = new Map([
  ["claude", { provider_name: "claude", create: (cfg) => new ClaudeProvider(cfg) }],
  ["codex", { provider_name: "codex", create: (cfg) => new CodexProvider(cfg) }],
  ["ollama", { provider_name: "ollama", create: (cfg) => new OllamaProvider(cfg) }],
]);
```

New providers register by adding an entry to `PROVIDER_FACTORIES` and implementing the `ModelProvider` interface.

## Relationship to ExecutionProvider

The existing `ExecutionProvider` interface (Runtime/001-SDK.md) and `ModelProvider` (this document) coexist:

| Aspect | ExecutionProvider | ModelProvider |
|--------|------------------|---------------|
| Purpose | Runtime action execution | AI model inference |
| Methods | `execute(action, params)`, `executeStream(action, params)` | `execute(request)`, `executeStream(request)` |
| Domain | Browser, Trading, Robotics, CLI | Claude, Codex, Ollama, GPT |
| Route | RuntimeManager â†’ ExecutionProvider | LLMOS Pipeline â†’ ModelProvider |
| Schema | Action-based payload | Chat completion / embedding payload |
| Streaming | Event-based action progress | Token-by-token text generation |

Dual-implementation providers (Claude, Codex, Ollama) implement both interfaces. The LLMOS path is canonical for AI inference; the `ExecutionProvider` path is deprecated for AI operations.

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-SDK-001 | Every `ModelProvider` implementation has a unique `provider_name`. | Schema â€” registration uniqueness |
| LLM-SDK-002 | `initialize()` must resolve credentials before any other method is called. | Architectural â€” lifecycle ordering |
| LLM-SDK-003 | `healthCheck()` is called within 5 seconds or times out to `degraded`. | Algorithmic â€” timeout enforcement |
| LLM-SDK-004 | Provider errors are always wrapped in `ProviderError` with a valid code. | Schema â€” error type enforcement |
| LLM-SDK-005 | Streaming is always supported â€” `executeStream` may delegate to `execute` + synthetic stream if provider does not support native streaming. | Algorithmic â€” fallback streaming |
| LLM-SDK-006 | `shutdown()` is idempotent â€” calling it multiple times has no effect. | Algorithmic â€” idempotency design |
| LLM-SDK-007 | Credentials are never logged, serialized, or exposed outside the `initialize()` scope. | Governance â€” security policy |
| LLM-SDK-008 | Token counting never throws â€” returns 0 on failure. | Algorithmic â€” safe fallback |

## Events (Provider-Level)

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.ProviderRegistered` | provider_name, version, model_count, registered_at | After initialize() |
| `LLMOS.ProviderDeregistered` | provider_name, reason, uptime_seconds | On shutdown() |
| `LLMOS.ProviderHealthChanged` | provider_name, old_status, new_status, latency_ms, error | On healthCheck() change |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Provider SDK is the sole provider interface definition |
| R2 â€” Dependency Order | Provider SDK implementations consumed by Registry and Retry Engine |
| R3 â€” DRY | Single interface for all providers |
| R4 â€” Builder Pattern | ProviderRequest/ProviderResponse built through typed interfaces |
| R5 â€” Liskov Substitution | All providers are drop-in replacements via the interface |
| R6 â€” DI over Singletons | Provider instances injected via ProviderFactory |
| R9 â€” Deterministic | Same request produces same response for same model |
| R10 â€” Simpler Over Complex | Minimal interface surface over provider-specific SDKs |
| R13 â€” Design for Failure | ProviderError model covers all failure modes |
| R14 â€” Paved Path | Standardized interface defines paved path for provider integration |
| R15 â€” Open/Closed | New providers implement existing interface without SDK changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/009-Retry-Engine.md | Consumes ModelProvider::execute/executeStream |
| LLMOS/001-Model-Registry.md | Consumes ModelProvider::listModels for registry population |
| LLMOS/008-Streaming-Manager.md | Consumes ModelProvider::executeStream for streaming |
| Bible/04-Execution/Runtime/001-SDK.md | Existing ExecutionProvider interface (dual-interface providers) |
| Bible/04-Execution/Runtime/002-Claude.md | Claude implementation of ModelProvider |
| Bible/04-Execution/Runtime/004-Ollama.md | Ollama implementation of ModelProvider |
| Bible/04-Execution/Security/SSM/000-SSM.md | SSM provides credential resolution |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Provider not in FACTORIES | â€” | LLMOS startup fails; log configuration error |
| Credential resolution fails | â€” | `initialize()` throws; provider not registered |
| healthCheck() times out | â€” | Status returned as `degraded` with timeout error |
| Provider returns unexpected response | â€” | Map to `UNKNOWN` error code; log full response for debugging |
| Token counter fails | â€” | Return 0; log error; pipeline uses fallback estimation |
