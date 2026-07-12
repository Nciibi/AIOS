# AIOS Bible â€” Brain/LLMOS
## 009 â€” Retry Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-009 |
| Source Laws | Law 8 â€” Law of Verification-First (reliability), Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 12 â€” Provider Call with Retry |

## Purpose

The Retry Engine manages the safe, observable execution of provider API calls with configurable retry logic and fallback chains. It is the bridge between the LLMOS pipeline and the Provider SDK. Every provider call passes through the Retry Engine, which handles transient failures, rate limiting, timeouts, and model unavailability â€” ensuring the pipeline produces a response or a clear failure reason.

## Architecture

```
ProviderRequest (from Prompt Compiler)
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚          RETRY ENGINE                       â”‚
â”‚                                             â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
â”‚  â”‚ Attempt Managerâ”‚â”€â”€â–ºâ”‚ Backoff Calculatorâ”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚         â”‚                                    â”‚
â”‚         â–¼                                    â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚
â”‚  â”‚         Fallback Chain               â”‚   â”‚
â”‚  â”‚  Model A (primary) â†’ attempt 1..N    â”‚   â”‚
â”‚  â”‚  Model B (fallback 1) â†’ attempt 1..N â”‚   â”‚
â”‚  â”‚  Model C (fallback 2) â†’ attempt 1..N â”‚   â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚         â”‚                                    â”‚
â”‚         â–¼                                    â”‚
â”‚  Provider SDK â†’ Provider API â†â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚
â”‚         â”‚                                    â”‚
â”‚         â–¼                                    â”‚
â”‚  Success or FinalFailure                     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Retry Configuration

```typescript
interface RetryConfig {
  max_attempts: u64;              // Per model (default: 3)
  max_total_attempts: u64;        // Across all fallbacks (default: 6)
  backoff: BackoffConfig;
  timeout: TimeoutConfig;
  retryable_errors: ErrorType[];  // Which errors trigger retry
  circuit_breaker: CircuitBreakerConfig;
}

interface BackoffConfig {
  strategy: "exponential" | "linear" | "fixed";
  initial_delay_ms: u64;          // Default: 1000
  max_delay_ms: u64;              // Default: 30000
  jitter: f64;                    // Random jitter fraction (default: 0.1)
  multiplier: f64;                // For exponential (default: 2.0)
}

interface TimeoutConfig {
  request_timeout_ms: u64;        // Per attempt (default: 60000)
  stream_timeout_ms: u64;         // For streaming (default: 120000)
  total_timeout_ms: u64;          // All attempts combined (default: 300000)
}

interface CircuitBreakerConfig {
  enabled: boolean;               // Default: true
  failure_threshold: u64;         // Consecutive failures to open (default: 5)
  half_open_timeout_ms: u64;      // Time before testing (default: 30000)
  recovery_threshold: u64;        // Successes to close (default: 3)
}
```

## Retryable Errors

| Error Type | Retryable | Backoff | Notes |
|-----------|-----------|---------|-------|
| `provider_rate_limit` | Yes | Exponential + jitter | Respect Retry-After header if present |
| `provider_timeout` | Yes | Linear | Connection or read timeout |
| `provider_unavailable` | Yes | Exponential | 503, 502 from provider |
| `provider_overloaded` | Yes | Exponential | 429 without Retry-After |
| `provider_internal_error` | Yes | Exponential | 500 from provider |
| `network_error` | Yes | Exponential | DNS, TLS, connection errors |
| `auth_error` | No | â€” | 401, 403 â€” fail immediately |
| `invalid_request` | No | â€” | 400, 422 â€” fail immediately |
| `content_filter` | No | â€” | Provider blocked content â€” fail immediately |
| `model_not_found` | No | â€” | Trigger fallback to next model instead |

## Fallback Chain

```typescript
interface FallbackChain {
  primary: ModelEntry;
  alternatives: ModelEntry[];     // Ordered, from most to least preferred
  strategy: FallbackStrategy;
}

type FallbackStrategy = 
  | { type: "strict"; downgrade_ok: false }         // Same or higher quality
  | { type: "quality_tolerant"; max_downgrade: QualityTier }
  | { type: "cost_tolerant"; max_cost_increase: f64 }
  | { type: "any"; }                                // Any available model
```

The fallback chain is constructed by the Router (Stage 5) as part of model selection. The primary model is the Router's top choice. Alternatives are the next N candidates from the Router's ranked list.

## Execution Flow

```typescript
async function executeWithRetry(
  request: ProviderRequest,
  fallbackChain: FallbackChain,
  config: RetryConfig
): Promise<ProviderResult>

interface ProviderResult {
  success: boolean;
  response: ProviderResponse | null;
  error: ErrorInfo | null;
  attempts: AttemptRecord[];
  fallback_chain_used: string[];    // Models actually tried
  final_attempt: u64;
}
```

### Algorithm

1. **Circuit breaker check**: If circuit is open for primary model, skip to fallback immediately
2. **Attempt loop** (for each model in fallback chain):
   a. Execute provider call via Provider SDK
   b. On success: return response with attempt records
   c. On retryable error: apply backoff, increment attempt counter
   d. On non-retryable error: fail immediately for this model, move to next fallback
   e. On rate limit: parse Retry-After, wait that long, retry
3. **Fallback transition**: When primary model's attempts exhausted, move to next model in chain
4. **Exhaustion**: When all models exhausted, return final failure with combined attempt records

## Attempt Record

```typescript
interface AttemptRecord {
  attempt_number: u64;
  model_id: string;
  provider: string;
  is_fallback: boolean;
  started_at: DateTime;
  duration_ms: u64;
  result: "success" | "retryable_error" | "non_retryable_error" | "timeout" | "circuit_open";
  error: ErrorInfo | null;
  backoff_applied_ms: u64;
  tokens_consumed: TokenUsage | null;   // May be null if error before response
}
```

## Circuit Breaker

```typescript
interface CircuitBreakerState {
  model_id: string;
  state: "closed" | "open" | "half_open";
  failure_count: u64;
  last_failure_at: DateTime;
  opened_at: DateTime | null;
  recovery_success_count: u64;
}
```

- When `closed`: normal operation
- When threshold exceeded: transition to `open`, produce `LLMOS.CircuitBreakerOpened` Event
- After `half_open_timeout_ms`: transition to `half_open`, allow one test request
- Test request succeeds: transition to `closed`, reset counters
- Test request fails: transition back to `open`, reset timer

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-RTY-001 | Every provider call is wrapped by the Retry Engine â€” no direct provider calls from any pipeline component. | Architectural â€” sole provider call gateway |
| LLM-RTY-002 | Max total attempts across all fallbacks is never exceeded. | Algorithmic â€” attempt counter enforcement |
| LLM-RTY-003 | Backoff with jitter ensures no thundering herd on provider recovery. | Algorithmic â€” jittered backoff calculation |
| LLM-RTY-004 | Non-retryable errors (auth, invalid request, content filter) never trigger retry. | Algorithmic â€” error classification |
| LLM-RTY-005 | Circuit breaker state is shared across all pipeline instances for the same model. | Architectural â€” distributed state |
| LLM-RTY-006 | The attempt record is always produced regardless of success or failure. | Architectural â€” observability invariant |
| LLM-RTY-007 | Fallback never upgrades to a more expensive model without router approval. | Algorithmic â€” fallback strategy enforcement |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.ProviderCalled |   request_id, model_id, provider, attempt_number, is_fallback, latency_ms, tokens_consumed | Each provider API call |
| LLM.ProviderRetry |   request_id, attempt_number, error_code, backoff_ms, fallback_activated | Before retry attempt |
| LLM.CircuitBreakerOpened |   model_id, provider, failure_count, opened_at | Circuit opens |
| LLM.CircuitBreakerClosed |   model_id, provider, recovery_success_count, closed_at | Circuit recovers |


## Cross-Cutting Concerns

### Security

LLMOS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), LLMOS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), LLMOS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), LLMOS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Retry Engine is the sole provider call executor |
| R2 â€” Dependency Order | Retry Engine depends on Provider SDK for execution |
| R3 â€” DRY | Single retry logic applied to all providers |
| R4 â€” Builder Pattern | RetryConfig built via builder pattern |
| R5 â€” Liskov Substitution | All providers interchangeable through ModelProvider interface |
| R6 â€” DI over Singletons | RetryEngine injected into pipeline |
| R9 â€” Deterministic | Same request produces same retry sequence |
| R10 â€” Simpler Over Complex | Configurable backoff over opaque retry logic |
| R13 â€” Design for Failure | Core purpose â€” design for failure with circuit breakers |
| R14 â€” Paved Path | Default retry config for all provider calls |
| R15 â€” Open/Closed | New error types retried without engine changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/013-Provider-SDK.md | Retry Engine calls ProviderSDK::execute() |
| LLMOS/002-Router.md | Router constructs fallback chain consumed by Retry Engine |
| LLMOS/008-Streaming-Manager.md | Streaming passes through Retry Engine for initial connection |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| All retries exhausted | LLM-0501 | Return provider unavailable with combined attempt records |
| All fallbacks exhausted | LLM-0502 | Return all providers unavailable; include last error from each |
| Circuit breaker open | â€” | Skip to fallback; record as circuit_open in attempts |
| Total timeout exceeded | â€” | Cancel current attempt; return timeout error |
