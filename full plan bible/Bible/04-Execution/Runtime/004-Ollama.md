# AIOS Bible — Execution
## 004 — Ollama Local Model Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-004 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Ollama Provider implements both the `ExecutionProvider` interface (Runtime SDK) and the `ModelProvider` interface (LLMOS Provider SDK). Under the canonical LLMOS architecture, all AI inference requests route through the LLMOS pipeline (`Bible/04-Execution/LLMOS/`) which handles routing, prompt compilation, context management, memory injection, guardrails, retry, and caching before calling this provider through the `ModelProvider` interface. The `ExecutionProvider` path is deprecated for AI inference and maintained only for backward compatibility during migration.

The provider executes model inference actions against locally hosted models through the Ollama API. It provides access to open-weight models (Llama 3, Mistral, Qwen, DeepSeek, Gemma, Phi) running on local or private infrastructure, enabling air-gapped and low-latency inference within AIOS capability bounds.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.ollama` |
| action_types | `model.inference`, `model.inference.stream`, `model.inference.embed` |
| max_parallelism | 8 concurrent executions (per local GPU) |
| default_timeout_ms | 300000 (5 minutes) |
| supported_autonomy_levels | L0, L1, L2, L3, L4 |
| supported_models | Configurable via model registry; default: llama3, mistral, qwen2.5, deepseek-coder, gemma2, phi4 |

## Execution Flow

1. Runtime Manager dispatches a `model.inference` action to the Ollama Provider
2. Provider resolves the Ollama endpoint URL (localhost or private network) from configuration
3. Provider selects the model from the entity's allowed model list in the capability bounds
4. Provider sends a POST request to `{endpoint}/api/generate` or `{endpoint}/api/chat`
5. For streaming, the provider reads the NDJSON response stream and emits chunks
6. Provider monitors inference time and resource consumption against capability bounds
7. On completion, provider returns the generated response with metrics

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| endpoint | `http://localhost:11434` | Ollama service endpoint |
| default_model | `llama3` | Default model for inference |
| model_pull_timeout_ms | 300000 | Timeout for pulling a model before marking unavailable |
| keep_alive_seconds | 300 | Duration to keep model loaded in GPU memory |
| max_loaded_models | 2 | Maximum models loaded simultaneously per GPU |
| gpu_layers | -1 | Number of layers to offload to GPU (-1 = all) |
| num_ctx | 4096 | Context window size in tokens |

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Model not pulled but storage space insufficient | Return StorageExhausted error; suggest freeing space |
| GPU memory fragmentation after many model loads | Periodically unload all models and reload on demand |
| Embedding dimension mismatch between models | Normalize embeddings to maximum dimension; pad shorter vectors |
| Ollama service restarts during execution | Retry with exponential backoff; return Failed if unavailable |
| Multiple concurrent embedding requests | Batch embeddings into single API call when possible |

## Model Selection Strategy

The provider selects models based on capability bounds and hardware availability. The selection priority is: allowed model list from capability bounds → model availability (loaded in GPU) → model size (fits within VRAM budget) → model capability (supports the requested action type). If no model satisfies all constraints, the provider returns an Unsupported error with details on which constraint was not met.

## Integration Patterns

The Ollama Provider is the default provider for air-gapped deployments where external API access is restricted or prohibited. It integrates with the Academy Knowledge Graph by providing local embedding generation for document indexing without data leaving the private network. For inference, the provider is typically used alongside the Claude or Codex providers in a tiered model strategy — Ollama handles low-complexity, high-volume inference while Claude/Codex handle complex reasoning. The provider also supports fine-tuned model serving for domain-specific tasks through custom Modelfile definitions.

## Embedding Support

The `model.inference.embed` action type generates vector embeddings using Ollama's embedding API. Parameters include: model, input text(s), and options (truncate). This enables local embedding generation for Knowledge Graph and RAG workflows without external API calls.

## Model Management

The provider maintains a local model registry that maps logical model names to Ollama model tags. Models are pulled on demand if not locally available. The provider reports model availability in its health status. Models that exceed the local hardware capacity are marked as unavailable.

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| OLL-0001 | Ollama service not reachable | Return Unhealthy status; deny execution |
| OLL-1001 | Model not found locally | Attempt to pull model; return Unsupported if pull fails |
| OLL-2001 | GPU memory exhausted | Return resource exceeded error; suggest smaller model |
| OLL-3001 | Inference timeout | Terminate generation; return partial output if available |
| OLL-4001 | Embedding dimension mismatch | Validate dimensions against declared capability before returning |

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Ollama.InferenceStarted` | execution_id, model, parameter_count, input_length |
| `Provider.Ollama.InferenceChunk` | execution_id, sequence, token_count, generation_speed_tps |
| `Provider.Ollama.InferenceCompleted` | execution_id, model, total_tokens, duration_ms, tokens_per_second |
| `Provider.Ollama.InferenceFailed` | execution_id, error_code, error_message, partial_output |
| `Provider.Ollama.ModelPulled` | model_name, model_size_bytes, pull_duration_ms |
| `Provider.Ollama.ModelUnavailable` | model_name, reason |

## Cross-Cutting Concerns

### Security

The Ollama endpoint is bound to localhost or a private network interface. Remote access to the Ollama API is blocked by the provider's network configuration. Model files are verified by SHA-256 checksum before loading. The provider validates that requested models are in the entity's allowed model list before execution.

### Evidence

Every inference produces an InferenceStarted and InferenceCompleted/Failed Event. Embedding operations produce dimension and vector count metrics in the completion Event for downstream audit.

### Lifecycle

The provider checks Ollama service health on `initialize()`. It maintains a model availability cache. On `shutdown()`, it releases GPU memory handles and closes the HTTP connection pool. Health checks verify Ollama service responsiveness and available model list.

### Capability Bounds

The provider enforces: max tokens per generation, max input length, max embedding dimensions, GPU memory limits (model size must fit within allocated VRAM budget), generation time limits, and allowed model lists per entity.

### Communication

The provider communicates with Ollama over localhost HTTP. No external network access is required. Provider-to-Runtime communication uses the SDK interface.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles local model inference and embeddings — two facets of the same domain |
| R5 | Interchangeable with cloud model providers for `model.inference` action type |
| R10 | Execution path is a direct HTTP-to-model proxy with bounds checking |
| R12 | All local errors map to OLL-NNNN codes with diagnostic context |
| R13 | If Ollama is unreachable, the provider returns Unhealthy; the Runtime Manager selects a different provider |
| R14 | Paved path: validate → select model → call Ollama → stream → return |
| R15 | New models are added via configuration without provider code changes |

## Performance Characteristics

| Metric | Target | Notes |
|--------|--------|-------|
| Time to first token | < 100ms | Local inference; no network latency |
| Generation speed | ~30-60 tokens/s | Depends on model size and GPU capability |
| Embedding throughput | 500 inputs/s | Full batch parallelism on local GPU |
| Model load time | 2-10s | First-load model loading into GPU memory |
| Concurrent model switching | < 500ms | Unload/reload time between active models |

## Provider-Specific Metrics

Each inference Event includes: `model_selection_reason`, `gpu_memory_used_mb`, `inference_speed_tps` (tokens per second), `model_load_duration_ms` (if model was loaded fresh), `embedding_dimensions` (for embedding actions), and `quantization_level` (e.g., Q4_K_M, Q8_0) for resource accounting.

## Autonomy Level Behavior

| Level | Behavior |
|-------|----------|
| L0 | Model selection and prompt require human approval before inference |
| L1 | Inference proceeds autonomously with local models; results flagged for review |
| L2 | Fully autonomous local inference within token and GPU memory bounds |
| L3 | Provider may switch between local models based on task requirements |
| L4 | Provider may pull new models autonomously if within storage budget |

## LLMOS Integration

This provider implements the `ModelProvider` interface (LLMOS/013-Provider-SDK.md) with the following mapping:

| ModelProvider Method | Execution | Notes |
|---------------------|-----------|-------|
| `initialize(config)` | Resolves endpoint from config | Credential path: `/aios/providers/ollama/` |
| `healthCheck()` | GET /api/tags | < 5s timeout |
| `listModels()` | GET /api/tags | Returns all local model tags |
| `execute(request)` | POST /api/chat | Non-streaming inference |
| `executeStream(request)` | POST /api/chat (stream: true) | SSE streaming |
| `embed(inputs, model)` | POST /api/embed | Native Ollama embedding |
| `countTokens(content, model)` | POST /api/tokenize | Ollama tokenizer |

All LLMOS pipeline stages (routing, guardrails, caching) run before this provider is called.

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Bible/04-Execution/LLMOS/013-Provider-SDK.md | LLMOS ModelProvider interface (canonical path) |
| Bible/04-Execution/LLMOS/000-Overview.md | LLMOS pipeline overview |
| Physics/010-Execution.md | Execution invariants for local model inference |
| Physics/007-Capabilities.md | Capability bounds for GPU memory and model selection |
