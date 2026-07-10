# AIOS Bible — Execution/LLMOS
## 011 — Cache

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/LLMOS |
| Document ID | AIOS-BBL-004-LLM-011 |
| Source Laws | Law 13 — Design for Failure, Law 14 — Paved Path |
| Pipeline Stage | 7 — Cache Lookup, Stage 16 — Cache Store |

## Purpose

The Cache stores AI model responses for reuse, reducing latency, cost, and provider load. Every LLMOS request checks the cache before calling a provider (Stage 7). Validated responses are written to cache (Stage 16). Cache supports both exact-match and semantic-match lookup.

## Cache Key Model

```typescript
interface CacheKey {
  model_id: string;
  prompt_hash: string;              // SHA-256 of the compiled prompt text
  system_hash: string;              // SHA-256 of the system prompt
  tools_hash: string;               // SHA-256 of tool definitions
  schema_hash: string;              // SHA-256 of response schema
  temperature: f64;                 // Rounded to 1 decimal for cache matching
  max_tokens: u64;
  entity_id: UUIDv7;
  cache_version: u64;               // Incremented on cache format changes
}
```

Cache key construction:
```typescript
function buildCacheKey(
  compiledPrompt: CompiledPrompt,
  entity_id: UUIDv7,
  model_id: string
): CacheKey {
  return {
    model_id,
    prompt_hash: sha256(compiledPrompt.provider_request.messages),
    system_hash: sha256(compiledPrompt.provider_request.system || ""),
    tools_hash: sha256(JSON.stringify(compiledPrompt.provider_request.tools || [])),
    schema_hash: sha256(JSON.stringify(compiledPrompt.provider_request.response_format || {})),
    temperature: round(compiledPrompt.provider_request.temperature, 1),
    max_tokens: compiledPrompt.provider_request.max_tokens,
    entity_id,
    cache_version: CURRENT_CACHE_VERSION,
  };
}
```

## Cache Storage Schema

```typescript
interface CacheEntry {
  cache_key: CacheKey;
  
  // Response data
  response: CacheResponse;
  
  // Metadata
  created_at: DateTime;
  ttl: Duration;                     // Time-to-live (default: 1 hour)
  access_count: u64;
  last_accessed_at: DateTime;
  hits: u64;
  misses: u64;
  
  // Source
  original_request_id: UUIDv7;       // Request that produced this entry
  provider: string;
  
  // Cost tracking
  cost_if_regenerated: f64;           // Estimated cost to regenerate
  saved_cost: f64;                    // Cumulative cost saved by cache hits
  saved_latency_ms: u64;              // Cumulative latency saved
  
  // Semantic search
  embedding: f64[] | null;            // Semantic embedding for similarity search
}

interface CacheResponse {
  content: string;
  tool_calls: ToolCall[] | null;
  finish_reason: string;
  usage: TokenUsage;
  model_used: string;
}
```

## Cache Lookup (Stage 7)

```typescript
async function lookupCache(
  request: InferenceRequest,
  compiledPrompt: CompiledPrompt,
  model: ModelEntry
): Promise<CacheLookupResult>

type CacheLookupResult = 
  | { hit: true; entry: CacheEntry; similarity: f64 }
  | { hit: false; semantic_candidates: CacheEntry[] };
```

### Exact Match

- Build `CacheKey` from compiled prompt and request parameters
- Query cache by full key
- On match: return entry, increment hit count, update `last_accessed_at`
- On miss: proceed to semantic match

### Semantic Match

Enabled when `cache_policy.semantic_match` is true:

- Build embedding vector for the compiled prompt
- Query cache by vector similarity (cosine distance) within same `model_id` and `entity_id`
- Threshold: similarity > 0.95 (configurable via `cache_policy.semantic_threshold`)
- Return top 1 match above threshold
- If no semantic match: return miss with empty candidates

### Cache Policy

```typescript
interface CachePolicy {
  mode: "read_write" | "read_only" | "write_only" | "disabled";
  ttl: Duration | null;              // null = use default (1 hour)
  semantic_match: boolean;
  semantic_threshold: f64;           // Default: 0.95
  max_age: Duration | null;          // Reject cached responses older than this
  exempt_if_cost_below: f64 | null;  // Don't cache responses below this cost
  entity_scope: "global" | "entity" | "session";
}
```

| Mode | Read Behavior | Write Behavior |
|------|---------------|----------------|
| `read_write` | Check cache before provider call | Write validated response to cache |
| `read_only` | Check cache before provider call | Never write to cache |
| `write_only` | Skip cache lookup | Write validated response to cache |
| `disabled` | Skip cache entirely | Never write to cache |

## Cache Storage (Stage 16)

```typescript
async function storeCache(
  request: InferenceRequest,
  compiledPrompt: CompiledPrompt,
  response: ValidatedResponse,
  model: ModelEntry
): Promise<void>
```

1. Build `CacheKey` from compiled prompt
2. Check if entry already exists for same key (deduplication)
3. If exists: update access count, skip write
4. If not: create new `CacheEntry` with response data
5. If semantic matching enabled: compute embedding for the prompt
6. Set TTL based on `cache_policy.ttl` or default (1 hour)
7. Store in cache backend

## Cache Backend

The cache is backed by EVS for persistence across restarts:

```typescript
interface CacheBackend {
  get(key: CacheKey): Promise<CacheEntry | null>;
  set(key: CacheKey, entry: CacheEntry): Promise<void>;
  delete(key: CacheKey): Promise<void>;
  semanticSearch(embedding: f64[], model_id: string, entity_id: UUIDv7, limit: u64, threshold: f64): Promise<CacheEntry[]>;
  evict(older_than: Duration): Promise<u64>;
  stats(): Promise<CacheStats>;
}

interface CacheStats {
  total_entries: u64;
  total_hits: u64;
  total_misses: u64;
  hit_rate: f64;
  total_saved_cost: f64;
  total_saved_latency_ms: u64;
  cache_size_bytes: u64;
}
```

## Eviction Policy

| Trigger | Action |
|---------|--------|
| TTL expired | On next read attempt, delete and return miss |
| Max entries exceeded (1M per model) | LRU eviction within same model |
| Manual invalidation | `cache.delete(key)` called by entity or operator |
| Model deregistered | Purge all cache entries for that model |
| Entity removed | Purge all cache entries for that entity |

## Cache Warming

Entities can pre-warm the cache by submitting requests with `cache_policy.mode = "write_only"`:
```typescript
// Entity pre-warms cache with anticipated prompts
// During off-peak hours, submit likely prompts as write_only
// Subsequent read_write requests will hit cache
```

## Invariants

- LLM-CCH-001: Cache is checked before every provider call (Stage 7).
- LLM-CCH-002: Cache is written only after response validation passes (Stage 16).
- LLM-CCH-003: Cache hits still produce Events with full cost and usage records.
- LLM-CCH-004: Cache keys are unique per (model, prompt_hash, system_hash, tools_hash, schema_hash, temperature, max_tokens, entity_id).
- LLM-CCH-005: Semantic cache matches never return results with similarity below the configured threshold.
- LLM-CCH-006: Cache entries are immutable after creation — no partial updates.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.CacheHit` | request_id, cache_key, age, similarity_score, saved_cost, saved_latency_ms | Cache hit (Stage 7) |
| `LLMOS.CacheMiss` | request_id, cache_key, reason, semantic_candidates_count | Cache miss (Stage 7) |
| `LLMOS.CacheStored` | request_id, cache_key, ttl, storage_size_bytes | Cache write (Stage 16) |
| `LLMOS.CacheEvicted` | cache_key, reason, age, access_count, saved_cost_total | Eviction |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/012-Response-Validator.md | Only validated responses are cached |
| LLMOS/000-Overview.md | Cache is Stage 7 (lookup) and Stage 16 (store) |
| Bible/05-Platform/004-EVS.md | EVS provides the persistence layer for the cache |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Cache backend unavailable | — | Treat all lookups as miss; continue without caching |
| Embedding service unavailable | — | Disable semantic matching; fall back to exact match only |
| Cache write fails | — | Log warning; pipeline continues without caching |
| Semantic match below threshold | — | Return miss; no false positives |
