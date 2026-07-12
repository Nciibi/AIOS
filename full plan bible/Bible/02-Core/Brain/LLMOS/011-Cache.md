# AIOS Bible — Brain/LLMOS
## 011 — Cache

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-011 |
| Source Laws | Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 7 — Cache Lookup, Stage 16 — Cache Store |

## Purpose

The Cache stores AI model responses for reuse, reducing latency, cost, and provider load. Every LLMOS request checks the cache before calling a provider (Stage 7). Validated responses are written to cache (Stage 16). Cache supports both exact-match and semantic-match lookup.

## Cache Key Model

The cache runs at Stage 7, before prompt compilation (Stage 10) and context building (Stage 8). The cache key is derived from the raw request input — not the compiled prompt — to enable early cache lookup without costly pre-processing.

```typescript
interface CacheKey {
  model_id: string;
  input_hash: string;               // SHA-256 of serialized messages + system prompt from raw request
  tools_hash: string;               // SHA-256 of tool definitions from raw request
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
  request: InferenceRequest,
  model_id: string
): CacheKey {
  const rawInput = {
    messages: request.messages,
    system_prompt: request.system_prompt,
    tools: request.tools,
  };
  return {
    model_id,
    input_hash: sha256(JSON.stringify(rawInput)),
    tools_hash: sha256(JSON.stringify(request.tools || [])),
    schema_hash: sha256(JSON.stringify(request.response_schema || {})),
    temperature: round(request.temperature ?? 0.7, 1),
    max_tokens: request.max_tokens ?? 4096,
    entity_id: request.entity_id,
    cache_version: CURRENT_CACHE_VERSION,
  };
}
```

The cache hit returns a complete `CacheEntry` with the stored response, bypassing Stages 8-16 entirely. Cache miss proceeds to Stage 8 (Context Builder) for full pipeline processing.

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
  model: ModelEntry
): Promise<CacheLookupResult>

type CacheLookupResult = 
  | { hit: true; entry: CacheEntry; similarity: f64 }
  | { hit: false; semantic_candidates: CacheEntry[] };
```

### Exact Match

- Build `CacheKey` from raw request input (messages + system prompt + tools + schema)
- Query cache by full key
- On match: return entry, increment hit count, update `last_accessed_at`
- On miss: proceed to semantic match

### Semantic Match

Enabled when `cache_policy.semantic_match` is true:

- Build embedding vector for the raw request input (messages concatenated as text)
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
  response: ValidatedResponse,
  model: ModelEntry
): Promise<void>
```

1. Build `CacheKey` from original request
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

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-CCH-001 | Cache is checked before every provider call (Stage 7). | Architectural — pre-call stage enforcement |
| LLM-CCH-002 | Cache is written only after response validation passes (Stage 16). | Architectural — post-validation stage enforcement |
| LLM-CCH-003 | Cache hits still produce Events with full cost and usage records. | Architectural — event logging invariant |
| LLM-CCH-004 | Cache keys are unique per (model_id, input_hash, tools_hash, schema_hash, temperature, max_tokens, entity_id). | Algorithmic — composite key uniqueness |
| LLM-CCH-005 | Semantic cache matches never return results with similarity below the configured threshold. | Algorithmic — threshold-based filtering |
| LLM-CCH-006 | Cache entries are immutable after creation — no partial updates. | Schema — immutability design |

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.CacheHit` | request_id, cache_key, age, similarity_score, saved_cost, saved_latency_ms | Cache hit (Stage 7) |
| `LLMOS.CacheMiss` | request_id, cache_key, reason, semantic_candidates_count | Cache miss (Stage 7) |
| `LLMOS.CacheStored` | request_id, cache_key, ttl, storage_size_bytes | Cache write (Stage 16) |
| `LLMOS.CacheEvicted` | cache_key, reason, age, access_count, saved_cost_total | Eviction |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Cache is the single caching authority in the pipeline |
| R2 — Dependency Order | Cache lookup precedes pipeline processing (Stage 7) |
| R3 — DRY | Single cache key model across all entries |
| R4 — Builder Pattern | CacheEntry built via structured construction |
| R5 — Liskov Substitution | All responses cached uniformly regardless of provider |
| R6 — DI over Singletons | CacheManager injected into pipeline |
| R9 — Deterministic | Same request produces same cache key and lookup result |
| R10 — Simpler Over Complex | SHA-256 hashing over complex content addressing |
| R13 — Design for Failure | Cache miss falls through to normal pipeline |
| R14 — Paved Path | Standard TTL and eviction for all entities |
| R15 — Open/Closed | New backends added without pipeline changes |

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
