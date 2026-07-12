# AIOS Bible â€” Brain
## 002 â€” Discovery Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-002 |
| Source Laws | Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Discovery Engine enables Sou to find the right tool for any task. It provides multiple discovery modes â€” listing all tools, filtering by capability or category, semantic search over tool descriptions, and goal-based recommendation. The Discovery Engine wraps the Tool Registry with intelligence: it ranks results, caches frequent queries, and maps Sou's natural language goals to tool capability requirements.

Under TLS-000, Discovery ensures Sou only discovers tools within its capability bounds. Unavailable or deprecated tools are filtered out unless explicitly requested.

## Data Model

### DiscoveryQuery

```typescript
DiscoveryQuery {
  mode: "list_all" | "filter_capability" | "filter_category" | "semantic_search" | "recommend"
  capability?: string[]
  category?: "read" | "write" | "compute" | "communicate" | "system"
  query_text?: string
  goal?: string
  include_experimental?: boolean
  include_deprecated?: boolean
  max_results?: number
  sort_by?: "relevance" | "name" | "category" | "popularity"
}
```

### DiscoveryResult

```typescript
DiscoveryResult {
  query: DiscoveryQuery
  results: ScoredTool[]
  total_count: number
  execution_time_ms: number
  from_cache: boolean
  metadata: {
    query_id: string
    timestamp: timestamp
    filter_summary: string
  }
}
```

### ScoredTool

```typescript
ScoredTool {
  registration: ToolRegistration
  score: number                        // 0.0â€“1.0, relevance score
  match_reasons: string[]              // Why this tool matched
  capability_coverage: number          // Fraction of required capabilities satisfied
}
```

### DiscoveryCache

```typescript
DiscoveryCache {
  entries: Map<string, CachedEntry>
  max_entries: number
  ttl_ms: number
  hit_count: number
  miss_count: number
}
```

### CapabilityInference

```typescript
CapabilityInference {
  capabilities: string[]
  confidence: number
  reasoning: string
}
```

## Core Concepts

### Discovery Modes

| Mode | Query Fields | Behavior | Use Case |
|------|-------------|----------|----------|
| List all | none | Return all active, healthy tools | Sou exploring available capabilities |
| Filter by capability | `capability` | Return tools matching all required capabilities | Sou needs a specific capability |
| Filter by category | `category` | Return tools in a named category | Sou wants read/write/compute tools |
| Semantic search | `query_text` | Embedding similarity over tool descriptions | "Find me a tool that can search the web" |
| Recommend | `goal` | Goal â†’ capability inference â†’ tool scoring | Sou has a goal but no tool in mind |

### Scoring Algorithm

```
For each tool matching the query:
  base_score = 1.0

  If semantic search:
    base_score = embedding_similarity(query_text, tool.description + tool.name)
    capped at [0.0, 1.0]

  If capability filter:
    coverage = matching_capabilities / requested_capabilities
    base_score *= coverage

  If category filter:
    base_score = (tool.category === requested_category) ? 1.0 : 0.0

  If recommend:
    base_score = goal_similarity * capability_coverage

  Apply penalties:
    if tool.status === "deprecated": score *= 0.5
    if tool.health_status === "degraded": score *= 0.7
    if tool.status === "experimental": score *= 0.3

  Final score = base_score
```

### Discovery Caching

Frequent or identical queries are cached to reduce Registry load:

| Cache Policy | Behavior |
|-------------|----------|
| TTL | 30 seconds for list queries, 60 seconds for search queries |
| Invalidation | On ToolRegistered, ToolDeregistered, ToolHealthChanged events |
| Max entries | 1000 cached query results |
| Eviction | LRU when cache is full |

### Recommendation Engine

The recommendation mode uses goal-to-capability mapping:

```
1. Sou provides a goal: "I need to analyze this dataset"
2. Recommendation Engine parses the goal for intent keywords
3. Extracts capability requirements: ["tool.compute.analyze", "tool.read.file"]
4. Scores tools by capability coverage Ã— description relevance
5. Returns top-N ScoredTools with match reasons
```

## Operations

### Discover

```typescript
discover(mode: "list_all", options?: {
  include_experimental?: boolean
  include_deprecated?: boolean
  sort_by?: string
}): DiscoveryResult
```

- Lists all active, healthy tools from the Registry
- Sorted by name by default

### Search

```typescript
search(query_text: string, options?: {
  max_results?: number
  include_deprecated?: boolean
}): DiscoveryResult
```

- Performs semantic search over tool names and descriptions
- Returns scored results ranked by relevance

### Recommend

```typescript
recommend(goal: string, options?: {
  max_results?: number
  min_score?: number
}): DiscoveryResult
```

- Infers capability requirements from the goal text
- Matches and scores tools by capability coverage
- Returns top recommendations with match reasons

### GetCapabilities

```typescript
getCapabilities(goal?: string): CapabilityInference[]
```

- Returns all known capabilities if no goal provided
- Infers capabilities from a goal if provided
- Used by Sou to understand what it can do

### ClearCache

```typescript
clearCache(): void
```

- Invalidates all cached discovery results
- Called on Registry state changes

## Internal Interface

```typescript
interface DiscoveryEngine {
  discover(mode: "list_all", options?: {
    include_experimental?: boolean
    include_deprecated?: boolean
    sort_by?: string
  }): DiscoveryResult

  search(query_text: string, options?: {
    max_results?: number
    include_deprecated?: boolean
  }): DiscoveryResult

  recommend(goal: string, options?: {
    max_results?: number
    min_score?: number
  }): DiscoveryResult

  getCapabilities(goal?: string): CapabilityInference[]

  clearCache(): void

  getCacheStats(): {
    hit_count: number
    miss_count: number
    entry_count: number
    max_entries: number
  }
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `TLS.DiscoveryQuery` | mode, filter_summary, result_count, duration_ms | Discovery query executed |
| `TLS.DiscoveryCacheHit` | query_hash, result_count | Cache returned cached results |
| `TLS.DiscoveryCacheMiss` | query_hash, reason | No cached results found |
| `TLS.DiscoveryCacheEvicted` | query_hash, age_ms | Cache entry evicted |
| `TLS.ToolRecommended` | goal, recommended_tool_id, score, reason | Tool recommended for goal |
| `TLS.CapabilityInferred` | goal, capabilities, confidence | Capabilities inferred from goal text |
| `TLS.SemanticSearchExecuted` | query_text, result_count, top_score | Semantic search completed |
| `TLS.DiscoveryCacheCleared` | entry_count | Discovery cache invalidated |
| `TLS.DiscoveryNoResults` | mode, query_summary | Query returned zero results |
| `TLS.DiscoveryFallback` | primary_mode, fallback_mode, reason | Discovery fell back to alternative mode |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DSC-001 | Discovery never returns unavailable tools | Algorithmic â€” health filtered by default |
| DSC-002 | Discovery never returns tools outside Sou's capability bounds | Application-level â€” capability intersection filter |
| DSC-003 | Same query with same registry state returns same results | Algorithmic â€” deterministic scoring |
| DSC-004 | Cache is invalidated on any Registry mutation | Event-driven â€” subscribes to Registry events |
| DSC-005 | ScoredTool scores are always normalized to 0.0â€“1.0 | Algorithmic â€” score clamping |
| DSC-006 | Recommendation results include at least one match_reason | Schema â€” match_reasons array is never empty |
| DSC-007 | Experimental tools are excluded unless explicitly requested | API-level â€” default filter applied |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No tools match query | `DSC_NO_RESULTS` | Return empty results; suggest broadening |
| Invalid mode | `DSC_INVALID_MODE` | Return error; show valid modes |
| Empty search query | `DSC_EMPTY_QUERY` | Return error; provide query text |
| Unable to infer capabilities from goal | `DSC_CAPABILITY_INFERENCE_FAILED` | Return error; suggest manual capability selection |
| Discovery Engine not initialized | `DSC_NOT_INITIALIZED` | Return error; initialize with Registry |
| Cache at capacity | `DSC_CACHE_FULL` | Evict LRU entry; continue normally |
| Embedding service unavailable (semantic search) | `DSC_EMBEDDING_UNAVAILABLE` | Fall back to text-match search |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Discovery Engine handles only tool finding and ranking |
| R2 â€” Dependency Order | Depends on Tool Registry; no upward deps |
| R3 â€” DRY | Scoring logic defined once, applied to all modes |
| R4 â€” Builder Pattern | DiscoveryResult built by Query â†’ Match â†’ Score â†’ Cache |
| R5 â€” Liskov Substitution | Any DiscoveryEngine implements the interface |
| R6 â€” DI over Singletons | Scorer, embedder, and cache strategies injected |
| R9 â€” Deterministic | Same query and registry state produce same results |
| R10 â€” Simpler Over Complex | Flat set of discovery modes with clear input/output |
| R13 â€” Design for Failure | Cache and fallback modes ensure graceful degradation |
| R14 â€” Paved Path | All discovery flows through discover(), search(), or recommend() |
| R15 â€” Open/Closed | New discovery modes added via mode plugins |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Discovery Engine is the tool-finding layer |
| Brain/Tools/001-Registry.md | Discovery Engine queries the Registry for tool data |
| Brain/Tools/003-Invocation.md | Discovered tools passed to Invocation Manager |
| Brain/Tools/006-Lifecycle.md | Lifecycle state affects discovery visibility |
| Brain/Sou/000-Overview.md | Sou uses Discovery Engine to find tools |
| Brain/Decision/000-Overview.md | Decision System uses Discovery recommendations |
| Brain/Planning/000-Overview.md | Plans may require discovery of specific tool categories |
