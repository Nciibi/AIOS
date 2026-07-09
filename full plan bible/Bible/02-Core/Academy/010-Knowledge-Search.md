# AIOS Bible — Core
## Academy — 010: Knowledge Search

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-010 |
| Source Laws | Law 4 — Evidence |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Knowledge Search provides a query interface over all accepted Academy knowledge. It enables entities to find relevant knowledge artifacts through full-text, semantic, graph, and faceted search. Search is the primary pull mechanism for knowledge consumers (complementing the push mechanism of Distribution, 009).

## Search Index

The Search index is maintained by the Academy and updated on every knowledge lifecycle event:

| Index Update Trigger | Action |
|----------------------|--------|
| Knowledge accepted | Add artifact to index |
| Knowledge updated (new version) | Update index entry |
| Knowledge deprecated | Mark as deprecated in index (include_deprecated=false for default) |
| Knowledge archived | Remove from active index (move to archive index) |

### Index Structure

| Index | Type | Description |
|-------|------|-------------|
| Full-text | Inverted index (content fields) | Title, description, content body |
| Semantic | Vector embedding (dense) | Content embedded via embedding model |
| Graph | Adjacency index | Relationships from Knowledge Graph (003) |
| Faceted | Categorical | Type, status, organization, tags, timestamp |

## Query Types

### 1. Full-Text Search

Search artifact content using text queries.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `q` | Yes | Query string |
| `fields` | No | Fields to search (default: title, description, content) |
| `fuzziness` | No | Edit distance for fuzzy matching (default: AUTO) |
| `operator` | No | `or` (default) or `and` for multiple terms |

**Example**: `GET /search?q=authentication+JWT&fields=title,description&operator=and`

### 2. Semantic Search

Search by meaning using vector embeddings.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `q` | Yes | Natural language query |
| `model` | No | Embedding model to use (default: academy-default) |
| `top_k` | No | Number of results (default: 10, max: 100) |
| `min_score` | No | Minimum cosine similarity threshold (default: 0.5) |

**Example**: `GET /search?q=how+do+I+authenticate+a+user+with+JWT&type=semantic&top_k=5`

### 3. Graph Traversal Search

Search using graph relationships from Knowledge Graph (003).

| Parameter | Required | Description |
|-----------|----------|-------------|
| `start_node_id` | Yes | Starting node ID |
| `edge_types` | Yes | Edge types to traverse |
| `max_depth` | No | Maximum traversal depth (default: 3) |
| `filter` | No | Node property filter |

**Example**: `GET /search?type=graph&start_node_id=A-001&edge_types=derived_from,supports&max_depth=2`

### 4. Faceted Filter Search

Search with structured filters.

| Filter | Type | Description |
|--------|------|-------------|
| `type` | Enum | Knowledge type |
| `status` | Enum | Artifact status (default: active) |
| `organization_id` | UUID | Owning organization |
| `tags` | String[] | Tags (AND logic) |
| `created_after` | DateTime | Minimum acceptance timestamp |
| `created_before` | DateTime | Maximum acceptance timestamp |
| `confidence_min` | Float | Minimum confidence score |

**Example**: `GET /search?type=operational&organization_id=ORG-001&tags=deployment,security&confidence_min=0.7`

## Ranking

Search results are ranked by a composite score:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Relevance** | 0.40 | Text/semantic match quality (BM25 or cosine similarity) |
| **Freshness** | 0.15 | Recency of acceptance (newer = higher) |
| **Confidence** | 0.20 | Verification confidence score (from 006) |
| **Authority** | 0.15 | Authority score of source entity/organization |
| **Popularity** | 0.10 | Query frequency / consumption count (from 012) |

The composite score is computed as:

```
score = 0.40 * relevance + 0.15 * freshness + 0.20 * confidence + 0.15 * authority + 0.10 * popularity
```

## Search Authorization

Search results are filtered based on the requesting entity's authorization:

| Entity Property | Filter Applied |
|-----------------|----------------|
| Organization | Results scoped to own org (plus global knowledge) |
| Autonomy level | Higher autonomy = broader scope (see 009 scope table) |
| Entity type | Entity-type-specific restrictions |
| Capabilities | `knowledge.query` capability required |

Authorization is applied *after* ranking but *before* returning results. Unauthorized results are silently excluded (not flagged).

### Result Format

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Artifact ID |
| `type` | Enum | Knowledge type |
| `title` | String | Artifact title |
| `description` | String | Artifact description |
| `score` | Float | Composite ranking score |
| `confidence` | Float | Verification confidence |
| `version` | String | Latest version |
| `organization_id` | UUID | Owning organization |
| `accepted_at` | DateTime | When accepted |
| `tags` | String[] | Artifact tags |
| `highlights` | String[] | Snippet highlights (full-text only) |

### Pagination

| Parameter | Default | Max |
|-----------|---------|-----|
| `page` | 1 | 10000 |
| `page_size` | 20 | 100 |
| `max_total` | 1000 | — (truncated count) |

## Search Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Search.QueryExecuted` | Search query is executed | query_type, result_count, latency_ms |
| `Search.ResultClicked` | Consumer selects a search result | artifact_id, consumer_id, rank_position |
| `Search.IndexUpdated` | Search index is updated | artifact_id, update_type, index_version |
| `Search.IndexRebuilt` | Full index rebuild completes | total_artifacts, build_duration_ms |
| `Search.RankingRecalculated` | Ranking weights are updated | new_weights, effective_date |

## Performance Targets

| Metric | Target |
|--------|--------|
| P50 query latency | < 50 ms |
| P99 query latency | < 200 ms |
| Index update lag | < 1 second (from acceptance to searchable) |
| Index rebuild time | < 10 minutes (full rebuild of 100K artifacts) |
| Concurrent queries | 1000+ |

## Cross-Cutting Concerns

### Security

Search results are filtered by entity authorization. An entity cannot discover knowledge it is not authorized to access. Search queries are authenticated and logged. Query patterns are monitored for exfiltration attempts (Physics/008-Security.md).

### Evidence

Every search query produces an Event. Search analytics (012) are derived from these Events. Query patterns may be used for gap analysis and knowledge improvement.

### Lifecycle

Search index follows artifact lifecycle. Only `Published` artifacts are indexed. `Deprecated` artifacts are indexed but excluded from default results. `Archived` artifacts are moved to a separate archive index.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| Full-text search | `knowledge.query` |
| Semantic search | `knowledge.query.semantic` (higher resource cost) |
| Graph search | `knowledge.query.graph` |
| Faceted search | `knowledge.query` |

### Communication

All search requests go through ACF. The Search service maintains its own index but reads from KMS (002) for index updates. Search does not call KMS on each query — it queries its local index.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Search does querying — does not store artifacts |
| R2 | Search depends on KMS (index source), not vice versa |
| R6 | Search receives index, ACF, and auth dependencies through injection |
| R8 | All queries complete within 200ms (P99) |
| R9 | Same query on same index state → same results |
| R10 | Search uses four query types — no more unless justified |
| R13 | Search fails closed on index failure |
| R14 | Paved path: query → authorize → rank → return |
| R15 | New query types added without modifying existing types |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Search events recorded for audit |
| Physics/007-Capabilities.md | Capability-bounded search access |
| Governance/006-AKM.md | AKM Published state determines index inclusion |
| Foundations/002-Design-DNA.md | R1, R2, R6, R8, R9, R10, R13, R14, R15 |
| Foundations/003-Core-Principles.md | CPR-010 — search respects org boundaries |
| 002-KMS.md | KMS provides artifact data for indexing |
| 003-Knowledge-Graph.md | Graph traversal search uses Knowledge Graph |
| 006-Knowledge-Verifier.md | Confidence score from Verifier used in ranking |
| 009-Knowledge-Distribution.md | Pull distribution uses Search as its query interface |
| 012-Knowledge-Analytics.md | Analytics consumes search query data |
| 016-Knowledge-API.md | Search API endpoint |
