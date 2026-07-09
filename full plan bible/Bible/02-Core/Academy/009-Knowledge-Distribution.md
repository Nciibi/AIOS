# AIOS Bible — Core
## Academy — 009: Knowledge Distribution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-009 |
| Source Laws | Law 4 — Evidence |
| Source Physics | Physics/007-Capabilities.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Knowledge Distribution propagates accepted knowledge from the Academy to consumers. It ensures the right knowledge reaches the right entities at the right time, respecting organizational boundaries (CPR-010), autonomy levels, and entity capability bounds.

## Distribution Mechanisms

The Academy supports three distribution mechanisms:

| Mechanism | Latency | Best For |
|-----------|---------|----------|
| **Push (subscription)** | Real-time (sub-second) | Entities that need immediate notification of new/updated knowledge |
| **Pull (query)** | On-demand | Entities that query knowledge when needed |
| **Cache (local TTL)** | Cached (configurable TTL) | Entities that frequently access the same knowledge |

### Push Distribution

Entities subscribe to knowledge topics and receive artifacts automatically when published.

| Topic Pattern | Description | Subscriber Example |
|---------------|-------------|-------------------|
| `knowledge.published.{org_id}` | All knowledge published by an Organization | Organization entities |
| `knowledge.published.{org_id}.{type}` | Knowledge of a specific type | Type-specific consumers |
| `knowledge.published.global.{type}` | Global knowledge of a type (constitutional only) | All entities |
| `knowledge.published.{entity_id}` | Knowledge relevant to a specific entity | Individual entity |

**Push Delivery**:

| Step | Description |
|------|-------------|
| 1 | Knowledge is accepted by Registry |
| 2 | Distribution service evaluates subscribers matching the artifact |
| 3 | Artifact is delivered to each subscriber over ACF topic |
| 4 | Subscriber acknowledges receipt |
| 5 | Undeliverable messages are queued (max 3 retries) |

### Pull Distribution

Entities query the Distribution service for knowledge artifacts.

| Operation | Description |
|-----------|-------------|
| `getKnowledge(id)` | Retrieve specific artifact by ID |
| `listKnowledge(filters)` | List artifacts matching filters |
| `getLatestByType(type)` | Get latest accepted artifact of a type |
| `getKnowledgeBySource(event_id)` | Get artifacts derived from a specific Event |

Pull responses include the artifact content plus distribution metadata:

| Field | Description |
|-------|-------------|
| `artifact` | Full knowledge artifact |
| `distributed_at` | When this artifact was distributed to this consumer |
| `cache_ttl` | Suggested cache duration (seconds) |
| `distribution_id` | Unique ID for this distribution event |

### Cache Distribution

Entities may cache knowledge locally for performance. The Distribution service provides cache control:

| Cache Directive | Description |
|----------------|-------------|
| `cache_ttl` | How long the artifact may be cached (seconds) |
| `cache_scope` | Per-entity or per-organization |
| `stale_while_revalidate` | Serve stale content while fetching fresh (seconds) |
| `cache_invalidation_key` | Key that, when changed, invalidates the cache |

## Distribution Scope

Knowledge distribution is scoped by three dimensions:

### 1. Per-Organization (CPR-010)

| Scope | Description | Example |
|-------|-------------|---------|
| `Organization` | Knowledge is only distributed within the owning Organization | Operational runbooks |
| `Federated` | Knowledge is shared with federated Organizations | Cross-org domain knowledge |
| `Global` | Knowledge is distributed to all entities | Constitutional knowledge |

### 2. Per-Autonomy-Level

| Autonomy Level | Knowledge Access |
|----------------|------------------|
| L0 (Directed) | Only operational knowledge directly assigned |
| L1 (Supervised) | Operational knowledge in assigned domain |
| L2 (Delegated) | Operational + domain knowledge in scope |
| L3 (Trusted) | All knowledge except constitutional interpretations |
| L4 (Sovereign) | All knowledge including constitutional |

### 3. Per-Entity-Type

| Entity Type | Knowledge Access |
|-------------|------------------|
| Worker | Operational knowledge for assigned tasks |
| Supervisor | Operational + domain knowledge for supervised domain |
| Organization | All organizational knowledge |
| Sou | All knowledge (strategic, constitutional) |
| Security Council | All knowledge (full access) |
| Academy | All knowledge (full access) |

## Cache Invalidation

| Trigger | Action |
|---------|--------|
| Artifact updated (new version) | Cache invalidated for that artifact ID |
| Artifact deprecated | Cache marked stale; re-fetch shows deprecation warning |
| Artifact archived | Cache entry removed |
| Organization scope changed | Cache invalidated for all artifacts in that org |
| TTL expired | Cache entry evicted naturally |

## Distribution Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Distribution.KnowledgeDistributed` | Knowledge is distributed to a consumer | distribution_id, artifact_id, consumer_id, mechanism |
| `Distribution.KnowledgeCached` | Consumer caches a distributed artifact | artifact_id, consumer_id, ttl, cache_key |
| `Distribution.KnowledgeCacheInvalidated` | Cache entry is invalidated | artifact_id, consumer_id, invalidation_reason |
| `Distribution.SubscriptionCreated` | Entity subscribes to a topic | subscriber_id, topic_pattern, created_at |
| `Distribution.SubscriptionRemoved` | Entity unsubscribes | subscriber_id, topic_pattern |
| `Distribution.DeliveryFailed` | Push delivery fails after retries | distribution_id, consumer_id, attempts, error |

## ACF Integration

The Distribution service is built on ACF:

| ACF Topic | Direction | Purpose |
|-----------|-----------|---------|
| `academy.knowledge.accepted` | Input | Receives accepted artifacts from Registry |
| `academy.knowledge.deprecated` | Input | Receives deprecation events |
| `academy.knowledge.distribute` | Internal | Triggers distribution evaluation |
| `knowledge.published.*` | Output | Publishes to subscribers |
| `academy.cache.invalidate` | Output | Cache invalidation notifications |

## Distribution Architecture

```
Accepted Artifact (from Registry)
    │
    ▼
┌──────────────────────────────────────────────┐
│  Distribution Service                          │
│                                                │
│  1. Evaluate scope (org, autonomy, type)       │
│  2. Match against active subscriptions         │
│  3. Deliver via push mechanism                 │
│  4. Update search index (for pull queries)     │
│  5. Publish cache invalidation (if applicable) │
└──────────────────────────────────────────────┘
    │
    ├──▶ Push to subscribers (ACF topics)
    ├──▶ Available for pull (Search API)
    └──▶ Cache invalidation (ACF topic)
```

## Cross-Cutting Concerns

### Security

Distribution respects organizational boundaries (CPR-010). Cross-organization distribution requires explicit federation policy. All distribution operations are authenticated and authorized through ACF. Push subscriptions are verified against entity capability bounds.

### Evidence

Every distribution event is recorded. The complete distribution history of every artifact is auditable. This includes which entities received which knowledge, when, and by what mechanism.

### Lifecycle

Distribution applies only to artifacts in `Published` state. Artifacts in `Generated`, `Proposed`, `Validated`, or `Review` state are never distributed. Deprecated artifacts are unpushed but remain accessible via pull with warnings.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| Create subscription | `knowledge.subscribe` |
| Pull knowledge | `knowledge.query` |
| Receive push | `knowledge.subscribe` |
| Cache knowledge | `knowledge.cache` (implicit with query) |
| Invalidate cache | `knowledge.cache.invalidate` |

Capabilities are scoped by organization and knowledge type (Physics/007-Capabilities.md).

### Communication

All distribution uses ACF. Push uses ACF pub-sub topics. Pull uses ACF request-response. Cache invalidation uses ACF broadcast. No direct entity-to-entity knowledge sharing bypasses the Distribution service.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Distribution does delivery — does not store or validate |
| R3 | Distribution is the single path for knowledge to reach consumers |
| R6 | Distribution receives dependencies (Registry, ACF) through injection |
| R10 | Distribution has three mechanisms (push/pull/cache) — no more |
| R13 | Distribution fails closed (undeliverable = queued, not dropped) |
| R14 | Paved path: accept → evaluate scope → deliver |
| R15 | New distribution mechanisms can be added without modifying existing |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/007-Capabilities.md | Capability bounds scope distribution access |
| Physics/008-Security.md | Security context for cross-org distribution |
| Governance/006-AKM.md | AKM Published state triggers distribution |
| Foundations/001-AIOS-Philosophy.md | CPR-010 — evidence privacy |
| Foundations/002-Design-DNA.md | R1, R3, R6, R10, R13, R14, R15 |
| 004-Knowledge-Registry.md | Registry triggers distribution on acceptance |
| 010-Knowledge-Search.md | Search provides pull distribution interface |
| 016-Knowledge-API.md | Distribution operations exposed through API |
