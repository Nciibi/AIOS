# AIOS Bible — Core
## Sou 005 — Knowledge

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-SOU-005 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou's Knowledge store is the constitutional memory of the AIOS will engine. It is Sou's private knowledge base — distinct from the Academy (public knowledge). Knowledge stores constitutional interpretations, strategic context, entity performance history, and decision precedents.

Knowledge is private to Sou unless explicitly shared with the Academy under CPR-010 (Evidence Privacy). Sou's Knowledge is not directly accessible to other entities — it is queried through Sou's API.

## Knowledge Storage Example

```
Type: Strategic Knowledge
Payload: { context: "Q3-2026 resource optimization", 
           decision: "phased rollout strategy",
           outcome: "92% goal achievement",
           confidence: 0.92 }
Source Events: [EVT-mission-resource-opt-q3-completion, 
                EVT-dgp-decision-approval-phased-rollout]
Privacy Level: AcademyShareable
Tags: ["resource-optimization", "phased-rollout", "q3-2026"]
Expires: 2027-12-31

→ Stored as: KNW-0042
→ Later queried: "show me successful resource optimization strategies"
→ Returned: KNW-0042 (confidence 0.92, tags: resource-optimization)
```

## Knowledge Is Private

Sou's Knowledge is distinct from the Academy's public knowledge:

| Aspect | Sou Knowledge | Academy Knowledge |
|--------|--------------|-------------------|
| Scope | Strategic context, Sou's internal reasoning | System-wide patterns, curricula |
| Visibility | Private to Sou | Public to authorized entities |
| Sharing | Only through explicit Academy publication | Freely queryable |
| Content | Constitutional interpretations, entity performance, decision precedents | Learned patterns, best practices, statistical models |
| Lifecycle | Managed by Sou | Managed by Academy KMS |

## Knowledge Types

| Type | Description | Example |
|------|-------------|---------|
| Constitutional Knowledge | Interpretations of constitutional text, precedents | "Law 2 interpretation ruling RFC-042" |
| Strategic Knowledge | Context about current and historical strategy | "Q3 priority shift toward resource optimization" |
| Entity Knowledge | Performance and compliance history per entity | "Worker-X completed 95% of missions on time" |
| Outcome Knowledge | Results of past decisions and missions | "Plan Y failed due to underestimated resource needs" |

## Edge Cases — Knowledge

| Scenario | Handling |
|----------|----------|
| Knowledge store capacity exceeded | Oldest knowledge records are pruned per retention policy. Critical records (constitutional interpretations) are never pruned. |
| Privacy filter blocks Academy sharing attempt | Share is blocked. Privacy block Event is recorded. Knowledge remains private. |
| Query returns too many results | Query is rejected with SOU_KNW_006. Requester must refine query. Maximum results: 1000. |
| Knowledge record's source Events are purged from Event Store | Knowledge record becomes orphaned. It is flagged for review but not automatically deleted. |
| Two knowledge records contradict each other | More recent record takes precedence. Both are retained for audit. Contradiction is flagged. |
| Knowledge is queried by an unauthorized entity | Query is rejected. Security Event is produced. Attempt is logged. |
| Knowledge store is offline | Sou operates in degraded mode. Knowledge queries return empty results. Reasoning uses only evidence-based methods. |

## Knowledge Operations

### storeKnowledge

```
Input:  knowledge_payload, knowledge_type, privacy_level
Process: validate → classify → index → store
Output: KnowledgeRecord { knowledge_id, stored_at }
Event: Sou.KnowledgeStored
```

### retrieveKnowledge

```
Input:  knowledge_id
Process: authorize → fetch → return
Output: KnowledgeRecord or null
Event: Sou.KnowledgeRetrieved
```

### queryKnowledge

```
Input:  query (type, filters, time_range, relevance_criteria)
Process: tokenize → search index → rank results → return
Output: KnowledgeQueryResult { results: KnowledgeRecord[], total_count }
Event: Sou.KnowledgeQueried
```

### shareWithAcademy

```
Input:  knowledge_id, privacy_filter_level
Process: apply privacy filter (CPR-010) → package → submit to Academy
Output: AcademySubmission { submission_id, knowledge_id }
Event: Sou.KnowledgeSharedWithAcademy
```

### pruneKnowledge

```
Input:  retention_policy
Process: identify expired knowledge → archive → notify
Output: PruneReport { archived_count, freed_capacity }
Event: Sou.KnowledgePruned
```

## Knowledge Schema

| Field | Type | Description |
|-------|------|-------------|
| knowledge_id | UUID | Unique identifier |
| type | KnowledgeType | Constitutional, Strategic, Entity, Outcome |
| payload | JSON | The knowledge content |
| privacy_level | PrivacyLevel | Private (default), AcademyShareable, Public |
| source_events | EventRef[] | Evidence Events that contributed |
| created_at | Timestamp | When stored |
| expires_at | Timestamp | Optional retention date |
| version | int | Monotonic version for updates |
| tags | string[] | Searchable metadata tags |
| related_knowledge | UUID[] | Links to related knowledge records |

## Knowledge Lifecycle

```
Created → Active → Updated → Archived (retention expired)
                                           → Shared (with Academy)
```

| State | Description | Can Query? |
|-------|-------------|------------|
| Created | Knowledge record exists, not yet indexed | No |
| Active | Indexed and queryable | Yes |
| Updated | Replaced by newer version (old version archived) | Yes (both versions) |
| Archived | Retained for audit, removed from active queries | No (audit only) |
| Shared | Published to Academy, removed from private store | No (via Academy) |

## Knowledge Performance Requirements

| Metric | Target | Hard Limit |
|--------|--------|------------|
| storeKnowledge() latency | < 100ms | 500ms |
| retrieveKnowledge() latency | < 50ms | 200ms |
| queryKnowledge() latency (simple) | < 200ms | 1 second |
| queryKnowledge() latency (semantic) | < 1 second | 5 seconds |
| Maximum knowledge records | 100000 | 500000 |
| Maximum query results | 100 | 1000 |
| Knowledge record max size | 1 MB | 10 MB |
| Privacy filter application | < 50ms | 200ms |

## Knowledge Query Types

| Query Type | Description | Example |
|------------|-------------|---------|
| exact_match | Retrieve knowledge by ID | `getKnowledge(KNW-0042)` |
| semantic_search | Search by meaning and context | `semanticSearch("resource optimization strategies")` |
| tag_query | Filter by tags | `tagQuery(["resource-optimization", "q3-2026"])` |
| time_range | Filter by creation time | `timeRange("2026-01-01", "2026-12-31")` |
| type_filter | Filter by knowledge type | `typeFilter("Strategic Knowledge")` |
| combined | Multiple criteria | `combined(type=Strategic, tags=[q3], min_confidence=0.8)` |

## Knowledge Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.KnowledgeStored` | New knowledge is stored | knowledge_id, type, privacy_level |
| `Sou.KnowledgeRetrieved` | Knowledge is retrieved | knowledge_id, requester_id |
| `Sou.KnowledgeQueried` | Knowledge store is queried | query_id, query_type, result_count |
| `Sou.KnowledgeUpdated` | Existing knowledge is updated | knowledge_id, new_version, change_summary |
| `Sou.KnowledgeSharedWithAcademy` | Knowledge is shared with Academy | knowledge_id, submission_id |
| `Sou.KnowledgePruned` | Knowledge is pruned by retention policy | archived_count, policy_version |
| `Sou.KnowledgePrivacyBlocked` | Share attempt blocked by privacy filter | knowledge_id, privacy_rule |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| SOU_KNW_001 | Knowledge record not found |
| SOU_KNW_002 | Privacy level prevents requested operation |
| SOU_KNW_003 | Knowledge store capacity exceeded |
| SOU_KNW_004 | Invalid knowledge schema — required field missing |
| SOU_KNW_005 | Share to Academy blocked — privacy filter violation |
| SOU_KNW_006 | Query returned too many results — refinement required |

## Cross-Cutting Concerns

### Security

Knowledge store access is controlled. Only Sou and authorized entities may query. Privacy levels enforce access boundaries. (Physics/008-Security.md, CPR-010)

### Evidence

Every knowledge operation produces an Event. Knowledge is evidence-based — every record traces to source Events. Knowledge without evidence chain is invalid. (PHI-008, CPR-004)

### Lifecycle

Knowledge records follow a defined lifecycle (Created → Active → Archived). Retention policies govern expiration. (Physics/006-Lifecycles.md)

### Capability Bounds

Sou may store, retrieve, query, and share knowledge. It may NOT modify knowledge outside its type, access Academy knowledge directly (must go through Academy API), or share knowledge that violates privacy rules. (Physics/007-Capabilities.md)

### Communication

Knowledge operations communicate via ACF internally. Academy sharing uses ACF streams. Queries from other entities arrive through ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Knowledge is focused solely on Sou's constitutional memory |
| R3 (DRY) | Knowledge is canonical — reasoning and planning query it rather than duplicate |
| R6 (DI) | Knowledge store is injected into Sou components that need it |
| R10 (Simpler Over Complex) | Knowledge uses the simplest query interface sufficient for each retrieval |
| R12 (Embrace Errors) | All errors have unique codes (SOU_KNW_001–006) |
| R13 (Design for Failure) | Knowledge store has degraded read capability during store unavailability |
| R14 (Paved Path) | Knowledge operations follow a single paved path: store → index → query |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — knowledge stores evidence chains |
| Physics/012-Experience.md | Experience — knowledge is Sou's experience repository |
| Bible/02-Core/Sou/000-Overview.md | Sou overview — knowledge is a core Sou component |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — knowledge informs reasoning |
| Bible/02-Core/Sou/002-Planner.md | Planner — knowledge informs planning estimates |
| Bible/02-Core/Sou/003-Missions.md | Missions — knowledge stores mission outcomes |
| Bible/02-Core/Sou/004-Learning.md | Learning — knowledge stores learned patterns |
| Bible/02-Core/Academy/002-KMS.md | KMS — Academy knowledge management, distinct from Sou's private store |
| Bible/02-Core/Academy/003-Knowledge-Graph.md | Knowledge Graph — Academy's public knowledge graph |
| Bible/01-Governance/002-DGP.md | DGP — knowledge informs decision proposals |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles (esp. CPR-010) |
