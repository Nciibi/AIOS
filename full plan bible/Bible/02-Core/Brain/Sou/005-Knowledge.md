# AIOS Bible â€” Brain
## 005 â€” Memory and Knowledge (Delegated to Memory OS)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 2.0.0 |
| Category | Bible â€” Brain |
| Document ID | AIOS-BBL-002-SOU-005 |
| Source Laws | Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/005-Knowledge.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou accesses memory and knowledge through the **Memory OS** â€” a Brain service that manages persistent memory, working memory, and knowledge retrieval. Sou has read access to ALL memories (BRAIN-008), unlike other Brain services which have scoped access.

Memory OS stores Sou's private knowledge â€” constitutional interpretations, strategic context, entity performance history, and decision precedents. This is distinct from the Academy (public knowledge).

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

â†’ Stored as: KNW-0042
â†’ Later queried: "show me successful resource optimization strategies"
â†’ Returned: KNW-0042 (confidence 0.92, tags: resource-optimization)
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

## Edge Cases â€” Knowledge

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
Process: validate â†’ classify â†’ index â†’ store
Output: KnowledgeRecord { knowledge_id, stored_at }
Event: Sou.KnowledgeStored
```

### retrieveKnowledge

```
Input:  knowledge_id
Process: authorize â†’ fetch â†’ return
Output: KnowledgeRecord or null
Event: Sou.KnowledgeRetrieved
```

### queryKnowledge

```
Input:  query (type, filters, time_range, relevance_criteria)
Process: tokenize â†’ search index â†’ rank results â†’ return
Output: KnowledgeQueryResult { results: KnowledgeRecord[], total_count }
Event: Sou.KnowledgeQueried
```

### shareWithAcademy

```
Input:  knowledge_id, privacy_filter_level
Process: apply privacy filter (CPR-010) â†’ package â†’ submit to Academy
Output: AcademySubmission { submission_id, knowledge_id }
Event: Sou.KnowledgeSharedWithAcademy
```

### pruneKnowledge

```
Input:  retention_policy
Process: identify expired knowledge â†’ archive â†’ notify
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
Created â†’ Active â†’ Updated â†’ Archived (retention expired)
                                           â†’ Shared (with Academy)
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

## Events

| SOU.EventType |   Produced When | Fields |
|-----------|--------------|--------|
| SOU.KnowledgeStored |   New knowledge is stored | knowledge_id, type, privacy_level |
| SOU.KnowledgeRetrieved |   Knowledge is retrieved | knowledge_id, requester_id |
| SOU.KnowledgeQueried |   Knowledge store is queried | query_id, query_type, result_count |
| SOU.KnowledgeUpdated |   Existing knowledge is updated | knowledge_id, new_version, change_summary |
| SOU.KnowledgeSharedWithAcademy |   Knowledge is shared with Academy | knowledge_id, submission_id |
| SOU.KnowledgePruned |   Knowledge is pruned by retention policy | archived_count, policy_version |
| SOU.KnowledgePrivacyBlocked |   Share attempt blocked by privacy filter | knowledge_id, privacy_rule |

## Error Cases

| Condition | Error Code | Severity | Recovery |
|-----------|------------|----------|----------|
| Knowledge record not found | SOU_KNW_001 | Low | Return null; caller handles missing record |
| Privacy level prevents requested operation | SOU_KNW_002 | Medium | Deny operation; log security event with requester context |
| Knowledge store capacity exceeded | SOU_KNW_003 | High | Reject store; trigger pruning per retention policy |
| Invalid knowledge schema â€” required field missing | SOU_KNW_004 | Medium | Reject store; return validation errors |
| Share to Academy blocked â€” privacy filter violation | SOU_KNW_005 | High | Block share; record privacy block event; knowledge remains private |
| Query returned too many results â€” refinement required | SOU_KNW_006 | Low | Reject query; return error with max allowed count and refinement hints |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-KNW-001 | Sou has read access to all memories (BRAIN-008) | API-level â€” Memory OS grants Sou universal read |
| SOU-KNW-002 | Knowledge without evidence chain is invalid | Schema â€” source_events required on all records |
| SOU-KNW-003 | Private knowledge is never shared without explicit privacy filter | Governance â€” privacy filter enforced before Academy sharing |
| SOU-KNW-004 | Knowledge records are never mutated â€” only created, updated (new version), or archived | API-level â€” update creates new version |

| BRAIN-002 | Sou is the only component with strategic decision authority. | Constitutional - SOU-001. Verified by Security Council. |
| BRAIN-005 | Every user-facing response passes through Sou. | Constitutional - SOU-005. ACF routing enforced. |
## Cross-Cutting Concerns

### Security

Knowledge store access is controlled. Only Sou and authorized entities may query. Privacy levels enforce access boundaries. (Physics/008-Security.md, CPR-010)

### Evidence

Every knowledge operation produces an Event. Knowledge is evidence-based â€” every record traces to source Events. Knowledge without evidence chain is invalid. (PHI-008, CPR-004)

### Lifecycle

Knowledge records follow a defined lifecycle (Created â†’ Active â†’ Archived). Retention policies govern expiration. (Physics/006-Lifecycles.md)

### Capability Bounds

Sou may store, retrieve, query, and share knowledge. It may NOT modify knowledge outside its type, access Academy knowledge directly (must go through Academy API), or share knowledge that violates privacy rules. (Physics/007-Capabilities.md)

### Communication

Knowledge operations communicate via ACF internally. Academy sharing uses ACF streams. Queries from other entities arrive through ACF. (Law 3 â€” Communication)

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 â€” Modulsingularity | Knowledge is focused solely on Sou's constitutional memory |
| R2 â€” Dependency Order | Knowledge depends on Memory OS and Event Store; no upward dependencies |
| R3 â€” DRY | Knowledge is canonical â€” reasoning and planning query it rather than duplicate |
| R4 â€” Builder Pattern | Knowledge records are built through the store â†’ index â†’ query pipeline |
| R5 â€” Liskov Substitution | All knowledge types implement the KnowledgeRecord interface |
| R6 â€” DI over Singletons | Memory OS is injected into Sou components that need knowledge access |
| R9 â€” Deterministic | Same query on same data returns identical results |
| R10 â€” Simpler Over Complex | Knowledge uses the simplest query interface sufficient for each retrieval |
| R13 â€” Design for Failure | Knowledge store has degraded read capability during store unavailability |
| R14 â€” Paved Path | Knowledge operations follow a single paved path: store â†’ index â†’ query |
| R15 â€” Open/Closed | New knowledge types added by extending KnowledgeRecord, not by modifying the store |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence â€” memory stores evidence chains |
| Physics/012-Experience.md | Experience â€” memory is Sou's experience repository |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview â€” memory access is a capability of the executive intelligence |
| Bible/02-Core/Brain/Sou/001-Reasoning.md | Reasoning â€” memory informs reasoning |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planning â€” memory informs planning estimates |
| Bible/02-Core/Brain/Sou/003-Missions.md | Missions â€” memory stores mission outcomes |
| Bible/02-Core/Brain/Sou/004-Learning.md | Learning â€” memory stores learned patterns |
| Bible/02-Core/Brain/Memory/000-Overview.md | Memory OS â€” Brain service that manages all memory types |
| Bible/02-Core/Academy/002-KMS.md | KMS â€” Academy knowledge management, distinct from Sou's private store |
| Bible/02-Core/Academy/003-Knowledge-Graph.md | Knowledge Graph â€” Academy's public knowledge graph |
| Bible/01-Governance/002-DGP.md | DGP â€” memory informs decision proposals |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles (esp. CPR-010) |
