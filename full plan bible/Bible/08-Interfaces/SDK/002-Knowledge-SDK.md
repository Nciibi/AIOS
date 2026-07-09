# AIOS Bible — Interfaces
## SDK — 002: Knowledge SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-SDK-002 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge SDK provides the standard interface for knowledge-aware tools and applications to interact with the Academy — AIOS's learning and knowledge management system. It defines how tools propose, query, validate, compose, and execute knowledge artifacts within the AIOS knowledge ecosystem.

Knowledge is a first-class concept in AIOS. The Academy transforms raw evidence into structured, validated, distributable knowledge. The Knowledge SDK exposes this capability to Workers, Organizations, and external tools, enabling them to participate in the knowledge lifecycle — from evidence ingestion through knowledge distribution and execution.

## Knowledge Provider Interface

Every knowledge-aware tool must implement the `KnowledgeProvider` interface:

```
interface KnowledgeProvider {
  // Query
  searchKnowledge(query: KnowledgeQuery): SearchResult[]
  getKnowledgeById(knowledgeId: KnowledgeID): KnowledgeArtifact
  getKnowledgeGraph(query: GraphQuery): KnowledgeGraph

  // Propose
  proposeKnowledge(artifact: KnowledgeArtifact): ProposalReceipt
  getProposalStatus(proposalId: ProposalID): ProposalStatus

  // Validate
  validateKnowledge(artifact: KnowledgeArtifact): ValidationResult
  verifyKnowledge(artifact: KnowledgeArtifact): VerificationResult

  // Compose
  composeKnowledge(sources: KnowledgeID[], composition: CompositionSpec): KnowledgeArtifact
  getCompositionStatus(compositionId: CompositionID): CompositionStatus

  // Execute
  executeKnowledge(knowledgeId: KnowledgeID, context: ExecutionContext): ExecutionResult
  dryRunKnowledge(knowledgeId: KnowledgeID, context: ExecutionContext): DryRunResult

  // Subscribe
  subscribeToTopic(topic: KnowledgeTopic): SubscriptionHandle
  getNotifications(filter: NotificationFilter): Notification[]
}
```

| Method | Description | Latency SLO |
|--------|-------------|-------------|
| `searchKnowledge` | Search the knowledge base | < 500 ms |
| `getKnowledgeById` | Retrieve a specific knowledge artifact | < 200 ms |
| `getKnowledgeGraph` | Query the knowledge graph structure | < 1 second |
| `proposeKnowledge` | Submit a new knowledge artifact for validation | < 1 second (accepted) |
| `getProposalStatus` | Check the status of a knowledge proposal | < 100 ms |
| `validateKnowledge` | Run validation rules against an artifact | < 5 seconds |
| `verifyKnowledge` | Verify artifact against source evidence | < 30 seconds |
| `composeKnowledge` | Combine knowledge artifacts into new insight | < 10 seconds |
| `getCompositionStatus` | Check composition progress | < 100 ms |
| `executeKnowledge` | Execute a knowledge-driven action (KEE) | Varies by action |
| `dryRunKnowledge` | Preview execution without side effects | < 5 seconds |
| `subscribeToTopic` | Subscribe to knowledge topic notifications | < 500 ms |

## Knowledge Query Language

Knowledge queries use a structured query language:

```
{
  "query_type": "search | graph | similarity | recommendation",
  "filters": {
    "knowledge_types": ["string"],
    "domains": ["string"],
    "tags": ["string"],
    "confidence_range": { "min": 0.0, "max": 1.0 },
    "time_range": { "start": "ISO8601", "end": "ISO8601" }
  },
  "text_query": "natural language or structured query",
  "embedding": [0.0, ...],
  "limit": 50,
  "offset": 0,
  "order_by": "relevance | recency | confidence"
}
```

| Query Type | Description | Algorithm |
|------------|-------------|-----------|
| `search` | Full-text and semantic search | Hybrid (BM25 + embedding) |
| `graph` | Knowledge graph traversal | BFS/DFS with edge filters |
| `similarity` | Find similar knowledge artifacts | Embedding similarity (cosine) |
| `recommendation` | Recommended knowledge for context | Collaborative + content-based |

## Knowledge Artifact Schema

Every knowledge artifact processed through the Knowledge SDK conforms to this schema:

```
{
  "knowledge_id": "uuid-v7",
  "artifact_type": "insight | model | pattern | procedure | reference",
  "version": "1.0.0",
  "status": "generated | validated | accepted | published | deprecated",
  "provenance": {
    "source_event_ids": ["uuid"],
    "creator_entity_id": "uuid",
    "created_at": "ISO8601",
    "validation_chain": [ ... ]
  },
  "content": {
    "summary": "string",
    "body": "object (type-specific)",
    "confidence": 0.0,
    "evidence_quality": 0.0
  },
  "metadata": {
    "domains": ["string"],
    "tags": ["string"],
    "language": "string",
    "organizations": ["uuid"]
  }
}
```

Artifact types define the structure of the `content.body` field. The Knowledge SDK validates artifacts against their type schema before acceptance.

## Knowledge Execution Protocol

Knowledge execution (via KEE) follows this protocol:

```
1. Request: executeKnowledge(knowledgeId, context)
2. Knowledge SDK validates:
   └─ Knowledge is in Published status
   └─ Requesting entity has execution authorization
   └─ Context contains required parameters
3. KEE loads knowledge artifact
4. KEE prepares execution environment
5. KEE executes knowledge-driven action
6. KEE streams intermediate results
7. On completion, KEE returns ExecutionResult
8. Execution evidence recorded as Event
9. Academy may learn from execution outcome
```

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `SDK.KnowledgeSearched` | Knowledge search is executed | query_id, query_hash, result_count, duration_ms |
| `SDK.KnowledgeProposed` | Knowledge artifact is submitted | proposal_id, artifact_type, source_event_ids |
| `SDK.KnowledgeValidated` | Knowledge validation completes | artifact_id, validator_id, passed, validation_score |
| `SDK.KnowledgeComposed` | Knowledge composition finishes | composition_id, source_ids, result_id |
| `SDK.KnowledgeExecuted` | Knowledge execution runs | execution_id, knowledge_id, outcome, evidence_hash |
| `SDK.KnowledgeSubscriptionCreated` | Topic subscription is registered | subscription_id, topic, entity_id |

## Cross-Cutting Concerns

### Security

Knowledge access is scoped by Organization policy. A Worker may only query knowledge within its Organization's scope unless cross-Organization sharing is explicitly authorized. Knowledge proposals are validated against constitutional constraints before acceptance. Execution of knowledge-driven actions requires the same authorization as any capability invocation. (Physics/008-Security.md)

### Evidence

Every Knowledge SDK operation produces an Event — queries, proposals, validations, compositions, and executions. Knowledge artifacts include full provenance chains linking back to source evidence Events. Knowledge execution outcomes produce new evidence for further learning. (PHI-008)

### Lifecycle

Knowledge artifacts follow the AKM lifecycle (Governance/006-AKM.md): Generated → Proposed → Validated → Accepted → Published → Deprecated → Archived. The Knowledge SDK provides methods for each lifecycle stage. Compositions follow a sub-lifecycle within the broader artifact lifecycle. (Physics/006-Lifecycles.md)

### Capability Bounds

Knowledge SDK capabilities are bounded by the requesting entity's knowledge access scope. A Worker may only query knowledge types authorized in its Genome. Knowledge proposal is bounded by the entity's knowledge creation capability. Knowledge execution is bounded by resource budgets and capability authorization. (Physics/007-Capabilities.md)

### Communication

All Knowledge SDK communication flows through ACF. Knowledge queries, proposals, and subscriptions use ACF RPC patterns. Knowledge distribution uses ACF pub/sub for push notifications. Knowledge execution results stream through ACF streaming topics. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Knowledge SDK covers only knowledge operations — no runtime or audit concerns |
| R3 (DRY) | Knowledge artifacts are stored once in Academy Registry, queried by reference |
| R5 (Liskov) | All knowledge-aware tools implement the same KnowledgeProvider interface |
| R9 (Deterministic) | Same knowledge query and input produces identical results |
| R10 (Simpler Over Complex) | Knowledge execution is linear — no branching execution plans |
| R13 (Design for Failure) | Knowledge query degradation returns partial results; knowledge execution failures return with error evidence |
| R14 (Paved Path) | Paved path: query → validate → propose → compose → execute |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — Knowledge SDK operations produce Events |
| Physics/012-Experience.md | Experience — Knowledge SDK enables experience-driven learning |
| Bible/08-Interfaces/API/000-Specifications.md | API — Knowledge SDK uses ACF API contracts |
| Bible/08-Interfaces/SDK/000-Runtime-SDK.md | Runtime SDK — Knowledge execution requires Runtime SDK session |
| Bible/02-Core/Academy/000-Overview.md | Academy — Knowledge SDK implements Academy interface |
| Bible/02-Core/Academy/013-KEE.md | KEE — Knowledge Execution Engine |
| Bible/02-Core/Academy/014-KCE.md | KCE — Knowledge Composition Engine |
| Bible/02-Core/Academy/015-Knowledge-SDK.md | Academy Knowledge SDK — Detailed API specification |
| Bible/01-Governance/006-AKM.md | AKM — Knowledge lifecycle governance |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA — R1–R15 compliance for knowledge tools |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
