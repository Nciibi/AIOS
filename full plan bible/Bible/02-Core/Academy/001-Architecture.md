# AIOS Bible — Core
## Academy — 001: Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-001 |
| Source Laws | Law 4 — Evidence, Law 2 — Autonomy |
| Source Physics | Physics/012-Experience.md, Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Academy Engine architecture defines how the 16 Academy components are organised, how they communicate, how data flows through the learning pipeline, and how the Academy cluster is deployed. This document is the structural blueprint for Academy implementation.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ACADEMY ENGINE                                   │
│                                                                           │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────┐    │
│  │  Evidence     │───▶│   Knowledge       │───▶│   Knowledge          │    │
│  │  Ingestor     │    │   Pipeline        │    │   Management System  │    │
│  └──────────────┘    └──────────────────┘    └──────────────────────┘    │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │                   Validation Layer                              │          │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │          │
│  │  │  Validator   │  │  Verifier    │  │  Review      │        │          │
│  │  │  (005)       │  │  (006)       │  │  (007)       │        │          │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │          │
│  └──────────────────────────────────────────────────────────────┘          │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────┐    ┌──────────────────────┐                      │
│  │  Knowledge Registry  │    │  Knowledge Graph      │                      │
│  │  (004)               │    │  (003)                │                      │
│  └──────────────────────┘    └──────────────────────┘                      │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐          │
│  │                 Distribution Layer                              │          │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │          │
│  │  │ Distribution │  │    Search    │  │  Provenance  │        │          │
│  │  │  (009)       │  │  (010)       │  │  (011)       │        │          │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │          │
│  └──────────────────────────────────────────────────────────────┘          │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐              │
│  │     KEE      │    │     KCE      │    │   Analytics      │              │
│  │  (013)       │    │  (014)       │    │   (012)          │              │
│  └──────────────┘    └──────────────┘    └──────────────────┘              │
│                                                                           │
│  ┌──────────────────────────────────────────────────────┐                │
│  │              Knowledge SDK / API Layer                 │                │
│  │  ┌────────────────────┐  ┌────────────────────┐      │                │
│  │  │  Knowledge SDK     │  │  Knowledge API     │      │                │
│  │  │  (015)             │  │  (016)             │      │                │
│  │  └────────────────────┘  └────────────────────┘      │                │
│  └──────────────────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components Detail

### 1. Evidence Ingestor

The Evidence Ingestor is the Academy's entry point. It subscribes to Event Store topics (Physics/005-Events.md) and filters Events that contain learnable content.

| Property | Value |
|----------|-------|
| Input | Event Store (ACF topic `events.learnable`) |
| Output | Filtered events queued for the Knowledge Pipeline |
| Filter Criteria | Event type in learnable set, entity authorized for learning, privacy constraints satisfied |
| Failure Mode | Event is skipped with logged reason; pipeline continues (R13) |

### 2. Knowledge Pipeline

The Pipeline transforms raw events into structured knowledge artifacts.

| Stage | Function |
|-------|----------|
| Parse | Extract structured fields from Event payload |
| Contextualize | Link event to existing knowledge graph nodes |
| Abstract | Derive generalised knowledge from event patterns |
| Format | Produce knowledge artifact in canonical schema |

### 3. Validation Layer

Three components operate in sequence:

| Order | Component | Function | Can Reject? |
|-------|-----------|----------|-------------|
| 1 | Validator (005) | Constitutional consistency, quality checks | Yes |
| 2 | Verifier (006) | Evidence accuracy, confidence scoring | Yes |
| 3 | Review (007) | Human/Engine review (conditional) | Yes |

### 4. Storage Layer

| Store | Contents | Queryable? |
|-------|----------|------------|
| Knowledge Registry (004) | Accepted knowledge artifacts (canonical index) | Yes (by ID, type, state) |
| Knowledge Graph (003) | Graph structure linking artifacts, entities, events | Yes (traversal, shortest path) |
| KMS (002) | Full artifact store including version chains | Yes (all metadata) |
| Event Log (internal) | Append-only log of knowledge lifecycle events | Yes (time-order replay) |

### 5. Distribution Layer

| Component | Mechanism | Consumer |
|-----------|-----------|----------|
| Distribution (009) | Push (ACF topic), Pull (API), Cache (local TTL) | Entities, Engines, Services |
| Search (010) | Full-text, semantic, graph, faceted | External queries |
| Provenance (011) | Trace endpoint, verification endpoint | Audit, Security Council |

### 6. Execution Layer

| Engine | Function | Consumed By |
|--------|----------|-------------|
| KEE (013) | Execute knowledge-driven actions | Runtime Engine |
| KCE (014) | Compose knowledge for new insights | Sou, Researchers |

## Data Flow

```
Raw Events (Event Store)
    │
    ▼
[Evidence Ingestor] ── filtered Events ──▶ [Knowledge Pipeline]
    │                                                  │
    │                                                  ▼
    │                                         Knowledge Artifact
    │                                                  │
    │                                                  ▼
    │                                    ┌─────────────────────┐
    │                                    │  Validation Layer   │
    │                                    │  Validator → Verify │
    │                                    │  → Review (if need) │
    │                                    └─────────┬───────────┘
    │                                              │
    │                                              ▼
    │                                     [Knowledge Registry]
    │                                              │
    │                                    ┌─────────┴──────────┐
    │                                    │                    │
    │                                    ▼                    ▼
    │                            [Distribution]      [Knowledge Graph]
    │                                    │                    │
    │                                    ▼                    ▼
    │                             Consumers            Analytics / Search
    │
    └────── Feedback loop: Knowledge usage generates new Events ──▶
```

## Cluster Architecture

The Academy uses an active-passive cluster with read replicas, analogous to IDS:

```
┌─────────────────────────────────────────────────────┐
│                  Academy Cluster                        │
│                                                        │
│  ┌──────────────────────┐  ┌──────────────────────┐   │
│  │   Primary (Active)   │  │   Standby (Passive)  │   │
│  │  - Writes to Registry│  │  - Syncs from Primary │   │
│  │  - Runs Pipeline     │  │  - Ready for failover │   │
│  │  - Validates/Verifies│  │  - No writes          │   │
│  └──────────────────────┘  └──────────────────────┘   │
│              │                         │               │
│              │                         │               │
│              ▼                         ▼               │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Read Replicas (N)                     │  │
│  │  - Serve Search queries (010)                      │  │
│  │  - Serve Distribution pull requests (009)          │  │
│  │  - Serve Analytics queries (012)                   │  │
│  │  - Eventual consistency (sub-second lag)           │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Failover

| Scenario | Action | RTO | RPO |
|----------|--------|-----|-----|
| Primary fails | Standby becomes primary | < 30s | < 1s |
| Read replica fails | Load balancer removes from pool | < 5s | N/A |
| Full cluster failure | Disaster recovery site activation | < 5 min | < 60s |

## Communication Architecture

All Academy components communicate over ACF:

| Topic | Publisher | Subscribers |
|-------|-----------|-------------|
| `academy.events.ingested` | Evidence Ingestor | Knowledge Pipeline |
| `academy.knowledge.proposed` | Knowledge Pipeline | Validator |
| `academy.knowledge.validated` | Validator | Verifier, Registry |
| `academy.knowledge.verified` | Verifier | Review, Registry |
| `academy.knowledge.accepted` | Registry | Distribution, Graph, Search |
| `academy.knowledge.published` | Distribution | All subscribers |
| `academy.knowledge.deprecated` | Registry | Distribution, Search |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Academy.PipelineStarted` | Knowledge pipeline begins processing | pipeline_id, source_event_ids |
| `Academy.PipelineCompleted` | Pipeline produces knowledge artifact | pipeline_id, artifact_id |
| `Academy.PipelineFailed` | Pipeline encounters unrecoverable error | pipeline_id, error_code, stage |
| `Academy.FailoverInitiated` | Standby becomes primary | new_primary_id, timestamp |
| `Academy.ReplicaSynced` | Read replica syncs from primary | replica_id, lag_ms |

## Cross-Cutting Concerns

### Security

The Academy cluster is isolated from untrusted networks. All inter-component communication is authenticated (ATS-level). The Evidence Ingestor validates that source Events are from authorized entities before processing (Physics/008-Security.md).

### Evidence

Every data flow step produces an Event. The pipeline's full processing history is reconstructable from Academy-internal Events. No step in the pipeline can be executed without producing evidence.

### Lifecycle

Academy components follow the canonical LMS lifecycle (Foundations/008-Object-Lifecycle.md). Pipeline runs are entities with their own lifecycle: Created → Running → Completed/Failed.

### Capability Bounds

Academy components have bounded capabilities (Physics/007-Capabilities.md). The Evidence Ingestor cannot write to the Registry. The Registry cannot execute knowledge. Capability separation is enforced by ACF authorization.

### Communication

All inter-component communication uses ACF with topic-based pub-sub. Components are decoupled (R6). The Academy API (016) is the only external-facing interface.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Each component does exactly one thing |
| R2 | Pipeline depends on Validator, not vice versa |
| R4 | Knowledge artifacts are built by the Pipeline, not constructed directly |
| R6 | All dependencies (Event Store, ACF, Registry) are injected |
| R10 | Pipeline is linear and sequential (no branching) |
| R13 | Each stage fails closed; Pipeline continues on non-fatal errors |
| R14 | Paved path: Ingest → Pipeline → Validate → Accept → Distribute |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Event sourcing for all Academy operations |
| Physics/012-Experience.md | Experience events drive the pipeline |
| Physics/007-Capabilities.md | Capability bounds for Academy components |
| Physics/008-Security.md | Cluster security, inter-component authentication |
| Governance/006-AKM.md | AKM governance implemented by this architecture |
| Foundations/005-Architectural-Patterns.md | Pipeline pattern, Event Sourcing patterns |
| Foundations/002-Design-DNA.md | R1–R15 engineering rules |
| 000-Overview.md | Academy overview |
| 002-KMS.md | Knowledge Management System |
| 016-Knowledge-API.md | External API layer |
