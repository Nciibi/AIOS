# AIOS Bible — Core
## Academy — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-000 |
| Source Laws | Law 4 — Evidence, Law 2 — Autonomy, Law 9 — Deterministic |
| Source Physics | Physics/012-Experience.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Academy is AIOS's learning and knowledge management system. It transforms raw evidence (Events) into structured, validated, distributable knowledge that entities use to operate autonomously within constitutional bounds. The Academy embodies PHI-002 (Evidence-Driven Operations) and PHI-008 (Evidence Over Opinion): every piece of knowledge is derived from verifiable evidence, never from assertion.

The Academy answers: *What does AIOS know, how does it know it, and how is that knowledge used?*

## Relationship to AKM

Governance/006-AKM.md defines the *governance* of knowledge — the lifecycle states, validation rules, and access policies. The Academy *implements* that governance. AKM says what must happen; the Academy does it.

| AKM Stage | Academy Component |
|-----------|------------------|
| Evidence | Evidence Ingestor (accepts raw Events) |
| Analysis | Knowledge Pipeline (transforms events into knowledge artifacts) |
| Validation | Knowledge Validator (005) + Knowledge Verifier (006) |
| Acceptance | Knowledge Registry (004) + Knowledge Review (007) |
| Distribution | Knowledge Distribution (009) |
| Search/Use | Knowledge Search (010), KEE (013), KCE (014) |

## Learning Model

The Academy operates a six-stage learning model:

```
Evidence → Analysis → Knowledge → Validation → Acceptance → Distribution
```

| Stage | Description | Component |
|-------|-------------|-----------|
| **Evidence** | Raw Events arrive from Event Store (Physics/005-Events.md) | Evidence Ingestor |
| **Analysis** | Events are analysed for patterns, insights, derivations | Knowledge Pipeline |
| **Knowledge** | Knowledge artifacts are produced (structured, typed, sourced) | KMS (002) |
| **Validation** | Artifacts pass constitutional and quality checks | Validator (005), Verifier (006) |
| **Acceptance** | Validated knowledge is accepted into the permanent registry | Registry (004), Review (007) |
| **Distribution** | Accepted knowledge is made available to consumers | Distribution (009), Search (010) |

## Components

| # | Component | File | Responsibility |
|---|-----------|------|----------------|
| 1 | Evidence Ingestor | 001-Architecture.md | Receives Events, filters for learnable content, queues for analysis |
| 2 | Knowledge Management System | 002-KMS.md | Stores, versions, and queries knowledge artifacts |
| 3 | Knowledge Graph | 003-Knowledge-Graph.md | Graph structure linking knowledge, entities, events, concepts |
| 4 | Knowledge Registry | 004-Knowledge-Registry.md | Authoritative index of all accepted knowledge |
| 5 | Knowledge Validator | 005-Knowledge-Validator.md | Constitutional and quality validation rules engine |
| 6 | Knowledge Verifier | 006-Knowledge-Verifier.md | Verifies knowledge against source evidence |
| 7 | Knowledge Review | 007-Knowledge-Review.md | Human/Engine review workflow for high-impact knowledge |
| 8 | Knowledge Versioning | 008-Knowledge-Versioning.md | Version scheme and lifecycle for knowledge artifacts |
| 9 | Knowledge Distribution | 009-Knowledge-Distribution.md | Push/pull mechanisms for knowledge consumers |
| 10 | Knowledge Search | 010-Knowledge-Search.md | Search and query API over accepted knowledge |
| 11 | Knowledge Provenance | 011-Knowledge-Provenance.md | Immutable traceability from knowledge to source Events |
| 12 | Knowledge Analytics | 012-Knowledge-Analytics.md | Usage metrics, quality metrics, gap detection |
| 13 | Knowledge Execution Engine | 013-KEE.md | Runtime for knowledge-driven actions |
| 14 | Knowledge Composition Engine | 014-KCE.md | Combines knowledge artifacts for new insights |
| 15 | Knowledge SDK | 015-Knowledge-SDK.md | SDK for building knowledge-aware tools |
| 16 | Knowledge API | 016-Knowledge-API.md | Complete API specification over ACF |

## Invariants

1. **ACD-I-001 — Evidence-Bound**: Every knowledge artifact is traceable to at least one source Event. No knowledge exists without evidence (PHI-008).
2. **ACD-I-002 — Validated Before Acceptance**: No knowledge artifact enters the Registry without passing validation and (where required) verification. Unvalidated knowledge is provisional only.
3. **ACD-I-003 — Immutable Provenance**: Once accepted, a knowledge artifact's provenance chain is immutable. Corrections create new versions; they do not modify history.
4. **ACD-I-004 — Constitutional Consistency**: No knowledge artifact may contradict the Constitution, Physics invariants, or Foundations principles. Contradictions are rejected at validation (GOV-001).
5. **ACD-I-005 — Organizational Privacy**: Knowledge is scoped to the Organization that produced it. Cross-Organization knowledge flows require explicit governance policy (CPR-010).

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Academy.KnowledgeProposed` | Knowledge artifact is submitted | artifact_id, type, source_entity_id, evidence_hashes |
| `Academy.KnowledgeValidated` | Knowledge passes validation | artifact_id, validator_id, validation_score |
| `Academy.KnowledgeVerified` | Knowledge passes verification | artifact_id, verifier_id, confidence_score |
| `Academy.KnowledgeAccepted` | Knowledge is accepted into Registry | artifact_id, reviewer_id, registry_entry |
| `Academy.KnowledgePublished` | Knowledge is published for distribution | artifact_id, distribution_scope |
| `Academy.KnowledgeDeprecated` | Knowledge is deprecated | artifact_id, superseded_by, reason |
| `Academy.KnowledgeArchived` | Knowledge is archived | artifact_id, retention_period |

## Cross-Cutting Concerns

### Security

Academy operates within Security Council oversight (Physics/008-Security.md). Knowledge artifacts are validated against constitutional constraints before acceptance. The Academy does not override entity capability bounds: knowledge is advisory unless explicitly executed by KEE (013) under entity authority.

### Evidence

All Academy operations are sourced from the Event Store (Physics/005-Events.md). Every knowledge artifact records its source Event IDs. The Academy does not generate knowledge from direct entity observation (PHI-002); it learns only from Events that entities produce.

### Lifecycle

Knowledge artifacts follow the AKM lifecycle (Governance/006-AKM.md): Generated → Proposed → Validated → Accepted → Published → Deprecated → Archived. Each transition is an Event. The lifecycle is enforced by the KMS (002) and Registry (004).

### Capability Bounds

Academy capabilities are bounded per-entity (Physics/007-Capabilities.md). An entity may propose knowledge, query knowledge, or execute knowledge only within its capability scope. Academy capabilities are granted by the Security Council at entity creation (PHI-007).

### Communication

All Academy communication flows through the Application Communication Framework (ACF). Internal Academy components communicate over ACF topics. External consumers interact through the Knowledge API (016). No direct inter-component coupling exists (R6).

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Each Academy component does exactly one thing (validate, verify, store, distribute) |
| R3 | Knowledge is stored once in the Registry (canonical source) |
| R7 | Every Academy Event has corresponding tests |
| R9 | Knowledge validation produces deterministic results |
| R10 | The learning model is linear and sequential (no branching) |
| R13 | Academy fails closed on dependency failure (deny knowledge acceptance) |
| R14 | The paved path for knowledge is: evidence → validate → accept → distribute |

## Learning Model Detail

The six-stage learning model is the core operational loop of the Academy:

### Stage 1: Evidence Ingestion

The Academy subscribes to the Event Store (Physics/005-Events.md) and receives Events as they are produced. Not all Events are learnable — the Evidence Ingestor filters for Events that contain actionable information, patterns, or outcomes that can improve AIOS's knowledge base.

| Event Learnability Criteria | Description |
|----------------------------|-------------|
| Has structured outcome | Event contains a result, decision, or outcome |
| Is constitutional | Event does not violate privacy (CPR-010) |
| Is analyzable | Event payload can be parsed and contextualized |
| Is consented | Entity/organization has consented to learning |

### Stage 2: Analysis

The Knowledge Pipeline transforms raw Events into structured knowledge artifacts. This involves parsing, contextualizing against existing knowledge, abstracting patterns, and formatting into the canonical artifact schema.

Analysis is deterministic (R9): given the same Events and the same existing knowledge state, the same analysis output is produced. This ensures reproducibility of knowledge generation.

### Stage 3: Knowledge Production

The KMS (002) accepts the structured artifact from the Pipeline and assigns it a version (1.0.0), a status (Generated), and a unique ID. The artifact is now persisted in the KMS event log.

### Stage 4: Validation

The artifact passes through three gates:
1. **Validator (005)** — Constitutional consistency, schema, provenance, non-contradiction, privacy, quality
2. **Verifier (006)** — Evidence replay, cross-validation, confidence scoring, adversarial testing
3. **Review (007)** — Human/Engine review (conditional: high-impact, low-confidence, novel)

Any gate can reject the artifact. Rejection returns the artifact with structured feedback.

### Stage 5: Acceptance

The Knowledge Registry (004) registers the approved artifact. This is a constitutional event — once registered, the knowledge is authoritative. The Registry entry is signed and includes the full validation chain.

### Stage 6: Distribution

The Distribution service (009) pushes the artifact to subscribers, makes it available via Search (010), and updates the Knowledge Graph (003). The artifact is now consumable by entities across AIOS.

```
┌─────────────────────────────────────────────────────────────┐
│  Learning Loop                                                 │
│                                                               │
│  Evidence ──▶ Analysis ──▶ Knowledge ──▶ Validation ──▶      │
│       ▲                                   Acceptance ──▶      │
│       │                                   Distribution        │
│       └────────────────── Feedback ◀──────┘                   │
│                                                               │
│  Feedback: KEE (013) execution results,                       │
│  KCE (014) composition results, usage analytics (012)         │
└─────────────────────────────────────────────────────────────┘
```

## Academy Integration Points

The Academy integrates with the following AIOS systems:

| System | Integration | Documents |
|--------|-------------|-----------|
| Event Store | Source of all evidence for learning | Physics/005-Events.md |
| IDS — Identity Service | Entity identity for knowledge operations | Foundations/001-AIOS-Philosophy.md (PHI-004) |
| ATS — Authentication | Authentication for all API/SDK calls | Physics/008-Security.md |
| CCA — Capabilities | Capability bounds for knowledge operations | Physics/007-Capabilities.md |
| ROS — Resources | Resource budgets for knowledge execution | Core/ROS/000-Overview.md |
| Runtime Engine | Execution of knowledge-driven plans | Physics/010-Execution.md |
| DTS — Decision Trust | Confidence scoring and reputation | Core/DTS/004-Confidence.md |
| Sou — Decision Engine | Strategic knowledge consumption | Core/Sou/005-Knowledge.md |
| Security Council | Oversight, deprecation, escalation | Physics/008-Security.md |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/012-Experience.md | Experience drives learning — Academy consumes experience events |
| Physics/005-Events.md | Events are the source of all Academy knowledge |
| Physics/007-Capabilities.md | Entity capability bounds limit knowledge access |
| Physics/008-Security.md | Security Council oversees Academy operations |
| Governance/006-AKM.md | AKM governs the knowledge lifecycle implemented by Academy |
| Foundations/001-AIOS-Philosophy.md | PHI-002, PHI-008 — evidence-driven, evidence-over-opinion |
| Foundations/003-Core-Principles.md | CPR-010 — evidence privacy across organizations |
| Foundations/002-Design-DNA.md | R1, R3, R7, R9, R10, R13, R14 |
| Core/Sou/005-Knowledge.md | Sou consumes Academy knowledge for decision-making |
| Core/DTS/004-Confidence.md | DTS confidence scoring integrates with knowledge verification |
| 001-Architecture.md | Detailed Academy architecture |
