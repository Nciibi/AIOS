# AIOS Bible — Core
## Sou 004 — Learning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-SOU-004 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou's Learning engine is the self-improvement mechanism of AIOS constitutional consciousness. It ingests outcomes from missions, decisions, and entity performance, and uses them to refine reasoning models, improve planning heuristics, and update decision criteria.

Learning is evidence-driven (PHI-008), constitutionally bounded (CPR-009), and privacy-preserving (CPR-010). Sou learns only from recorded Events — never from intuition, speculation, or unverified sources.

## Learning Sources

Sou learns from four categories of evidence:

| Source | Evidence Type | Produced By |
|--------|---------------|-------------|
| Mission Outcomes | Mission completion events, milestone achievements, failure Events | LMS, Workers |
| Decision Outcomes | Decision approval/rejection, implementation results | DGP, Security Council |
| Entity Performance | Capability usage, error rates, compliance history | Workers, Security Council |
| Academy Knowledge | Published knowledge artifacts, pattern extractions | Academy (Core/002-KMS.md) |

```
Evidence Sources
    │
    ├── Mission Outcomes ──► Learning
    ├── Decision Outcomes ──► Learning
    ├── Entity Performance ─► Learning
    └── Academy Knowledge ──► Learning
                                    │
                                    ▼
                        ┌──────────────────────┐
                        │  Learning Engine      │
                        │  (ingest → analyze →  │
                        │   update → validate)  │
                        └──────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌────────────┐  ┌────────────┐  ┌────────────┐
            │ Reasoning  │  │  Planner   │  │ Knowledge  │
            │ (improved) │  │ (improved) │  │ (updated)  │
            └────────────┘  └────────────┘  └────────────┘
```

## Learning Products

Learning produces three types of improvements:

| Product | Description | Consumer |
|---------|-------------|----------|
| Improved Reasoning Models | Updated decision trees, better option evaluation | Reasoning engine |
| Better Planning Heuristics | Refined milestone estimation, resource prediction | Planner |
| Updated Decision Criteria | Enhanced constitutional interpretation, risk assessment | Reasoning, Knowledge |

## Learning Is Constitutional

Sou's learning is bounded by three constitutional constraints:

| Constraint | Source | Enforcement |
|------------|--------|-------------|
| Law-Bounded | CPR-009 | Learning may not produce recommendations that violate Laws |
| Evidence-Driven | PHI-008 | Every learning update must trace to specific Evidence Events |
| Privacy-Preserving | CPR-010 | Learning may not expose entity-identifiable information in shared models |

## Learning Operations

### ingestOutcome

```
Input:  outcome_event (from Event Store), source_type
Process: validate evidence → extract outcome data → classify outcome type
Output: IngestedOutcome { outcome_id, extracted_pattern, confidence }
Validation: evidence chain must be complete (PHI-008)
Event: Sou.LearningIngested
```

### updateModel

```
Input:  model_id, ingested_outcome, update_strategy
Process: apply outcome to model → recalculate parameters → validate update
Output: ModelUpdate { model_id, new_version, change_log }
Validation: new model must not reduce constitutional compliance
Event: Sou.ModelUpdated
```

### evaluateImprovement

```
Input:  model_before, model_after, test_scenarios
Process: run test scenarios on both models → compare results → assess improvement
Output: ImprovementEvaluation { improved: bool, metrics, regression_check }
Event: Sou.ImprovementEvaluated
```

## Learning Flow

```
1. Evidence Event arrives at Sou via ACF Stream
2. ingestOutcome validates and classifies the evidence
3. Learning analyzes the outcome against current models
4. If improvement opportunity identified → updateModel
5. evaluateImprovement validates the updated model
6. If improvement confirmed → model deployed to Reasoning/Planner
7. If improvement regresses → model rolled back, learning recorded
```

## Validation Rules

| Rule | Description | Enforcement |
|------|-------------|-------------|
| Evidence Completeness | Every learning update traces to one or more Events | Event Store query |
| No Privacy Leak | Shared models (via Academy) contain no entity-identifiable data | Privacy filter validation |
| Constitutional Integrity | Updated models do not violate any Law or constitutional principle | Constitutional reasoning check |
| Regression Testing | Updated models perform at least as well on historical scenarios | Historical replay |
| Provenance Tracking | Every model version tracks which outcomes informed it | Version metadata |

## Learning Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Sou.LearningIngested` | Outcome evidence is ingested | outcome_id, source_type, evidence_hash |
| `Sou.ModelUpdated` | A learning model is updated | model_id, old_version, new_version, change_summary |
| `Sou.ImprovementEvaluated` | An improvement is evaluated | model_id, improved, metrics |
| `Sou.ModelRolledBack` | A model update is rolled back | model_id, version, regression_details |
| `Sou.LearningPrivacyBlocked` | Learning input blocked by privacy filter | outcome_id, privacy_rule_violated |
| `Sou.KnowledgeSharedWithAcademy` | Learned pattern shared with Academy | knowledge_id, pattern_type |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| SOU_LRN_001 | Evidence event not found in Event Store |
| SOU_LRN_002 | Privacy filter blocked outcome ingestion |
| SOU_LRN_003 | Model update fails constitutional validation |
| SOU_LRN_004 | Regression test failure — improved model performs worse |
| SOU_LRN_005 | Evidence chain incomplete — missing causal Events |

## Cross-Cutting Concerns

### Security

Learning models are Sou's internal state. Access is controlled by the Security Council. Models shared with the Academy are privacy-filtered. Learning Events are recorded for audit. (Physics/008-Security.md)

### Evidence

Learning is evidence-driven (PHI-008). Every model update traces to specific Evidence Events. Learning without evidence is a constitutional violation. (Physics/005-Events.md, Physics/012-Experience.md)

### Lifecycle

Learning models have a version lifecycle: Created → Trained → Validated → Deployed → Deprecated → Archived. Each version is tracked. (Physics/006-Lifecycles.md)

### Capability Bounds

Sou learns only from evidence it is authorized to access. Learning about entities requires their authorization level. Cross-entity learning requires Academy mediation. (Physics/007-Capabilities.md)

### Communication

Learning communicates via ACF. Academy knowledge is received as evidence. Updated models are distributed to Reasoning and Planner internally. Patterns may be shared with Academy through ACF streams. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Learning is focused solely on self-improvement from evidence |
| R3 (DRY) | Learned patterns are stored in Knowledge, not re-learned |
| R9 (Deterministic) | Learning from the same evidence produces the same update |
| R10 (Simpler Over Complex) | Learning uses the simplest sufficient model for each outcome type |
| R12 (Embrace Errors) | All errors have unique codes (SOU_LRN_001–005) |
| R13 (Design for Failure) | Learning failures do not block Sou operations — stale models are used |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — learning consumes Event store |
| Physics/012-Experience.md | Experience — learning is Sou's experience mechanism |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — learning improves reasoning models |
| Bible/02-Core/Sou/002-Planner.md | Planner — learning improves planning heuristics |
| Bible/02-Core/Sou/003-Missions.md | Missions — learning from mission outcomes |
| Bible/02-Core/Sou/005-Knowledge.md | Knowledge — learning stores patterns in Knowledge |
| Bible/02-Core/Academy | Academy — Sou shares learned patterns via Academy |
| Bible/02-Core/DTS/004-Confidence.md | Confidence — learning updates confidence models |
| Bible/01-Governance/002-DGP.md | DGP — learning from decision outcomes |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles (esp. CPR-009, CPR-010) |
