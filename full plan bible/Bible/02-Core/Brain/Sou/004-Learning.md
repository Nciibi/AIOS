# AIOS Bible â€” Brain
## 004 â€” Learning (Integration and Adaptation)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 2.0.0 |
| Category | Bible â€” Brain |
| Document ID | AIOS-BBL-002-SOU-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Bible/02-Core/Sou/004-Learning.md v1.0 |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Sou learns from every outcome â€” every mission completion, every decision, every interaction. Learning is how Sou improves its reasoning, planning, and decision-making over time. Sou integrates evidence from the **Academy** (outside the Brain) and stores learned patterns in **Memory OS** (inside the Brain).

Learning is evidence-driven (PHI-008), constitutionally bounded (CPR-009), and privacy-preserving (CPR-010). Sou learns only from recorded Events â€” never from intuition, speculation, or unverified sources.

## Learning Sources

Sou learns from four categories of evidence:

| Source | Evidence Type | Produced By |
|--------|---------------|-------------|
| Mission Outcomes | Mission completion events, milestone achievements, failure Events | LMS, Workers |
| Decision Outcomes | Decision approval/rejection, implementation results | DGP, Security Council |
| Entity Performance | Capability usage, error rates, compliance history | Workers, Security Council |
| Academy Knowledge | Published knowledge artifacts, pattern extractions | Academy (Bible/02-Core/Academy/002-KMS.md) |

```
Evidence Sources
    â”‚
    â”œâ”€â”€ Mission Outcomes â”€â”€â–º Learning
    â”œâ”€â”€ Decision Outcomes â”€â”€â–º Learning
    â”œâ”€â”€ Entity Performance â”€â–º Learning
    â””â”€â”€ Academy Knowledge â”€â”€â–º Learning
                                    â”‚
                                    â–¼
                        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                        â”‚  Learning Engine      â”‚
                        â”‚  (ingest â†’ analyze â†’  â”‚
                        â”‚   update â†’ validate)  â”‚
                        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                    â”‚
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â–¼               â–¼               â–¼
            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
            â”‚ Reasoning  â”‚  â”‚  Planner   â”‚  â”‚ Knowledge  â”‚
            â”‚ (improved) â”‚  â”‚ (improved) â”‚  â”‚ (updated)  â”‚
            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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
Process: validate evidence â†’ extract outcome data â†’ classify outcome type
Output: IngestedOutcome { outcome_id, extracted_pattern, confidence }
Validation: evidence chain must be complete (PHI-008)
Event: Sou.LearningIngested
```

### updateModel

```
Input:  model_id, ingested_outcome, update_strategy
Process: apply outcome to model â†’ recalculate parameters â†’ validate update
Output: ModelUpdate { model_id, new_version, change_log }
Validation: new model must not reduce constitutional compliance
Event: Sou.ModelUpdated
```

### evaluateImprovement

```
Input:  model_before, model_after, test_scenarios
Process: run test scenarios on both models â†’ compare results â†’ assess improvement
Output: ImprovementEvaluation { improved: bool, metrics, regression_check }
Event: Sou.ImprovementEvaluated
```

## Learning Example

```
Outcome Event: Mission "Resource-Opt-Q3" completed with 92% goal achievement
Source: LMS (Lifecycle Event)

ingestOutcome:
  Evidence validation: All mission Events present (18 milestones, 3 deviation Events)
  Outcome extraction: Goal achievement = 92%, key success = phased rollout
  Classification: Positive outcome â€” update planning heuristic
  â†’ Event: Sou.LearningIngested { outcome_id, source: "mission", confidence: 0.95 }

updateModel:
  Model: PlanningHeuristic v3.2
  Update: Increase weight of "phased rollout" in resource planning
  Validation: All historical scenarios pass with new heuristic
  â†’ Event: Sou.ModelUpdated { model: "PlanningHeuristic", v3.2 â†’ v3.3 }

evaluateImprovement:
  Test: Run 100 historical missions with old and new heuristic
  Result: Old success rate: 73%, New success rate: 76% (+3%)
  Regression: No scenario regresses by more than 1%
  â†’ Event: Sou.ImprovementEvaluated { improved: true, delta: +3% }
```

## Learning Flow

```
1. Evidence Event arrives at Sou via ACF Stream
2. ingestOutcome validates and classifies the evidence
3. Learning analyzes the outcome against current models
4. If improvement opportunity identified â†’ updateModel
5. evaluateImprovement validates the updated model
6. If improvement confirmed â†’ model deployed to Reasoning/Planner
7. If improvement regresses â†’ model rolled back, learning recorded
```

## Validation Rules

| Rule | Description | Enforcement |
|------|-------------|-------------|
| Evidence Completeness | Every learning update traces to one or more Events | Event Store query |
| No Privacy Leak | Shared models (via Academy) contain no entity-identifiable data | Privacy filter validation |
| Constitutional Integrity | Updated models do not violate any Law or constitutional principle | Constitutional reasoning check |
| Regression Testing | Updated models perform at least as well on historical scenarios | Historical replay |
| Provenance Tracking | Every model version tracks which outcomes informed it | Version metadata |

## Edge Cases â€” Learning

| Scenario | Handling |
|----------|----------|
| Outcome evidence is partially missing | Learning uses available evidence. Missing data is noted. Update has lower confidence. |
| Model update causes regression on historical scenarios | Update is rolled back automatically. Previous model version is restored. Regression report is stored. |
| Privacy filter blocks all outcome data | No learning update occurs. Learning produces privacy block Event. Knowledge store is not updated. |
| Learning rate is too fast (model oscillates) | Learning rate is capped. If oscillation detected, rate is halved automatically. |
| Academy publishes conflicting knowledge | Sou resolves conflicts by recency â€” most recent Academy knowledge takes precedence. |
| Learning from entity performance lacks sufficient data points | Minimum data points required (default: 10). Below minimum, no model update is made. |
| Model update is interrupted mid-operation | Rollback to previous version. Interruption Event recorded. System state is preserved. |

## Learning â€” Relationship to DTS and Academy

| System | Sou Learning Relationship |
|--------|--------------------------|
| DTS (Confidence Engine) | Sou Learning updates ConfidenceCalibration model based on decision outcome accuracy |
| DTS (Trust Scorer) | Sou Learning updates EntityPerformance model based on entity behavior |
| Academy (KMS) | Sou shares learned patterns with Academy for system-wide improvement (CPR-010) |
| Academy (ML Models) | Sou may request ML predictions from Academy-trained models |

## Learning Model Types

Sou maintains several learning models:

| Model | Purpose | Update Source | Consumers |
|-------|---------|---------------|-----------|
| PlanningHeuristic | Resource estimation, milestone timing | Mission outcomes | Planner (002) |
| ReasoningPreference | Option ranking, decision tree weights | Decision outcomes | Reasoning (001) |
| RiskAssessment | Risk identification and probability | Mission outcomes + Security Events | Planner (002) |
| ConfidenceCalibration | DTS confidence accuracy | Decision outcomes (fed to DTS) | DTS (004) |
| EntityPerformance | Entity trust score refinement | Entity Events (fed to Trust Scorer) | DTS Trust Scorer |

Each model is versioned independently. Models may be shared with the Academy for system-wide improvement.

## Events

| SOU.EventType |    Produced When | Fields |
|-----------|--------------|--------|
| SOU.LearningIngested |    Outcome evidence is ingested | outcome_id, source_type, evidence_hash |
| SOU.ModelUpdated |    A learning model is updated | model_id, old_version, new_version, change_summary |
| SOU.ImprovementEvaluated |    An improvement is evaluated | model_id, improved, metrics |
| SOU.ModelRolledBack |    A model update is rolled back | model_id, version, regression_details |
| SOU.LearningPrivacyBlocked |    Learning input blocked by privacy filter | outcome_id, privacy_rule_violated |
| SOU.KnowledgeSharedWithAcademy |    Learned pattern shared with Academy | knowledge_id, pattern_type |

## Error Cases

| Condition | Error Code | Severity | Recovery |
|-----------|------------|----------|----------|
| Evidence event not found in Event Store | SOU_LRN_001 | High | Skip ingestion; log missing event for audit |
| Privacy filter blocked outcome ingestion | SOU_LRN_002 | Medium | Record privacy block event; do not ingest |
| Model update fails constitutional validation | SOU_LRN_003 | Critical | Roll back to previous model version; log validation failure |
| Regression test failure â€” improved model performs worse | SOU_LRN_004 | High | Roll back automatically; restore previous version; log regression report |
| Evidence chain incomplete â€” missing causal Events | SOU_LRN_005 | Medium | Continue with partial evidence; reduce confidence on affected models |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SOU-LRN-001 | Learning never produces recommendations that violate Laws | Algorithmic â€” constitutional validation before model deployment |
| SOU-LRN-002 | Every learning update traces to specific Evidence Events | Schema â€” evidence_chain required in ModelUpdate |
| SOU-LRN-003 | Learning does not expose entity-identifiable information in shared models | Governance â€” privacy filter enforced before Academy sharing |
| SOU-LRN-004 | Model updates are always validated before deployment | API-level â€” evaluateImprovement runs before model activation |

| BRAIN-002 | Sou is the only component with strategic decision authority. | Constitutional - SOU-001. Verified by Security Council. |
| BRAIN-005 | Every user-facing response passes through Sou. | Constitutional - SOU-005. ACF routing enforced. |
## Cross-Cutting Concerns

### Security

Learning models are Sou's internal state. Access is controlled by the Security Council. Models shared with the Academy are privacy-filtered. Learning Events are recorded for audit. (Physics/008-Security.md)

### Evidence

Learning is evidence-driven (PHI-008). Every model update traces to specific Evidence Events. Learning without evidence is a constitutional violation. (Physics/005-Events.md, Physics/012-Experience.md)

### Lifecycle

Learning models have a version lifecycle: Created â†’ Trained â†’ Validated â†’ Deployed â†’ Deprecated â†’ Archived. Each version is tracked. (Physics/006-Lifecycles.md)

### Capability Bounds

Sou learns only from evidence it is authorized to access. Learning about entities requires their authorization level. Cross-entity learning requires Academy mediation. (Physics/007-Capabilities.md)

### Communication

Learning communicates via ACF. Academy knowledge is received as evidence. Updated models are distributed to Reasoning and Planner internally. Patterns may be shared with Academy through ACF streams. (Law 3 â€” Communication)

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 â€” Modulsingularity | Learning is focused solely on self-improvement from evidence |
| R2 â€” Dependency Order | Learning depends on Event Store, Memory OS, Academy; no upward dependencies |
| R3 â€” DRY | Learned patterns are stored in Knowledge, not re-learned |
| R4 â€” Builder Pattern | Model updates are built through the ingest â†’ update â†’ validate pipeline |
| R5 â€” Liskov Substitution | All learning models implement the LearningModel interface |
| R6 â€” DI over Singletons | Event Store and Memory OS clients are injected dependencies |
| R9 â€” Deterministic | Learning from the same evidence produces the same update |
| R10 â€” Simpler Over Complex | Learning uses the simplest sufficient model for each outcome type |
| R13 â€” Design for Failure | Learning failures do not block Sou operations â€” stale models are used |
| R14 â€” Paved Path | All learning flows through ingestOutcome â†’ updateModel â†’ evaluateImprovement |
| R15 â€” Open/Closed | New learning models added by extending LearningModel, not by modifying the engine |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence â€” learning consumes Event store |
| Physics/012-Experience.md | Experience â€” learning is Sou's experience mechanism |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou overview â€” learning is a capability of the executive intelligence |
| Bible/02-Core/Brain/Sou/001-Reasoning.md | Reasoning â€” learning improves reasoning models |
| Bible/02-Core/Brain/Sou/002-Planner.md | Planning â€” learning improves planning heuristics |
| Bible/02-Core/Brain/Sou/003-Missions.md | Missions â€” learning from mission outcomes |
| Bible/02-Core/Brain/Sou/005-Knowledge.md | Knowledge â€” learning stores patterns in Memory OS |
| Bible/02-Core/Brain/Memory/000-Overview.md | Memory OS â€” stores learned patterns |
| Bible/02-Core/Academy | Academy â€” Sou consumes evidence from Academy |
| Bible/02-Core/DTS/004-Confidence.md | Confidence â€” learning updates confidence models |
| Bible/01-Governance/002-DGP.md | DGP â€” learning from decision outcomes |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles (esp. CPR-009, CPR-010) |
