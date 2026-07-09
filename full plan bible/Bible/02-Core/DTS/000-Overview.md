# AIOS Bible — Core
## DTS 000 — Overview (Decision & Trust System)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-DTS-000 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Decision & Trust System (DTS) evaluates decisions and assesses trust within AIOS. It answers two fundamental questions:

1. **"How confident are we that this decision is correct?"** — DTS evaluates proposals from Sou and produces confidence scores.
2. **"How trustworthy is this entity?"** — DTS maintains per-entity trust scores based on constitutional compliance history.

DTS enables informed governance. It ensures that decisions are made with appropriate caution and that entities are trusted proportional to their demonstrated reliability.

## What DTS Is Not

DTS is NOT:
- A decision-maker (DTS scores decisions, it does not make them)
- A governance system (DTS informs governance, it does not govern)
- An execution engine (DTS evaluates decisions before execution, it does not execute)
- A learning system (DTS produces learning inputs, but Sou's Learning engine does the learning)
- A security system (DTS evaluates trust, but the Security Council authorizes)

## DTS Core Questions

| Question | Answer | Consumer |
|----------|--------|----------|
| Is this decision correct? | Confidence interval (0.0–1.0) | Sou, DGP |
| Can we trust this entity? | Trust score (0.0–1.0) | Security Council |
| Should we simulate this decision? | Simulation recommendation (yes/no/partial) | Sim Pipeline |
| What would happen if we execute? | Predicted outcome with risks | Sou Planner |
| Why is confidence at this level? | Decomposed score with component contributions | All consumers |

## DTS Inputs and Outputs

| Input | Source | Description |
|-------|--------|-------------|
| Decision Proposal | Sou (Reasoning) | The decision to evaluate |
| Evidence Events | Event Store (Physics/005) | Evidence supporting or contradicting the decision |
| Entity Identity | IDS | Identity of the entity proposing the decision |
| Current Trust Score | DTS Trust Scorer | Trustworthiness of the proposer |
| Historical Precedent | Event Store | Outcomes of similar past decisions |

| Output | Destination | Description |
|--------|-------------|-------------|
| Confidence Interval | Sou, DGP, Security Council | How confident DTS is in the decision |
| Trust Score | Security Council, Sou | Trustworthiness of an entity |
| Risk Assessment | Sou, DGP | Potential risks of executing the decision |
| Simulation Results | Sou Planner | Outcome predictions to refine planning |
| Confidence Decomposition | Any requester | Breakdown of confidence into components |

## DTS Architecture

```
┌──────────────────────────────────────────────────────────┐
│                Decision & Trust System                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Decision   │  │     Trust    │  │  Confidence  │   │
│  │  Evaluator   │  │   Scorer     │  │   Engine     │   │
│  │              │  │              │  │              │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │            │
│         ▼                 ▼                 ▼            │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Sim Pipeline (002)                   │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐│   │
│  │  │Scenario │ │Sim      │ │Outcome  │ │Conf.    ││   │
│  │  │Gen.     │ │Engine   │ │Predict  │ │Score    ││   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘│   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  ┌──────────────┐    ┌──────────────┐
  │     Sou      │    │  Security    │
  │  (decisions) │    │  Council     │
  └──────────────┘    │  (auth)      │
                      └──────────────┘
```

## DTS Components

| Component | Document | Function |
|-----------|----------|----------|
| Decision Evaluator | DTS/001-Architecture.md | Evaluates proposed decisions against evidence and constitutional constraints |
| Trust Scorer | DTS/001-Architecture.md | Maintains per-entity trust scores based on compliance history |
| Confidence Engine | DTS/004-Confidence.md | Produces confidence intervals for decisions (0.0–1.0) |
| Sim Pipeline | DTS/002-Sim-Pipeline.md | Simulates decisions before execution to predict outcomes |
| Sim Engines | DTS/003-Sim-Engines.md | Available simulation engines plugging into the pipeline |

## DTS Invariants

1. **Evidence-Driven Scoring**: Every confidence score and trust score must be derived from evidence Events. Unexplained scores are prohibited. (PHI-008, CPR-004)

2. **Confidence is a Range**: DTS never produces a single confidence value — it always produces a confidence interval with bounds. False precision is prohibited. (CPR-003)

3. **Trust Is Per-Entity and Decays**: Trust scores are per-entity, time-weighted, and decay without recent evidence. Stale trust is low trust. (PHI-006)

4. **Simulation Before Execution**: Every decision with confidence < 0.9 must be simulated before execution. High-confidence decisions may proceed directly. (Law 8 — Verification-First)

5. **Transparency**: All confidence scores and trust scores are explainable. Any score can be decomposed into its contributing factors. (PHI-001)

## DTS Decision Flow — Example

```
1. Sou proposes: "Increase Worker-A memory allocation from 8GB to 16GB"
2. DTS Decision Evaluator receives proposal
3. Evidence check: Query Event Store for Worker-A memory utilization Events
   → Found: Worker-A avg utilization 85%, max 97% (last 30 days)
   → Evidence quality: 0.90 (comprehensive data)
4. Trust check: Worker-A's trust score = 0.88
   → Trust trend: Improving (+0.05 over 30 days)
5. Simulation: Run Monte Carlo with 1000 scenarios
   → 95th percentile outcome: 35% performance improvement
   → Risk: memory contention with neighboring Workers (12% probability)
6. Historical precedent: 23 similar memory allocation changes
   → 19 successful (83% success rate)
7. Confidence calculation:
   Evidence: 0.90 × 0.40 = 0.360
   Simulation: 0.85 × 0.30 = 0.255
   Precedent: 0.83 × 0.20 = 0.166
   Trust: 0.88 × 0.10 = 0.088
   Total: 0.869 (interval: [0.819, 0.919])
8. Threshold: 0.7 ≤ 0.869 < 0.9 → "Execute with monitoring"
9. DTS sends confidence score to Sou and DGP
```

## Edge Cases — DTS Operations

| Scenario | Handling |
|----------|----------|
| No simulation engine available for decision type | simulation_score = 0.0. Confidence is reduced. Warning returned. |
| Trust Scorer data is stale (no recent Events) | Score decayed to default (0.3). Low trust weight applied. |
| Evidence Event stream is empty | evidence_score = 0.0. Decision confidence starts at minimum. |
| Historical precedent database has no matches | precedent_score = 0.3 (default minimum). No negative adjustment. |
| Confidence interval calculation produces NaN | Fallback: [0.0, 0.0] with error code DTS_CON_005. |
| Decision is in Human Override threshold | Confidence overridden to 0.0 — decision requires human confirmation regardless. |

## DTS Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `DTS.DecisionEvaluated` | A decision is evaluated | decision_id, confidence_interval, risk_level |
| `DTS.TrustScoreUpdated` | An entity's trust score changes | entity_id, old_score, new_score, reason |
| `DTS.SimulationRun` | A simulation is executed | sim_id, decision_id, engine_type, outcome |
| `DTS.ScenarioGenerated` | A simulation scenario is generated | scenario_id, parameters, constraints |
| `DTS.ConfidenceThresholdExceeded` | Decision confidence crosses a threshold | decision_id, threshold, action_required |
| `DTS.TrustDecayApplied` | Trust scores are decayed for inactivity | entity_id, decay_factor, time_period |

## Cross-Cutting Concerns

### Security

DTS confidence scores influence authorization decisions. Low confidence can trigger additional verification by the Security Council. Trust scores are protected from manipulation — only evidence-based changes are accepted. (Physics/008-Security.md)

### Evidence

Every DTS operation produces an Event. Confidence scores are decomposed into their evidence components. Trust scores are based on Events, not subjective assessment. (PHI-008)

### Lifecycle

Decision evaluation follows a pipeline lifecycle: Submitted → Simulated → Scored → Reviewed → Executed. Trust scores have a decay lifecycle — refreshed by evidence, decayed by time. (Physics/006-Lifecycles.md)

### Capability Bounds

DTS evaluates and scores — it does not make decisions. Confidence scores inform but do not determine governance outcomes. The Security Council retains final authority. (Physics/007-Capabilities.md)

### Communication

All DTS evaluations arrive via ACF. Results are communicated back to Sou, the Security Council, and relevant governance entities via ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | DTS focused solely on decision evaluation and trust scoring |
| R3 (DRY) | Scoring models are shared between Decision Evaluator and Trust Scorer |
| R5 (Liskov) | All simulation engines implement the SimEngine interface |
| R10 (Simpler Over Complex) | Confidence scoring uses additive component model, not neural networks |
| R12 (Embrace Errors) | All errors have unique codes |
| R13 (Design for Failure) | Sim pipeline degrades — returns partial confidence if some engines unavailable |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — DTS consumes Events for scoring |
| Physics/012-Experience.md | Experience — trust is built from experience evidence |
| Bible/02-Core/DTS/001-Architecture.md | DTS architecture — component diagram and data flow |
| Bible/02-Core/DTS/002-Sim-Pipeline.md | Sim Pipeline — simulation pipeline |
| Bible/02-Core/DTS/003-Sim-Engines.md | Sim Engines — available simulation engines |
| Bible/02-Core/DTS/004-Confidence.md | Confidence — confidence engine details |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — DTS evaluates Sou's reasoning proposals |
| Bible/02-Core/Sou/002-Planner.md | Planner — DTS evaluates Sou's plans |
| Bible/01-Governance/002-DGP.md | DGP — DTS confidence informs DGP routing decisions |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
