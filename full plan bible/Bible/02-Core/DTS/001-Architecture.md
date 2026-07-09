# AIOS Bible — Core
## DTS 001 — Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-DTS-001 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document describes the internal architecture of the Decision & Trust System, including the component diagram, data flow, and clustering topology. DTS is a mission-critical system — its architecture emphasizes availability for trust queries and consistency for confidence scoring.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     DTS Application Layer                      │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │  Decision Evaluator │    │   Trust Scorer     │            │
│  │                    │    │                    │            │
│  │  - evaluate()      │    │  - getScore()      │            │
│  │  - validate()      │    │  - updateScore()   │            │
│  │  - categorize()    │    │  - decayScores()   │            │
│  └────────┬───────────┘    └────────┬───────────┘            │
│           │                        │                          │
│           ▼                        ▼                          │
│  ┌──────────────────────────────────────────────┐            │
│  │           Confidence Engine (004)              │            │
│  │                                                │            │
│  │  - calculateConfidence()                       │            │
│  │  - getConfidenceHistory()                      │            │
│  │  - updateConfidenceModel()                     │            │
│  └────────────────────┬───────────────────────────┘            │
│                       │                                        │
│                       ▼                                        │
│  ┌──────────────────────────────────────────────┐            │
│  │           Sim Pipeline (002)                  │            │
│  │                                                │            │
│  │  Scenario Generation → Simulation → Prediction │            │
│  └────────────────────┬───────────────────────────┘            │
│                       │                                        │
│                       ▼                                        │
│  ┌──────────────────────────────────────────────┐            │
│  │           Sim Engines (003)                   │            │
│  │                                                │            │
│  │  PlanningSim | MonteCarlo | ConstraintSolver  │            │
│  └──────────────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                     DTS Data Layer                              │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │  Confidence Store  │    │   Trust Store       │            │
│  │  (primary +       │    │  (read replicas)    │            │
│  │   read replicas)  │    │                     │            │
│  └────────────────────┘    └────────────────────┘            │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │  Simulation Cache  │    │   Score History    │            │
│  │  (LRU, TTL-based)  │    │   (Event Store)    │            │
│  └────────────────────┘    └────────────────────┘            │
└──────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Decision Evaluator

The Decision Evaluator processes incoming decision proposals from Sou (and other authorized entities). It:

| Function | Description |
|----------|-------------|
| evaluate(decision) | Runs full evaluation: evidence check → constraint check → confidence scoring → risk assessment |
| validate(decision) | Validates the decision proposal structure and evidence chain completeness |
| categorize(decision) | Categorizes the decision type (strategic, operational, constitutional, etc.) for appropriate scoring model |

### Trust Scorer

The Trust Scorer maintains per-entity trust scores. It:

| Function | Description |
|----------|-------------|
| getScore(entity_id) | Returns current trust score (0.0–1.0) with decomposition |
| updateScore(entity_id, event) | Adjusts trust score based on a new evidence Event |
| decayScores() | Periodically decays all scores that lack recent evidence |

Trust score components:

| Component | Weight | Source |
|-----------|--------|--------|
| Constitutional compliance | 50% | Security Council violation events |
| Mission completion rate | 25% | LMS mission lifecycle events |
| Evidence accuracy | 15% | Academy evidence verification |
| Response reliability | 10% | Communication latency and error rate |

### Confidence Engine

The Confidence Engine produces confidence intervals for decisions. It combines evidence quality, simulation accuracy, historical precedent, and entity trustworthiness into a single confidence interval. See DTS/004-Confidence.md for full details.

## Data Flow

```
1. Sou proposes decision → DTS receives via ACF
2. Decision Evaluator categorizes the decision type
3. Confidence Engine queries Trust Scorer for proposer's trust score
4. Sim Pipeline generates scenarios and runs simulations (if needed)
5. Confidence Engine combines: evidence quality + simulation + precedent + trust
6. Decision Evaluator produces EvaluationResult { confidence_interval, risk_level, recommendations }
7. Result sent to Sou and DGP via ACF
```

## DTS Clustering

DTS uses an active-passive clustering topology:

| Role | Description | Reads | Writes |
|------|-------------|-------|--------|
| Primary (active) | Handles all confidence scoring and trust updates | Yes | Yes |
| Replica 1 | Read-only trust queries | Yes | No |
| Replica 2 | Read-only trust queries | Yes | No |
| Replica N | Additional replicas as needed | Yes | No |

### Failover

If the primary fails, a replica is promoted to primary. The new primary replays Event Store to reconstruct state. During failover, DTS returns cached confidence scores (with a warning header).

## DTS Component Interfaces

### Decision Evaluator Interface

```
interface DecisionEvaluator {
  evaluate(decision: DecisionProposal): EvaluationResult;
  validate(decision: DecisionProposal): ValidationReport;
  categorize(decision: DecisionProposal): DecisionCategory;
}

interface EvaluationResult {
  decision_id: UUID;
  category: DecisionCategory;
  confidence_interval: [float, float];
  risk_level: RiskLevel;
  recommendations: Recommendation[];
  simulation_id: UUID | null;
  evaluated_at: Timestamp;
  components: ConfidenceComponents;  // for decomposition
}
```

### Trust Scorer Interface

```
interface TrustScorer {
  getScore(entity_id: UUID): TrustScore;
  updateScore(entity_id: UUID, event: EvidenceEvent): ScoreDelta;
  decayScores(): DecayReport;
  getScoreHistory(entity_id: UUID, time_range: DateRange): ScoreEntry[];
}

interface TrustScore {
  entity_id: UUID;
  score: float;           // 0.0-1.0
  components: {            // weighted contributions
    constitutional_compliance: float;
    mission_completion: float;
    evidence_accuracy: float;
    response_reliability: float;
  };
  last_updated: Timestamp;
  data_points: int;       // number of evidence Events contributing
}
```

## DTS Integrations

| System | Integration | Protocol |
|--------|-------------|----------|
| Sou | Receives decision proposals, sends confidence scores | ACF command/response |
| DGP | Sends confidence scores for routing decisions | ACF event stream |
| Security Council | Receives evaluation reports for low-confidence decisions | ACF event stream |
| Event Store | Reads evidence Events for scoring | ACF stream subscription |
| Academy | Queries for historical pattern data | ACF command/response |
| Sim Engines | Invokes simulation engines | ACF command/response |

## DTS Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `DTS.EvaluationStarted` | Decision evaluation begins | decision_id, category, proposer |
| `DTS.EvaluationCompleted` | Evaluation finishes | decision_id, confidence_interval, risk_level |
| `DTS.TrustScoreChanged` | Entity trust score changes | entity_id, delta, new_score, reason_event |
| `DTS.ClusterRoleChanged` | DTS cluster role changes | node_id, old_role, new_role |
| `DTS.ReplicaSynced` | Read replica synchronization completes | replica_id, lag_events |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| DTS_ARC_001 | Decision proposal missing required evidence chain |
| DTS_ARC_002 | Trust scorer unavailable — all replicas down |
| DTS_ARC_003 | Confidence engine timeout — simulation exceeded time budget |
| DTS_ARC_004 | Decision category unknown — cannot select scoring model |
| DTS_ARC_005 | Cluster failover in progress — returning cached scores |

## Cross-Cutting Concerns

### Security

DTS evaluates trust — its own trustworthiness is critical. All DTS component communications are authenticated and authorized. Cluster state changes are security Events. (Physics/008-Security.md)

### Evidence

Every evaluation and score update produces an Event. The complete score history is an immutable record in the Event Store. (PHI-008)

### Lifecycle

Decision evaluations have a pipeline lifecycle: Submitted → Categorized → Evaluated → Scored → Reported. Trust scores decay over time (lifecycle: Active → Decaying → Stale). (Physics/006-Lifecycles.md)

### Capability Bounds

DTS evaluates and scores — it does not make or execute decisions. It may not block execution unilaterally — the Security Council retains that authority. (Physics/007-Capabilities.md)

### Communication

All DTS communications use ACF. Inter-component calls within DTS also use ACF (no direct IPC). (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each DTS component has a single responsibility |
| R2 (Dependency Order) | DTS depends on Event Store and Sou — no circular dependencies |
| R5 (Liskov) | Sim Engines implement a common interface |
| R6 (DI) | Confidence Engine receives Trust Scorer and Sim Pipeline through injection |
| R10 (Simpler Over Complex) | Active-passive clustering — simpler than multi-primary |
| R13 (Design for Failure) | Failover returns cached scores — evaluation never blocks indefinitely |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — DTS consumes and produces Events |
| Physics/012-Experience.md | Experience — trust scoring model |
| Bible/02-Core/DTS/000-Overview.md | DTS overview — architecture context |
| Bible/02-Core/DTS/002-Sim-Pipeline.md | Sim Pipeline — invoked by Confidence Engine |
| Bible/02-Core/DTS/003-Sim-Engines.md | Sim Engines — pluggable simulation backends |
| Bible/02-Core/DTS/004-Confidence.md | Confidence — confidence engine details |
| Bible/01-Governance/002-DGP.md | DGP — consumes DTS confidence scores |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
