# AIOS Bible — Core
## DTS 004 — Confidence Scoring

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-DTS-004 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Confidence Scoring quantifies how certain DTS is about a decision's correctness. It combines evidence quality, simulation accuracy, historical precedent, and entity trustworthiness into a single confidence interval (0.0–1.0). Confidence scores inform governance decisions — they are the primary input for determining whether a decision requires additional verification or can proceed autonomously.

## Confidence Score Model

The confidence score is a weighted combination of four components:

```
Confidence = (Evidence × 0.40) + (Simulation × 0.30) + (Precedent × 0.20) + (Trust × 0.10)
```

### Component 1 — Evidence Quality (40% weight)

Measures the quality and completeness of evidence supporting the decision.

| Factor | Weight Within Component | Source |
|--------|------------------------|--------|
| Evidence completeness | 40% | Ratio of required evidence fields populated |
| Evidence recency | 25% | Time-weighted freshness of evidence |
| Evidence source reliability | 20% | Trust score of evidence providers |
| Evidence consistency | 15% | Degree of agreement across evidence sources |

```
evidence_score = 0.40 × completeness + 0.25 × recency + 0.20 × source_reliability + 0.15 × consistency
```

### Component 2 — Simulation Accuracy (30% weight)

Measures how accurate the simulation engine has been for similar decisions historically.

| Factor | Weight Within Component | Source |
|--------|------------------------|--------|
| Engine historical accuracy | 50% | Engine accuracy metrics (DTS/003-Sim-Engines.md) |
| Simulation convergence | 25% | How well Monte Carlo runs converged |
| Scenario coverage | 25% | Percentage of relevant scenarios covered |

```
simulation_score = 0.50 × engine_accuracy + 0.25 × convergence + 0.25 × scenario_coverage
```

### Component 3 — Historical Precedent (20% weight)

Measures how similar past decisions turned out.

| Factor | Weight Within Component | Source |
|--------|------------------------|--------|
| Precedent match quality | 50% | Similarity score between current and past decisions |
| Precedent outcome success | 30% | Historical success rate of similar decisions |
| Precedent recency | 20% | Time-weighted relevance of past decisions |

```
precedent_score = 0.50 × match_quality + 0.30 × success_rate + 0.20 × recency
```

### Component 4 — Entity Trustworthiness (10% weight)

Measures the trust score of the entity proposing the decision.

| Factor | Weight Within Component | Source |
|--------|------------------------|--------|
| Trust score | 60% | Current trust score from Trust Scorer |
| Trust trend | 25% | Whether trust is improving or declining |
| Decision history | 15% | Entity's track record with similar decision types |

```
trust_score_component = 0.60 × trust_score + 0.25 × trust_trend + 0.15 × decision_history
```

## Final Confidence Calculation

```
confidence_raw = (evidence_score × 0.40) + (simulation_score × 0.30) + (precedent_score × 0.20) + (trust_score_component × 0.10)

confidence_interval = [
  max(0.0, confidence_raw - uncertainty_margin),
  min(1.0, confidence_raw + uncertainty_margin)
]

where uncertainty_margin = f(simulation_convergence, evidence_consistency)
  = 0.10 × (1 - simulation_convergence) + 0.05 × (1 - evidence_consistency)
```

DTS NEVER returns a point estimate. It always returns a confidence interval.

## Confidence Thresholds

| Range | Action | Description |
|-------|--------|-------------|
| 0.9 – 1.0 | **Execute autonomously** | Decision may proceed without additional verification |
| 0.7 – 0.9 | **Execute with monitoring** | Decision may proceed but must be monitored (enhanced observability) |
| 0.5 – 0.7 | **Require human confirmation** | Decision must be reviewed by a human operator before execution |
| 0.0 – 0.5 | **Do not execute** | Decision confidence is too low — requires re-evaluation |

## Confidence Decomposition

When asked "Why is confidence at [interval]?", DTS returns:

```
{ decision_id: "dec-0042",
  confidence_interval: [0.72, 0.86],
  components: {
    evidence_quality: {
      score: 0.85,
      weight: 0.40,
      contribution: 0.340,
      factors: { completeness: 0.90, recency: 0.82, source_reliability: 0.85, consistency: 0.80 }
    },
    simulation_accuracy: {
      score: 0.72,
      weight: 0.30,
      contribution: 0.216,
      factors: { engine_accuracy: 0.78, convergence: 0.70, coverage: 0.65 }
    },
    historical_precedent: {
      score: 0.68,
      weight: 0.20,
      contribution: 0.136,
      factors: { match_quality: 0.65, success_rate: 0.72, recency: 0.60 }
    },
    entity_trustworthiness: {
      score: 0.82,
      weight: 0.10,
      contribution: 0.082,
      factors: { trust_score: 0.85, trust_trend: 0.78, decision_history: 0.80 }
    }
  },
  raw_total: 0.774,
  uncertainty_margin: 0.07,
  final_interval: [0.704, 0.844]
}
```

## Edge Cases

| Scenario | Handling |
|----------|----------|
| No simulation run | simulation_score = 0.0 → confidence halved |
| No historical precedent | precedent_score = 0.3 (default minimal) |
| New entity (no trust history) | trust_score_component = 0.3 (default starting trust) |
| Conflicting evidence | evidence_consistency factor reduces confidence |
| Simulation time budget exceeded | partial simulation results used, uncertainty margin increased |

## Confidence Operations

### calculateConfidence(decision, evidence, simulation_result)

```
Input:  decision, evidence (evidence metadata), simulation_result (from Sim Pipeline)
Process:
  1. Compute evidence_score from evidence metadata
  2. Compute simulation_score from simulation results
  3. Compute precedent_score from Event Store history
  4. Query Trust Scorer for trust_score_component
  5. Combine with weights
  6. Compute uncertainty margin
  7. Produce confidence interval
Output: ConfidenceResult { interval, components, uncertainty_margin }
Event: DTS.ConfidenceCalculated
```

### getConfidenceHistory(decision_id)

```
Input:  decision_id
Process: query Event Store for all confidence calculations for this decision
Output: ConfidenceHistoryEntry[]
```

### updateConfidenceModel(event)

```
Input:  event (an outcome Event — the actual result after the decision was executed)
Process:
  1. Compare predicted outcome with actual outcome
  2. Adjust component weights: increase weight of more accurate components
  3. Update engine accuracy metrics
  4. Update precedent database
Output: ModelUpdate { new_weights, accuracy_improvement }
Event: DTS.ConfidenceModelUpdated
```

## Confidence Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `DTS.ConfidenceCalculated` | Confidence is calculated for a decision | decision_id, interval, component_scores |
| `DTS.ConfidenceModelUpdated` | Confidence model weights are adjusted | model_version, new_weights, adjustment_reason |
| `DTS.ConfidenceThresholdExceeded` | A threshold boundary is crossed | decision_id, threshold, action_required |
| `DTS.ConfidenceDecomposed` | A confidence score is decomposed on request | decision_id, decomposition |
| `DTS.ConfidencePredictionCompared` | Predicted vs actual outcome compared | decision_id, predicted_interval, actual_outcome |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| DTS_CON_001 | Evidence metadata missing — cannot compute evidence_score |
| DTS_CON_002 | Simulation result missing — cannot compute simulation_score |
| DTS_CON_003 | Trust Scorer unavailable — using default trust score |
| DTS_CON_004 | Confidence model not found — using baseline weights |
| DTS_CON_005 | Confidence interval is NaN — invalid calculation |

## Cross-Cutting Concerns

### Security

Confidence scores influence authorization. Low confidence triggers additional verification. Confidence model updates must be authenticated and authorized. (Physics/008-Security.md)

### Evidence

Confidence is entirely evidence-derived. The model is transparent — every score decomposes into evidence components. DTS Never adds synthetic confidence. (PHI-008)

### Lifecycle

Confidence calculations follow a request lifecycle: Requested → Calculated → Stored → (optionally) Recalculated after outcome. Models have a version lifecycle. (Physics/006-Lifecycles.md)

### Capability Bounds

Confidence scoring may not block execution unilaterally — it informs governance. The Security Council may override confidence recommendations. (Physics/007-Capabilities.md)

### Communication

Confidence requests arrive via ACF. Results are returned via ACF. Model updates are broadcast via ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Confidence engine focused solely on scoring |
| R3 (DRY) | Scoring model is the single source of truth — no redundant scoring algorithms |
| R9 (Deterministic) | Same inputs produce same confidence interval |
| R10 (Simpler Over Complex) | Linear weighted model — simpler than machine learning for this purpose |
| R12 (Embrace Errors) | All errors have unique codes (DTS_CON_001–005) |
| R13 (Design for Failure) | Missing component returns reduced confidence — does not fail |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — confidence consumes evidence metadata |
| Physics/012-Experience.md | Experience — confidence model learns from outcomes |
| Bible/02-Core/DTS/000-Overview.md | DTS overview — confidence is a core DTS output |
| Bible/02-Core/DTS/001-Architecture.md | Architecture — confidence engine component |
| Bible/02-Core/DTS/002-Sim-Pipeline.md | Pipeline — simulation feeds confidence |
| Bible/02-Core/DTS/003-Sim-Engines.md | Engines — simulation accuracy weights |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — Sou proposes decisions for confidence scoring |
| Bible/02-Core/Sou/004-Learning.md | Learning — confidence model updates feed Sou learning |
| Bible/01-Governance/002-DGP.md | DGP — confidence thresholds inform routing |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
