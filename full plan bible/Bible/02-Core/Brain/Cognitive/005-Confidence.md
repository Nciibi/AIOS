# AIOS Bible â€” Brain
## 005 â€” Confidence

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-005 |
| Source Laws | Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Confidence scoring quantifies how certain Sou is about each thought step, reasoning chain, and conclusion. It provides per-step confidence estimation, aggregate confidence across chains, calibration against historical accuracy, evidence-based confidence adjustment, and a framework for handling low-confidence situations. Confidence scores drive metacognitive decisions â€” whether to continue, request more information, qualify an answer, or defer entirely. Confidence thresholds gate actions across all Cognitive OS components.

## Data Model

### ConfidenceRequest

```typescript
ConfidenceRequest {
  request_id: string
  target_id: string
  target_type: "step" | "chain" | "decision" | "evidence_set"
  context: {
    chain?: ThoughtStep[]
    evidence_quality?: EvidenceQuality
    historical_accuracy?: number
    calibration_curve_id?: string
    difficulty_estimate?: number      // 0.0â€“1.0
    task_type?: string
    similar_tasks_accuracy?: number
  }
  options?: {
    include_per_step: boolean
    include_decomposition: boolean    // Show factors contributing to confidence
    low_confidence_threshold: number  // Default 0.5
  }
}
```

### ConfidenceOutput

```typescript
ConfidenceOutput {
  request_id: string
  target_id: string
  target_type: string
  score: number                      // 0.0â€“1.0 final confidence
  calibrated_score: number           // Score adjusted by calibration curve
  decomposition: ConfidenceDecomposition
  low_confidence_actions: LowConfidenceAction[]
  threshold_assessment: {
    above_threshold: boolean
    threshold_used: number
    exceeded_by: number
  }
  metadata: {
    calibration_applied: boolean
    calibration_offset: number
    evidence_adjustment: number
    volatility: number               // Variance across input factors
    computed_at: timestamp
    llmos_usage?: {
      tokens_consumed: number
      model_used: string
      latency_ms: number
    }
  }
}

ConfidenceDecomposition {
  base_confidence: number            // Raw score before adjustments
  evidence_quality_factor: number    // Adjustment from evidence quality
  calibration_factor: number         // Adjustment from historical calibration
  complexity_penalty: number         // Penalty for task difficulty
  bias_adjustment: number            // Adjustment from bias detection
  final_score: number                // After all adjustments applied
}
```

### EvidenceQuality

```typescript
EvidenceQuality {
  average_reliability: number        // 0.0â€“1.0
  recency_score: number              // 0.0â€“1.0 (1.0 = current)
  consistency_score: number          // 0.0â€“1.0 (1.0 = fully consistent)
  completeness_score: number         // 0.0â€“1.0 (1.0 = no gaps)
  relevance_score: number            // 0.0â€“1.0 (1.0 = directly relevant)
  conflicts: number                  // Count of contradictory evidence
  overall_quality: number            // Weighted aggregate
}
```

### LowConfidenceAction

```typescript
LowConfidenceAction {
  action_id: string
  type: "request_more_info" | "qualify_answer" | "defer" | "switch_strategy" | "escalate"
  trigger_reason: string
  confidence_at_trigger: number
  threshold: number
  suggestion: string                 // What to do next
  priority: number                   // 0.0â€“1.0 urgency
  executed: boolean
}

ConfidenceThresholds {
  auto_act: number                   // â‰¥ 0.9 â€” Proceed without review
  normal_act: number                 // â‰¥ 0.7 â€” Proceed with normal review
  qualify: number                    // â‰¥ 0.4 â€” Qualify answer with uncertainty
  request_info: number               // â‰¥ 0.2 â€” Request more information
  defer: number                      // < 0.2 â€” Defer decision entirely
}

ConfidenceCalibrationCurve {
  curve_id: string
  bins: CalibrationBin[]
  calibration_error: number
  sample_size: number
  last_updated: timestamp
  metadata: {
    domain?: string
    model_used?: string
    task_type?: string
  }
}
```

## Core Concepts

### 1. Confidence Scoring Per Thought Step

```
ThoughtStep {
  content: "The database timeout suggests a connection pool exhaustion"
  confidence: 0.82                   â† Per-step confidence
}
```

Each step receives a confidence score at generation time:

```
Step confidence = f(
  llmos_logprobs,              // Model's own probability estimate
  evidence_support,            // How well evidence supports this claim
  step_type,                   // Premise (higher) vs inference (lower)
  consistency_with_prior,      // Alignment with earlier steps
  complexity                   // More complex â†’ lower confidence
)
```

The scoring function uses weighted combination, with weights configurable per strategy.

### 2. Confidence Aggregation

```
Chain confidence = aggregate(step_confidences)

Methods:
  - MINIMUM:     chain_conf = min(step_confidences)        // Conservative
  - GEOMETRIC:   chain_conf = prod(step_confidences)^(1/n) // Balanced
  - WEIGHTED:    chain_conf = sum(w_i * step_conf_i)       // Position-weighted
  - DECAY:       chain_conf = weighted with later steps weighted higher

Default: GEOMETRIC â€” penalizes chains where any step is weak.
```

The aggregate method is configurable per pipeline and can be overridden by Sou.

### 3. Confidence Calibration

```
Input: Confidence score (0.0â€“1.0)
         â”‚
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Look up calibration    â”‚
â”‚  bin for this score     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
           â”‚
           â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Retrieve actual        â”‚
â”‚  accuracy for bin       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
           â”‚
           â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  calibrated_score =     â”‚
â”‚  score * (1 - offset)   â”‚
â”‚  where offset =         â”‚
â”‚  |score - bin_accuracy| â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
           â”‚
           â–¼
      Calibrated Confidence
```

Calibration curves are built from historical pairs of (estimated_confidence, actual_correctness). The curve is updated after each decision outcome is known.

### 4. Evidence-Based Confidence Adjustment

```
base_confidence
       â”‚
       â–¼
Evidence Quality Assessment
       â”‚
       â”œâ”€â”€ reliability_factor:   if source_reliability < 0.5 â†’ -0.15
       â”œâ”€â”€ recency_factor:       if evidence_age > 30 days â†’ -0.05
       â”œâ”€â”€ consistency_factor:   if conflicts > 0 â†’ -0.10 per conflict
       â”œâ”€â”€ completeness_factor:  if gaps detected â†’ -0.08
       â””â”€â”€ relevance_factor:     if relevance < 0.6 â†’ -0.12
       â”‚
       â–¼
adjusted_confidence = base_confidence + sum(adjustments)
clamped to [0.0, 1.0]
```

Evidence-based adjustments ensure confidence reflects not just the reasoning quality but also the quality of supporting evidence.

### 5. Low Confidence Handling

```
Confidence Score
       â”‚
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Compare against thresholds     â”‚
â”‚                                 â”‚
â”‚  â‰¥ 0.9 â”€â”€â–º Auto-act (proceed)  â”‚
â”‚  â‰¥ 0.7 â”€â”€â–º Normal act (review) â”‚
â”‚  â‰¥ 0.4 â”€â”€â–º Qualify answer      â”‚
â”‚           ("I'm fairly confident but...") â”‚
â”‚  â‰¥ 0.2 â”€â”€â–º Request more info   â”‚
â”‚           ("I need additional data on X") â”‚
â”‚  < 0.2 â”€â”€â–º Defer               â”‚
â”‚           ("I cannot answer this now")   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Low confidence actions are returned as structured recommendations:

```
LowConfidenceAction: {
  type: "request_more_info",
  suggestion: "Request database connection pool metrics from the monitoring service",
  confidence_at_trigger: 0.35,
  threshold: 0.4,
  priority: 0.8
}
```

### 6. Confidence Thresholds for Actions

| Threshold | Value | Behavior | Example |
|-----------|-------|----------|---------|
| auto_act | â‰¥ 0.9 | Execute without Sou review | Trivial deductions |
| normal_act | â‰¥ 0.7 | Proceed, include in context for Sou | Routine reasoning |
| qualify | â‰¥ 0.4 | Add uncertainty qualifier to output | "Based on available evidence..." |
| request_info | â‰¥ 0.2 | Pause and request additional data | "I need to check X before concluding" |
| defer | < 0.2 | Do not proceed; return "cannot answer" | Insufficient data for any conclusion |

Thresholds are configurable per session and can be overridden by Sou or Metacognition.

## Internal Interface

```typescript
interface ConfidenceEstimator {
  // Core estimation
  estimate(request: ConfidenceRequest): Promise<ConfidenceOutput>
  estimateStep(step: ThoughtStep, context: StepConfidenceContext): Promise<number>
  estimateChain(chain: ThoughtStep[], method: AggregationMethod): Promise<number>
  
  // Calibration
  calibrate(score: number, calibration_curve_id?: string): Promise<number>
  getCalibrationCurve(session_id: string): ConfidenceCalibrationCurve
  updateCalibration(session_id: string, actual: AccuracyFeedback): ConfidenceCalibrationCurve
  resetCalibration(session_id: string): void
  
  // Aggregation
  aggregate(confidences: number[], method: AggregationMethod): number
  setAggregationMethod(method: AggregationMethod): void
  
  // Low confidence
  getLowConfidenceActions(score: number, context: LowConfidenceContext): LowConfidenceAction[]
  handleLowConfidence(action: LowConfidenceAction): Promise<LowConfidenceResolution>
  
  // Thresholds
  getThresholds(): ConfidenceThresholds
  setThresholds(thresholds: Partial<ConfidenceThresholds>): void
  assessAgainstThresholds(score: number): ThresholdAssessment
  
  // Adjustment
  adjustByEvidence(score: number, evidence_quality: EvidenceQuality): number
  adjustByBias(score: number, bias_adjustment: BiasAdjustment): number
  adjustByComplexity(score: number, difficulty: number): number
}

interface StepConfidenceContext {
  step_type: string
  evidence_quality: EvidenceQuality
  prior_step_confidence: number
  logprobs?: number[]
  consistency_score: number
  task_difficulty: number
}

interface AccuracyFeedback {
  session_id: string
  confidence_estimated: number
  was_correct: boolean
  target_id: string
  target_type: string
  domain?: string
}

interface AggregationMethod = "minimum" | "geometric" | "weighted" | "decay"

interface LowConfidenceContext {
  score: number
  goal: string
  available_evidence_count: number
  knowledge_gaps: number
  time_remaining_ms?: number
  alternatives_available: boolean
}

interface LowConfidenceResolution {
  action_id: string
  resolved: boolean
  new_confidence?: number
  resolution_note: string
}

interface ThresholdAssessment {
  score: number
  threshold: number
  above_threshold: boolean
  exceeded_by: number
  action_type: string
}

interface BiasAdjustment {
  overconfidence_offset: number
  total_adjustment: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| COG.COGEvent |  request_id, target_id, score, target_type | Confidence score computed |
| COG.COGEvent |  request_id, step_number, score, decomposition | Individual step confidence assigned |
| COG.COGEvent |  request_id, chain_id, aggregate_score, method | Chain-level confidence computed |
| COG.COGEvent |  request_id, score_before, score_after, offset_applied | Calibration adjustment applied |
| COG.COGEvent |  curve_id, new_error, sample_size, domain | Calibration curve updated with new data |
| COG.COGEvent |  session_id, previous_sample_size | Calibration curve reset |
| COG.COGEvent |  request_id, adjustment_value, factor | Evidence quality adjusted confidence |
| COG.COGEvent |  request_id, score, threshold, action_type | Confidence below threshold |
| COG.COGEvent |  action_id, resolved, new_confidence, resolution | Low confidence action handled |
| COG.COGEvent |  session_id, threshold_type, old_value, new_value | Confidence threshold updated |
| COG.COGEvent |  target_id, original_score, override_score, reason | Sou overrode a confidence score |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-CONF-001 | All confidence scores are bounded [0.0, 1.0] | Schema â€” clamped at domain boundaries |
| COG-CONF-002 | Aggregated chain confidence never exceeds the maximum per-step confidence | Algorithmic â€” bounded by max |
| COG-CONF-003 | Calibration error is monotonically non-increasing as sample size grows | Algorithmic â€” only improves with data |
| COG-CONF-004 | Low confidence actions are advisory; Sou decides whether to execute | Architectural â€” no auto-execution |
| COG-CONF-005 | Evidence adjustment never increases confidence above base + 0.1 | Algorithmic â€” evidence can only slightly boost |
| COG-CONF-006 | Calibration curves are session-scoped and reset on new session | Algorithmic â€” per-session state |
| COG-CONF-007 | Every confidence estimate is logged with its full decomposition | Architectural â€” audit trail required |
| COG-CONF-008 | Threshold comparisons use calibrated scores, not raw scores | Algorithmic â€” calibration applied first |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No calibration data available | `COG_CONF_NO_CALIBRATION` | Use raw confidence; apply nominal penalty |
| Empty chain for aggregation | `COG_CONF_EMPTY_CHAIN` | Return confidence=0.0; cannot assess |
| Unknown aggregation method | `COG_CONF_UNKNOWN_METHOD` | Default to geometric; log warning |
| Evidence quality data incomplete | `COG_CONF_INCOMPLETE_EVIDENCE` | Use available factors; mark adjustment as partial |
| Calibration curve not found for ID | `COG_CONF_CURVE_NOT_FOUND` | Use session default curve; log warning |
| Low confidence action type not recognized | `COG_CONF_UNKNOWN_ACTION_TYPE` | Default to "qualify_answer" |
| Confidence override outside bounds | `COG_CONF_OVERRIDE_OUT_OF_BOUNDS` | Clamp to [0.0, 1.0]; apply with warning |
| Threshold configuration invalid (high < low) | `COG_CONF_INVALID_THRESHOLDS` | Reject config; keep previous thresholds |


## Cross-Cutting Concerns

### Security

Cognitive OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Cognitive OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Cognitive OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Cognitive OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Confidence Estimator only quantifies certainty |
| R2 â€” Dependency Order | Depends on Evidence Evaluator, Metacognition calibration |
| R3 â€” DRY | Calibration algorithm defined once; aggregation methods as strategies |
| R4 â€” Builder Pattern | ConfidenceOutput built from decomposition â†’ calibration â†’ adjustment |
| R5 â€” Liskov Substitution | Any aggregation method is interchangeable |
| R6 â€” DI over Singletons | Calibration curves and threshold configs injected |
| R9 â€” Deterministic | Same inputs produce same confidence at temperature=0 |
| R10 â€” Simpler Over Complex | Uses linear decomposition model with named factors |
| R13 â€” Design for Failure | Missing calibration falls back to raw score with penalty |
| R14 â€” Paved Path | All confidence flows through `estimate` method |
| R15 â€” Open/Closed | New aggregation methods added by registering with estimator |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Cognitive/000-Overview.md | Confidence scoring is embedded in all Cognitive OS outputs |
| Brain/Cognitive/001-Reasoning-Pipeline.md | Every ThoughtStep has a confidence score |
| Brain/Cognitive/002-Reflection-Engine.md | Reflection confidence is estimated by this component |
| Brain/Cognitive/003-Metacognition.md | Metacognition consumes confidence for calibration and gap detection |
| Brain/Cognitive/004-Cognitive-Biases.md | Overconfidence detection feeds into bias adjustment |
| Brain/LLMOS/000-Overview.md | LLMOS logprobs inform step-level confidence |
| Bible/05-Platform/004-EVS.md | Evidence quality assessment uses Event Store data |
| Brain/Sou/001-Reasoning.md | Sou acts on low confidence recommendations |
| Brain/Decision/000-Overview.md | Confidence thresholds gate whether decisions proceed |
