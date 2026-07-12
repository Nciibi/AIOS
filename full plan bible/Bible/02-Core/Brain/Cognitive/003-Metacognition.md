# AIOS Bible — Brain
## 003 — Metacognition

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-003 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Metacognition is thinking about thinking — monitoring, regulating, and optimizing Sou's cognitive processes. It implements 6 metacognitive functions: confidence calibration, cognitive load monitoring, strategy selection, knowledge gap detection, uncertainty quantification, and progress assessment. Metacognition runs as a feedback loop over active reasoning and reflection, adjusting parameters, suggesting strategy switches, and flagging when Sou needs more information or should defer a decision.

## Data Model

### MetacognitionRequest

```typescript
MetacognitionRequest {
  request_id: string
  session_id: string
  functions: MetacognitiveFunction[]
  target_id: string                    // pipeline_id or reflection_id
  target_type: "reasoning_pipeline" | "reflection" | "decision"
  context: {
    goal: string
    query: string
    pipeline_state?: ReasoningPipelineState
    reflection_output?: ReflectionOutput
    cognitive_history: CognitiveHistoryEntry[]
    active_duration_ms: number
    iteration_count: number
  }
  depth: "light" | "full"             // Light = selected functions only
}

MetacognitiveFunction = "confidence_calibration" | "cognitive_load_monitoring" | "strategy_selection" | "knowledge_gap_detection" | "uncertainty_quantification" | "progress_assessment"
```

### MetacognitionOutput

```typescript
MetacognitionOutput {
  request_id: string
  target_id: string
  target_type: string
  results: Record<MetacognitiveFunction, MetacognitiveResult>
  overall_assessment: {
    health: "healthy" | "strained" | "stuck" | "off_track"
    recommended_action: string         // e.g., "request_more_info", "switch_strategy", "continue", "defer"
    priority: number                   // 0.0–1.0 urgency of action
  }
  feedback_signals: FeedbackSignal[]
  metadata: {
    functions_executed: MetacognitiveFunction[]
    duration_ms: number
    llmos_usage: {
      tokens_consumed: number
      model_used: string
      latency_ms: number
    }
  }
}

MetacognitiveResult {
  function: MetacognitiveFunction
  value: number | string | object      // Function-specific output
  confidence: number                   // 0.0–1.0
  narrative: string                    // Human-readable explanation
  action_suggested?: string
}
```

### CognitiveHistoryEntry

```typescript
CognitiveHistoryEntry {
  entry_id: string
  timestamp: timestamp
  target_type: "reasoning" | "reflection" | "decision"
  target_id: string
  metrics: {
    confidence: number
    cognitive_load: number             // 0.0–1.0
    progress: number                   // 0.0–1.0
    uncertainty: number                // 0.0–1.0
  }
  action_taken?: string
  outcome?: string
}
```

### FeedbackSignal

```typescript
FeedbackSignal {
  signal_id: string
  type: "strategy_change" | "confidence_adjustment" | "knowledge_gap" | "load_warning" | "uncertainty_spike" | "progress_stall"
  severity: "info" | "warning" | "critical"
  source_function: MetacognitiveFunction
  target: string                       // What the signal applies to
  value: number | string
  narrative: string
}
```

## Core Concepts

### 1. Six Metacognitive Functions

| Function | Input | Algorithm | Output |
|----------|-------|-----------|--------|
| Confidence calibration | ThoughtStep confidences + historical accuracy | Compare estimated vs actual accuracy; adjust calibration curve | Calibrated confidence score, calibration offset |
| Cognitive load monitoring | Step count, depth, branching, complexity | Calculate load = f(tokens, steps, depth, branching, time) | Load score (0.0–1.0), simplification suggestion |
| Strategy selection | Goal type, available evidence, load | Match goal to optimal strategy via rule engine | Recommended strategy + rationale |
| Knowledge gap detection | Evidence refs, step content, query | Identify claims without supporting evidence; flag missing domains | Gap list with specificity scores |
| Uncertainty quantification | Step confidences, evidence quality, conflicts | Aggregate uncertainties across chain with Bayesian combination | Uncertainty distribution, confidence interval |
| Progress assessment | Steps taken, goal criteria, time elapsed | Evaluate completeness against goal criteria | Progress %, remaining steps estimate, ETA |

### 2. Metacognitive Feedback Loop

```
Active Reasoning/Reflection
        │
        ▼
┌─────────────────────────────┐
│  Metacognition Trigger       │
│  (periodic / event-based)    │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Function 1: Confidence     │
│  Calibration                │
├─────────────────────────────┤
│  Function 2: Cognitive Load │
│  Monitoring                 │
├─────────────────────────────┤
│  Function 3: Strategy       │
│  Selection                  │
├─────────────────────────────┤
│  Function 4: Knowledge Gap  │
│  Detection                  │
├─────────────────────────────┤
│  Function 5: Uncertainty    │
│  Quantification             │
├─────────────────────────────┤
│  Function 6: Progress       │
│  Assessment                 │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Feedback Signals Generated  │
│  ─────────────────────────── │
│  ● Low confidence?           │──► Request more info
│  ● High load?                │──► Simplify or switch strategy
│  ● Knowledge gap?            │──► Seek evidence
│  ● High uncertainty?         │──► Qualify answer
│  ● Stalled progress?         │──► Reassess approach
│  ● Healthy?                  │──► Continue
└──────────┬──────────────────┘
           │
           ▼
    Feedback consumed by
    Reasoning Pipeline / Sou
           │
           └─────────► Adjustments applied → Loop continues
```

### 3. Confidence Calibration Algorithm

```
Input: Array of (estimated_confidence, actual_correctness) pairs
  │
  ├── Bin estimated confidence into deciles [0.0–0.1, 0.1–0.2, ..., 0.9–1.0]
  ├── For each bin, calculate actual accuracy = correct_count / total_count
  ├── Compute calibration error = |estimated_confidence_bin_center - actual_accuracy|
  │
  ├── If calibration error > threshold (default 0.15):
  │     ├── Adjust future confidence estimates by offset
  │     └── Emit calibration adjustment signal
  │
  └── Return calibrated confidence = estimated * (1 - calibration_error)
```

Calibration improves over time as more accuracy data accumulates. Initial calibration uses default parameters from configuration.

### 4. Knowledge Gap Detection

```
Input: Reasoning chain + evidence references + query
  │
  ├── Parse each step for factual claims
  ├── Cross-reference each claim against:
  │   ├── Evidence Store (does supporting evidence exist?)
  │   ├── Knowledge Graph (is this a known fact?)
  │   └── Memory (has this been experienced before?)
  │
  ├── For unsubstantiated claims:
  │     ├── Tag as knowledge gap
  │     ├── Categorize gap type: "missing_evidence" | "missing_domain_knowledge" | "unsupported_assumption"
  │     ├── Estimate specificity: how precisely can the gap be described
  │     └── Rank by impact on conclusion confidence
  │
  └── Return gap list with recommendations for evidence retrieval
```

### 5. Progress Assessment

```
Progress = completeness_weighted_sum(criteria_met) / total_criteria

where criteria_met is evaluated against:
  - Goal completion state
  - Sufficient evidence gathered
  - Confidence threshold reached
  - User satisfaction signal (if available)
  - All key questions answered

If progress < threshold (default 0.3):
  → Flag as "stuck"
  → Suggest alternative approach or more information

If progress > threshold (default 0.85):
  → Flag as "sufficient"
  → Suggest answer preparation
```

## Internal Interface

```typescript
interface MetacognitionEngine {
  // Core metacognition
  metacognize(request: MetacognitionRequest): Promise<MetacognitionOutput>
  calibrateConfidence(pipeline_id: string, accuracy_feedback: CalibrationData[]): Promise<CalibrationResult>
  detectGaps(pipeline_id: string): Promise<KnowledgeGap[]>
  assessProgress(pipeline_id: string, goal_criteria: GoalCriterion[]): Promise<ProgressAssessment>

  // Function-specific
  monitorCognitiveLoad(pipeline_id: string): Promise<CognitiveLoadReport>
  quantifyUncertainty(pipeline_id: string): Promise<UncertaintyReport>
  selectStrategy(goal: string, context: StrategySelectionContext): Promise<StrategySelection>
  
  // Feedback loop
  getFeedbackSignals(target_id: string): FeedbackSignal[]
  applyFeedback(target_id: string, signal: FeedbackSignal): void
  evaluateHealth(target_id: string): Promise<CognitiveHealth>

  // Calibration management
  getCalibrationCurve(session_id: string): CalibrationCurve
  resetCalibration(session_id: string): void
  updateCalibration(session_id: string, data: CalibrationData): CalibrationCurve

  // History
  getMetacognitionHistory(session_id: string, limit?: number): MetacognitionOutput[]
  getLatestAssessment(target_id: string): MetacognitionOutput | null
}

interface CalibrationData {
  estimated_confidence: number
  was_correct: boolean
  step_type: string
  timestamp: timestamp
}

interface CalibrationCurve {
  bins: CalibrationBin[]
  calibration_error: number
  is_calibrated: boolean
  sample_size: number
  last_updated: timestamp
}

interface CalibrationBin {
  range_low: number
  range_high: number
  count: number
  accuracy: number
  offset: number
}

interface KnowledgeGap {
  gap_id: string
  step_number: number
  claim: string
  gap_type: "missing_evidence" | "missing_domain_knowledge" | "unsupported_assumption"
  specificity: number               // 0.0–1.0
  impact_estimate: number           // How much closing this gap would improve confidence
  suggested_query?: string          // What to search for
}

interface CognitiveLoadReport {
  pipeline_id: string
  load_score: number                // 0.0–1.0
  load_factors: {
    step_count: number
    depth: number
    branching_factor: number
    token_consumption: number
    elapsed_minutes: number
  }
  load_level: "low" | "moderate" | "high" | "critical"
  simplification_suggestion?: string
}

interface UncertaintyReport {
  pipeline_id: string
  overall_uncertainty: number       // 0.0–1.0
  per_step_uncertainty: Map<number, number>
  dominant_source: "evidence_quality" | "conflicting_evidence" | "knowledge_gaps" | "model_stochasticity"
  confidence_interval: [number, number]
}

interface ProgressAssessment {
  pipeline_id: string
  progress: number                  // 0.0–1.0
  criteria_met: number
  criteria_total: number
  eta_remaining_ms?: number
  status: "on_track" | "stalled" | "sufficient" | "off_track"
  recommendation: string
}

interface CognitiveHealth {
  target_id: string
  health: "healthy" | "strained" | "stuck" | "off_track"
  active_signals: FeedbackSignal[]
  summary: string
}

interface StrategySelectionContext {
  load: number
  uncertainty: number
  knowledge_gaps: number
  depth_remaining: number
  evidence_quality: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `COG.META.MetacognitionStarted` | request_id, functions[], target_id, depth | Metacognition analysis began |
| `COG.META.MetacognitionCompleted` | request_id, health, recommended_action, signals_count | Metacognition finished |
| `COG.META.ConfidenceCalibrated` | request_id, calibration_error, offset_applied | Confidence calibration adjusted |
| `COG.META.CognitiveLoadWarning` | target_id, load_score, level, suggestion | Cognitive load threshold exceeded |
| `COG.META.StrategyRecommended` | target_id, recommended_strategy, rationale, alternatives | Strategy change suggested |
| `COG.META.KnowledgeGapDetected` | target_id, gap_count, impact_estimate | One or more knowledge gaps found |
| `COG.META.UncertaintySpike` | target_id, uncertainty, dominant_source | Uncertainty above threshold |
| `COG.META.ProgressStalled` | target_id, progress, stalled_duration_ms | Progress below threshold for extended period |
| `COG.META.ProgressSufficient` | target_id, progress, criteria_met | Goal criteria sufficiently met |
| `COG.META.FeedbackEmitted` | target_id, signal_type, severity, narrative | Individual feedback signal sent |
| `COG.META.HealthChanged` | target_id, previous_health, new_health, reason | Overall cognitive health status changed |
| `COG.META.CalibrationReset` | session_id, sample_size_before | Calibration curve was reset |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-META-001 | Metacognition never modifies the reasoning chain it analyzes | Architectural — read-only analysis |
| COG-META-002 | Confidence calibration error is monotonically non-increasing over time | Algorithmic — calibration only improves |
| COG-META-003 | Cognitive load scores are bounded [0.0, 1.0] | Schema — clamped at domain boundaries |
| COG-META-004 | Knowledge gaps always reference a specific step or claim | Schema — required fields |
| COG-META-005 | Feedback signals are consumed within 1 reasoning cycle or discarded | Algorithmic — TTL enforced |
| COG-META-006 | Metacognition runs at most once every N steps (configurable frequency) | Algorithmic — rate-limited |
| COG-META-007 | A strategy recommendation is advisory; Sou must approve changes | Architectural — no auto-switching |
| COG-META-008 | The calibration curve is session-scoped and resets on new session | Algorithmic — session-scoped state |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Pipeline not found for metacognition | `COG_META_TARGET_NOT_FOUND` | Return error; no target to analyze |
| Insufficient steps for calibration | `COG_META_INSUFFICIENT_STEPS` | Return null calibration; request more steps |
| LLMOS unavailable during metacognition | `COG_META_LLMOS_UNAVAILABLE` | Skip deep analysis; return light assessment only |
| Knowledge gap detection timeout | `COG_META_GAP_DETECTION_TIMEOUT` | Return detected gaps so far with incomplete flag |
| Calibration with fewer than 10 data points | `COG_META_CALIBRATION_BELOW_MINIMUM` | Use default calibration curve; log warning |
| Recognized strategy not available | `COG_META_STRATEGY_UNAVAILABLE` | Recommend next-best strategy; document why |
| Metacognition function not recognized | `COG_META_UNKNOWN_FUNCTION` | Skip unknown function; execute remainder |
| Circular feedback loop detected | `COG_META_FEEDBACK_CYCLE` | Break loop; apply last valid signal; emit warning |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Metacognition only monitors and regulates cognitive processes |
| R2 — Dependency Order | Depends on Reasoning Pipeline, LLMOS, Evidence Store |
| R3 — DRY | Calibration algorithm defined once; functions as plugins |
| R4 — Builder Pattern | Output assembled per function, then aggregated into assessment |
| R5 — Liskov Substitution | Any metacognitive function implements the same result interface |
| R6 — DI over Singletons | Calibration curves, load monitors, gap detectors injected |
| R9 — Deterministic | Same cognitive state produces same assessment at temperature=0 |
| R10 — Simpler Over Complex | Uses 6 explicit functions, not monolithic self-analysis |
| R13 — Design for Failure | Light assessment available when LLMOS is down |
| R14 — Paved Path | All metacognition flows through `metacognize` method |
| R15 — Open/Closed | New metacognitive functions added by registering with engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Cognitive/000-Overview.md | Metacognition is a Cognitive OS component |
| Brain/Cognitive/001-Reasoning-Pipeline.md | Metacognition monitors and adjusts reasoning |
| Brain/Cognitive/002-Reflection-Engine.md | Reflection results inform metacognitive analysis |
| Brain/Cognitive/004-Cognitive-Biases.md | Bias detection feeds into confidence calibration |
| Brain/Cognitive/005-Confidence.md | Confidence calibration directly relates to Confidence Estimator |
| Brain/LLMOS/000-Overview.md | LLMOS provides inference for metacognitive analysis |
| Brain/Sou/001-Reasoning.md | Sou receives and acts on metacognitive feedback |
| Brain/Decision/000-Overview.md | Metacognition flags whether Sou should decide or defer |
