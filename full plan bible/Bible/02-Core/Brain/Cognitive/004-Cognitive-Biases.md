# AIOS Bible — Brain
## 004 — Cognitive Biases

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-004 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/009-Causality.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Cognitive Biases identifies, mitigates, and logs systematic deviations from rational reasoning in Sou's cognitive processes. It monitors 6 bias types — confirmation bias, recency bias, anchoring, overconfidence, availability heuristic, and framing effect — during active reasoning and reflection. When biases are detected, the system applies mitigation strategies including debiasing prompts, counterargument generation, and perspective shifting. All bias detections are logged for analysis, pattern tracking, and metacognitive calibration.

## Data Model

### BiasDetectionRequest

```typescript
BiasDetectionRequest {
  request_id: string
  target_id: string
  target_type: "reasoning_pipeline" | "reflection" | "decision"
  bias_types: BiasType[]               // Which biases to check (all if empty)
  context: {
    chain: ThoughtStep[]
    goal: string
    query: string
    evidence: EvidenceRef[]
    decision_context?: string
    previous_decisions?: string[]
  }
  depth: "quick" | "thorough"          // Thorough runs multi-pass detection
}
```

### BiasReport

```typescript
BiasReport {
  request_id: string
  target_id: string
  detections: BiasDetection[]
  overall_bias_score: number           // 0.0 (unbiased) – 1.0 (heavily biased)
  mitigation_applied: MitigationAction[]
  residual_bias_estimate: number       // Bias remaining after mitigation
  recommendations: string[]
  metadata: {
    bias_types_checked: BiasType[]
    steps_analyzed: number
    mitigation_success_rate: number
    duration_ms: number
    llmos_usage: {
      tokens_consumed: number
      model_used: string
      latency_ms: number
    }
  }
}
```

### BiasDetection

```typescript
BiasDetection {
  detection_id: string
  bias_type: BiasType
  confidence: number                   // 0.0–1.0 confidence in detection
  severity: "low" | "medium" | "high" | "critical"
  location: {
    step_numbers: number[]
    evidence_ids?: string[]
    quote?: string                     // The text exhibiting bias
  }
  indicators: string[]                 // What signals suggest this bias
  impact_assessment: string            // How this bias affects conclusion quality
  context: {
    mitigating_factors?: string[]
    exacerbating_factors?: string[]
  }
}

BiasType = "confirmation_bias" | "recency_bias" | "anchoring" | "overconfidence" | "availability_heuristic" | "framing_effect"
```

### MitigationAction

```typescript
MitigationAction {
  action_id: string
  bias_type: BiasType
  detection_id: string
  strategy: MitigationStrategy
  prompt_applied?: string             // The debiasing prompt used
  counterargument_generated?: string  // For anchoring/framing
  alternative_perspective?: string    // For confirmation bias
  effectiveness: number               // 0.0–1.0 estimated effectiveness
  outcome: "applied" | "skipped" | "failed"
  applied_at: timestamp
}

MitigationStrategy = "debiasing_prompt" | "counterargument" | "perspective_shift" | "evidence_reevaluation" | "confidence_adjustment" | "strategy_change"
```

### BiasLog

```typescript
BiasLog {
  log_id: string
  session_id: string
  timestamp: timestamp
  bias_type: BiasType
  severity: string
  target_id: string
  detection: BiasDetection
  mitigation: MitigationAction
  recurrence_count: number            // How many times this bias pattern appeared
  pattern_id?: string                 // Links to pattern in Reflection Engine
}
```

## Core Concepts

### 1. Six Bias Types

| Bias Type | Definition | Detection Method | Typical Severity |
|-----------|-----------|------------------|-----------------|
| Confirmation bias | Favoring evidence that supports existing beliefs | Scan for selective evidence引用; check for contradicting evidence dismissal | Medium–High |
| Recency bias | Overweighting recent information over older data | Analyze evidence age vs. weight; check temporal ordering | Medium |
| Anchoring | Over-relying on first piece of information encountered | Compare first step influence on later reasoning; detect insufficient adjustment | Low–Medium |
| Overconfidence | Estimated confidence exceeds actual accuracy | Compare confidence scores against historical calibration curve | High–Critical |
| Availability heuristic | Overweighting easily recalled examples over statistical reality | Check if examples are vivid/recent vs. representative | Medium |
| Framing effect | Drawing different conclusions from same data presented differently | Analyze how problem presentation shapes reasoning direction | Medium–High |

### 2. Bias Detection During Reasoning

```
ThoughtStep Chain
       │
       ▼
┌─────────────────────────────┐
│  Step-by-step scan           │
│                              │
│  For each step:              │
│  ├── Check for confirmation  │
│  │   bias: selective citing  │
│  ├── Check recency bias:     │
│  │   evidence age weighting  │
│  ├── Check anchoring: first- │
│  │   step influence          │
│  ├── Check overconfidence:   │
│  │   confidence vs accuracy  │
│  ├── Check availability:     │
│  │   example                │
│  │   representativeness      │
│  └── Check framing: prompt   │
│      dependency              │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Cross-step pattern analysis │
│                              │
│  ├── Temporal dependencies  │
│  ├── Evidence selection     │
│  │   patterns               │
│  └── Confidence trajectory  │
└──────────┬──────────────────┘
           │
           ▼
      BiasReport
```

Detection runs both per-step and across the entire chain to catch systemic patterns that individual steps may not reveal.

### 3. Bias Mitigation Strategies

| Strategy | Applied To | Method |
|----------|-----------|--------|
| Debiasing prompt | All biases | Inject prompt instructing Sou to consider alternative viewpoints or re-evaluate evidence |
| Counterargument | Anchoring, framing | Generate explicit counterargument to the biased position; force consideration |
| Perspective shift | Confirmation bias | Ask "What would someone with opposing view conclude?" |
| Evidence re-evaluation | Availability, recency | Re-weight evidence by objective criteria rather than retrieval ease |
| Confidence adjustment | Overconfidence | Apply calibration offset from Metacognition curve |
| Strategy change | All (severe) | Switch to different reasoning strategy (e.g., tree-of-thought to explore alternatives) |

### 4. Debiasing Prompts

Debiasing prompts are inserted as additional context into the next LLMOS call:

```
Confirmation bias prompt:
  "Before concluding, list 3 pieces of evidence that contradict your current hypothesis.
   Evaluate each one systematically."

Anchoring prompt:
  "Ignore the initial value you considered. Re-estimate from first principles."

Overconfidence prompt:
  "You are calibrated at X% overconfidence for this problem type. Adjust your confidence
   estimates downward by Y points."

Framing effect prompt:
  "Reconsider the problem reframed as: [alternative framing]. Does your conclusion change?"
```

Prompts are constructed from templates and parameterized with the detection context.

### 5. Bias Logging

```
BiasDetection
       │
       ▼
┌─────────────────────────────┐
│  Log Entry                   │
│  ├── session_id              │
│  ├── bias_type               │
│  ├── severity                │
│  ├── step_numbers            │
│  ├── confidence              │
│  ├── mitigation_applied      │
│  └── recurrence_count        │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  Periodic Analysis           │
│                              │
│  ├── Per-session bias       │
│  │   summary                │
│  ├── Cross-session pattern  │
│  │   detection              │
│  ├── Bias type frequency    │
│  │   distribution           │
│  └── Mitigation             │
│      effectiveness tracking │
└─────────────────────────────┘
```

Bias logs feed into the Reflection Engine's pattern detection and Metacognition's calibration.

## Internal Interface

```typescript
interface BiasDetector {
  // Detection
  detectBias(request: BiasDetectionRequest): Promise<BiasReport>
  detectBiasInChain(chain: ThoughtStep[], goal: string): Promise<BiasDetection[]>
  detectBiasInDecision(decision: string, context: DecisionContext): Promise<BiasDetection[]>

  // Mitigation
  mitigateBias(detections: BiasDetection[], target_id: string, chain: ThoughtStep[]): Promise<MitigationAction[]>
  applyDebiasingPrompt(detection: BiasDetection, next_step_context: string): string
  generateCounterargument(detection: BiasDetection, original: string): string
  shiftPerspective(step: ThoughtStep, opposite_view: string): ThoughtStep

  // Reporting
  getBiasReport(request_id: string): BiasReport | null
  getBiasHistory(session_id: string, filter?: BiasFilter): BiasLog[]
  getBiasSummary(session_id: string): BiasSummary

  // Configuration
  configureThresholds(thresholds: Partial<BiasThresholds>): void
  registerDebiasingTemplate(bias_type: BiasType, template: string): void
  getActiveMitigations(target_id: string): MitigationAction[]

  // Pattern analysis
  getReccurringBiases(session_id: string, min_occurrences: number): BiasPattern[]
  getBiasTypeDistribution(session_id: string): Record<BiasType, number>
  getMitigationEffectiveness(session_id: string): Record<MitigationStrategy, number>
}

interface BiasThresholds {
  detection_confidence_min: number     // 0.0–1.0 (default 0.6)
  severity_low_max: number             // Indicator count (default 2)
  severity_medium_max: number          // (default 4)
  mitigation_trigger_severity: string  // Minimum severity that auto-triggers mitigation
  recurrence_pattern_min: number       // Minimum occurrences to flag as pattern
}

interface BiasSummary {
  session_id: string
  total_detections: number
  biases_by_type: Record<BiasType, number>
  overall_bias_score: number
  avg_mitigation_effectiveness: number
  most_common_bias: BiasType
  trend: "improving" | "stable" | "worsening"
}

interface BiasPattern {
  bias_type: BiasType
  occurrence_count: number
  first_detected: timestamp
  last_detected: timestamp
  common_context: string[]             // Recurring conditions
  avg_severity: number
  mitigation_effectiveness: number
}

interface DecisionContext {
  decision: string
  alternatives_considered: string[]
  evidence_used: EvidenceRef[]
  confidence: number
  outcome?: string
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `COG.BIAS.BiasDetected` | request_id, bias_type, confidence, severity, step_numbers | Bias found in reasoning chain |
| `COG.BIAS.BiasMitigated` | request_id, bias_type, strategy, effectiveness | Mitigation action applied |
| `COG.BIAS.MitigationFailed` | request_id, bias_type, strategy, reason | Mitigation could not be applied |
| `COG.BIAS.BiasReportGenerated` | request_id, overall_score, detections_count, mitigations_count | Full bias report created |
| `COG.BIAS.DebiasingPromptInjected` | request_id, bias_type, prompt_template | Debiasing prompt sent to LLMOS |
| `COG.BIAS.CounterargumentGenerated` | request_id, bias_type, target_step | Counterargument created for anchored/framed step |
| `COG.BIAS.PerspectiveShifted` | request_id, bias_type, original_conclusion, shifted_view | Alternative perspective considered |
| `COG.BIAS.RecurrencePatternDetected` | bias_type, occurrence_count, session_ids, avg_severity | Recurring bias pattern identified |
| `COG.BIAS.BiasThresholdAdjusted` | bias_type, threshold_before, threshold_after, reason | Detection threshold changed |
| `COG.BIAS.HighSeverityBiasFlagged` | request_id, bias_type, severity, impact_assessment | Critical bias requiring immediate attention |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-BIAS-001 | Every bias detection includes a specific step or evidence reference | Schema — required location fields |
| COG-BIAS-002 | Mitigation is never applied without prior detection | Algorithmic — ordered pipeline |
| COG-BIAS-003 | Bias logging is write-once and immutable | Architectural — append-only log |
| COG-BIAS-004 | Overconfidence detection always references the calibration curve | Algorithmic — requires calibration data |
| COG-BIAS-005 | A single step can exhibit multiple bias types simultaneously | Schema — supports multiple detections |
| COG-BIAS-006 | Bias detection is idempotent — same input produces same report at temperature=0 | Algorithmic — deterministic analysis |
| COG-BIAS-007 | Mitigation does not modify the original reasoning chain | Architectural — creates advisory output |
| COG-BIAS-008 | Recurrence patterns require ≥3 occurrences in a session to be logged | Threshold — configurable via BiasThresholds |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No reasoning steps to analyze | `COG_BIAS_EMPTY_CHAIN` | Return empty report; cannot detect without chain |
| LLMOS unavailable for debiasing | `COG_BIAS_LLMOS_UNAVAILABLE` | Skip LLMOS-dependent mitigation; apply rule-based only |
| Unknown bias type requested | `COG_BIAS_UNKNOWN_TYPE` | Skip unknown type; return detection for known types |
| Mitigation strategy not registered | `COG_BIAS_UNKNOWN_MITIGATION` | Fall back to default debiasing prompt |
| Bias detection timeout | `COG_BIAS_DETECTION_TIMEOUT` | Return partial detections; mark as incomplete |
| Calibration curve unavailable for overconfidence check | `COG_BIAS_NO_CALIBRATION_DATA` | Flag as potential overconfidence without confirmation |
| Counterargument generation fails | `COG_BIAS_COUNTERARGUMENT_FAILED` | Skip counterargument; use perspective shift instead |
| Recurrence pattern query exceeds session history | `COG_BIAS_PATTERN_QUERY_LIMIT` | Return partial pattern results; limit to last N sessions |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Cognitive Biases only detects and mitigates reasoning biases |
| R2 — Dependency Order | Depends on Reasoning Pipeline, Metacognition, LLMOS |
| R3 — DRY | Bias detection rules defined once per type in detector registry |
| R4 — Builder Pattern | BiasReport built from detections → mitigations → recommendations |
| R5 — Liskov Substitution | Any bias detector implementation is interchangeable |
| R6 — DI over Singletons | Detection strategies and mitigation templates injected |
| R9 — Deterministic | Same chain produces same bias report at temperature=0 |
| R10 — Simpler Over Complex | Uses 6 explicit bias types, not free-form bias detection |
| R13 — Design for Failure | Partial detection results returned on timeout |
| R14 — Paved Path | All bias detection flows through `detectBias` method |
| R15 — Open/Closed | New bias types added by registering detector and mitigation strategy |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Cognitive/000-Overview.md | Cognitive Biases is a cross-cutting Cognitive OS concern |
| Brain/Cognitive/001-Reasoning-Pipeline.md | Bias detection analyzes reasoning chain steps |
| Brain/Cognitive/002-Reflection-Engine.md | Bias detection feeds into reflection's bias analysis |
| Brain/Cognitive/003-Metacognition.md | Bias adjustments inform confidence calibration |
| Brain/Cognitive/005-Confidence.md | Overconfidence detection directly relates to confidence scoring |
| Brain/LLMOS/000-Overview.md | Debiasing prompts injected into LLMOS calls |
| Brain/Evidence/000-Overview.md | Evidence re-evaluation corrects biased evidence weighting |
