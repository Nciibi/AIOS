# AIOS Bible â€” Brain
## 002 â€” Reflection Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Reflection Engine enables Sou to reason about past experiences and outcomes. It implements 5 reflection types â€” outcome analysis, mistake analysis, success analysis, bias detection, and learning extraction â€” that consume episodic memory and produce structured lessons, bias reports, and pattern insights. Reflection results are stored in the Evidence Store and inform future reasoning, metacognition, and Academy learning.

## Data Model

### ReflectionRequest

```typescript
ReflectionRequest {
  request_id: string
  session_id: string
  type: "outcome_analysis" | "mistake_analysis" | "success_analysis" | "bias_detection" | "learning_extraction"
  experience_id: string                // Links to Episodic Memory
  context: {
    goal: string
    decision?: string                  // The decision that led to outcome
    expected_outcome?: string
    actual_outcome?: string
    actions_taken: string[]
    evidence_used: EvidenceRef[]
    reasoning_chain_id?: string         // Links to the reasoning that produced the decision
  }
  depth: "quick" | "deep"             // Deep includes multi-pass analysis
  constraints?: string[]
}
```

### ReflectionOutput

```typescript
ReflectionOutput {
  request_id: string
  experience_id: string
  type: ReflectionType
  analysis: string                     // Natural language analysis
  lessons: Lesson[]
  patterns: Pattern[]
  biases_detected: DetectedBias[]
  confidence: number                   // 0.0â€“1.0
  alternative_interpretations: string[]
  metadata: {
    reflection_depth: "quick" | "deep"
    evidence_sources_consulted: number
    similar_experiences_found: number
    llmos_usage: {
      tokens_consumed: number
      model_used: string
      latency_ms: number
    }
  }
}

ReflectionType = "outcome_analysis" | "mistake_analysis" | "success_analysis" | "bias_detection" | "learning_extraction"
```

### Lesson

```typescript
Lesson {
  lesson_id: string
  reflection_id: string
  category: "process" | "knowledge" | "strategy" | "communication" | "domain"
  content: string                      // Actionable lesson statement
  severity: "info" | "warning" | "critical"
  applicability: string[]              // Tags for when this lesson applies
  generalizability: number             // 0.0 (specific) â€“ 1.0 (universal)
  source_experience_id: string
  created_at: timestamp
  evidence_strength: number            // How well supported this lesson is
  is_validated: boolean                // Has this lesson been confirmed by subsequent experience
}
```

### Pattern

```typescript
Pattern {
  pattern_id: string
  reflection_id: string
  type: "behavioral" | "cognitive" | "outcome" | "error"
  description: string
  occurrences: number                  // How many times this pattern observed
  frequency: number                    // 0.0â€“1.0 (how often it manifests)
  evidence_ids: string[]               // Supporting experiences
  confidence: number                   // Pattern detection confidence
  hypothesis: string                   // Tentative explanation
  is_correlated_with?: string          // Linked to another pattern
}
```

### DetectedBias

```typescript
DetectedBias {
  bias_id: string
  reflection_id: string
  bias_type: BiasType
  confidence: number
  evidence: string                     // What suggests this bias
  impact: "low" | "medium" | "high"   // Impact on decision quality
  mitigation_strategy?: string         // How to avoid next time
  source_step_ids?: string[]           // Which reasoning steps exhibited bias
}
```

## Core Concepts

### 1. Five Reflection Types

| Type | Input | Process | Output |
|------|-------|---------|--------|
| Outcome analysis | Decision + expected outcome + actual outcome | Compare expected vs actual; identify contributing factors | Root cause assessment, outcome quality score |
| Mistake analysis | Failed action + context | Identify failure point; determine why; classify error type | Mistake category, root cause, prevention strategy |
| Success analysis | Successful action + context | Identify success factors; assess reproducibility | Success factors, reproducibility score |
| Bias detection | Decision history | Scan for systematic deviation patterns; flag cognitive biases | Bias types detected, severity, examples |
| Learning extraction | Experience history | Distill actionable insights; filter noise; generalize | Structured lessons, applicability tags |

### 2. Input from Episodic Memory

```
Episodic Memory â”€â”€â–º Experience Record
                        â”‚
                        â”œâ”€â”€ experience_id
                        â”œâ”€â”€ session_id
                        â”œâ”€â”€ goal
                        â”œâ”€â”€ decisions_made
                        â”œâ”€â”€ actions_taken
                        â”œâ”€â”€ outcome
                        â”œâ”€â”€ reasoning_chain_id
                        â”œâ”€â”€ evidence_used
                        â””â”€â”€ metadata (importance, recency)
                              â”‚
                              â–¼
                    Reflection Engine
                              â”‚
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚                   â”‚
              Single experience      Batch (N experiences)
              (detailed)             (pattern detection)
```

The Reflection Engine does not own Episodic Memory; it queries it through Memory OS using `experience_id` or by filtering on goal/tags/outcome.

### 3. Reflection Output Format

Each reflection produces a structured output:

```
ReflectionOutput {
  analysis:       "The decision to use strategy X was correct, but execution failed because..."
  lessons: [
    { lesson_id: "L-001", category: "process", content: "Always validate API response before proceeding", severity: "warning" },
    { lesson_id: "L-002", category: "domain", content: "Database transactions require rollback handling", severity: "critical" }
  ],
  patterns: [
    { type: "error", description: "Timeouts occur when input exceeds 10MB", occurrences: 3, confidence: 0.87 }
  ],
  biases_detected: [
    { bias_type: "overconfidence", confidence: 0.72, impact: "medium" }
  ]
}
```

### 4. Lesson Extraction Pipeline

```
Experience â†’ Analyze â†’ Identify cause/effect â†’ Formulate lesson
                                                    â”‚
                                          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                          â”‚                    â”‚
                                    Generalizable        Specific
                                    â”‚                    â”‚
                                    â–¼                    â–¼
                              Tag applicability    Store as is
                              Store in Evidence    â”‚
                              â”‚                    â–¼
                              â–¼              Future reference
                        Academy consumption
```

Lessons progress through a lifecycle: extracted â†’ stored â†’ validated â†’ refined (or archived if disproven).

### 5. Pattern Detection

```
Batch of N experiences â†’ Feature extraction â†’ Similarity clustering
                                                      â”‚
                                                      â–¼
                                              Pattern hypothesis
                                                      â”‚
                                                      â–¼
                                            Statistical validation
                                                      â”‚
                                                      â–¼
                                            Pattern accepted/rejected
                                                      â”‚
                                                      â–¼
                                            Stored in Evidence Store
```

Pattern detection runs asynchronously, triggered when a minimum threshold of similar experiences accumulates.

## Internal Interface

```typescript
interface ReflectionEngine {
  // Core reflection
  reflect(request: ReflectionRequest): Promise<ReflectionOutput>
  analyzeOutcome(experience_id: string, expected: string, actual: string): Promise<ReflectionOutput>
  analyzeMistake(experience_id: string, context: MistakeContext): Promise<ReflectionOutput>
  analyzeSuccess(experience_id: string, context: SuccessContext): Promise<ReflectionOutput>
  detectBias(experience_ids: string[]): Promise<DetectedBias[]>
  extractLessons(experience_ids: string[]): Promise<Lesson[]>

  // Batch operations
  reflectBatch(requests: ReflectionRequest[]): Promise<ReflectionOutput[]>
  getPatterns(filter: PatternFilter): Promise<Pattern[]>

  // Lesson management
  validateLesson(lesson_id: string, confirming_experience_id: string): Promise<Lesson>
  archiveLesson(lesson_id: string, reason: string): void
  getApplicableLessons(context: LessonContext): Promise<Lesson[]>

  // History
  getReflectionHistory(session_id: string, limit?: number): ReflectionOutput[]
  getReflection(reflection_id: string): ReflectionOutput | null
}

interface MistakeContext {
  action: string
  expected: string
  actual: string
  failure_mode: "timeout" | "error" | "incorrect" | "incomplete"
  reasoning_chain_id?: string
  environment_state?: string
}

interface SuccessContext {
  action: string
  expected: string
  actual: string
  success_factors: string[]
  reproducibility_estimate?: number
  reasoning_chain_id?: string
}

interface LessonContext {
  session_id: string
  goal: string
  domain?: string
  action_type?: string
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| COG.COGEvent |   request_id, type, experience_id, depth | Reflection process began |
| COG.COGEvent |   request_id, type, lesson_count, pattern_count, bias_count | Reflection finished |
| COG.COGEvent |   request_id, error_code, partial_results | Reflection terminated with error |
| COG.COGEvent |   lesson_id, category, severity, generalizability | New lesson created |
| COG.COGEvent |   lesson_id, confirming_experience_id, evidence_strength | Lesson confirmed by new experience |
| COG.COGEvent |   lesson_id, reason, lessons_replaced_by | Lesson archived after being disproven |
| COG.COGEvent |   pattern_id, type, occurrences, confidence | New pattern identified |
| COG.COGEvent |   bias_id, bias_type, confidence, impact, source_experience | Bias detected in decision history |
| COG.COGEvent |   request_ids, total_lessons, total_patterns | Batch reflection finished |
| COG.COGEvent |   request_id, phase_number, phases_total | Multi-pass deep reflection progress |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-REFL-001 | Every reflection requires at least one linked experience_id | Schema â€” required field |
| COG-REFL-002 | Reflection is read-only on Episodic Memory â€” never modifies experiences | Architectural â€” query-only access |
| COG-REFL-003 | Lessons are uniquely identified and deduplicated across reflections | Algorithmic â€” lesson_id dedup check |
| COG-REFL-004 | A lesson's evidence_strength cannot exceed the number of supporting experiences | Algorithmic â€” bounded by count |
| COG-REFL-005 | Patterns require a minimum of 3 occurrences before acceptance | Threshold â€” configurable via PatternFilter |
| COG-REFL-006 | Bias detection compares against a baseline of unbiased reasoning | Algorithmic â€” baseline embedded in detector |
| COG-REFL-007 | Deep reflection always includes at least 2 passes (analysis + verification) | Algorithmic â€” multi-pass enforced |
| COG-REFL-008 | Lessons cannot be deleted, only archived with an explanation | Architectural â€” immutable audit trail |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Experience not found in Episodic Memory | `COG_REFL_EXPERIENCE_NOT_FOUND` | Return error; reflection cannot proceed without source |
| Insufficient experiences for pattern detection | `COG_REFL_INSUFFICIENT_SAMPLES` | Return empty patterns; log warning |
| LLMOS timeout during deep reflection | `COG_REFL_DEEP_REFLECTION_TIMEOUT` | Return analysis at current depth with confidence penalty |
| Biased analysis detected by metacognition | `COG_REFL_ANALYSIS_BIASED` | Request re-reflection with debiasing prompt |
| Lesson with duplicate content already exists | `COG_REFL_DUPLICATE_LESSON` | Return existing lesson_id; skip creation |
| Empty experience batch for bias detection | `COG_REFL_NO_EXPERIENCES` | Return error; provide at least one experience |
| Reflection type not recognized | `COG_REFL_UNKNOWN_TYPE` | Default to outcome_analysis |
| Lesson validation cycle detected | `COG_REFL_VALIDATION_CYCLE` | Reject validation if same experience used twice |


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
| R1 â€” Modulsingularity | Reflection Engine only analyzes past experiences |
| R2 â€” Dependency Order | Depends on Episodic Memory, LLMOS, Evidence Store |
| R3 â€” DRY | Reflection type templates defined once per type |
| R4 â€” Builder Pattern | Reflection output built progressively across passes |
| R5 â€” Liskov Substitution | Any reflection type implementation is interchangeable |
| R6 â€” DI over Singletons | Pattern detectors and lesson extractors injected |
| R9 â€” Deterministic | Same experience produces same reflection at temperature=0 |
| R10 â€” Simpler Over Complex | Uses 5 explicit types, not free-form analysis |
| R13 â€” Design for Failure | Deep reflection can return partial results on timeout |
| R14 â€” Paved Path | All reflections flow through `reflect` method |
| R15 â€” Open/Closed | New reflection types added by registering with engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Cognitive/000-Overview.md | Reflection Engine is a Cognitive OS component |
| Brain/Cognitive/001-Reasoning-Pipeline.md | Reflection consumes reasoning chain outputs |
| Brain/Cognitive/003-Metacognition.md | Metacognition uses reflection results for calibration |
| Brain/Cognitive/004-Cognitive-Biases.md | Bias detection feeds into Cognitive Biases system |
| Brain/Memory/002-Episodic-Memory.md | Primary input source â€” experiences to reflect on |
| Bible/05-Platform/004-EVS.md | Reflection outputs stored as evidence in Event Store |
| Bible/02-Core/Academy/000-Overview.md | Academy consumes lessons for formal learning |
| Brain/Sou/001-Reasoning.md | Sou initiates reflection via delegate |
