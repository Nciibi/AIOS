# AIOS Bible â€” Brain
## 001 â€” Reasoning Pipeline

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Reasoning Pipeline is the end-to-end execution engine for structured reasoning within Cognitive OS. It orchestrates 7 reasoning strategies â€” chain-of-thought, tree-of-thought, abductive, deductive, inductive, analogical, and counterfactual â€” as ordered sequences of thought steps routed through LLMOS for inference. The pipeline manages strategy selection, step generation, confidence tracking per step, streaming output, and integration with the Reflection and Metacognition engines. It produces reasoning chains that Sou consumes for decision-making.

## Data Model

### ReasoningPipelineState

```typescript
ReasoningPipelineState {
  pipeline_id: string
  request_id: string
  session_id: string
  strategy: ReasoningStrategy
  thought_chain: ThoughtStep[]
  current_step: number
  total_steps: number
  status: "pending" | "running" | "paused" | "completed" | "failed" | "streaming"
  confidence: ConfidenceSnapshot
  llmos_usage: {
    total_tokens: number
    total_cost: number
    model_used: string
    latency_ms: number
  }
  started_at: timestamp
  completed_at?: timestamp
  metadata: {
    branching_factor?: number       // For tree-of-thought
    depth_limit: number
    temperature: number
    strategy_rationale: string      // Why this strategy was chosen
  }
}

ConfidenceSnapshot {
  per_step: Map<number, number>    // step_number â†’ confidence (0.0â€“1.0)
  aggregate: number                // Overall chain confidence
  volatility: number               // Variance across steps
  low_confidence_steps: number[]   // Steps below threshold
}
```

### ThoughtStep

```typescript
ThoughtStep {
  step_number: number
  type: "premise" | "inference" | "evidence_check" | "counterargument" | "synthesis" | "branch" | "revert"
  content: string
  evidence_ref?: string
  confidence: number                // 0.0â€“1.0
  parent_step?: number             // For tree-of-thought branching
  alternatives?: AlternativeBranch[]
  token_cost: number
  latency_ms: number
  metadata: {
    strategy_used: ReasoningStrategy
    source: "llmos" | "memory" | "cache" | "override"
    includes_evidence: boolean
  }
}

AlternativeBranch {
  label: string
  content: string
  confidence: number
  selected: boolean
}
```

### StrategySelectorConfig

```typescript
StrategySelectorConfig {
  default_strategy: ReasoningStrategy
  fallback_strategy: ReasoningStrategy
  selection_rules: StrategySelectionRule[]
  max_depth: number
  branching_limit: number           // For tree-of-thought
  confidence_threshold: number      // Minimum confidence per step
  streaming_enabled: boolean
  timeouts: {
    per_step_ms: number
    total_ms: number
  }
}

StrategySelectionRule {
  condition: string                 // DSL or function name
  strategy: ReasoningStrategy
  priority: number
  rationale: string
}

ReasoningStrategy = "chain_of_thought" | "tree_of_thought" | "abductive" | "deductive" | "inductive" | "analogical" | "counterfactual"
```

## Core Concepts

### 1. Seven Reasoning Strategies

| Strategy | Behavior | Step Pattern | Best For |
|----------|----------|--------------|----------|
| Chain-of-thought | Sequential step-by-step reasoning | Premise â†’ Inference â†’ Inference â†’ Conclusion | Complex multi-step problems |
| Tree-of-thought | Branching exploration with backtracking | Premise â†’ Branch A â†’ Branch B â†’ Prune â†’ Select | Open-ended exploration, creativity |
| Abductive | Infer best explanation from available evidence | Evidence â†’ Hypotheses â†’ Rank â†’ Best Match | Debugging, root cause diagnosis |
| Deductive | Apply known rules to reach logical conclusion | Rules â†’ Facts â†’ Apply â†’ Logical Conclusion | Compliance checks, math proofs |
| Inductive | Generalize patterns from specific examples | Examples â†’ Pattern â†’ Hypothesis â†’ Generalize | Learning, pattern recognition |
| Analogical | Map known solution from source domain to target | Source â†’ Mapping â†’ Analog â†’ Adapt | Transfer learning, novel problems |
| Counterfactual | Simulate alternative scenarios | Fact â†’ Alter â†’ Simulate â†’ Compare | Planning, risk assessment |

### 2. Strategy Selection

```
Input: goal, context, problem_type, available_evidence
  â”‚
  â”œâ”€â”€ Analyze problem characteristics
  â”‚   â”œâ”€â”€ Well-defined? â†’ Deductive
  â”‚   â”œâ”€â”€ Open-ended? â†’ Tree-of-thought
  â”‚   â”œâ”€â”€ Evidence-heavy? â†’ Abductive
  â”‚   â”œâ”€â”€ Pattern-based? â†’ Inductive
  â”‚   â”œâ”€â”€ Known similar problem? â†’ Analogical
  â”‚   â”œâ”€â”€ Risk assessment? â†’ Counterfactual
  â”‚   â””â”€â”€ Default â†’ Chain-of-thought
  â”‚
  â”œâ”€â”€ Check selection rules (priority order)
  â”œâ”€â”€ Apply confidence threshold filter
  â””â”€â”€ Return selected strategy + rationale
```

### 3. Thought Step Generation

```
For each step in the reasoning chain:
  1. Determine next step type based on strategy pattern
  2. Prepare prompt context (previous steps, evidence, goal)
  3. Call LLMOS with strategy-specific prompt template
  4. Parse LLMOS output into ThoughtStep
  5. Assign step-level confidence score
  6. Emit ThoughtStepGenerated event
  7. Check for early termination conditions:
     - Conclusion reached â†’ complete pipeline
     - Low confidence â†’ flag for metacognition
     - Timeout â†’ return partial chain
```

### 4. Streaming Thought Output

The pipeline supports streaming through `AsyncIterable<ThoughtStep>`:

```typescript
interface StreamingReasoningResult {
  [Symbol.asyncIterator](): AsyncIterator<{
    step: ThoughtStep
    pipeline_progress: {
      current: number
      total: number
      confidence: number
      status: "streaming" | "complete" | "failed"
    }
  }>
}
```

Each step is emitted as it is generated, allowing Sou to display or act on intermediate results before the full chain is complete.

### 5. LLMOS Integration

```
Pipeline â†’ Strategy Prompt Builder â†’ LLMOS Gateway â†’ Step Parser â†’ ThoughtStep
                â”‚                          â”‚
                â””â”€â”€ Templates for each      â””â”€â”€ Token tracking
                    strategy                     Cost tracking
                    Context assembly              Streaming support
```

LLMOS handles model selection, prompt templates, and streaming. The pipeline only orchestrates.

## Internal Interface

```typescript
interface ReasoningEngine {
  // Core execution
  reason(request: ReasoningRequest): Promise<ReasoningOutput>
  selectStrategy(goal: string, context: ReasoningContext): StrategySelection
  getThoughtChain(pipeline_id: string): Promise<ThoughtStep[]>
  streamReason(request: ReasoningRequest): AsyncIterable<StreamEvent>
  
  // Strategy management
  registerStrategy(strategy: ReasoningStrategy, executor: StrategyExecutor): void
  getAvailableStrategies(): ReasoningStrategy[]
  setDefaultStrategy(strategy: ReasoningStrategy): void
  
  // Pipeline control
  pausePipeline(pipeline_id: string): void
  resumePipeline(pipeline_id: string): void
  cancelPipeline(pipeline_id: string): void
  getPipelineState(pipeline_id: string): ReasoningPipelineState
  
  // Step operations
  getStep(pipeline_id: string, step_number: number): ThoughtStep | null
  overrideStep(pipeline_id: string, step_number: number, override: Partial<ThoughtStep>): ThoughtStep
  addBranch(pipeline_id: string, parent_step: number, branch: AlternativeBranch): void
  
  // History
  getReasoningHistory(session_id: string, limit?: number): ReasoningOutput[]
  getPipelineTimeline(pipeline_id: string): PipelineTimelineEntry[]
}

interface StrategyExecutor {
  name: ReasoningStrategy
  initialize(config: StrategySelectorConfig): void
  execute(request: ReasoningRequest, llmos: LLMOSGateway): AsyncIterable<ThoughtStep>
  getStepPattern(): StepType[]
  validateChain(chain: ThoughtStep[]): ValidationResult
}

interface ReasoningContext {
  query: string
  goal: string
  evidence: EvidenceRef[]
  constraints: string[]
  previous_chains?: ReasoningOutput[]
  cognitive_load?: number
  user_preference?: ReasoningStrategy
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| COG.COGEvent |   pipeline_id, request_id, strategy, depth_limit | Reasoning pipeline initialized |
| COG.COGEvent |   pipeline_id, confidence, total_steps, token_cost | Pipeline finished successfully |
| COG.COGEvent |   pipeline_id, error_code, partial_steps | Pipeline terminated with error |
| COG.COGEvent |   pipeline_id, step_number, type, confidence, token_cost | Individual step produced |
| COG.COGEvent |   pipeline_id, strategy, rationale, alternatives | Strategy chosen by selector |
| COG.COGEvent |   pipeline_id, step_number, branch_count | Alternative branch added (tree-of-thought) |
| COG.COGEvent |   pipeline_id, step_number, pruned_label | Branch discarded |
| COG.COGEvent |   pipeline_id, step_number, confidence_before, confidence_after | Sou overrode a step |
| COG.COGEvent |   pipeline_id, reason | Pipeline paused for metacognition |
| COG.COGEvent |   pipeline_id, reason | Pipeline resumed after metacognition |
| COG.COGEvent |   pipeline_id, step_number, confidence, threshold | Step below confidence threshold |
| COG.COGEvent |   pipeline_id, original_strategy, fallback_strategy, reason | Fallback to alternative strategy |
| COG.COGEvent |   pipeline_id, step_number, bytes | Streaming output delivered |
| COG.COGEvent |   pipeline_id, step_number, reason, confidence | Pipeline terminated before full depth |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-REASON-001 | Every reasoning pipeline has exactly one active strategy | Algorithmic â€” no hybrid execution |
| COG-REASON-002 | Step numbers are strictly monotonically increasing | Algorithmic â€” auto-increment per step |
| COG-REASON-003 | Every step in a chain has a non-null confidence score | Schema â€” required field on ThoughtStep |
| COG-REASON-004 | Pipeline state transitions follow: pending â†’ running â†’ streaming â†’ completed/failed | Algorithmic â€” state machine enforced |
| COG-REASON-005 | A completed pipeline cannot be resumed | Algorithmic â€” immutable after completion |
| COG-REASON-006 | All reasoning steps are logged to Event Store before emission | Architectural â€” write-before-emit |
| COG-REASON-007 | Strategy selection is deterministic for identical inputs at temperature=0 | Algorithmic â€” selection rules ordered by priority |
| COG-REASON-008 | Branching depth never exceeds configured branching_limit | Algorithmic â€” enforced in tree-of-thought executor |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| LLMOS unavailable during pipeline | `COG_REASON_LLMOS_DOWN` | Pause pipeline; set status to "paused"; emit PipelinePaused |
| Step generation timeout | `COG_REASON_STEP_TIMEOUT` | Emit partial step with confidence=0.3; continue or terminate based on config |
| Total pipeline timeout | `COG_REASON_PIPELINE_TIMEOUT` | Return partial chain with confidence penalty; emit EarlyTermination |
| Unknown strategy requested | `COG_REASON_UNKNOWN_STRATEGY` | Fall back to default strategy; emit StrategyFallback |
| Invalid parent step for branch | `COG_REASON_INVALID_PARENT` | Reject branch; return error; pipeline continues |
| Step override conflicts with chain structure | `COG_REASON_OVERRIDE_INVALID` | Reject override; return validation error |
| Streaming buffer overflow | `COG_REASON_STREAM_OVERFLOW` | Drop oldest buffered step; continue streaming |
| Circular reference in thought chain | `COG_REASON_CIRCULAR_CHAIN` | Detect cycle; prune to break cycle; emit warning |
| Pipeline not found for getThoughtChain | `COG_REASON_PIPELINE_NOT_FOUND` | Return null; no error |
| Strategy executor not registered | `COG_REASON_EXECUTOR_MISSING` | Fall back to chain-of-thought; log warning |


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
| R1 â€” Modulsingularity | Reasoning Pipeline only manages step-by-step reasoning |
| R2 â€” Dependency Order | Depends on LLMOS, Event Store, Strategy Registry |
| R3 â€” DRY | Strategy step patterns defined once per executor |
| R4 â€” Builder Pattern | Pipeline built step by step via strategy executor |
| R5 â€” Liskov Substitution | Any StrategyExecutor implements the interface |
| R6 â€” DI over Singletons | Strategy executors and prompt templates injected |
| R9 â€” Deterministic | Same inputs produce same chain at temperature=0 |
| R10 â€” Simpler Over Complex | Uses explicit strategy enum, not free-form reasoning |
| R13 â€” Design for Failure | Timeouts and partial chains always handled |
| R14 â€” Paved Path | All reasoning flows through `reason` method |
| R15 â€” Open/Closed | New strategies added by registering an executor |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Cognitive/000-Overview.md | Reasoning Pipeline is the core Cognitive OS component |
| Brain/Cognitive/002-Reflection-Engine.md | Reflection consumes reasoning chains for analysis |
| Brain/Cognitive/003-Metacognition.md | Metacognition monitors and adjusts reasoning |
| Brain/Cognitive/005-Confidence.md | Confidence scoring integrated per step and aggregate |
| Brain/LLMOS/000-Overview.md | LLMOS provides inference for all step generation |
| Brain/Sou/001-Reasoning.md | Sou delegates reasoning to this pipeline |
| Brain/Decision/000-Overview.md | Decision System consumes reasoning outputs |
| Brain/Context/000-Overview.md | Context System provides reasoning context |
