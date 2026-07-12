# AIOS Bible â€” Brain
## 000 â€” Cognitive OS

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Cognitive |
| Document ID | AIOS-BBL-002-COG-000 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Cognitive OS is Sou's reasoning engine. It implements the cognitive processes that Sou delegates to â€” reasoning, reflection, metacognition, and synthesis. When Sou needs to think through a problem, evaluate evidence, reflect on past experiences, or generate insights, it delegates to Cognitive OS.

Cognitive OS does not make decisions. It produces reasoning chains that Sou consumes. Sou decides; Cognitive OS thinks.

## Architecture

```
Sou (reasons, reflects, synthesizes via delegation)
   â–²
   â”‚
   â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Cognitive OS                      â”‚
â”‚                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚ Reasoning â”‚  â”‚ Reflectionâ”‚  â”‚ Metacog-  â”‚ â”‚
â”‚  â”‚ Engine    â”‚â”€â–ºâ”‚ Engine   â”‚â”€â–ºâ”‚ nition    â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚ Engine    â”‚ â”‚
â”‚                              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”               â”‚
â”‚  â”‚ Synthesisâ”‚  â”‚ Evidence  â”‚               â”‚
â”‚  â”‚ Engine   â”‚  â”‚ Evaluator â”‚               â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜               â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚
                    â–¼
             â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
             â”‚  LLMOS       â”‚
             â”‚ (inference)  â”‚
             â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Cognitive OS is the primary consumer of LLMOS within the Brain. All reasoning, reflection, and metacognition routes through LLMOS for AI inference. Cognitive OS does not contain AI models â€” it orchestrates the thinking process.

## Core Concepts

### Cognitive Model

```
ReasoningRequest {
  request_id: string
  type: "reason" | "reflect" | "metacognize" | "synthesize"
  context: {
    session_id: string
    goal: string
    query: string
    evidence: EvidenceRef[]
    constraints: string[]
    temperature: number       // 0.0 (deterministic) â€“ 1.0 (creative)
  }
}

ReasoningOutput {
  request_id: string
  chain: ThoughtStep[]
  conclusion: string
  confidence: number          // 0.0â€“1.0
  alternative_viewpoints: AlternativeViewpoint[]
  uncertainty_zones: string[] // Areas where reasoning is weak
  llmos_usage: {
    tokens_consumed: number
    model_used: string
    latency_ms: number
  }
}

ThoughtStep {
  step_number: number
  type: "premise" | "inference" | "evidence_check" | "counterargument" | "synthesis"
  content: string
  evidence_ref?: string       // Links to evidence in Evidence Store
  confidence: number          // 0.0â€“1.0
  alternatives?: string[]     // Alternative conclusions at this step
}
```

### 1. Reasoning Engine

The core reasoning capability. Supports multiple reasoning strategies:

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| Chain-of-thought | Step-by-step sequential reasoning | Complex problem solving |
| Tree-of-thought | Branching exploration of multiple paths | Open-ended exploration |
| Abductive | Infer best explanation from evidence | Debugging, diagnosis |
| Deductive | Apply rules to reach logical conclusion | Compliance checks |
| Inductive | Generalize patterns from examples | Learning, pattern recognition |
| Analogical | Map known solution to novel problem | Transfer learning |
| Counterfactual | "What if" scenario analysis | Planning, risk assessment |

Each strategy produces a chain of ThoughtSteps that Sou can inspect, question, or override.

### 2. Reflection Engine

Reflection is reasoning about past experiences and outcomes:

| Reflection Type | Input | Output |
|----------------|-------|--------|
| Outcome analysis | Previous decision + outcome | What worked, what didn't, why |
| Mistake analysis | Failed action + context | Root cause, pattern detection |
| Success analysis | Successful action + context | Reinforcing factors, reproducibility |
| Bias detection | Decision history | Potential bias patterns |
| Learning extraction | Experience history | Actionable lessons |

Reflection results are stored in the Evidence Store and can be consumed by Academy for formal learning.

### 3. Metacognition Engine

Metacognition is thinking about thinking â€” monitoring and regulating cognitive processes:

| Function | Behavior |
|----------|----------|
| Confidence calibration | Assess whether confidence matches actual accuracy |
| Cognitive load monitoring | Track complexity and suggest simplifications |
| Strategy selection | Choose optimal reasoning strategy for the task |
| Knowledge gap detection | Identify areas where Sou lacks sufficient information |
| Uncertainty quantification | Estimate how uncertain Sou is about a conclusion |
| Progress assessment | Evaluate how close Sou is to a sufficient answer |

Metacognition feeds back into the reasoning process. If confidence is low, Sou may request more information or choose a different reasoning strategy.

### 4. Synthesis Engine

Synthesis combines multiple reasoning outputs into a coherent whole:

| Synthesis Mode | Behavior | Use Case |
|----------------|----------|----------|
| Merge | Combine parallel reasoning chains | Multi-perspective analysis |
| Summarize | Condense reasoning into key points | Reporting to user |
| Contrast | Highlight differences between viewpoints | Decision preparation |
| Reconcile | Resolve contradictory evidence | Evidence-based conclusion |

### 5. Evidence Evaluator

Before Sou can trust a reasoning conclusion, the Evidence Evaluator assesses the quality of supporting evidence:

| Dimension | Assessment | Impact |
|-----------|------------|--------|
| Source reliability | Trust level of evidence source | Weight in reasoning |
| Recency | Age of evidence | Recency bias adjustment |
| Consistency | How well evidence aligns with other evidence | Corroboration score |
| Completeness | Are there gaps in the evidence chain | Uncertainty penalty |
| Relevance | How directly evidence applies | Relevance weight |

## Interfaces

### Cognitive OS API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `reason(request)` | Sou only | Execute chain-of-thought reasoning |
| `reflect(experience_id, type)` | Sou only | Reflect on a past experience |
| `metacognize(request)` | Sou only | Perform metacognitive analysis |
| `synthesize(inputs, mode)` | Sou only | Combine multiple reasoning outputs |
| `evaluateEvidence(evidence_refs)` | Sou only | Assess evidence quality |
| `selectStrategy(goal, context)` | Sou only | Recommend optimal reasoning strategy |
| `getReasoningHistory(session_id, limit?)` | Sou only | Retrieve past reasoning chains |

### Internal Interfaces

```
interface ReasoningStrategy {
  name: string
  execute(request: ReasoningRequest, llmos: LLMOSGateway): AsyncIterable<ThoughtStep>
}

interface EvidenceScorer {
  score(evidence: EvidenceRef): EvidenceScore
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| COG.ReasoningStarted |  request_id, type, strategy | Reasoning process began |
| COG.ReasoningCompleted |  request_id, confidence, token_cost | Reasoning finished |
| COG.ThoughtStepGenerated |  request_id, step_number, type | Individual thought step produced |
| COG.ReflectionCompleted |  request_id, type, lessons | Reflection finished |
| COG.MetacognitionUpdate |  request_id, function, result | Metacognitive insight produced |
| COG.SynthesisCompleted |  request_id, mode, source_count | Synthesis finished |
| COG.LowConfidenceDetected |  request_id, confidence, reason | Confidence below threshold |
| COG.StrategySelected |  request_id, strategy, rationale | Reasoning strategy chosen |
| COG.EvidenceEvaluated |  request_id, evidence_count, avg_reliability | Evidence quality assessed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| COG-001 | Cognitive OS reasons; Sou decides | API-level â€” no auto-execution of conclusions |
| COG-002 | All reasoning routes through LLMOS | Architectural â€” Cognitive OS has no embedded models |
| COG-003 | Reasoning chains are always logged as evidence | Architectural â€” every output is recorded |
| COG-004 | Cognitive OS is stateless â€” chains live in Event Store | Architectural â€” no internal persistence |
| COG-005 | Every reasoning step has a confidence score | Schema â€” required field on ThoughtStep |
| COG-006 | Evidence must be evaluated before it can inform reasoning | Algorithmic â€” enforced in Evidence Evaluator |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Cognitive OS is a Brain Service |
| Brain/Sou/001-Reasoning.md | Sou delegates reasoning to Cognitive OS |
| Brain/LLMOS/000-Overview.md | LLMOS provides the inference backend for reasoning |
| Brain/Decision/000-Overview.md | Decision System consumes reasoning output |
| Brain/Planning/000-Overview.md | Planning uses reasoning for goal decomposition |
| Brain/Memory/000-Overview.md | Reasoning context retrieved from memory |
| Bible/04-Execution/Security/ | Evidence evaluation uses Security Council trust data |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| LLMOS unavailable | `COG_LLMOS_UNAVAILABLE` | Queue reasoning; return "thinking paused" |
| Reasoning timeout | `COG_REASONING_TIMEOUT` | Return partial chain with confidence penalty |
| No evidence found for reflection | `COG_NO_EVIDENCE` | Return "no relevant experience" |
| Conflicting evidence cannot be reconciled | `COG_UNRESOLVABLE_CONFLICT` | Present both sides with uncertainty flag |
| Unknown reasoning strategy | `COG_UNKNOWN_STRATEGY` | Default to chain-of-thought |


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
| R1 â€” Modulsingularity | Cognitive OS does one thing: structured thinking |
| R2 â€” Dependency Order | Depends on LLMOS, Event Store; no upward deps |
| R3 â€” DRY | Reasoning strategies defined once in Strategy Registry |
| R4 â€” Builder Pattern | Reasoning chain built step by step |
| R5 â€” Liskov Substitution | Any ReasoningStrategy implements the interface |
| R6 â€” DI over Singletons | Strategies and evidence scorers injected |
| R9 â€” Deterministic | Same inputs produce same reasoning at temperature=0 |
| R10 â€” Simpler Over Complex | Uses explicit reasoning strategies, not free-form generation |
| R13 â€” Design for Failure | Timeouts and partial results always handled |
| R14 â€” Paved Path | All reasoning flows through `reason` method |
| R15 â€” Open/Closed | New reasoning strategies added via Registry |
