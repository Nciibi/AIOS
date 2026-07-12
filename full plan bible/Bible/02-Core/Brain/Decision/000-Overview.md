# AIOS Bible â€” Brain
## 000 â€” Decision System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-000 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Decision System provides structured, multi-factor decision-making capabilities to Sou. When Sou faces a choice â€” which action to take, which tool to use, which plan to follow, which trade-off to accept â€” the Decision System evaluates the options against configurable criteria and produces a ranked, scored recommendation.

The Decision System does not make decisions. Sou makes decisions. The Decision System provides the analytical framework â€” scoring, trade-off analysis, constraint checking â€” that Sou uses to reach a strategic choice.

## Architecture

```
Sou (consumes recommendation, makes decision)
   â–²
   â”‚
   â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Decision System                   â”‚
â”‚                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚ Scorer   â”‚  â”‚ Trade-offâ”‚  â”‚ Constraintâ”‚ â”‚
â”‚  â”‚ Engine   â”‚â”€â–ºâ”‚ Analyzer â”‚â”€â–ºâ”‚ Checker   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜ â”‚
â”‚                                    â”‚       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚       â”‚
â”‚  â”‚ Criteria â”‚  â”‚ History  â”‚       â”‚       â”‚
â”‚  â”‚ Registry â”‚  â”‚ Logger   â”‚       â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”˜
                                     â”‚
                                     â–¼
                            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                            â”‚  Event Store â”‚
                            â”‚ (evidence)   â”‚
                            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Core Concepts

### Decision Model

```
DecisionContext {
  session_id: string
  goal: string
  constraints: string[]
  relevant_history: string[]       // Decision IDs from past similar choices
  context_window_snapshot: string  // Hash of context at decision time
  metadata: Record<string, unknown>
}

DecisionRequest {
  request_id: string
  context: DecisionContext
  options: DecisionOption[]
  criteria: DecisionCriterion[]
  constraints: DecisionConstraint[]
}

DecisionOption {
  option_id: string
  label: string
  description: string
  attributes: Record<string, unknown>
  estimated_outcome?: EstimatedOutcome
}

DecisionCriterion {
  criterion_id: string
  name: string
  weight: number            // 0.0â€“1.0, sum of weights = 1.0
  scoring_function: string  // "linear" | "threshold" | "boolean" | "custom"
  preferences: PreferenceDirection  // "maximize" | "minimize" | "target"
}

DecisionRecommendation {
  request_id: string
  ranked_options: RankedOption[]
  trade_offs: TradeOff[]
  constraints_satisfied: boolean
  violated_constraints: ViolatedConstraint[]
  confidence: number       // 0.0â€“1.0
  explanation: string      // Human-readable justification
  created_at: timestamp
}

RankedOption {
  option_id: string
  option: DecisionOption
  weighted_score: number   // 0.0â€“1.0
  rank: number             // 1-based ranking
  criterion_scores: Record<criterion_id, number>
  strength: string         // "strong" | "moderate" | "weak"
  weakness: string         // Key area where this option falls short
}

ViolatedConstraint {
  constraint_id: string
  option_id: string
  type: "hard" | "soft"
  detail: string           // Human-readable explanation
}
```

### 1. Scoring Engine

Evaluates each option against each criterion to produce a score matrix:

```
ScoreMatrix {
  option_id: string
  scores: Record<criterion_id, number>  // 0.0â€“1.0 per criterion
  weighted_total: number                // sum of (score Ã— weight)
}
```

Scoring functions determine how raw attributes map to scores:

| Function | Behavior | Use Case |
|----------|----------|----------|
| Linear | Direct proportion: `value / max_value` | Speed, cost, resource usage |
| Threshold | Score = 1.0 if value passes threshold, else 0.0 | Compliance, security checks |
| Boolean | 1.0 for true, 0.0 for false | Capability presence |
| Custom | User-defined function | Domain-specific logic |

### 2. Trade-Off Analyzer

When options have competing strengths, the Trade-Off Analyzer surfaces the conflicts:

```
TradeOff {
  criteria: [criterion_id, criterion_id]
  options: [option_id, option_id]
  description: string          // "Option A is faster; Option B is cheaper"
  magnitude: number            // 0.0â€“1.0, how severe the trade-off
}
```

Trade-off types:

| Type | Description | Example |
|------|-------------|---------|
| Performance vs Cost | Faster options consume more resources | Use GPT-4 (accurate, slow, expensive) vs GPT-3.5 (faster, cheaper, less capable) |
| Speed vs Quality | Quick options reduce output quality | Summarize vs full analysis |
| Scope vs Depth | Broad options are shallow; deep options are narrow | Search many sources vs deep-dive one source |
| Safety vs Autonomy | Overly constrained options reduce freedom | Require approval for every step vs unconstrained execution |

### 3. Constraint Checker

Hard constraints that must be satisfied for an option to be viable:

```
DecisionConstraint {
  constraint_id: string
  type: "hard" | "soft"        // Hard = must pass; Soft = penalty if violated
  expression: string           // Evaluable expression against option attributes
  description: string
}
```

Hard constraints: If violated, the option is removed from consideration. Example: "Must not exceed 4096 tokens."

Soft constraints: If violated, the option's score is penalized. Example: "Prefer options with lower latency."

### 4. Criteria Registry

A persistent store of named criteria that can be reused across decisions:

| Criterion | Default Weight | Scoring Function | Description |
|-----------|---------------|------------------|-------------|
| speed | 0.15 | Linear (maximize) | How fast the option executes |
| cost | 0.15 | Linear (minimize) | Resource cost of the option |
| quality | 0.25 | Threshold | Expected output quality |
| safety | 0.25 | Boolean | Is the option safe |
| reliability | 0.10 | Linear (maximize) | Expected success rate |
| explainability | 0.10 | Boolean | Can the option be explained |

Criteria are configurable at decision time. Sou can override weights or supply custom criteria.

### 5. History Logger

Every decision is recorded as evidence (Law 4):

```
DecisionRecord {
  request_id: string
  session_id: string
  sou_identity: string
  context_snapshot: string     // Hash of context at decision time
  options: DecisionOption[]
  criteria: DecisionCriterion[]
  recommendation: DecisionRecommendation
  final_choice: string         // option_id of Sou's actual choice (may differ from recommendation)
  decision_latency_ms: number
  created_at: timestamp
}
```

## Interfaces

### Decision System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `evaluateOptions(request)` | Sou only | Evaluate multiple options against criteria; return recommendation |
| `scoreOption(option, criteria)` | Sou only | Score a single option against criteria |
| `analyzeTradeOffs(options, criteria)` | Sou only | Surface trade-offs between options |
| `checkConstraints(options, constraints)` | Sou only | Check hard/soft constraints for options |
| `getRegistry(criteria_filter?)` | Sou only | List available criteria from Criteria Registry |
| `registerCriterion(criterion)` | Sou only | Register a new criterion |
| `getDecisionHistory(session_id, limit?)` | Sou only | Retrieve past decisions |

### Internal Interfaces

```
interface ScoringFunction {
  name: string
  score(attribute_value: number | boolean, preferences: PreferenceDirection): number
}

interface ConstraintExpression {
  evaluate(attributes: Record<string, unknown>): ConstraintResult
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| DEC.EvaluationRequested |      request_id, option_count, criteria_count | Decision evaluation started |
| DEC.EvaluationCompleted |      request_id, recommendation | Evaluation finished |
| DEC.DecisionMade |      request_id, final_choice | Sou made the final decision |
| DEC.ConstraintViolated |      constraint_id, option_id, detail | Hard constraint violated |
| DEC.TradeOffIdentified |      criteria_pair, options, magnitude | Trade-off surfaced |
| DEC.CriterionRegistered |      criterion_id, name, weight | New criterion added |
| DEC.PreferenceOverridden |      criterion_id, old_weight, new_weight | Criterion weight changed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEC-001 | The Decision System recommends; Sou decides | API-level â€” no auto-execution |
| DEC-002 | Every decision is recorded as evidence | Architectural â€” History Logger is mandatory |
| DEC-003 | Hard constraints always remove non-compliant options | Algorithmic â€” checked before scoring |
| DEC-004 | Criteria weights always sum to 1.0 | Validation â€” enforced on EvaluationRequest |
| DEC-005 | The Decision System is stateless â€” history lives in Event Store | Architectural â€” no internal persistence |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Decision System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou is the exclusive consumer of Decision System output |
| Brain/Context/000-Overview.md | Context System provides the context snapshot for decisions |
| Brain/Planning/000-Overview.md | Planning System uses decisions for goal decomposition |
| Brain/Tools/000-Overview.md | Tool System provides options for tool selection decisions |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No options provided | `DEC_NO_OPTIONS` | Return error; no evaluation |
| Criteria weights don't sum to 1.0 | `DEC_INVALID_WEIGHTS` | Normalize weights and proceed |
| Unknown scoring function | `DEC_UNKNOWN_FUNCTION` | Return error; reject request |
| Hard constraint eliminates all options | `DEC_ALL_ELIMINATED` | Return empty recommendation with explanation |


## Cross-Cutting Concerns

### Security

Decision System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Decision System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Decision System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Decision System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Decision System does one thing: structured evaluation |
| R2 â€” Dependency Order | Depends on Event Store; no upward deps |
| R3 â€” DRY | Criteria defined in Registry, reused across decisions |
| R4 â€” Builder Pattern | Recommendation built by Scorer â†’ Trade-off Analyzer â†’ Constraint Checker |
| R5 â€” Liskov Substitution | Any ScoringFunction implements the interface |
| R6 â€” DI over Singletons | Criteria, scoring functions injected |
| R9 â€” Deterministic | Same inputs produce same recommendation (no randomness) |
| R10 â€” Simpler Over Complex | Uses weighted sum model (no neural networks or ML) |
| R13 â€” Design for Failure | Decision System degrades gracefully â€” missing criteria trigger fallback scoring, not hard failure |
| R14 â€” Paved Path | All evaluation flows through `evaluateOptions` |
| R15 â€” Open/Closed | New scoring functions added via Registry, not by modifying core |
