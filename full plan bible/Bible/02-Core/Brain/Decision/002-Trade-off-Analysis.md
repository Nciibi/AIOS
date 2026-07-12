# AIOS Bible â€” Brain
## 002 â€” Trade-off Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-002 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Trade-off Analyzer surfaces conflicts between competing criteria across options. When no single option dominates all criteria, the Trade-off Analyzer identifies which criteria are in tension, quantifies the magnitude of trade-offs, and presents them to Sou for strategic judgment.

The Trade-off Analyzer does not resolve trade-offs. It illuminates them. Sou applies strategic judgment to decide which competing priority yields.

## Data Model

### TradeOff

```typescript
TradeOff {
  trade_off_id: string
  request_id: string
  criteria: [criterion_id, criterion_id]   // The two criteria in tension
  options: [option_id, option_id]          // The two options compared
  option_a_label: string
  option_b_label: string
  winner_criterion_1: criterion_id         // Which criterion Option A wins on
  winner_criterion_2: criterion_id         // Which criterion Option B wins on
  magnitude: number                        // 0.0â€“1.0
  magnitude_label: "low" | "medium" | "high"
  description: string                      // "Option A is faster; Option B is cheaper"
  type: TradeOffType
}
```

### TradeOffPair

```typescript
TradeOffPair {
  option_a: string                         // option_id
  option_b: string                         // option_id
  criterion_scores_a: Record<criterion_id, number>
  criterion_scores_b: Record<criterion_id, number>
  trade_offs: TradeOff[]                   // All tensions between this pair
  dominance: "a_dominates_b" | "b_dominates_a" | "non_dominated" | "equal"
}
```

### CompetingCriteria

```typescript
CompetingCriteria {
  criterion_x: criterion_id
  criterion_y: criterion_id
  conflict_strength: number                // 0.0â€“1.0, how often these conflict
  pair_count: number                       // How many option pairs exhibit this tension
  average_magnitude: number                // Average magnitude across all pairs
  typical_description: string              // Common description template
}
```

### DominanceMatrix

```typescript
DominanceMatrix {
  option_ids: string[]
  matrix: Record<string, Record<string, DominanceResult>>
  // matrix[a][b] = how a compares to b
}

DominanceResult {
  dominates: boolean      // Does option_id column dominate option_id row?
  pareto_rank: number     // Lower = better (0 = frontier)
  strengths: string[]     // Criteria where this option wins
  weaknesses: string[]    // Criteria where this option loses
}
```

### ParetoFrontier

```typescript
ParetoFrontier {
  frontier_options: string[]               // Non-dominated options
  dominated_options: string[]              // Dominated options
  frontier_count: number
  total_options: number
  efficiency_ratio: number                 // frontier_count / total_options
  trade_off_surface: TradeOff[]            // Trade-offs among frontier options only
  dominance_chains: DominanceChain[]       // A â†’ B â†’ C chains of domination
}

DominanceChain {
  dominant: string                         // option_id
  dominated: string                        // option_id
  criteria_superset: criterion_id[]        // Criteria where dominant is strictly better
  criteria_equal: criterion_id[]           // Criteria where they tie
}
```

### TradeOffReport

```typescript
TradeOffReport {
  request_id: string
  option_pairs: TradeOffPair[]             // All pairwise comparisons
  competing_criteria: CompetingCriteria[]  // Criteria that frequently conflict
  pareto_frontier: ParetoFrontier          // Frontier analysis
  dominant_option: string | null           // option_id if one option dominates all
  has_pareto_frontier: boolean             // true if multiple non-dominated options
  trade_off_count: number
  highest_magnitude: TradeOff | null       // The most severe trade-off
  recommendations: TradeOffRecommendation[]
  generated_at: timestamp
}

TradeOffRecommendation {
  type: "dominance" | "pareto_trade_off" | "pareto_no_trade_off" | "all_equal"
  description: string
  suggested_approach: string               // How Sou might proceed
}
```

### TradeOffConfig

```typescript
TradeOffConfig {
  magnitude_thresholds: {
    low: number                            // < 0.3
    medium: number                         // 0.3â€“0.7
    high: number                           // > 0.7
  }
  max_comparisons: number                  // Cap on pairwise comparisons (O(nÂ²))
  include_dominated: boolean               // Whether to report dominated options
  custom_trade_off_types: CustomTradeOffType[]
}

CustomTradeOffType {
  criterion_x: criterion_id
  criterion_y: criterion_id
  label: string
  description_template: string
}
```

## Trade-off Detection

### Pairwise Comparison

Every option is compared against every other option across all criteria:

```
For each pair (A, B):
  For each criterion C:
    score_A = scoreMatrix[A][C]
    score_B = scoreMatrix[B][C]
    Determine winner, loser, or tie

  If A >= B on all criteria and A > B on at least one:
    â†’ A dominates B
  If B >= A on all criteria and B > A on at least one:
    â†’ B dominates A
  If A and B tie on all criteria:
    â†’ Equal
  Otherwise:
    â†’ Non-dominated (trade-off exists)
```

### Pareto Dominance Rule

```
Option A dominates Option B iff:
  âˆ€ criterion c: score(A, c) >= score(B, c)
  âˆ§ âˆƒ criterion c: score(A, c) > score(B, c)
```

### Trade-off Identification

For non-dominated pairs, the trade-off detector identifies which criteria are in tension:

```
Tension exists between criterion X and criterion Y when:
  score(A, X) > score(B, X)  AND  score(B, Y) > score(A, Y)
  // Option A wins on X, Option B wins on Y
```

Multiple tensions may exist within a single pair. Each tension is recorded as a separate TradeOff.

### Dominated Option Handling

Dominated options are flagged with an explanation but not removed from the report. Sou retains the freedom to choose a dominated option based on non-analytical factors (e.g., user preference, instinct, external constraints).

```
Flag example:
  "Option C is dominated by Option A.
   A is strictly better on: speed, cost, quality.
   A and C are equal on: safety.
   Sou may still select C, but should be aware A exceeds or matches it everywhere."
```

## Trade-off Types

### 1. Performance vs Cost

```
Type identifier: "performance_vs_cost"
Criterion pair: [performance, cost]
Behavior:
  - Higher performance typically increases resource consumption
  - Magnitude scales with performance gain Ã— cost increase
  - Common in: model selection, infrastructure choices, algorithm selection
Description template: "{OptionA} is {magnitude_label}ly more performant; {OptionB} is proportionally cheaper"
Example: GPT-4 vs GPT-3.5 â€” GPT-4 scores 0.9 on performance, 0.2 on cost; GPT-3.5 scores 0.6 on performance, 0.8 on cost
```

### 2. Speed vs Quality

```
Type identifier: "speed_vs_quality"
Criterion pair: [speed, quality]
Behavior:
  - Faster execution often sacrifices thoroughness
  - Magnitude scales with speed gain Ã— quality loss
  - Common in: summarization depth, analysis detail, retrieval breadth
Description template: "{OptionA} delivers results {magnitude_label}ly faster; {OptionB} produces higher quality output"
Example: Quick summary vs deep analysis â€” quick summary scores 0.9 on speed, 0.4 on quality; deep analysis scores 0.3 on speed, 0.9 on quality
```

### 3. Scope vs Depth

```
Type identifier: "scope_vs_depth"
Criterion pair: [scope, depth]
Behavior:
  - Broad coverage reduces per-item depth
  - Magnitude scales with coverage breadth Ã— depth loss
  - Common in: research approaches, data collection, search strategies
Description template: "{OptionA} covers {magnitude_label}ly more ground; {OptionB} goes deeper on each item"
Example: Search 50 sources (scope: 0.9, depth: 0.3) vs deep-dive 5 sources (scope: 0.2, depth: 0.9)
```

### 4. Safety vs Autonomy

```
Type identifier: "safety_vs_autonomy"
Criterion pair: [safety, autonomy]
Behavior:
  - More constraints reduce freedom of action
  - Magnitude scales with safety gain Ã— autonomy loss
  - Common in: execution mode selection, approval workflows, permission levels
Description template: "{OptionA} is {magnitude_label}ly safer and more constrained; {OptionB} is freer but carries more risk"
Example: Require approval each step (safety: 0.9, autonomy: 0.1) vs unconstrained execution (safety: 0.2, autonomy: 0.9)
```

### 5. Custom (User-Defined Dimension Pairs)

```
Type identifier: "custom"
Criterion pair: [criterion_x, criterion_y]   // User-defined
Behavior:
  - Defined in TradeOffConfig.custom_trade_off_types
  - Same detection and magnitude logic as built-in types
  - Sou registers custom types via Criteria Registry
Description template: "{custom_label}: {OptionA} wins on {crit_x_label}; {OptionB} wins on {crit_y_label}"
Example: "Innovation vs Stability â€” Option A is more innovative; Option B is more stable"
```

## Magnitude Calculation

### Formula

```
magnitude = |score_a_criterion1 - score_b_criterion1|
          Ã— |score_a_criterion2 - score_b_criterion2|
```

Where `criterion1` and `criterion2` are the two criteria in tension.

### Normalization

```
// Scores are already normalized to [0.0, 1.0] by the Scoring Engine
// Each difference term is in [0.0, 1.0]
// Product of two terms is therefore also in [0.0, 1.0]
// No additional normalization needed

magnitude_normalized = magnitude  // Already [0.0, 1.0]
```

### Thresholds

| Label | Range | Interpretation |
|-------|-------|----------------|
| Low | < 0.3 | Minor tension â€” either option is acceptable |
| Medium | 0.3â€“0.7 | Significant tension â€” Sou should consider preferences |
| High | > 0.7 | Severe tension â€” this trade-off dominates the decision |

### Examples

```
Pair (A, B):
  A: speed=0.9, quality=0.3    B: speed=0.4, quality=0.8
  magnitude = |0.9 - 0.4| Ã— |0.3 - 0.8|
            = 0.5 Ã— 0.5
            = 0.25  â†’ Low

Pair (C, D):
  C: cost=0.9, performance=0.2    D: cost=0.1, performance=0.9
  magnitude = |0.9 - 0.1| Ã— |0.2 - 0.9|
            = 0.8 Ã— 0.7
            = 0.56  â†’ Medium

Pair (E, F):
  E: speed=0.95, quality=0.1    F: speed=0.05, quality=0.95
  magnitude = |0.95 - 0.05| Ã— |0.1 - 0.95|
            = 0.9 Ã— 0.85
            = 0.765  â†’ High
```

## Pareto Analysis

### Pareto Frontier Computation

```
Input: ScoreMatrix for all options across all criteria
Output: ParetoFrontier

Algorithm:
  1. For each option A:
       dominated = false
       For each option B != A:
         If B dominates A (B >= A on all criteria, B > A on at least one):
           dominated = true
           Record B â†’ A as a dominance chain
           Break
       If not dominated:
         Add A to frontier
       Else:
         Add A to dominated list

  2. For each dominance chain (dominator â†’ dominated):
       Identify the criteria_superset (where dominator is strictly >)
       Identify the criteria_equal (where dominator == dominated)

  3. Among frontier options only:
       Run pairwise trade-off detection
       â†’ Results form the trade-off surface

  4. Compute efficiency_ratio = frontier_count / total_options
```

### Pareto Rank Assignment

```
Rank 0: On the Pareto frontier (non-dominated)
Rank 1: Dominated by at least one Rank 0 option
Rank 2: Dominated by at least one Rank 1 option (but not by any Rank 0)
Rank N: Dominated by at least one Rank N-1 option
```

### Option Strength

| Rank | Strength Label | Interpretation |
|------|---------------|----------------|
| 0 | "frontier" | On the Pareto frontier â€” no strictly better option exists |
| 1 | "weak" | Dominated by a frontier option â€” dominated on at least one criterion |
| 2+ | "dominated" | Multiply dominated â€” strictly worse on multiple criteria |

### Visualization (Text-Based)

#### Trade-off Matrix

```
Option Ã— Criterion Scores:
                    speed    cost    quality    safety
    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Option A         0.9     0.2      0.4       0.8
    Option B         0.5     0.8      0.7       0.6
    Option C         0.3     0.9      0.9       0.5
    Option D         0.7     0.4      0.6       0.9
```

#### Radar Chart Description (Text-Based)

```
Radar Chart (text):
                      speed
                      â–²
                    0.9â”‚  A
                    0.7â”‚  D
                    0.5â”‚  B
                    0.3â”‚  C
    safety â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º cost
                    0.3â”‚  C
                    0.5â”‚  B
                    0.7â”‚  D
                    0.9â”‚  A
                      â”‚
                      â–¼
                    quality

    A: high speed & safety, low cost & quality
    B: moderate across board, best cost
    C: low speed, best quality & cost
    D: good balance, best safety
```

#### Trade-off Summary Format

```
Trade-off: Option A vs Option B
  â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
  â•‘ Criterion        â•‘ Option A    â•‘ Option B    â•‘
  â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¬â•â•â•â•â•â•â•â•â•â•â•â•â•â•¬â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
  â•‘ speed            â•‘ 0.9 (WIN)   â•‘ 0.5         â•‘
  â•‘ cost             â•‘ 0.2         â•‘ 0.8 (WIN)   â•‘
  â•‘ quality          â•‘ 0.4         â•‘ 0.7 (WIN)   â•‘
  â•‘ safety           â•‘ 0.8 (WIN)   â•‘ 0.6         â•‘
  â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•

  Result: Non-dominated â€” trade-off exists
  "Option A wins on speed and safety; Option B wins on cost and quality"
  Magnitude: 0.56 (Medium)
```

#### Dominance Flag Format

```
âš  Dominated Option: Option C
  Dominated by: Option A
  Superset criteria: speed, cost, quality
  Equal criteria: safety
  Recommendation: Option A is strictly better on 3 of 4 criteria.
    Consider Option C only if non-analytical factors (e.g., user preference) apply.
```

## Internal Interfaces

```typescript
interface TradeOffAnalyzer {
  analyze(request: DecisionRequest, scoreMatrix: ScoreMatrix[]): TradeOffReport

  getTradeOffs(report: TradeOffReport): TradeOff[]

  getParetoFrontier(
    scoreMatrix: ScoreMatrix[],
    config?: Partial<TradeOffConfig>
  ): ParetoFrontier

  findDominance(
    option_a: ScoreMatrix,
    option_b: ScoreMatrix
  ): DominanceResult

  comparePairwise(
    scoreMatrices: ScoreMatrix[],
    config?: Partial<TradeOffConfig>
  ): TradeOffPair[]

  getCompetingCriteria(
    pairs: TradeOffPair[],
    threshold?: number
  ): CompetingCriteria[]

  calculateMagnitude(
    score_a_c1: number,
    score_a_c2: number,
    score_b_c1: number,
    score_b_c2: number
  ): number

  classifyMagnitude(
    magnitude: number,
    config?: TradeOffConfig
  ): "low" | "medium" | "high"

  generateReport(
    pairs: TradeOffPair[],
    frontier: ParetoFrontier,
    competing: CompetingCriteria[]
  ): TradeOffReport
}
```

### Supporting Utilities

```typescript
interface TradeOffVisualizer {
  renderMatrix(scoreMatrices: ScoreMatrix[], optionLabels: Record<string, string>): string
  renderRadarDescription(scoreMatrices: ScoreMatrix[], optionLabels: Record<string, string>): string
  renderPairSummary(pair: TradeOffPair): string
  renderDominanceFlag(chain: DominanceChain, optionLabels: Record<string, string>): string
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| DEC.DECEvent |     request_id, option_count, criteria_count | Trade-off analysis initiated |
| DEC.DECEvent |     request_id, trade_off_count, frontier_size | Analysis finished |
| DEC.DECEvent |     request_id, pair_count | All pairwise comparisons done |
| DEC.DECEvent |     request_id, frontier_options, dominated_options | Pareto frontier calculated |
| DEC.DECEvent |     request_id, magnitude, criteria_pair, option_pair | Trade-off exceeds high threshold |
| DEC.DECEvent |     request_id, dominator_id, dominated_id, criteria_superset | Option A dominates Option B |
| DEC.DECEvent |     request_id, pair_count | No option dominates â€” trade-offs present |
| DEC.DECEvent |     request_id, criterion_x, criterion_y, label | Custom trade-off type added |
| DEC.DECEvent |     request_id | All options score identically |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| TRO-001 | Every TradeOff involves exactly two criteria and two options | Schema â€” TradeOff.criteria length is 2, options length is 2 |
| TRO-002 | Magnitude is always in [0.0, 1.0] | Algorithmic â€” normalized product of differences |
| TRO-003 | A Pareto frontier always contains at least one option | Algorithmic â€” at minimum, the highest-scoring option per criterion |
| TRO-004 | Dominance is transitive: if A dominates B and B dominates C, then A dominates C | Algorithmic â€” enforced by pairwise comparison closure |
| TRO-005 | Trade-off analysis is deterministic given identical inputs | Architectural â€” no randomness in comparison logic |
| TRO-006 | The report always includes the full pairwise comparison matrix | Architectural â€” consumers need complete picture |
| TRO-007 | Dominated options are never silently removed | Architectural â€” always flagged and explained, never hidden |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Fewer than 2 options provided | `TRO_INSUFFICIENT_OPTIONS` | Return error; comparison requires at least 2 options |
| Fewer than 2 criteria provided | `TRO_INSUFFICIENT_CRITERIA` | Return error; trade-off requires at least 2 criteria |
| Score matrix is empty or malformed | `TRO_INVALID_SCORE_MATRIX` | Return error; cannot analyze without valid scores |
| Scores out of [0.0, 1.0] range | `TRO_SCORE_OUT_OF_RANGE` | Clamp scores and emit warning |
| Maximum pairwise comparisons exceeded | `TRO_TOO_MANY_COMPARISONS` | Sample option pairs instead of full matrix |
| Custom trade-off type references unknown criteria | `TRO_UNKNOWN_CRITERION` | Return error; register criteria first |
| Circular dependency in custom trade-off definitions | `TRO_CIRCULAR_DEFINITION` | Return error; reject configuration |

## Usage Patterns

### Pattern 1: Tool Selection Decision

```
1. Sou has 4 tools that can accomplish the goal
2. Criteria: speed, cost, quality, safety
3. Trade-off Analyzer compares all 6 pairs
4. Results:
   - Tool C is Pareto-dominated by Tool A
   - Tools A, B, D form the Pareto frontier
   - Trade-off: "Tool A is fastest; Tool B is safest; Tool D is best quality"
   - Highest magnitude: A vs D (Speed vs Quality: 0.72 High)
5. Sou sees the trade-off surface and selects Tool A based on strategic priority (speed)
```

### Pattern 2: Plan Selection with Custom Criteria

```
1. Sou has 3 plans for implementing authentication
2. Criteria: speed, maintainability, security, innovation (custom)
3. Sou registered "innovation_vs_stability" as a custom trade-off type
4. Trade-off Analyzer detects:
   - Plan 1 vs Plan 2: Innovation vs Maintainability (magnitude: 0.45 Medium)
   - Plan 2 vs Plan 3: Security vs Speed (magnitude: 0.63 Medium)
   - All 3 options on the Pareto frontier (efficiency_ratio: 1.0)
5. Trade-off surface shows no dominant option â€” clear strategic choice required
6. Sou selects Plan 2, balancing innovation and maintainability
```

### Pattern 3: Post-Decision Trade-off Audit

```
1. Sou made a decision, recorded in Decision History
2. Sou requests: "Show me what I traded off in that last decision"
3. Trade-off Analyzer re-runs on the recorded DecisionRequest
4. Results:
   - 12 trade-offs identified (3 options, 5 criteria)
   - 1 dominated option (Option C)
   - Highest magnitude: Scope vs Depth (0.81 High)
   - Competing Criteria: [scope, depth] conflicts in 4 of 6 pairs
5. Sou reviews and confirms the trade-off was consciously accepted
6. Audit evidence stored alongside DecisionRecord
```


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
| R1 â€” Modulsingularity | Trade-off Analyzer does one thing: surface criterion conflicts |
| R2 â€” Dependency Order | Depends on Score Matrix from Scorer Engine; produces input for Constraint Checker |
| R3 â€” DRY | Trade-off types defined in config, reused across all comparisons |
| R4 â€” Builder Pattern | Report built by Pairwise â†’ Pareto â†’ Competing â†’ Aggregation pipeline |
| R5 â€” Liskov Substitution | Any TradeOffConfig with custom types implements the same interface |
| R6 â€” DI over Singletons | Thresholds, custom types, comparison limits injected via TradeOffConfig |
| R9 â€” Deterministic | Same score matrix and config always produce identical report |
| R10 â€” Simpler Over Complex | Uses O(nÂ²) pairwise comparison with Pareto ordering â€” no ML or heuristics |
| R13 â€” Design for Failure | Option sampling protects against combinatorial explosion |
| R14 â€” Paved Path | All analysis flows through `analyze(request, scoreMatrix)` |
| R15 â€” Open/Closed | New trade-off types added via CustomTradeOffType in config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Decision/000-Overview.md | Trade-off Analyzer is a sub-system of the Decision System |
| Decision/001-Scoring-Engine.md | Scorer Engine produces the ScoreMatrix consumed by Trade-off Analyzer |
| Decision/003-Constraints.md | Constraint Checker runs after trade-off analysis for final filtering |
| Brain/Sou/000-Overview.md | Sou consumes TradeOffReport to make strategic decisions |
| Brain/Context/000-Overview.md | Context System provides the context snapshot for trade-off framing |
| Bible/05-Platform/004-EVS.md | All Trade-off events recorded as evidence |
| Bible/05-Platform/007-EIP.md | TradeOffConfig stored in platform configuration |
