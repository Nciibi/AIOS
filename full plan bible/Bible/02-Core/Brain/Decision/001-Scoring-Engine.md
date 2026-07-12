# AIOS Bible â€” Brain
## 001 â€” Scoring Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-001 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Scoring Engine evaluates each decision option against each criterion to produce a normalized score matrix. It implements 4 scoring functions (linear, threshold, boolean, custom), weighted aggregation, and confidence estimation.

Under DEC-004, criteria weights must sum to 1.0 and are enforced at request validation.

## Data Model

### ScoreMatrix

```typescript
ScoreMatrix {
  request_id: string
  option_scores: ScoredOption[]
  computed_at: timestamp
  metadata: {
    scoring_function_count: number
    criteria_weights_validated: boolean
    normalizer_version: string
  }
}
```

### ScoredOption

```typescript
ScoredOption {
  option_id: string
  option: DecisionOption
  criterion_scores: CriterionScore[]
  raw_total: number           // Sum of raw scores before weighting
  weighted_total: number      // Sum of (score Ã— weight)
  rank: number                // 1-based, descending by weighted_total
  confidence: number          // 0.0â€“1.0 per-option confidence
}
```

### CriterionScore

```typescript
CriterionScore {
  criterion_id: string
  criterion_name: string
  raw_score: number           // Pre-normalization output of scoring function
  normalized_score: number    // After normalization to [0.0, 1.0]
  weighted_score: number      // normalized_score Ã— criterion.weight
  weight: number              // Copied from criterion at evaluation time
}
```

### ScoringFunction

```typescript
interface ScoringFunction {
  name: string
  type: "linear" | "threshold" | "boolean" | "custom"
  score(
    attribute_value: number | boolean | unknown,
    preferences: PreferenceDirection,
    config: ScoringConfig
  ): number
}
```

### ScoringConfig Variants

```typescript
LinearConfig {
  max_value: number              // Reference maximum for normalization
  min_value?: number             // Reference minimum (default 0)
  target_value?: number          // For "target" preference direction
  sigma?: number                 // Standard deviation for gaussian target (default 1.0)
}

ThresholdConfig {
  threshold: number
  direction: "above" | "below"  // Pass if value is above or below threshold
  pass_score: number             // Default 1.0
  fail_score: number             // Default 0.0
}

BooleanConfig {
  true_score: number             // Default 1.0
  false_score: number            // Default 0.0
}

CustomConfig {
  function_id: string            // Registered custom function identifier
  parameters: Record<string, unknown>
}
```

### ScoreNormalizer

```typescript
ScoreNormalizer {
  method: "minmax" | "zscore" | "none"
  options: {
    clamp_min: number            // Default 0.0
    clamp_max: number            // Default 1.0
    outlier_threshold: number    // Z-score threshold for outlier detection (default 3.0)
  }
}
```

### AggregationConfig

```typescript
AggregationConfig {
  normalize_first: boolean       // Normalize before weighting (default true)
  weight_verification: boolean   // Verify sum of weights = 1.0 (default true)
  confidence_enabled: boolean    // Compute confidence estimates (default true)
  ranking_method: "weighted_total" | "weighted_total_desc"
}
```

## Scoring Functions

### 1. Linear

Linear scoring maps a numeric attribute value to a score using direct proportion. The behavior depends on preference direction:

```
Linear (maximize):
  score = value / max_value
  Use case: Speed, throughput, reliability
  Example: latency = 50ms, max_value = 200ms â†’ score = 0.25

Linear (minimize):
  score = 1 - (value / max_value)
  Use case: Cost, resource usage, error rate
  Example: cost = $10, max_value = $50 â†’ score = 0.80

Linear (target):
  score = exp(-0.5 Ã— ((value - target) / sigma)Â²)
  (Gaussian centered at target value)
  Use case: Ideal operating point, preferred configuration
  Example: workers = 8, target = 10, sigma = 2 â†’ score = 0.88

Edge: value > max_value â†’ score clamped to 1.0 (maximize) or 0.0 (minimize)
Edge: max_value = 0 â†’ score = 0.0 (division by zero guard)
```

### 2. Threshold

Threshold scoring is a step function that assigns a pass or fail score based on a cutoff:

```
Threshold (above):
  if value >= threshold â†’ pass_score (1.0)
  else â†’ fail_score (0.0)
  Use case: Minimum quality gate, compliance check

Threshold (below):
  if value <= threshold â†’ pass_score (1.0)
  else â†’ fail_score (0.0)
  Use case: Maximum cost cap, time limit

Edge: value equals threshold exactly â†’ pass_score
Edge: threshold is NaN â†’ fail_score
```

### 3. Boolean

Boolean scoring maps an exact truth value to a binary score:

```
Boolean:
  if value === true â†’ true_score (1.0)
  if value === false â†’ false_score (0.0)
  Use case: Capability presence, feature flag, compatibility check

Edge: value is undefined or null â†’ false_score
Edge: value is truthy but not boolean â†’ treated as true (coerced)
```

### 4. Custom

Custom scoring provides a plugin interface for domain-specific logic:

```
Custom:
  score = registered_functions[function_id].evaluate(value, parameters)
  Use case: Domain-specific heuristics, ML model output, composite formulas

Contract:
  - Input: value (unknown), parameters (Record<string, unknown>)
  - Output: number in [0.0, 1.0] (must be clamped by implementation)
  - Registered via ScoringEngine.registerFunction()

Edge: function_id not found â†’ throw DEC_UNKNOWN_FUNCTION
Edge: function throws â†’ score defaults to 0.0, error logged
```

## Score Matrix Computation

The Scoring Engine computes a complete score matrix in five phases:

### Phase 1: Raw Score Computation

For each (option Ã— criterion) pair, compute the raw score using the criterion's scoring function:

```
For each option in request.options:
  For each criterion in request.criteria:
    raw_score = scoring_function.score(
      option.attributes[criterion.scoring_function],
      criterion.preferences,
      criterion.config
    )
    Store in criterion_scores[]
```

### Phase 2: Normalization

Normalize each raw score to [0.0, 1.0] using the configured ScoreNormalizer:

```
If normalizer.method is "minmax":
  For each criterion across all options:
    min = min(raw_scores for criterion)
    max = max(raw_scores for criterion)
    if max == min: normalized = 0.5 for all (uniform)
    else: normalized = (raw - min) / (max - min)

If normalizer.method is "zscore": (cross-option)
  For each criterion across all options:
    mean = average(raw_scores for criterion)
    std = standard_deviation(raw_scores for criterion)
    if std == 0: normalized = 0.5 for all (uniform)
    else: z = (raw - mean) / std
    normalized = clamp((z + 3) / 6, 0.0, 1.0)  // Map z [-3, 3] to [0.0, 1.0]

If normalizer.method is "none":
  normalized = raw (must already be in [0.0, 1.0])
```

### Phase 3: Weight Application

```
For each CriterionScore:
  weighted_score = normalized_score Ã— criterion.weight
```

### Phase 4: Total and Rank

```
For each ScoredOption:
  weighted_total = sum of weighted_score for all criterion_scores
  raw_total = sum of normalized_score for all criterion_scores

Rank all ScoredOptions by weighted_total descending:
  rank 1 = highest weighted_total
  ties receive same rank (gap left for count: 1, 2, 2, 4)
```

### Phase 5: Confidence Estimation

```
For each ScoredOption:
  option_confidence = computeConfidence(option, criteria)
```

## Weighted Aggregation

### Normalization

All scores must be on [0.0, 1.0] scale before weighting. The Scoring Engine applies normalization as the first step in aggregation (AggregationConfig.normalize_first = true).

```
Guarantee: Every CriterionScore.normalized_score âˆˆ [0.0, 1.0]
Enforcement: ScoreNormalizer clamps final output to [clamp_min, clamp_max]
```

### Weight Application

```
weighted_score = normalized_score Ã— criterion.weight

Weight properties:
  - criterion.weight âˆˆ [0.0, 1.0]
  - Higher weight â†’ greater influence on weighted_total
  - weight = 0.0 â†’ criterion has no effect (can be used for tracking only)
```

### Summation

```
weighted_total = Î£ (normalized_score_i Ã— weight_i) for i = 1 to N criteria

Properties:
  - weighted_total âˆˆ [0.0, 1.0] (since normalized_score âˆˆ [0,1], weights sum to 1.0)
  - weighted_total = 1.0 â†’ all criteria maximally satisfied
  - weighted_total = 0.0 â†’ all criteria minimally satisfied
```

### Weight Verification

Per DEC-004, the sum of all criterion weights must equal 1.0:

```
On EvaluationRequest validation:
  weight_sum = Î£ criterion.weight for all criteria in request
  If abs(weight_sum - 1.0) > EPSILON (1e-6):
    If AggregationConfig.weight_verification is true:
      Normalize: criterion.weight = criterion.weight / weight_sum
    Else:
      Emit DEC.InvalidWeights warning, proceed with unnormalized weights
```

## Confidence Estimation

Confidence reflects how reliable the scored recommendation is. It is computed per-option and aggregated into an overall confidence for the ScoreMatrix.

### Confidence Formula

```
confidence = completeness Ã— coverage Ã— (1 - variance_penalty)

Where:
  completeness      = fraction of criteria that have non-null attribute values for this option
  coverage          = fraction of criteria that were successfully scored (no errors)
  variance_penalty  = min(variance of normalized scores across criteria, 1.0)
```

### Confidence Levels

| Range | Label | Interpretation |
|-------|-------|---------------|
| > 0.8 | High | Strong recommendation; all criteria scored, low variance |
| 0.5â€“0.8 | Medium | Moderate confidence; some data gaps or moderate variance |
| < 0.5 | Low | Weak recommendation; significant data missing or high variance |

### Per-Component Details

```
Computation details:

Completeness:
  criteria_with_value = count(criterion where option.attributes[criterion_id] != null)
  total_criteria = count(criteria)
  completeness = criteria_with_value / total_criteria

Coverage:
  criteria_scored = count(criterion where scoring_function did not error)
  coverage = criteria_scored / total_criteria

Variance Penalty:
  scores = [normalized_score for each criterion]
  if len(scores) <= 1: variance_penalty = 0
  else:
    mean = average(scores)
    variance = sum((s - mean)Â² for s in scores) / len(scores)
    variance_penalty = min(variance, 1.0)
```

## Score Normalization

### Min-Max Normalization

Min-max normalization scales raw scores linearly to [0.0, 1.0] based on the observed range:

```
normalized = (raw - min) / (max - min)

Properties:
  - Preserves relative distances between scores
  - Sensitive to outliers (one extreme value compresses the rest)
  - Default method for linear scoring functions
```

### Boolean / Threshold Normalization

Boolean and threshold functions already produce normalized outputs:

```
Boolean: output is always 0.0 or 1.0 (already normalized)
Threshold: output is always pass_score or fail_score (already normalized)
Normalizer method: "none" (bypass min-max)
```

### Cross-Option Normalization (Z-Score)

Z-score normalization applies across all options for a given criterion, useful for handling outliers:

```
z = (raw - mean) / std
normalized = clamp((z + 3) / 6, 0.0, 1.0)

Properties:
  - Mitigates outlier impact (extreme values compressed)
  - Assumes approximately normal distribution of scores
  - Negative scores possible before clamping (clamped to 0.0)
```

### Outlier Handling

```
If ScoreNormalizer.outlier_threshold is set:
  For each criterion:
    z_scores = compute all option z-scores for this criterion
    options with |z| > outlier_threshold are flagged
    Flagged options are logged in ScoreMatrix.metadata.outliers

Treatment:
  - Outliers are not removed (Sou must decide)
  - Normalization adjusts to reduce outlier impact
  - ScoreMatrix.metadata includes outlier_info for transparency
```

## Internal Interface

```typescript
interface ScoringEngine {
  score(request: EvaluationRequest): ScoreMatrix
  scoreOption(option: DecisionOption, criteria: DecisionCriterion[]): ScoredOption
  getScoreMatrix(request_id: string): ScoreMatrix | null
  getConfidence(option_id: string, request_id: string): number | null
  registerFunction(name: string, fn: ScoringFunction): void
  getRegisteredFunctions(): Map<string, ScoringFunction>
}
```

### Method Details

```
score(request):
  - Validates criteria weights sum to 1.0 (DEC-004)
  - Iterates over all option Ã— criterion pairs
  - Applies scoring function, normalization, weighting, ranking
  - Computes confidence estimates
  - Returns ScoreMatrix
  - Emits DEC.ScoreMatrixComputed on completion

scoreOption(option, criteria):
  - Scores a single option against provided criteria
  - Returns ScoredOption with criterion_scores and weighted_total
  - Useful for incremental evaluation (fast path)

getScoreMatrix(request_id):
  - Retrieves cached ScoreMatrix for a completed request
  - Returns null if request_id not found or expired

getConfidence(option_id, request_id):
  - Returns confidence score for a specific option
  - Returns null if option not in matrix

registerFunction(name, fn):
  - Registers a custom ScoringFunction for use in scoring
  - Validates: function_id is unique, fn.score is callable
  - Throws DEC_DUPLICATE_FUNCTION if name already registered

getRegisteredFunctions():
  - Returns map of all registered custom scoring functions
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `DEC.ScoreMatrixComputed` | request_id, option_count, criteria_count | Score matrix computed and ranked |
| `DEC.ScoreApplied` | request_id, option_id, criterion_id, raw_score, normalized_score | Single score applied for a pair |
| `DEC.NormalizationApplied` | request_id, method, criteria_normalized | Normalization phase completed |
| `DEC.WeightsApplied` | request_id, weight_sum, verified | Weighting phase completed |
| `DEC.ConfidenceEstimated` | request_id, overall_confidence, option_confidences | Confidence estimation complete |
| `DEC.OutlierDetected` | request_id, criterion_id, option_id, z_score | Outlier flagged during normalization |
| `DEC.CustomFunctionInvoked` | function_id, request_id, option_id, success | Custom scoring function executed |
| `DEC.InvalidWeights` | request_id, weight_sum, normalized_flag | Criteria weights do not sum to 1.0 |
| `DEC.MatrixCached` | request_id, ttl_ms | ScoreMatrix cached for retrieval |
| `DEC.MatrixExpired` | request_id, age_ms | Cached ScoreMatrix evicted |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEC-001 | The Decision System recommends; Sou decides | API-level â€” ScoringEngine never auto-executes |
| DEC-004 | Criteria weights always sum to 1.0 | Validation â€” enforced on score() entry |
| DEC-SC-001 | Every normalized score is in [0.0, 1.0] | Algorithmic â€” ScoreNormalizer clamps output |
| DEC-SC-002 | Every weighted_total is in [0.0, 1.0] | Mathematical â€” sum of (score âˆˆ [0,1] Ã— weight âˆˆ [0,1]) where Î£ weight = 1 |
| DEC-SC-003 | Rank order is deterministic for identical inputs | Algorithmic â€” no randomness in scoring pipeline |
| DEC-SC-004 | Custom scoring functions cannot modify internal state | Architectural â€” functions receive values, return scores |
| DEC-SC-005 | Confidence never exceeds 1.0 | Algorithmic â€” confidence = product of three [0,1] factors |
| DEC-SC-006 | ScoreMatrix is immutable after computation | API-level â€” no update methods exposed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| No options provided | `DEC_NO_OPTIONS` | Return error; cannot score empty set |
| No criteria provided | `DEC_NO_CRITERIA` | Return error; cannot evaluate without criteria |
| Criteria weights don't sum to 1.0 | `DEC_INVALID_WEIGHTS` | Normalize weights and proceed (emit DEC.InvalidWeights) |
| Unknown scoring function | `DEC_UNKNOWN_FUNCTION` | Return error; reject request |
| Unknown custom function_id | `DEC_UNKNOWN_FUNCTION` | Return error; function must be registered |
| Duplicate function registration | `DEC_DUPLICATE_FUNCTION` | Return error; function_id must be unique |
| Division by zero in normalization | `DEC_NORMALIZATION_ERROR` | Default to uniform score (0.5) for affected criterion |
| Overflow in confidence computation | `DEC_CONFIDENCE_ERROR` | Default confidence to 0.0 for affected option |
| Request_id collision in cache | `DEC_CACHE_COLLISION` | Overwrite existing entry; emit warning |

## Usage Patterns

### Pattern 1: Tool Selection Scoring

```
1. Sou needs to choose a tool: SearchWeb, ReadFile, or ExecuteCommand
2. Criteria: speed (maximize), cost (minimize), safety (boolean)
3. Scoring Engine evaluates each tool:
   - SearchWeb:   speed=0.3, cost=0.8, safety=1.0 â†’ weighted_total=0.70
   - ReadFile:    speed=0.9, cost=1.0, safety=0.0 â†’ weighted_total=0.63
   - ExecCommand: speed=0.5, cost=0.6, safety=0.0 â†’ weighted_total=0.37
4. Ranked: [1] SearchWeb (0.70), [2] ReadFile (0.63), [3] ExecCommand (0.37)
5. Sou reviews, considers safety trade-off, selects SearchWeb
```

### Pattern 2: Plan Path Evaluation

```
1. Sou has two plan paths for "Implement auth": Path A (OAuth) and Path B (JWT)
2. Criteria: security (threshold), effort (minimize), maintainability (linear maximize)
3. Scoring:
   - Path A: security=1.0, effort=0.4, maintainability=0.8 â†’ weighted_total=0.73
   - Path B: security=0.0, effort=0.7, maintainability=0.6 â†’ weighted_total=0.43
4. Path A ranked first; confidence = 0.85 (high â€” all criteria scored, low variance)
5. Sou chooses Path A; decision logged for future plan similarity matching
```

### Pattern 3: Feature Comparison

```
1. Sou considering features to implement: caching, retry logic, logging
2. Criteria: user_value (linear maximize), complexity (linear minimize), reuse (boolean)
3. Custom scoring function "value_complexity_ratio" applied for user_value
4. ScoreMatrix reveals:
   - caching:    high value, medium complexity, reusable â†’ rank 1
   - retry:      medium value, low complexity, reusable â†’ rank 2
   - logging:    low value, low complexity, not reusable â†’ rank 3
5. Confidence for caching = 0.92 (high); retry = 0.88 (high); logging = 0.75 (medium)
6. Sou decides: implement caching first, retry second, defer logging
```

### Pattern 4: Batch Re-scoring with Custom Weights

```
1. Sou evaluated options with default criteria weights
2. User provides feedback: "I care more about cost than speed"
3. Sou updates criterion weights: cost=0.40, speed=0.05, quality=0.30, safety=0.25
4. Sou calls score() with same options but new criteria (weights sum to 1.0)
5. ScoreMatrix recomputed: options re-ranked with new weight distribution
6. Sou compares old and new rankings to understand cost impact on recommendation
```

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Scoring Engine handles only scoring, normalization, and aggregation |
| R2 â€” Dependency Order | Depends on Decision System models; no upward deps |
| R3 â€” DRY | Scoring functions defined once in Registry, referenced by name |
| R4 â€” Builder Pattern | ScoreMatrix built incrementally: score â†’ normalize â†’ weight â†’ rank |
| R5 â€” Liskov Substitution | Any ScoringFunction implements the interface |
| R6 â€” DI over Singletons | Scoring functions, normalizer, aggregator injected |
| R9 â€” Deterministic | Same inputs, same ScoreMatrix (no randomness) |
| R10 â€” Simpler Over Complex | Weighted sum model; no ML, neural networks, or probabilistic models |
| R13 â€” Design for Failure | Normalization errors fall back to uniform scores; custom function errors logged |
| R14 â€” Paved Path | All scoring flows through score() â†’ scoreMatrix() |
| R15 â€” Open/Closed | New scoring functions via registerFunction(); no engine modification |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Decision/000-Overview.md | Scoring Engine is the first stage of the Decision System pipeline |
| Decision/002-Trade-off-Analysis.md | Trade-off Analyzer consumes ScoreMatrix for conflict detection |
| Decision/003-Constraints.md | Constraint Checker runs before scoring to eliminate non-viable options |
| Decision/004-Criteria-Registry.md | Criteria Registry provides the scoring functions and weights |
| Decision/005-Decision-Pipeline.md | ScoreMatrix is logged via the pipeline's History Logger stage |
| Brain/000-Overview.md | Scoring Engine is a Brain Service component |
| Brain/Sou/000-Overview.md | Sou invokes the Scoring Engine via evaluateOptions |
| Bible/05-Platform/004-EVS.md | Events emitted throughout scoring lifecycle |

(End of file - total 449 lines)
