# AIOS Bible — Execution
## 003 — Validation & Results Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Simulation |
| Document ID | AIOS-BBL-004-SIM-003 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Validate simulation results against success criteria, detect anomalies, compute confidence intervals, and produce actionable recommendations. The Validation & Results Analysis layer transforms raw simulation output into structured evidence that informs decisions, drives learning, and verifies constitutional compliance.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│               Validation & Results Analysis                   │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Criterion   │    │   Anomaly    │    │  Confidence   │  │
│  │  Evaluator   │    │   Detector   │    │  Computer     │  │
│  └──────┬───────┘    └──────┬───────┘    └───────┬───────┘  │
│         │                   │                    │           │
│         └───────────┬───────┴────────┬───────────┘           │
│                     │                │                       │
│            ┌────────▼───────┐  ┌─────▼────────────┐         │
│            │  Comparison    │  │  Recommendation  │         │
│            │  Engine        │  │  Generator       │         │
│            │  (replay,      │  │  (from anomalies,│         │
│            │   multi-run)   │  │   criteria, CI)  │         │
│            └────────────────┘  └──────────────────┘         │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              Validation Report Builder                │    │
│  │  Aggregates criteria, anomalies, CI, comparisons,    │    │
│  │  and recommendations into a structured report        │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
           │                      │              │
           ▼                      ▼              ▼
     ┌──────────┐          ┌──────────┐    ┌──────────┐
     │   EVS    │          │ Decision │    │ Academy  │
     │ (evidence)│         │  System  │    │ (learning)│
     └──────────┘          └──────────┘    └──────────┘
```

### Success Criteria Evaluation

Each `Criterion` from the scenario is evaluated against the actual outcome metrics:

| Operator | Evaluation |
|----------|------------|
| `gt` | metric > value → passed |
| `gte` | metric >= value → passed |
| `lt` | metric < value → passed |
| `lte` | metric <= value → passed |
| `eq` | metric === value → passed |
| `neq` | metric !== value → passed |

Evaluation produces a `CriterionEvaluation` record with actual value, expected value, operator, pass/fail status, and the delta between expected and actual.

### Anomaly Detection

Three anomaly detection algorithms operate on the state trajectory:

1. **Outlier Detection**: Identifies state points where key indicators deviate beyond configured thresholds from the running mean/stddev
2. **Trend Deviation**: Detects when the trajectory slope deviates from expected trend bounds (linear regression on sliding window)
3. **State Divergence**: Flags points where the state hash diverges from the expected state (used in replay comparison)

Each anomaly includes the timestamp, anomaly type, severity level, affected metrics, and a description of the deviation.

### Confidence Computation

Confidence is computed per the base doc formula:

```
confidence = 1 - (uncertainty / maxPossibleUncertainty)
```

Where uncertainty is derived from:
- Variance in state trajectory metrics across simulation steps
- Number of anomalies detected (weighted by severity)
- Number of criteria that failed vs total
- Simulator model confidence (reported by each domain simulator)

The result is a confidence interval `{ low: number, high: number }` representing the range of likely outcome values.

### Replay Comparison

When a simulation is replayed, the original and replay results are compared:

- **State trajectory alignment**: Compare state hashes at each step; flag divergences
- **Metric comparison**: Compare outcome metrics with tolerance thresholds
- **Anomaly comparison**: Check if anomalies from the original run appear in the replay
- **Consistency score**: A 0–1 score where 1.0 indicates identical results

### Multi-Run Comparison

For hypothesis chains and variant analysis, multiple runs are compared:

- **Side-by-side metrics**: Compare outcome metrics across all runs
- **Relative delta**: Compute percentage difference between each variant and the base scenario
- **Pareto ranking**: Rank variants by multi-metric performance (useful for trade-off analysis)
- **Statistical significance**: Apply Student's t-test or ANOVA to determine if differences are meaningful

### Recommendation Generation

Based on validation results, the generator produces actionable recommendations:

| Condition | Recommendation |
|-----------|---------------|
| All criteria passed, no anomalies | Proceed with execution |
| Criteria passed but anomalies detected | Investigate anomalies; re-run with different seed |
| Criteria failed | Block execution; provide delta analysis |
| Multi-run comparison shows clear winner | Recommend winning variant |
| Low confidence interval | Recommend additional simulation runs with broader parameter sweep |
| Replay mismatch detected | Flag non-determinism; investigate domain simulator |

## Data Model

```typescript
interface ValidationResult {
  resultId: string;
  runId: string;
  scenarioId: string;
  scenarioVersion: number;
  criteriaEvaluations: CriterionEvaluation[];
  anomalies: AnomalyReport[];
  confidenceInterval: ConfidenceInterval;
  replayComparison: ReplayComparison | null;
  multiRunComparison: MultiRunComparison | null;
  recommendations: Recommendation[];
  overallStatus: 'passed' | 'failed' | 'inconclusive';
  timestamp: Timestamp;
}

interface CriterionEvaluation {
  metric: string;
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq';
  expectedValue: number;
  actualValue: number;
  delta: number;
  passed: boolean;
  description: string;
}

interface AnomalyReport {
  anomalyId: string;
  type: 'outlier' | 'trendDeviation' | 'stateDivergence';
  severity: 'low' | 'medium' | 'high' | 'critical';
  simulatedTime: Timestamp;
  stepNumber: number;
  affectedMetrics: string[];
  expectedValue: number | null;
  actualValue: number | null;
  description: string;
  confidence: number;
}

interface ConfidenceInterval {
  low: number;
  high: number;
  confidenceLevel: number;
  method: 'variance' | 'bayesian' | 'bootstrapping';
  samplesUsed: number;
}

interface Recommendation {
  recommendationId: string;
  type: 'proceed' | 'block' | 'investigate' | 'rerun' | 'compare' | 'retune';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  supportingEvidence: string[];
  conditions: string[];
  actions: string[];
}

interface ComparisonReport {
  comparisonId: string;
  type: 'replay' | 'multiRun';
  baseRunId: string;
  compareRunIds: string[];
  metrics: MetricComparison[];
  consistencyScore: number | null; // for replay comparisons
  ranking: VariantRanking[] | null; // for multi-run comparisons
  statisticalSignificance: StatisticalSignificance | null;
}

interface MetricComparison {
  metric: string;
  baseValue: number;
  compareValues: Record<string, number>;
  deltas: Record<string, number>;
  percentChange: Record<string, number>;
}

interface VariantRanking {
  variantId: string;
  rank: number;
  score: number;
  strengths: string[];
  weaknesses: string[];
}

interface StatisticalSignificance {
  method: 'ttest' | 'anova' | 'mannwhitney';
  pValue: number;
  isSignificant: boolean;
  effectSize: number;
}

interface ReplayComparison {
  originalRunId: string;
  replayRunId: string;
  stepCount: number;
  matchedSteps: number;
  divergentSteps: number;
  trajectoryMatchScore: number;
  metricMatchScore: number;
  anomalyMatchScore: number;
  overallConsistencyScore: number;
  divergentFrames: DivergentFrame[];
}

interface DivergentFrame {
  stepNumber: number;
  simulatedTime: Timestamp;
  originalStateHash: string;
  replayStateHash: string;
  mismatchedMetrics: Record<string, { original: number; replay: number }>;
}

interface MultiRunComparison {
  baseRunId: string;
  variantRunIds: string[];
  metricMatrix: Record<string, Record<string, number>>;
  rankings: VariantRanking[];
  statisticalTests: StatisticalSignificance[];
  recommendation: string;
}
```

## Core Concepts / Operations

- **Criterion Evaluation**: Run each criterion against actual metrics; produce pass/fail with deltas
- **Anomaly Scanning**: Run all three detection algorithms across the state trajectory
- **Confidence Calculation**: Aggregate uncertainty sources into a confidence interval
- **Replay Verification**: Compare original and replay state trajectories frame by frame
- **Multi-Run Analysis**: Compare base and variant runs across shared metrics
- **Recommendation Synthesis**: Combine criteria, anomalies, CI, and comparisons into a decision recommendation

## Internal Interfaces

```typescript
interface CriterionEvaluator {
  evaluate(metrics: Record<string, number>, criteria: Criterion[]): CriterionEvaluation[];
  evaluateSingle(metric: string, actual: number, criterion: Criterion): CriterionEvaluation;
}

interface AnomalyDetector {
  detectOutliers(trajectory: StatePoint[], thresholds: OutlierThresholds): AnomalyReport[];
  detectTrendDeviation(trajectory: StatePoint[], expectedTrend: TrendLine): AnomalyReport[];
  detectStateDivergence(actual: StatePoint[], expected: StatePoint[]): AnomalyReport[];
  setThresholds(thresholds: OutlierThresholds): void;
}

interface ConfidenceComputer {
  compute(result: SimulationResult, anomalies: AnomalyReport[], criteriaResults: CriterionEvaluation[]): ConfidenceInterval;
  fromVariance(values: number[], confidenceLevel: number): ConfidenceInterval;
  fromBayesian(prior: Distribution, evidence: number[]): ConfidenceInterval;
}

interface ComparisonEngine {
  compareReplay(original: SimulationResult, replay: SimulationResult): ReplayComparison;
  compareMultiRun(base: SimulationResult, variants: SimulationResult[]): MultiRunComparison;
  computeConsistency(original: ExecutionFrame[], replay: ExecutionFrame[]): number;
}

interface RecommendationGenerator {
  generate(result: ValidationResult): Recommendation[];
  prioritize(recommendations: Recommendation[]): Recommendation[];
  format(recommendation: Recommendation): string;
}

interface ValidationReportBuilder {
  build(resultId: string, runId: string, scenario: Scenario, simulationResult: SimulationResult): Promise<ValidationResult>;
  addReplayComparison(validationResult: ValidationResult, originalRunId: string): Promise<ValidationResult>;
  addMultiRunComparison(validationResult: ValidationResult, baseRunId: string, variantRunIds: string[]): Promise<ValidationResult>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `SIM.Val.ValidationStarted` | resultId, runId, scenarioId | Validation analysis began on simulation result |
| `SIM.Val.CriterionEvaluated` | resultId, metric, operator, passed | Individual criterion evaluated |
| `SIM.Val.AnomalyDetected` | resultId, anomalyType, severity, step | Anomaly detected in state trajectory |
| `SIM.Val.ConfidenceComputed` | resultId, low, high, confidenceLevel | Confidence interval calculated |
| `SIM.Val.ReplayCompared` | resultId, originalRunId, consistencyScore | Replay comparison completed |
| `SIM.Val.MultiRunCompared` | resultId, baseRunId, variantCount, topVariant | Multi-run comparison completed |
| `SIM.Val.RecommendationGenerated` | resultId, recommendationType, priority | Actionable recommendation produced |
| `SIM.Val.ValidationCompleted` | resultId, overallStatus, totalDuration | Full validation analysis completed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Criterion metric not found in results | `SIM_VAL_001` | Skip criterion; mark as unevaluated with warning |
| Anomaly detection algorithm failed | `SIM_VAL_002` | Log error; continue with remaining algorithms |
| Insufficient data points for confidence computation | `SIM_VAL_003` | Return wide confidence interval; flag as low confidence |
| Replay comparison requires matching runIds | `SIM_VAL_004` | Fail comparison; verify runId inputs |
| Multi-run comparison with fewer than 2 runs | `SIM_VAL_005` | Fail comparison; require at least 2 runs for comparison |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SIM-VAL-001 | Every criterion in the scenario must be evaluated exactly once per validation run | Algorithmic — CriterionEvaluator returns one result per criterion |
| SIM-VAL-002 | Anomaly detection algorithms are stateless and produce identical results for identical inputs | Algorithmic — algorithms are pure functions of trajectory data |
| SIM-VAL-003 | Confidence interval bounds are always within [0, 1] and low <= high | Algorithmic — ConfidenceComputer clamps and validates |
| SIM-VAL-004 | Replay comparison always produces a consistency score in [0, 1] | Algorithmic — ComparisonEngine normalizes output |
| SIM-VAL-005 | A validation result cannot be modified after it is recorded to EVS | Architectural — ValidationReportBuilder emits immutable records |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Validation is the sole authority on simulation result evaluation; no other component interprets criteria or anomalies |
| R2 — Dependency Order | Validation depends on SimulationResult and Scenario (for criteria); no circular dependencies |
| R3 — DRY | Criterion evaluation logic is defined once; all six operators share the same evaluation pipeline |
| R9 — Deterministic | Same simulation result + same criteria = same validation result; algorithms are pure functions |
| R10 — Simpler Over Complex | Single-criterion evaluation with binary pass/fail is the default; multi-run comparison is opt-in |
| R13 — Design for Failure | Anomaly detection algorithm failure does not block other algorithms; partial results are preserved |
| R14 — Paved Path | Single-criterion evaluation with confidence computation and proceed/block recommendation is the standard path |
| R15 — Open/Closed | New anomaly detection algorithms can be registered without modifying the evaluator or comparison engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Simulation/000-Overview.md | System overview defining validation as the result analysis layer |
| Bible/04-Execution/Simulation/001-Simulation-Engine.md | Engine produces SimulationResult consumed by validation |
| Bible/04-Execution/Simulation/002-Scenarios.md | Scenarios provide the successCriteria evaluated by validation |
| Bible/02-Core/Brain/Decision/000-Overview.md | Decision System consumes ValidationResult to determine whether to execute |
| Bible/02-Core/Academy/000-Overview.md | Academy learns from validation results (patterns in anomalies, criteria failures) |
| Bible/05-Platform/004-EVS.md | EVS stores ValidationResult as evidence records |
| Physics/010-Execution.md | Execution invariants — simulation results must be validated before execution decisions |
| Physics/005-Events.md | Evidence invariants — validation results are auditable evidence records |
