# AIOS Bible — Domains
## Economic — 003: Economic Simulation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-ECN-003 |
| Source Laws | Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Economic Simulation sub-domain provides the what-if analysis and scenario modeling infrastructure for AIOS — budget scenario modeling, resource pricing impact assessment, demand elasticity testing, market condition simulation, and comparative outcome analysis. Simulations consume economic models (Economic/001-Models.md), cost analysis data (Economic/002-Analysis.md), and base Economic types (Economic/000-Overview.md) to project outcomes under alternative conditions. Simulations are advisory (Law 6) and all simulation outputs must be traceable to input parameters and evidence (Law 4). Simulations are bounded by capability constraints to prevent runaway computation (Law 7).

## Architecture

```
Scenario Definition ──► Parameter Configuration ──► Simulation Execution ──► Outcome Analysis
        │                        │                          │                     │
        ▼                        ▼                          ▼                     ▼
Scenario Store            Parameter Bounds            Execution Engine      Comparison Reports
                                                                                  │
                                                                                  ▼
                                                                           Sensitivity Report
```

Users define scenarios by specifying what changes relative to a baseline (e.g., budget amount, resource price, demand level). Parameters are validated against bounds. The simulation engine runs the model with the modified parameters, collects outcomes, and produces comparison reports against the baseline. Sensitivity analysis varies parameters systematically to quantify impact.

## Data Model (TypeScript — extend the base doc types from Economic/000-Overview.md)

```typescript
interface EconomicScenario {
  scenarioId: string;
  name: string;
  description: string;
  baselineRef: string;  // reference to budget or model used as baseline
  changes: ScenarioChange[];
  params: SimulationParams;
  status: 'defined' | 'running' | 'completed' | 'failed' | 'diverged';
  outcomeRef: string | null;  // SimulationOutcome ID
  createdAt: Timestamp;
  evidenceRef: string;
}

interface SimulationParams {
  timeHorizon: Duration;
  timeStep: 'hour' | 'day' | 'week' | 'month';
  iterations: number;  // number of simulation runs
  confidenceLevel: number;  // e.g. 0.95
  seed: number;  // deterministic RNG seed
  bounds: SimulationBounds;
}

interface SimulationOutcome {
  outcomeId: string;
  scenarioId: string;
  resourceProjections: ResourceOutcome[];
  budgetImpact: BudgetImpact;
  totalCost: number;
  totalSavings: number;
  riskMetrics: RiskMetrics;
  stabilityScore: number;  // 0.0 to 1.0
  warnings: SimulationWarning[];
  completedAt: Timestamp;
}

interface ScenarioComparison {
  comparisonId: string;
  baselineScenarioId: string;
  alternativeScenarioIds: string[];
  metrics: ComparisonMetric[];
  ranking: ScenarioRanking[];
  recommendation: string;
  generatedAt: Timestamp;
}

interface SensitivityReport {
  reportId: string;
  baseScenarioId: string;
  variedParameters: VariedParameter[];
  impactMatrix: ImpactMatrixEntry[];
  keyDrivers: string[];  // highest-impact parameters
  stabilityAssessment: 'stable' | 'sensitive' | 'unstable';
  recommendation: string;
}

interface WhatIfResult {
  resultId: string;
  query: string;  // natural language or structured query
  assumptions: string[];
  baselineState: BaselineState;
  projectedState: ProjectedState;
  delta: StateDelta;
  confidence: number;
}

interface ScenarioChange {
  target: 'budget_amount' | 'resource_price' | 'demand_multiplier' | 'allocation_strategy' | 'resource_capacity';
  resourceType?: ResourceType;
  operator: 'set' | 'multiply' | 'add' | 'percentage';
  value: number;
}

interface SimulationBounds {
  maxIterations: number;
  maxTimeHorizon: Duration;
  allowedResourceTypes: ResourceType[];
  maxParameterDeviation: number;  // percentage
}

interface ResourceOutcome {
  resourceType: ResourceType;
  projectedDemand: number[];
  projectedCost: number[];
  priceElasticity: number;
  utilizationRate: number;
}

interface BudgetImpact {
  budgetId: string;
  projectedBurnRate: number;
  estimatedExhaustion: Timestamp | null;
  peakSpend: number;
  underutilizedAmount: number;
  categoryImbalances: CategoryImbalance[];
}

interface RiskMetrics {
  valueAtRisk: number;  // 95th percentile loss
  expectedShortfall: number;
  volatility: number;
  probabilityOfOverspend: number;
  worstCaseCost: number;
}

interface ComparisonMetric {
  name: string;
  baseline: number;
  alternatives: Record<string, number>;
  delta: Record<string, number>;
}

interface ScenarioRanking {
  scenarioId: string;
  rank: number;
  score: number;
  strengths: string[];
  weaknesses: string[];
}

interface ImpactMatrixEntry {
  parameterName: string;
  variedValue: number;
  impactOnCost: number;
  impactOnDemand: number;
  impactOnUtilization: number;
}

interface VariedParameter {
  name: string;
  baseValue: number;
  range: [number, number];
  steps: number;
}
```

## Core Concepts / Operations

### 1. Scenario Definition

Scenarios define a set of changes relative to a baseline budget, price sheet, or allocation strategy. Changes can set absolute values, apply multipliers, add increments, or adjust by percentage. Each scenario is validated against simulation bounds before execution.

### 2. Parameter Configuration

Simulation parameters control execution: time horizon, time step, number of iterations, confidence level, and RNG seed for reproducibility. Bounds constrain the parameter space to prevent unrealistic or runaway simulations.

### 3. Simulation Execution

The simulation engine runs the economic model with modified parameters and collects resource projections, budget impact, and risk metrics. Execution is deterministic given the same seed and inputs. Stability is assessed during execution; diverging simulations are terminated.

### 4. Outcome Analysis

Simulation outcomes include resource-level projections, budget impact analysis, and risk metrics. Outcomes are compared against baseline to quantify deltas. Stability scores indicate confidence in the results.

### 5. Scenario Comparison

Multiple scenarios can be compared side by side. The comparison engine ranks scenarios by configurable metrics (cost, risk, utilization). A recommendation is generated based on the ranking.

### 6. Sensitivity Testing

Systematic variation of individual parameters reveals which inputs have the greatest impact on outcomes. The sensitivity report identifies key drivers and assesses overall model stability. Parameters that cause instability are flagged.

### 7. What-If Queries

Ad-hoc what-if queries allow rapid exploration of economic outcomes without formal scenario creation. Queries specify assumptions and produce projected state deltas with confidence estimates.

## Internal Interfaces

```typescript
interface ScenarioManager {
  define(params: ScenarioDefinition): Promise<EconomicScenario>;
  validate(scenarioId: string): Promise<ValidationResult>;
  execute(scenarioId: string): Promise<SimulationOutcome>;
  abort(scenarioId: string): Promise<void>;
}

interface SimulationEngine {
  run(scenario: EconomicScenario, models: EconomicModel[]): Promise<SimulationOutcome>;
  step(scenario: EconomicScenario, timePoint: Timestamp): Promise<IterationResult>;
  assessStability(outcome: SimulationOutcome): Promise<number>;
  detectDivergence(iterations: IterationResult[]): Promise<boolean>;
}

interface ComparisonEngine {
  compare(scenarioIds: string[]): Promise<ScenarioComparison>;
  rank(comparison: ScenarioComparison, metric: string): Promise<ScenarioRanking[]>;
  recommend(comparison: ScenarioComparison): Promise<string>;
}

interface SensitivityTester {
  test(scenarioId: string, paramsToVary: string[]): Promise<SensitivityReport>;
  computeImpactMatrix(analysis: SensitivityReport): Promise<ImpactMatrixEntry[]>;
  identifyDrivers(report: SensitivityReport): Promise<string[]>;
}

interface WhatIfEngine {
  query(assumptions: WhatIfAssumption, baselineState: BaselineState): Promise<WhatIfResult>;
  estimateConfidence(query: WhatIfQuery): Promise<number>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `ECN.ScenarioDefined` | scenarioId, name, changeCount | New economic scenario created and validated |
| `ECN.SimulationDefined` | scenarioId, params, bounds | Simulation parameters configured and bounds checked |
| `ECN.SimulationRun` | scenarioId, iterations, timeHorizon | Simulation execution started |
| `ECN.SimulationCompleted` | scenarioId, stabilityScore, warnings | Simulation finished with results |
| `ECN.SimulationDiverged` | scenarioId, iteration, diagnostic | Simulation terminated due to divergence |
| `ECN.ScenarioCompared` | comparisonId, scenarioCount, topRanked | Multi-scenario comparison completed |
| `ECN.SensitivityTested` | reportId, driversCount, stabilityAssessment | Sensitivity analysis completed |
| `ECN.SimulationAborted` | scenarioId, reason | Simulation manually aborted before completion |
| `ECN.WhatIfQueried` | resultId, confidence | Ad-hoc what-if analysis completed |

## Error Cases

| Error Code | Condition | Severity | Recovery |
|------------|-----------|----------|---------|
| `ECN_SIM_BOUNDS_VIOLATION` | Scenario parameters exceed configured simulation bounds | Error | Constrain parameters to allowed ranges; adjust bounds if justified |
| `ECN_SIM_DIVERGENCE` | Simulation iterations produce increasingly extreme values | Error | Terminate simulation; simplify scenario or reduce time horizon |
| `ECN_SIM_OUTCOME_INSTABILITY` | Outcome metrics fluctuate beyond stability threshold | Warning | Increase iterations or tighten parameter ranges; flag low confidence |
| `ECN_SIM_COMPARISON_INCONSISTENCY` | Compared scenarios use incompatible baseline or metrics | Error | Align baseline references and metric definitions before re-comparing |
| `ECN_SIM_HORIZON_EXCEEDED` | Requested time horizon exceeds maximum allowed | Error | Reduce horizon to maxSimulationHorizon or request bounds override |
| `ECN_SIM_INSUFFICIENT_ITERATIONS` | Number of iterations too low for statistical significance | Warning | Increase iterations; flag confidence interval as unreliable |
| `ECN_SIM_BASELINE_NOT_FOUND` | Referenced baseline budget, model, or report does not exist | Error | Verify baseline ID; provide valid baseline reference |
| `ECN_SIM_BOUNDS_TOO_RESTRICTIVE` | Bounds exclude all meaningful parameter variation | Warning | Relax bounds; scenario cannot produce insight under current constraints |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ECN-SIM-001 | Identical scenario parameters and seed produce identical outcomes | Algorithmic — seeded RNG ensures deterministic simulation |
| ECN-SIM-002 | Every simulation outcome references its scenario definition | Architectural — SimulationOutcome.scenarioId is required |
| ECN-SIM-003 | Scenarios cannot be executed without validation passing | Algorithmic — ScenarioManager.execute checks status |
| ECN-SIM-004 | Simulation parameter exploration is bounded by capability constraints | Algorithmic — bounds checked before execution |
| ECN-SIM-005 | All simulation outputs reference input evidence records (Law 4) | Architectural — evidenceRef required on every scenario and outcome |
| ECN-SIM-006 | Comparisons are based on aligned time periods and resource scopes | Algorithmic — ComparisonEngine validates baseline compatibility |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Simulation owns what-if analysis and scenario modeling; Models owns forecasting engine; Analysis owns cost allocation |
| R2 — Dependency Order | Depends on Economic (Budget, CostRecord, PriceSheet), Models (DemandForecast, CostProjection), Analysis (VarianceReport), ACF (dispatch) |
| R3 — DRY | Scenario parameters are defined once and reused across simulation runs; comparison logic is shared across all scenario types |
| R4 — Builder Pattern | EconomicScenario uses builder for complex multi-change scenario definition |
| R5 — Stateless | Simulation execution is stateless given the same inputs; scenario state is metadata |
| R6 — Evident Complete | Every scenario definition, simulation run, and comparison produces evidence |
| R9 — Deterministic | Same scenario parameters and seed produce identical simulation outcomes |
| R10 — Simpler Over Complex | Single-parameter sensitivity is default; multi-parameter interaction testing is opt-in |
| R13 — Design for Failure | Diverging simulations are terminated early; unstable outcomes carry confidence warnings |
| R14 — Paved Path | Budget amount what-if with 30-day horizon and 100 iterations covers 80% of simulation use cases |
| R15 — Open/Closed | New scenario change types and simulation models can be registered without changing the engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Economic/000-Overview.md | Base Economic System — defines Budget, CostRecord, PriceSheet base types |
| Bible/07-Domains/Economic/001-Models.md | Economic Models provides the forecast engines that simulation drives |
| Bible/07-Domains/Economic/002-Analysis.md | Cost Analysis provides variance and trend data for scenario baselines |
| Bible/04-Execution/Simulation/000-Overview.md | Execution simulation framework; Economic Simulation integrates as a domain-specific simulation type |
| Bible/02-Core/ROS/000-Overview.md | ROS resource data feeds simulation baseline definitions |
| Bible/05-Platform/004-EVS.md | EVS stores all simulation evidence records |
| Bible/04-Execution/Workflow/000-Overview.md | WFE can trigger simulation runs as workflow steps |
| Bible/02-Core/Academy/000-Overview.md | Academy can consume simulation outcomes for learning |
| Physics/010-Execution.md | Execution constraints inform simulation bounds |
| Physics/007-Capabilities.md | Capability bounds limit simulation complexity and horizon |
