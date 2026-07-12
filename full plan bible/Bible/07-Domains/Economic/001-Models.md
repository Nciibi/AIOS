# AIOS Bible — Domains
## Economic — 001: Economic Models

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-ECN-001 |
| Source Laws | Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Economic Models sub-domain provides the forecasting and modeling infrastructure for AIOS — demand forecasting, cost projection, resource pricing models, supply/demand modeling, scenario simulation, and ROI computation. Models consume historical cost data from CostReports and PriceSheets (defined in Economic/000-Overview.md) and produce forward-looking projections that inform budget planning, pricing decisions, and resource strategy. Models are advisory — they inform decisions but never enforce them (Law 6). All model outputs must be traceable to their input evidence (Law 4).

## Architecture

```
Historical Data (CostReports, PriceSheets)
        │
        ▼
Model Selection ──► Parameter Fitting ──► Validation ──► Forecast Generation ──► Sensitivity Analysis
        │                                    │
        ▼                                    ▼
Rejected Model                          Validated Output
   feedback loop                         to Consumer
```

The pipeline proceeds sequentially: historical data is retrieved, a model type is selected based on data characteristics, parameters are fitted using optimization, the fitted model is validated against holdout data, forecasts are generated, and sensitivity analysis quantifies uncertainty. Each stage has quality gates that can abort with specific error codes.

## Data Model (TypeScript — extend the base doc types from Economic/000-Overview.md)

```typescript
interface EconomicModel {
  modelId: string;
  name: string;
  type: 'demand_forecast' | 'cost_projection' | 'supply_demand' | 'roi_analysis';
  version: string;
  params: ModelParams;
  inputRefs: string[];  // IDs of CostReports, PriceSheets used as input
  validationMetrics: ValidationMetrics;
  outputRef: string;  // ID of generated ForecastResult
  status: 'building' | 'validated' | 'failed' | 'deployed';
  createdAt: Timestamp;
  evidenceRef: string;
}

interface DemandForecast {
  forecastId: string;
  modelId: string;
  resourceType: ResourceType;
  horizon: Duration;
  interval: 'hourly' | 'daily' | 'weekly' | 'monthly';
  datapoints: ForecastPoint[];
  confidenceInterval: number;  // e.g. 0.95 for 95% CI
  lowerBound: number[];
  upperBound: number[];
  metadata: ForecastMetadata;
  generatedAt: Timestamp;
}

interface CostProjection {
  projectionId: string;
  budgetId: string;
  resourceBreakdown: ResourceCostProjection[];
  totalProjected: number;
  burnRate: number;  // credits per unit time
  exhaustionPoint: Timestamp | null;
  probabilityOfExhaustion: number;  // 0.0 to 1.0
  scenarios: AlternateScenario[];
}

interface SupplyDemandModel {
  modelId: string;
  resourceType: ResourceType;
  supplyCurve: CurvePoint[];
  demandCurve: CurvePoint[];
  equilibriumPrice: number;
  equilibriumQuantity: number;
  elasticityCoefficient: number;
  priceSensitivity: 'elastic' | 'inelastic' | 'unitary';
}

interface SensitivityAnalysis {
  analysisId: string;
  baseModelId: string;
  parameters: SensitivityParam[];
  tornadoRanking: { param: string; impact: number }[];
  breakevenPoints: BreakevenPoint[];
  recommendation: string;
}

interface ROIComputation {
  computationId: string;
  projectId: string;
  investmentAmount: number;
  projectedReturns: number[];
  timeHorizon: Duration;
  netPresentValue: number;
  internalRateOfReturn: number;
  paybackPeriod: Duration;
  riskAdjustedReturn: number;
}

interface ModelParams {
  algorithm: 'linear_regression' | 'exponential_smoothing' | 'arima' | 'neural_net' | 'ensemble';
  trainingWindow: Duration;
  holdoutFraction: number;
  featureSet: string[];
  hyperparameters: Record<string, number>;
}

interface ValidationMetrics {
  mae: number;  // Mean Absolute Error
  rmse: number; // Root Mean Squared Error
  mape: number; // Mean Absolute Percentage Error
  rSquared: number;
  residualStdDev: number;
}

interface ForecastPoint {
  timestamp: Timestamp;
  predicted: number;
  observed?: number;  // filled in after the fact for validation
}
```

## Core Concepts / Operations

### 1. Model Building

Models are constructed from historical data with configurable parameters. The builder selects the algorithm based on data characteristics (seasonality, trend, noise level) and fits parameters using optimization. Every model build is recorded as evidence.

### 2. Demand Forecasting

DemandForecast predicts future resource consumption by resource type. Forecasts include confidence intervals and are used for budget planning and capacity provisioning. Forecasts must specify their horizon and cannot exceed maximum horizon bounds.

### 3. Cost Projection

CostProjection takes a budget and its current burn rate to project when funds will be exhausted and at what total cost. Projections incorporate multiple scenarios (best case, expected, worst case) and assign probabilities to each.

### 4. Supply/Demand Modeling

SupplyDemandModel characterizes the relationship between resource price and consumption. Equilibrium analysis identifies the price point where supply meets demand. Elasticity coefficients inform pricing strategy.

### 5. ROI Computation

ROIComputation evaluates the financial return of projects or investments. It produces NPV, IRR, payback period, and risk-adjusted return metrics. Inputs come from cost data and projected outcomes.

### 6. Sensitivity Analysis

SensitivityAnalysis quantifies how changes in input parameters affect model outputs. Tornado ranking identifies the most influential parameters. Breakeven analysis determines thresholds for key decisions.

### 7. Model Lifecycle

Models progress through states: building (fitting parameters) → validated (quality gates passed) → deployed (available for forecasts) → failed (quality gates not met). Failed models produce error codes guiding parameter adjustment.

## Internal Interfaces

```typescript
interface ModelBuilder {
  build(dataRefs: string[], params: ModelParams): Promise<EconomicModel>;
  validate(modelId: string, holdoutData: string): Promise<ValidationMetrics>;
  retrain(modelId: string, newDataRefs: string[]): Promise<EconomicModel>;
}

interface ForecastEngine {
  forecast(modelId: string, horizon: Duration): Promise<DemandForecast>;
  project(budgetId: string, horizon: Duration): Promise<CostProjection>;
  computeROI(projectId: string, costData: CostReport, outcomeData: unknown): Promise<ROIComputation>;
}

interface SupplyDemandEngine {
  fitSupplyCurve(points: CurvePoint[]): Promise<SupplyCurve>;
  fitDemandCurve(points: CurvePoint[]): Promise<DemandCurve>;
  findEquilibrium(supply: SupplyCurve, demand: DemandCurve): Promise<Equilibrium>;
}

interface SensitivityEngine {
  analyze(modelId: string, paramsToVary: string[], ranges: number[][]): Promise<SensitivityAnalysis>;
  tornadoRank(analysisId: string): Promise<{ param: string; impact: number }[]>;
}
```

## Events

| Event Type | Produced When | Fields |
|-------|--------|-------------|
| `ECN.ModelBuildStarted` | modelId, modelType, algorithm | Economic model build initiated |
| `ECN.ModelBuilt` | modelId, validationMetrics | Model fitted and validated successfully |
| `ECN.ModelFailed` | modelId, errorCode, diagnostic | Model build or validation failed |
| `ECN.ForecastGenerated` | forecastId, modelId, horizon, confidenceInterval | DemandForecast produced and ready |
| `ECN.CostProjectionRun` | projectionId, budgetId, exhaustionProbability | CostProjection computed for a budget |
| `ECN.SupplyDemandUpdated` | modelId, resourceType, equilibriumPrice | Supply/demand equilibrium recalculated |
| `ECN.ROIComputed` | computationId, projectId, npv, irr | ROI analysis completed |
| `ECN.SensitivityRun` | analysisId, topParameter | Sensitivity analysis completed |
| `ECN.ModelDeployed` | modelId, version | Model promoted to production use |

## Error Cases

| Error Code | Condition | Severity | Recovery |
|------------|-----------|----------|---------|
| `ECN_MODEL_INSUFFICIENT_DATA` | Fewer data points than minimum required for selected algorithm | Error | Increase training window or select simpler algorithm |
| `ECN_MODEL_DIVERGENCE` | Training loss diverges instead of converging | Error | Adjust hyperparameters (learning rate, regularization) |
| `ECN_FORECAST_HORIZON_EXCEEDED` | Requested horizon exceeds maximum supported by model | Warning | Reduce horizon or retrain with longer training window |
| `ECN_SCENARIO_BOUNDS_VIOLATION` | Scenario parameters exceed model validity range | Error | Constrain parameters to observed historical ranges |
| `ECN_MODEL_VALIDATION_FAILED` | Validation metrics below quality threshold | Error | Review mape/rmse; retrain with different features or algorithm |
| `ECN_FORECAST_UNCERTAINTY_HIGH` | Confidence interval width exceeds acceptable threshold | Warning | Flag forecast as low confidence; recommend shorter horizon |
| `ECN_MODEL_STALE` | Model has not been retrained within validity period | Warning | Retrain model with latest available data |
| `ECN_ROI_INVALID_INPUT` | Cost data and outcome data have incompatible time ranges | Error | Align cost and outcome time ranges before recomputing |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ECN-MDL-001 | Every forecast must cite the model that produced it | Architectural — DemandForecast.modelId is required |
| ECN-MDL-002 | A model cannot be deployed without passing validation thresholds | Algorithmic — ModelBuilder.validate must pass before status becomes deployed |
| ECN-MDL-003 | Given identical input data and parameters, forecasts are deterministic | Algorithmic — seeded RNG ensures reproducibility |
| ECN-MDL-004 | Forecast horizon must not exceed training window length | Algorithmic — validation rejects horizon > training window |
| ECN-MDL-005 | All model inputs must reference evidence records (Law 4) | Architectural — inputRefs must resolve to valid evidence |
| ECN-MDL-006 | Model retraining produces a new version; prior versions remain available | Architectural — model versioning is append-only |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Economic Models owns forecasting and modeling; Budget Management owns budget state; Cost Accounting owns cost records |
| R2 — Dependency Order | Depends on Economic (CostReports, PriceSheets), EVS (evidence), ACF (dispatch); no circular dependencies |
| R3 — DRY | Model algorithms defined once in ModelParams; all forecast types reference the same interfaces |
| R4 — Builder Pattern | EconomicModel uses builder pattern for complex parameter configuration |
| R5 — Stateless | Model computation is stateless given the same inputs; state tracking is in the model metadata only |
| R6 — Evident Complete | Every model build, forecast, and analysis produces an evidence record |
| R9 — Deterministic | Same training data and parameters produce identical model outputs |
| R10 — Simpler Over Complex | Linear regression and exponential smoothing defaults; neural networks opt-in for high-volume resources |
| R13 — Design for Failure | Model validation gates prevent deployment of poor models; forecasts include confidence intervals |
| R14 — Paved Path | Monthly demand forecast with 90-day horizon covers 80% of use cases |
| R15 — Open/Closed | New model algorithms can be registered without changing the pipeline; new resource types use existing models |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Economic/000-Overview.md | Base Economic System — defines Budget, CostReport, PriceSheet base types |
| Bible/07-Domains/Economic/002-Analysis.md | Cost Analysis consumes models for trend detection and optimization |
| Bible/07-Domains/Economic/003-Simulation.md | Simulation uses models as underlying engines for what-if scenarios |
| Bible/02-Core/ROS/000-Overview.md | ROS provides resource consumption data that trains models |
| Bible/05-Platform/004-EVS.md | EVS stores all model evidence records |
| Bible/04-Execution/Workflow/000-Overview.md | WFE can trigger model retraining on schedule |
| Bible/02-Core/Academy/000-Overview.md | Academy provides learned patterns that improve model accuracy |
| Physics/010-Execution.md | Execution data feeds demand forecast models |
| Physics/007-Capabilities.md | Capability bounds constrain forecast horizons and model complexity |
