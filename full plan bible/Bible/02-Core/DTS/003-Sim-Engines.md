# AIOS Bible — Core
## DTS 003 — Simulation Engines

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-DTS-003 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Simulation Engines are the computational backends of the DTS Simulation Pipeline (002). Each engine implements a different simulation methodology. The pipeline selects the appropriate engine based on decision type, available evidence, and time constraints.

All engines implement the `SimEngine` interface (R5 — Liskov Substitution Principle).

## SimEngine Interface

Every simulation engine implements:

```
interface SimEngine {
  // Unique engine identifier
  engine_id: string;

  // Human-readable name
  name: string;

  // Types of decisions this engine can simulate
  supported_decision_types: DecisionType[];

  // Input schema the engine expects
  input_schema: JSONSchema;

  // Output schema the engine produces
  output_schema: JSONSchema;

  // Maximum number of scenarios this engine can simulate per run
  max_scenarios: number;

  // Estimated time per scenario (ms)
  time_per_scenario_ms: number;

  // Run simulation
  run(input: EngineInput): EngineOutput;

  // Get accuracy metrics
  getAccuracy(): AccuracyMetrics;

  // Check if engine is available
  health(): HealthStatus;
}
```

## Available Engines

### 1. Planning Simulator

| Property | Value |
|----------|-------|
| Engine ID | `planning_sim` |
| Type | Sou's Planner in simulation mode |
| Supported Decisions | Strategic, Operational, Architectural |
| Max Scenarios | 100 |
| Time Per Scenario | ~50ms |

The Planning Simulator invokes Sou's Planner (Sou/002-Planner.md) in simulation mode. Instead of producing a mission proposal, it evaluates a proposed plan against simulated constraints and resource availability.

| Input Schema | Field | Description |
|-------------|-------|-------------|
| decision | DecisionProposal | The decision to simulate |
| available_resources | ResourceMap | Current resource state |
| constraints | Constraint[] | Constitutional and policy constraints |
| autonomy_level | L0–L4 | Entity autonomy setting for simulation |

| Output Schema | Field | Description |
|--------------|-------|-------------|
| plan_feasibility | float | 0.0 (infeasible) to 1.0 (fully feasible) |
| resource_bottlenecks | string[] | Identified resource constraints |
| timeline_estimate | Duration | Estimated time to execute |
| risk_factors | Risk[] | Identified risks |

### 2. Monte Carlo Engine

| Property | Value |
|----------|-------|
| Engine ID | `monte_carlo` |
| Type | Statistical simulation through random sampling |
| Supported Decisions | Operational, Experimental |
| Max Scenarios | 100000 |
| Time Per Scenario | ~1ms |

The Monte Carlo Engine generates random scenarios within defined parameter distributions and runs each through a lightweight evaluation model.

| Input Schema | Field | Description |
|-------------|-------|-------------|
| decision | DecisionProposal | The decision to simulate |
| parameter_distributions | Distribution[] | Probability distributions for each variable |
| scenario_count | int | Number of scenarios to generate |
| confidence_target | float | Target confidence level (0.0–1.0) |

| Output Schema | Field | Description |
|--------------|-------|-------------|
| outcome_distribution | Distribution | Statistical distribution of outcomes |
| percentile_5 | Outcome | 5th percentile outcome |
| percentile_50 | Outcome | Median outcome |
| percentile_95 | Outcome | 95th percentile outcome |
| convergence_metric | float | How close to statistical convergence |

### 3. Constraint Solver

| Property | Value |
|----------|-------|
| Engine ID | `constraint_solver` |
| Type | Logical constraint satisfaction |
| Supported Decisions | Constitutional, Policy-compliance |
| Max Scenarios | N/A (deterministic) |
| Time Per Scenario | ~10ms |

The Constraint Solver evaluates a decision against a set of logical constraints derived from the Constitution, policies, and capability bounds.

| Input Schema | Field | Description |
|-------------|-------|-------------|
| decision | DecisionProposal | The decision to simulate |
| constraint_set | Constraint[] | Logical constraints to evaluate |
| allow_partial | bool | Whether partial satisfaction is acceptable |

| Output Schema | Field | Description |
|--------------|-------|-------------|
| satisfiable | bool | Whether all constraints are satisfied |
| violated_constraints | Violation[] | List of violated constraints |
| partial_score | float | If partial allowed, satisfaction ratio (0.0–1.0) |
| satisfying_assignment | Map | Variable assignment that satisfies constraints |

### 4. Machine Learning Predictor

| Property | Value |
|----------|-------|
| Engine ID | `ml_predictor` |
| Type | Academy-powered ML prediction |
| Supported Decisions | Operational, Experimental |
| Max Scenarios | N/A (model-dependent) |
| Time Per Scenario | ~100ms |

The ML Predictor uses models trained by the Academy to predict outcomes. It is the least deterministic engine but can capture patterns not accessible to the other engines.

| Input Schema | Field | Description |
|-------------|-------|-------------|
| decision | DecisionProposal | The decision to simulate |
| model_id | string | Which ML model to use |
| feature_set | string[] | Which features to include |
| confidence_threshold | float | Minimum confidence for prediction |

| Output Schema | Field | Description |
|--------------|-------|-------------|
| predicted_outcome | Outcome | ML-predicted outcome |
| model_confidence | float | Model's internal confidence (0.0–1.0) |
| feature_importance | Map | Which features influenced the prediction |
| model_version | string | Version of the model used |
| training_data_range | DateRange | Time range of training data |

## Engine Selection

DTS selects the appropriate engine based on:

| Decision Type | Optimal Engine | Fallback Engine |
|--------------|---------------|-----------------|
| Strategic | Planning Simulator | Constraint Solver (partial) |
| Operational | Monte Carlo | ML Predictor |
| Constitutional | Constraint Solver | None (only exact methods) |
| Architectural | Planning Simulator | Constraint Solver |
| Experimental | ML Predictor | Monte Carlo |
| Emergency | Constraint Solver (fastest) | Planning Simulator |

Selection algorithm:

```
function selectEngine(decision, evidence, timeBudget):
  primary = OPTIMAL_ENGINE[decision.type]
  if primary.available and primary.timeEstimate <= timeBudget:
    return primary
  fallback = FALLBACK_ENGINE[decision.type]
  if fallback.available and fallback.timeEstimate <= timeBudget:
    return fallback
  return null  // no engine available — return partial confidence from other factors
```

## Engine Accuracy Metrics

| Engine | Mean Error Rate | Last Calibration | Data Points |
|--------|----------------|-----------------|-------------|
| Planning Simulator | 12% | Daily | All plans |
| Monte Carlo | 8% | Per run | Per decision type |
| Constraint Solver | 0% (logical) | N/A | N/A |
| ML Predictor | 15% | Per model update | Training dataset |

## Engine Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `DTS.EngineInvoked` | An engine is invoked | sim_id, engine_id, decision_type |
| `DTS.EngineCompleted` | Engine finishes successfully | sim_id, engine_id, execution_time |
| `DTS.EngineFailed` | Engine encounters an error | sim_id, engine_id, error_code |
| `DTS.EngineHealthChanged` | Engine health status changes | engine_id, old_status, new_status |
| `DTS.EngineCalibrated` | Engine accuracy metrics are updated | engine_id, new_error_rate, data_points |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| DTS_ENG_001 | No engine available for the given decision type |
| DTS_ENG_002 | Engine input validation failed |
| DTS_ENG_003 | Engine execution timed out |
| DTS_ENG_004 | Engine health check failed — engine unavailable |
| DTS_ENG_005 | ML model not found for given model_id |
| DTS_ENG_006 | Constraint solver: unsatisfiable constraint set |

## Cross-Cutting Concerns

### Security

Simulation engines are computational resources. Access is controlled — only DTS and authorized sim requesters may invoke engines. Engine outputs are trusted evidence. (Physics/008-Security.md)

### Evidence

Every engine invocation produces an Event. Engine accuracy metrics are derived from evidence (comparing predictions to actual outcomes). (PHI-008)

### Lifecycle

Simulation engines have a version lifecycle: Active → Deprecated (replaced by better engine) → Removed. Deprecation requires evidence that the replacement is more accurate. (Physics/006-Lifecycles.md)

### Capability Bounds

Engines may only simulate within their defined capability bounds. No engine may execute decisions — only predict outcomes. ML engine predictions are bounded by training data. (Physics/007-Capabilities.md)

### Communication

Engines are invoked via ACF. Results are returned via ACF. Engine health is reported via ACF stream. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each engine has a single simulation methodology |
| R5 (Liskov) | All engines implement the SimEngine interface |
| R6 (DI) | Engines are injected into the pipeline — not instantiated by it |
| R10 (Simpler Over Complex) | Four engine types — sufficient for all decision types |
| R12 (Embrace Errors) | All errors have unique codes (DTS_ENG_001–006) |
| R13 (Design for Failure) | Engine failure triggers fallback — pipeline does not fail entirely |
| R15 (Open/Closed) | New engines can be added without modifying existing engine code |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — engines consume and produce Events |
| Physics/007-Capabilities.md | Capabilities — engines respect capability bounds |
| Physics/010-Execution.md | Execution — simulation engines predict execution |
| Bible/02-Core/DTS/000-Overview.md | DTS overview — engine context |
| Bible/02-Core/DTS/001-Architecture.md | Architecture — engines are pluggable components |
| Bible/02-Core/DTS/002-Sim-Pipeline.md | Pipeline — engines are invoked by the pipeline |
| Bible/02-Core/DTS/004-Confidence.md | Confidence — engine outputs feed confidence scoring |
| Bible/02-Core/Sou/002-Planner.md | Planner — Planning Simulator wraps the Planner |
| Bible/02-Core/Academy/000-Overview.md | Academy — ML Predictor uses Academy models |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
