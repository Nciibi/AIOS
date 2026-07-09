# AIOS Bible — Core
## DTS 002 — Simulation Pipeline

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-DTS-002 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/010-Execution.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Simulation Pipeline evaluates decisions before execution by generating scenarios, running simulations, predicting outcomes, and scoring confidence. This is the core predictive capability of DTS — it enables AIOS to assess the likely consequences of a decision before committing to execution.

## Pipeline Stages

```
Decision Proposal
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 1: Scenario Generation                                 │
│  Generates one or more scenarios to simulate                  │
│  Output: ScenarioSet { scenarios: Scenario[] }                │
│  Method: Based on simulation type (see below)                │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 2: Simulation Execution                                │
│  Runs simulations using the selected Sim Engine               │
│  Output: SimulationResult { per_scenario_results }            │
│  Method: Engine-specific execution                           │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 3: Outcome Prediction                                  │
│  Aggregates simulation results into outcome predictions       │
│  Output: PredictedOutcome { most_likely, distribution, risks }│
│  Method: Statistical aggregation across scenarios            │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 4: Confidence Scoring                                  │
│  Produces confidence interval for the decision                │
│  Output: ConfidenceScore { interval, components }             │
│  Method: Combines simulation accuracy with other factors     │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
ConfidenceScore → returned to Decision Evaluator → DGP
```

## Simulation Types

The pipeline supports three simulation types, selected based on the decision type and available evidence:

### Monte Carlo Simulation

Used for: decisions with high uncertainty, many variables, or stochastic outcomes.

```
Method:   Generate N random scenarios (N configurable, default 1000)
          Sample variable values from probability distributions
          Run each scenario through the Sim Engine
          Aggregate results statistically
Output:   Outcome distribution, confidence interval, percentile analysis
Accuracy: √N convergence — more scenarios = better accuracy
```

### Constraint-Based Simulation

Used for: decisions with well-defined constraints, policy compliance, capability bounds.

```
Method:   Define constraint space from constitutional bounds, capability registry, policies
          Generate boundary scenarios — edge cases and extremes
          Verify decision is valid across the entire constraint space
Output:   Feasibility map, constraint violation detection, safe operating region
Accuracy: Exact within constraint space — no statistical approximation
```

### Historical Simulation

Used for: decisions similar to past decisions with available outcome evidence.

```
Method:   Query Event Store for similar past decisions
          Extract outcome patterns from historical evidence
          Apply historical outcomes to current decision
Output:   Historical precedent match, outcome prediction with confidence
Accuracy: Depends on quantity and similarity of historical matches
```

## Pipeline Operations

### runSimulation(decision, simulation_config)

```
Input:  decision, simulation_config { type, scenarios, engines, time_budget }
Process:
  1. Select simulation type based on decision and config
  2. Generate scenarios (Stage 1)
  3. Execute simulations (Stage 2) — may use multiple engines
  4. Predict outcomes (Stage 3)
  5. Score confidence (Stage 4)
Output: SimulationResult { sim_id, outcome_prediction, confidence, risk_assessment }
Event: DTS.SimulationRun
```

### compareScenarios(scenario_a, scenario_b)

```
Input:  scenario_a, scenario_b
Process: run both scenarios through the pipeline → compare outcomes
Output: ScenarioComparison { scenario_a_outcome, scenario_b_outcome, tradeoffs }
Event: DTS.ScenarioComparison
```

### getSimulationHistory(decision_id)

```
Input:  decision_id
Process: query Event Store for all simulation runs for this decision
Output: SimulationHistoryEntry[]
```

## Simulation Output Schema

Every simulation produces:

| Field | Type | Description |
|-------|------|-------------|
| sim_id | UUID | Unique simulation identifier |
| decision_id | UUID | The decision that was simulated |
| engine_type | string | Which engine executed (monte_carlo, constraint, historical) |
| scenarios_count | int | Number of scenarios simulated |
| predicted_outcome | Outcome | Most likely outcome with distribution |
| confidence_interval | [float, float] | Lower and upper bounds (e.g., [0.72, 0.88]) |
| risk_assessment | RiskAssessment | Identified risks with probabilities |
| constitutional_impact | ImpactReport | How the decision affects constitutional compliance |
| evidence_chain | EventRef[] | Evidence Events that informed the simulation |
| execution_time_ms | int | Wall-clock time for the simulation |

## Pipeline Example

```
Decision: "Deploy new Worker with specialized image processing capabilities"

Stage 1 — Scenario Generation (type: Monte Carlo)
  Parameters: compute_units (100-500), memory_gb (4-32), concurrent_tasks (1-10)
  Scenarios generated: 500 random combinations
  → Event: DTS.ScenarioGenerated { scenario_count: 500 }

Stage 2 — Simulation Execution (engine: Planning Simulator)
  Engine evaluates each scenario against resource availability and capability bounds
  Results: 340 feasible scenarios (68%)
  → Event: DTS.SimulationRun { feasible: 340, infeasible: 160 }

Stage 3 — Outcome Prediction
  Aggregated results:
    Most likely outcome: "Successful deployment with moderate resource usage"
    Distribution: 68% feasible, 23% resource contention, 9% capability gap
  → Risk: Capability gap is high for advanced processing tasks

Stage 4 — Confidence Scoring
  Simulation evidence score: 0.78 (based on scenario coverage and convergence)
  → Combined with other factors for final confidence interval
  → Event: DTS.SimulationCompleted { confidence: 0.78 }
```

## Simulation Feedback to Sou

Simulation results are communicated back to Sou's Planner:

```
DTS Simulation Result
    │
    ▼
Sou Planner (002) ──► improved plan estimates
    │
    ▼
Sou Reasoning (001) ──► refined decision proposals
    │
    ▼
Sou Learning (004) ──► simulation accuracy becomes learning input
```

## Simulation Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `DTS.SimulationRun` | A simulation is executed | sim_id, decision_id, engine_type, scenario_count |
| `DTS.ScenarioGenerated` | Scenarios are generated for a simulation | sim_id, scenario_count, generation_type |
| `DTS.SimulationCompleted` | Simulation finishes successfully | sim_id, predicted_outcome, confidence_interval |
| `DTS.SimulationFailed` | Simulation encounters an error | sim_id, error_code, error_message |
| `DTS.ScenarioCompared` | Two scenarios are compared | comparison_id, scenario_a, scenario_b, recommendation |
| `DTS.SimulationTimeBudgetExceeded` | Simulation exceeds time budget | sim_id, time_budget, partial_results |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| DTS_SIM_001 | No applicable simulation engine for this decision type |
| DTS_SIM_002 | Monte Carlo scenario generation failed — invalid distribution |
| DTS_SIM_003 | Constraint space is empty — decision is infeasible |
| DTS_SIM_004 | Historical simulation has insufficient precedent Events |
| DTS_SIM_005 | Simulation time budget exceeded — returning partial results |
| DTS_SIM_006 | All selected simulation engines unavailable |

## Cross-Cutting Concerns

### Security

Simulation results are evidence that influences governance decisions. Integrity of the simulation pipeline is critical. All simulation inputs and outputs are recorded as Events. (Physics/008-Security.md)

### Evidence

Simulation consumes evidence Events and produces new evidence Events. Every simulation traceable to its source data. (PHI-008)

### Lifecycle

Simulations have a transient lifecycle: Queued → Running → Completed / Failed. Results are cached with TTL. (Physics/006-Lifecycles.md)

### Capability Bounds

Simulation may model any decision within AIOS. It does not execute decisions — it predicts outcomes. Simulation may not produce executable code or modify state. (Physics/007-Capabilities.md)

### Communication

Simulation requests arrive via ACF. Results are returned via ACF. Sim Engines are invoked through ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Pipeline focused solely on simulation of decisions |
| R3 (DRY) | Scenario generation logic shared across simulation types |
| R5 (Liskov) | All simulation types implement the ScenarioGenerator interface |
| R10 (Simpler Over Complex) | Pipeline is linear — stages do not branch or loop |
| R12 (Embrace Errors) | All errors have unique codes (DTS_SIM_001–006) |
| R13 (Design for Failure) | Time budget exceeded returns partial results — does not hang |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — simulation consumes Events |
| Physics/010-Execution.md | Execution — simulation predicts execution outcomes |
| Physics/012-Experience.md | Experience — simulation feeds into learning |
| Bible/02-Core/DTS/000-Overview.md | DTS overview — pipeline context |
| Bible/02-Core/DTS/001-Architecture.md | Architecture — pipeline is part of DTS architecture |
| Bible/02-Core/DTS/003-Sim-Engines.md | Sim Engines — pipeline invokes engines |
| Bible/02-Core/DTS/004-Confidence.md | Confidence — pipeline feeds confidence engine |
| Bible/02-Core/Sou/002-Planner.md | Planner — simulation results improve planning |
| Bible/02-Core/Sou/004-Learning.md | Learning — simulation accuracy is learning input |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
