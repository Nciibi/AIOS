# AIOS Bible — Execution
## 000 — Simulation System (SIM)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Simulation |
| Document ID | AIOS-BBL-004-SIM-000 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Simulation System answers "What happens if..." — it provides a sandboxed, deterministic environment for running scenarios before they affect the live system. You have a Decision System that chooses what to do, but you need a way to test those decisions before committing. Simulation is that safety net.

Simulation runs scenarios across multiple domains — economic, security, resource, mission, worker, organization, conversation, LLM behavior, and failure modes — all within isolated sandboxes that cannot affect real state. Results are captured as evidence and fed back into the Decision System, Academy, and Planning System to improve future decisions.

SIM is not a testing framework. It is a constitutional verification mechanism under Law 8 (Verification-First): every significant decision should be simulated before execution, and simulation results become part of the evidence chain that justifies or blocks the action.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                   Simulation System                     │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐│
│  │  Scenario     │    │  Simulation  │    │  Sandbox  ││
│  │  Builder      │───►│  Orchestrator│───►│  Manager  ││
│  └──────────────┘    └──────┬───────┘    └───────────┘│
│                             │                          │
│                    ┌────────▼────────┐                 │
│                    │   Domain        │                 │
│                    │   Simulators    │                 │
│                    │  (pluggable)    │                 │
│                    └────────┬────────┘                 │
│                             │                          │
│  ┌──────────────┐    ┌──────▼───────┐    ┌───────────┐│
│  │  Evidence     │    │  Result      │    │  Replay   ││
│  │  Recorder     │◄───│  Analyzer    │◄───│  Engine   ││
│  └──────────────┘    └──────────────┘    └───────────┘│
└────────────────────────────────────────────────────────┘
           │                      │              │
           ▼                      ▼              ▼
     ┌──────────┐          ┌──────────┐    ┌──────────┐
     │   EVS    │          │ Decision │    │ Academy  │
     │ (evidence)│         │  System  │    │ (learning)│
     └──────────┘          └──────────┘    └──────────┘
```

## Core Concepts

### 1. Scenario Definition

A scenario is a complete description of a "what if" question: initial state, parameters, actions to simulate, simulation domain, duration, and success criteria. Scenarios are expressed as typed, versioned definitions that can be stored, shared, and replayed.

See [Data Model](#data-model) for the full `Scenario` type definition including multi-domain support and evidence references.

### 2. Simulation Domains

SIM supports pluggable domain simulators, each modeling a different aspect of the AIOS universe:

| Domain | What It Simulates | Example Question |
|--------|-------------------|------------------|
| Economic | Resource allocation, budget consumption, trading | "What if we allocate 80% budget to Project A?" |
| Security | Authorization decisions, policy violations, attack scenarios | "What if this agent's token is compromised?" |
| Resource | CPU, memory, storage, network contention | "What if 50 concurrent Workers spawn?" |
| Mission | Mission completion rates, timeline estimation, dependencies | "What if Mission X depends on Mission Y?" |
| Worker | Worker behavior, capability bounds, error rates | "What if this Worker hits its retry limit?" |
| Organization | Org structure changes, delegation chains, load distribution | "What if we split Org Alpha into two teams?" |
| Conversation | Multi-turn dialogue paths, context window pressure | "What if the conversation exceeds 100K tokens?" |
| LLM | Model behavior, latency, hallucination rates, cost | "What if we switch from GPT-4 to Claude 4?" |
| Failure | Cascading failures, recovery time, degradation patterns | "What if the Database service goes down?" |

### 3. Simulation Orchestrator

The central engine that manages simulation lifecycle: receive scenario → validate → provision sandbox → execute domain simulator(s) → collect results → analyze → record evidence → teardown sandbox. The orchestrator ensures simulations are deterministic (same input → same output) and isolated from live state.

### 4. Sandbox Isolation

Every simulation runs in an isolated sandbox that cannot access or modify live system state. Sandboxes provide:
- **Snapshots**: A frozen copy of relevant state at simulation start
- **Virtual Time**: Accelerated or stepped time progression independent of real time
- **Resource Limits**: Bounded compute, memory, and storage per sandbox
- **No Side Effects**: All writes are captured as simulated output, never forwarded to real infrastructure

Sandbox isolation is constitutional — Law 8 (Verification-First) requires that simulation never becomes execution.

### 5. Domain Simulators

Pluggable simulation engines that model specific domains. Each domain simulator implements a standard interface: `initialize(snapshot, params) → simulate(actions) → Result`. Domain simulators are registered with the Simulation Orchestrator and can be composed for multi-domain scenarios (e.g., "What if we split the org AND switch LLM providers?").

### 6. Result Analysis

Simulation produces structured results: state trajectory (how state evolved over simulated time), outcome metrics (did it meet success criteria?), anomaly flags (unexpected behavior detected), and confidence intervals (how reliable is this simulation?). Results are tagged with the scenario version and simulation engine version for reproducibility.

### 7. Evidence Recording

Every simulation run produces an evidence record stored in EVS: scenario ID, domain, parameters, results, sandbox configuration, timestamp, and duration. Law 4 (Evidence) ensures every simulation is auditable — you can trace any decision back to the simulations that informed it.

### 8. Replay

Simulations can be replayed with the same parameters to verify reproducibility. The Replay Engine loads the original scenario, re-runs it, and compares results. Discrepancies indicate either a non-deterministic component (bug) or a change in system behavior that invalidates the original simulation. Replay also validates Law 6 (Lifecycle Compliance) — a completed simulation is in a terminal state and its sandbox cannot be re-entered; replay creates a fresh sandbox.

### 9. Hypothesis Testing

SIM supports "what if" chains: run Scenario A → analyze → propose Scenario B (variant) → run → compare. This enables the Decision System and Sou to explore decision trees before committing resources, similar to A/B testing but in simulation.

## Data Model

```typescript
type SimulationDomain =
  | 'economic' | 'security' | 'resource' | 'mission'
  | 'worker' | 'organization' | 'conversation' | 'llm' | 'failure';

interface Scenario {
  scenarioId: string;
  name: string;
  domain: SimulationDomain;
  multiDomain?: SimulationDomain[];
  initialState: SimulationState;
  actions: SimulatedAction[];
  parameters: Record<string, unknown>;
  duration: Duration;
  successCriteria: Criterion[];
  version: number;
  evidenceRef: string;
}

interface SimulatedAction {
  actionId: string;
  type: string;
  params: Record<string, unknown>;
  scheduledTime: Timestamp;
  dependsOn?: string[];
}

interface SimulationState {
  snapshotId: string;
  stateData: Record<string, unknown>;
  capturedAt: Timestamp;
  domain: SimulationDomain;
}

interface SimulationResult {
  runId: string;
  scenarioId: string;
  domain: SimulationDomain;
  status: 'completed' | 'failed' | 'timedOut' | 'diverged';
  stateTrajectory: StatePoint[];
  outcomeMetrics: Record<string, number>;
  anomalies: Anomaly[];
  confidenceInterval: { low: number; high: number };
  sandboxId: string;
  startedAt: Timestamp;
  completedAt: Timestamp;
  evidenceRef: string;
  scenarioVersion: number;
  simEngineVersion: string;
}

interface StatePoint {
  simulatedTime: Timestamp;
  stateHash: string;
  keyIndicators: Record<string, number>;
  events: string[];
}

interface Criterion {
  metric: string;
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq';
  value: number;
  description: string;
}
```

## Interfaces

### SIM API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `createScenario(scenario)` | Sou, Decision System | Register a new simulation scenario |
| `runSimulation(scenarioId)` | Sou, Decision System | Execute a scenario in an isolated sandbox |
| `runMultiDomain(scenarioId, domains)` | Sou, Academy | Run scenario across multiple domain simulators |
| `getSimulationResult(runId)` | Any | Retrieve results from a completed simulation |
| `replaySimulation(runId)` | Security Council | Re-run a simulation to verify reproducibility |
| `compareResults(runIdA, runIdB)` | Decision System, Academy | Compare two simulation runs |
| `proposeHypothesis(baseScenarioId, changes)` | Sou | Create a variant scenario from an existing one |
| `getDomainSimulators()` | Any | List registered domain simulators |
| `registerDomainSimulator(domain, endpoint)` | Security Council | Register a new domain simulator plugin |

### Internal Interfaces

```typescript
interface SimulationOrchestrator {
  run(scenario: Scenario): Promise<SimulationResult>;
  validate(scenario: Scenario): ValidationResult;
  provisionSandbox(scenario: Scenario): Promise<Sandbox>;
  teardownSandbox(sandboxId: string): Promise<void>;
}

interface SandboxManager {
  create(snapshot: SimulationState, limits: ResourceLimits): Promise<Sandbox>;
  destroy(sandboxId: string): Promise<void>;
  snapshot(sandboxId: string): Promise<SimulationState>;
}

interface DomainSimulator {
  domain: SimulationDomain;
  initialize(snapshot: SimulationState, params: Record<string, unknown>): Promise<void>;
  simulate(actions: SimulatedAction[]): Promise<SimulationResult>;
  cleanup(): Promise<void>;
}

interface ResultAnalyzer {
  evaluate(actual: SimulationResult, criteria: Criterion[]): EvaluationReport;
  detectAnomalies(trajectory: StatePoint[]): Anomaly[];
  computeConfidence(result: SimulationResult): { low: number; high: number };
}

interface ScenarioBuilder {
  create(params: ScenarioParams): Promise<Scenario>;
  validate(scenario: Scenario): ValidationResult;
  createVariant(baseScenarioId: string, changes: ScenarioChange[]): Promise<Scenario>;
}

interface EvidenceRecorder {
  recordSimulationRun(result: SimulationResult): Promise<string>;  // returns evidenceRef
  recordReplay(originalRunId: string, replayResult: SimulationResult): Promise<string>;
}

interface ReplayEngine {
  replay(runId: string): Promise<SimulationResult>;
  compare(original: SimulationResult, replay: SimulationResult): ReplayComparison;
}

interface HypothesisManager {
  propose(baseScenarioId: string, changes: ScenarioChange[]): Promise<Scenario>;
  chain(baseScenarioId: string, variants: ScenarioChange[][]): Promise<Scenario[]>;
  evaluateChain(scenarios: Scenario[]): Promise<HypothesisChainResult>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Scenario Builder | Scenario definition, validation, and versioning |
| Simulation Orchestrator | Manages simulation lifecycle — validate, run, collect, teardown |
| Sandbox Manager | Creates and manages isolated execution environments |
| Domain Simulators | Pluggable engines for each simulation domain |
| Result Analyzer | Evaluates outcomes against success criteria, detects anomalies |
| Evidence Recorder | Captures simulation runs as evidence records in EVS |
| Replay Engine | Re-runs scenarios and compares results for reproducibility |
| Hypothesis Manager | Chains scenarios for decision-tree exploration |

## Data Flow

```
Sou or Decision System creates a scenario
        │
        ▼
Scenario Builder validates definition
        │
        ▼
Simulation Orchestrator accepts scenario
        │
        ▼
Sandbox Manager provisions isolated sandbox with state snapshot
        │
        ▼
Domain Simulator initialized with snapshot and parameters
        │
        ▼
Simulation executes in virtual time through actions
        │
        ├── Success ──► Result Analyzer evaluates criteria
        │                    │
        │                    ▼
        │             Evidence recorded to EVS
        │                    │
        │                    ▼
        │             Results returned to caller (Sou / Decision System)
        │
        └── Failure ──► Sandbox teardown with failure evidence
                             │
                             ▼
                        Error returned to caller
        │
        ▼
Sandbox destroyed (both paths); no live state affected
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `SIM.ScenarioCreated` | scenarioId, domain, version | New scenario registered |
| `SIM.SimulationStarted` | runId, scenarioId, domain | Simulation execution began |
| `SIM.SandboxProvisioned` | runId, sandboxId, snapshotRef | Sandbox created for simulation |
| `SIM.DomainSimulatorLoaded` | runId, domain, engineVersion | Domain simulator initialized |
| `SIM.SimulationStepCompleted` | runId, step, simulatedTime | Individual simulation step finished |
| `SIM.SimulationCompleted` | runId, status, metrics | Simulation finished with results |
| `SIM.SimulationFailed` | runId, error, step | Simulation terminated with error |
| `SIM.SimulationTimedOut` | runId, duration, maxDuration | Simulation exceeded time limit |
| `SIM.AnomalyDetected` | runId, anomalyType, simulatedTime | Unexpected behavior during simulation |
| `SIM.ScenarioReplayed` | runId, originalRunId, matchScore | Simulation replayed and compared |
| `SIM.DomainSimulatorRegistered` | domain, endpoint, version | New domain simulator available |
| `SIM.HypothesisProposed` | baseScenarioId, variantScenarioId | Variant scenario created for comparison |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Scenario definition fails validation | `SIM_INVALID_SCENARIO` | Reject creation; return validation errors |
| Sandbox resource limit exceeded | `SIM_SANDBOX_OVERFLOW` | Terminate simulation; log resource profile |
| Domain simulator not found for domain | `SIM_DOMAIN_NOT_FOUND` | Reject run; list available domains |
| Simulation diverged from expected bounds | `SIM_DIVERGED` | Mark result as diverged; preserve partial trajectory |
| Scenario not found | `SIM_SCENARIO_NOT_FOUND` | Return error; no side effects |
| Sandbox creation failed | `SIM_SANDBOX_FAILURE` | Retry with backoff; if persists, report infrastructure error |
| Replay mismatch detected | `SIM_REPLAY_MISMATCH` | Flag discrepancy; preserve both original and replay results |
| Domain simulator returned error | `SIM_SIMULATOR_ERROR` | Fail simulation; log simulator error details |
| Hypothesis chain exceeds max depth | `SIM_HYPOTHESIS_DEPTH_EXCEEDED` | Reject new hypothesis; max chain depth configured |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SIM-001 | Simulations never modify live system state | Architectural — Sandbox Manager enforces write isolation |
| SIM-002 | Every simulation produces an evidence record (Law 4) | Architectural — Evidence Recorder runs on every completion/failure |
| SIM-003 | Given the same scenario and snapshot, two simulations produce identical results | Algorithmic — Replay Engine verifies reproducibility; governed by Design DNA R9 (Deterministic) |
| SIM-004 | Sandboxes have bounded resource consumption | Architectural — Sandbox Manager enforces configurable limits |
| SIM-005 | A simulation in a terminal state cannot be re-run | Algorithmic — completed sandboxes are immutable |
| SIM-006 | Scenario definitions are immutable once a simulation run references them | Architectural — versioned; edits create new version |
| SIM-007 | Multi-domain simulations run domains in isolation from each other | Architectural — each domain gets a separate sandbox layer |
| SIM-008 | Virtual time in simulation never advances faster than configured max rate | Algorithmic — Orchestrator throttles time progression |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | SIM owns simulation exclusively; Decision System owns decisions based on simulation output; Academy learns from simulation results |
| R2 — Dependency Order | SIM depends on EVS (evidence), ACF (dispatch), Sandbox infrastructure; no circular dependencies |
| R3 — DRY | Domain simulators are defined once in the registry; scenarios reference, not duplicate simulation logic |
| R4 — Builder Pattern | Scenario definitions use builder construction for complex multi-domain configurations |
| R9 — Deterministic | Same scenario + same snapshot = same result; Replay Engine enforces this invariant |
| R10 — Simpler Over Complex | Default single-domain simulation covers most cases; multi-domain compose is opt-in |
| R13 — Design for Failure | Sandbox overflow and divergence preserve partial results; domain simulator failures isolate to that domain |
| R14 — Paved Path | Single-domain scenario with default success criteria is the standard path |
| R15 — Open/Closed | New domain simulators can be registered via the Domain Simulator interface; scenario types are extensible |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Brain/Decision/000-Overview.md | Decision System consumes simulation results to inform choices |
| Bible/02-Core/Academy/000-Overview.md | Academy learns from simulation outcomes and improves models |
| Bible/02-Core/Brain/Planning/000-Overview.md | Planning System uses simulations to validate execution graphs |
| Bible/04-Execution/Runtime/000-Overview.md | Runtime provides the infrastructure for sandboxed execution |
| Bible/04-Execution/Security/000-Overview.md | Security Council verifies sandbox isolation integrity |
| Bible/04-Execution/Workflow/000-Overview.md | WFE can simulate workflows before execution to validate DAGs |
| Bible/05-Platform/004-EVS.md | EVS stores simulation evidence records |
| Bible/05-Platform/Observability/000-AOP.md | AOP monitors simulation health and sandbox resource usage |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy levels determine what simulations an agent can trigger |
| Physics/010-Execution.md | Execution invariants — simulation is pre-execution verification |
| Physics/005-Events.md | Evidence invariants — every simulation run produces auditable evidence |
