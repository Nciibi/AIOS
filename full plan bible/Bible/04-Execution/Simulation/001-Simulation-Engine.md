# AIOS Bible — Execution
## 001 — Simulation Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Simulation |
| Document ID | AIOS-BBL-004-SIM-001 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/010-Execution.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Core simulation engine — orchestrates scenario lifecycle, manages virtual time, coordinates domain simulators, and ensures deterministic execution. The engine is the central runtime that translates a scenario definition into an isolated, step-wise simulated execution producing verifiable results.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Simulation Engine                          │
│                                                              │
│  ┌──────────────────────────────────────────────────┐       │
│  │              Engine Lifecycle State               │       │
│  │  idle → running → paused → completed → failed     │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────┐       │
│  │               Step Sequencer                      │       │
│  │  Orders actions by scheduledTime, resolves deps   │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────┐       │
│  │           Virtual Time Controller                 │       │
│  │  Manages time steps, acceleration, stepping       │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         │                                    │
│  ┌──────────────────────▼───────────────────────────┐       │
│  │           Simulator Coordinator                   │       │
│  │  Load → Initialize → Step → Collect per domain    │       │
│  └──────────────────────────────────────────────────┘       │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Execution   │  │ Execution   │  │ Execution   │         │
│  │ Frame (1)   │  │ Frame (2)   │  │ Frame (N)   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

### Engine Lifecycle

The engine transitions through discrete states:

```
       ┌──────────┐
       │   idle   │
       └────┬─────┘
            │ loadScenario()
            ▼
     ┌──────────────┐
     │  initialized │
     └──────┬───────┘
            │ start()
            ▼
     ┌──────────────┐  pause()  ┌────────┐  resume()  ┌─────────┐
     │   running    │◄─────────►│ paused │◄──────────►│ running │
     └──────┬───────┘           └────────┘             └─────────┘
            │
            ├── all steps done ──► ┌───────────┐
            │                      │ completed │
            │                      └───────────┘
            └── fatal error ──► ┌───────┐
                               │ failed │
                               └───────┘
```

### Virtual Time Management

Virtual time decouples simulation progression from wall-clock time. The controller supports:

- **Fixed time step**: Each simulation step advances by a configurable duration (e.g., 1s simulated = 10ms real)
- **Time acceleration**: Rate multiplier applied to simulated time (e.g., 10x, 100x, 1000x)
- **Stepping mode**: Manual step-by-step advancement for debugging and replay analysis
- **Time bounds**: Virtual time cannot exceed configured max duration or advance faster than max rate

### Domain Simulator Coordination

The coordinator manages the lifecycle of each domain simulator within a simulation run:

1. **Load**: Instantiate the domain simulator from the registry by domain type
2. **Initialize**: Call `initialize(snapshot, params)` with the sandbox state snapshot and scenario parameters
3. **Step**: For each simulation step, call `simulate(actions)` with actions scheduled for that time window
4. **Collect**: Aggregate results from all domains into a unified `SimulationResult`

### Execution Frames

Each simulation step produces an `ExecutionFrame` — an immutable record of state at a point in virtual time:

- Contains the state trajectory point, events emitted during the step, and metrics snapshot
- Frames are ordered by simulated time and linked in a chain for forward/backward traversal
- Frames are persisted as evidence for replay verification

### Step Sequencer

The sequencer orders actions from the scenario definition into a deterministic execution schedule:

- Actions are sorted by `scheduledTime` (ascending)
- Dependencies (`dependsOn`) are resolved via topological ordering
- Actions scheduled for the same time step are executed in dependency order
- The sequencer guarantees reproducibility — same scenario always produces the same step order

## Data Model

```typescript
interface EngineConfig {
  maxSimulationDuration: Duration;
  virtualTimeStep: Duration;
  maxTimeAcceleration: number;
  maxConcurrentDomains: number;
  sandboxResourceLimits: ResourceLimits;
  stepTimeout: Duration;
}

interface VirtualTimeController {
  currentTime: Timestamp;
  timeStep: Duration;
  acceleration: number;
  maxDuration: Duration;
  state: 'running' | 'paused' | 'stopped';

  advance(): Timestamp;
  pause(): void;
  resume(): void;
  setAcceleration(rate: number): void;
  isExpired(): boolean;
}

interface SimulatorCoordinator {
  activeSimulators: Map<SimulationDomain, DomainSimulator>;
  domainResults: Map<SimulationDomain, SimulationResult>;

  loadDomain(domain: SimulationDomain): Promise<void>;
  initializeAll(snapshot: SimulationState, params: Record<string, unknown>): Promise<void>;
  stepAll(actions: SimulatedAction[], currentTime: Timestamp): Promise<Map<SimulationDomain, StepResult>>;
  collectAll(): Promise<Map<SimulationDomain, SimulationResult>>;
  cleanupAll(): Promise<void>;
}

interface ExecutionFrame {
  frameId: string;
  runId: string;
  sequenceNumber: number;
  simulatedTime: Timestamp;
  stateHash: string;
  domainStates: Map<SimulationDomain, DomainStateSnapshot>;
  events: SimulatedEvent[];
  metrics: Record<string, number>;
  previousFrameId: string | null;
  nextFrameId: string | null;
}

interface SimulationContext {
  runId: string;
  scenario: Scenario;
  sandbox: Sandbox;
  virtualTime: VirtualTimeController;
  coordinator: SimulatorCoordinator;
  frames: ExecutionFrame[];
  config: EngineConfig;
  startedAt: Timestamp;
  completedAt: Timestamp | null;
  status: 'idle' | 'running' | 'paused' | 'completed' | 'failed';
  error: SimulationError | null;
}

interface SimulationStep {
  stepNumber: number;
  scheduledActions: SimulatedAction[];
  domainInputs: Map<SimulationDomain, SimulatedAction[]>;
  timestamp: Timestamp;
}

interface StepResult {
  domain: SimulationDomain;
  stateDelta: Record<string, unknown>;
  events: SimulatedEvent[];
  metrics: Record<string, number>;
  duration: number;
}

interface SimulationError {
  code: string;
  message: string;
  step: number | null;
  domain: SimulationDomain | null;
  timestamp: Timestamp;
}
```

## Core Concepts / Operations

- **Engine Initialization**: Load configuration, validate sandbox resources, register available domain simulators
- **Scenario Loading**: Receive validated scenario, create sandbox, prepare virtual time controller
- **Execution Loop**: Sequencer dispatches steps → VirtualTimeController advances → Coordinator steps domain simulators → Frame recorded
- **Pause/Resume**: Suspend virtual time and step execution; preserve execution context for later resumption
- **Completion**: All steps executed, results collected, evidence recorded, sandbox torn down
- **Failure Handling**: Catch simulator errors, resource overflows, timeouts; preserve partial execution frames

## Internal Interfaces

```typescript
interface EngineLifecycle {
  initialize(config: EngineConfig): Promise<void>;
  loadScenario(scenario: Scenario): Promise<SimulationContext>;
  start(): Promise<SimulationResult>;
  pause(): Promise<void>;
  resume(): Promise<void>;
  cancel(): Promise<void>;
  getStatus(): EngineStatus;
}

interface StepSequencer {
  sequence(actions: SimulatedAction[]): SimulationStep[];
  resolveDependencies(actions: SimulatedAction[]): SimulatedAction[];
  getStepCount(): number;
  getStep(index: number): SimulationStep;
}

interface FrameStore {
  append(frame: ExecutionFrame): Promise<void>;
  getFrame(frameId: string): Promise<ExecutionFrame>;
  getChain(runId: string): Promise<ExecutionFrame[]>;
  getFrameAtTime(runId: string, simulatedTime: Timestamp): Promise<ExecutionFrame | null>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `SIM.Eng.Initialized` | engineVersion, config | Engine initialized with configuration |
| `SIM.Eng.ScenarioLoaded` | runId, scenarioId, domainCount | Scenario loaded into the engine |
| `SIM.Eng.VirtualTimeStarted` | runId, startTime, timeStep | Virtual time progression began |
| `SIM.Eng.VirtualTimePaused` | runId, currentTime | Virtual time paused at given timestamp |
| `SIM.Eng.VirtualTimeResumed` | runId, currentTime, acceleration | Virtual time resumed with (possibly new) acceleration |
| `SIM.Eng.StepExecuted` | runId, stepNumber, simulatedTime | Individual simulation step completed |
| `SIM.Eng.SimulatorCoordinated` | runId, domain, stepCount, duration | Domain simulator coordination completed |
| `SIM.Eng.EnginePaused` | runId, stepNumber, reason | Engine entered paused state |
| `SIM.Eng.EngineResumed` | runId, stepNumber | Engine resumed from paused state |
| `SIM.Eng.EngineCompleted` | runId, stepCount, totalDuration | Engine completed all steps successfully |
| `SIM.Eng.EngineFailed` | runId, errorCode, stepNumber | Engine terminated due to unrecoverable error |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Engine not initialized before scenario load | `SIM_ENG_001` | Reject load; require initialize() first |
| Scenario validation failed | `SIM_ENG_002` | Reject load; return validation errors |
| Virtual time exceeds max duration | `SIM_ENG_003` | Terminate simulation; mark as timedOut |
| Step execution timeout exceeded | `SIM_ENG_004` | Terminate step; fail simulation with partial frames |
| Domain simulator not registered for domain | `SIM_ENG_005` | Fail simulation; list available domains |
| Execution frame chain integrity violation | `SIM_ENG_006` | Fail simulation; frames are immutable evidence |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SIM-ENG-001 | Engine state transitions are unidirectional (no re-entry to idle after running) | Algorithmic — state machine guards on lifecycle methods |
| SIM-ENG-002 | Virtual time never advances faster than max configured acceleration | Algorithmic — VirtualTimeController throttles advance() |
| SIM-ENG-003 | Execution frames are immutable once appended to the store | Architectural — FrameStore enforces append-only |
| SIM-ENG-004 | Domain simulators execute in isolation; cross-domain state leaks are impossible | Architectural — each domain gets a separate sandbox layer |
| SIM-ENG-005 | The same scenario always produces the same step sequence | Algorithmic — StepSequencer is deterministic by construction |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Engine is the sole orchestrator of simulation execution; no other component manages virtual time or step sequencing |
| R2 — Dependency Order | Engine depends on Sandbox Manager, Domain Simulator registry, and Evidence Recorder; no circular dependencies |
| R9 — Deterministic | StepSequencer and VirtualTimeController guarantee reproducibility across runs |
| R10 — Simpler Over Complex | Single-domain single-step is default; multi-domain multi-step is explicit opt-in |
| R13 — Design for Failure | Partial execution frames preserved on failure; error code and step captured |
| R14 — Paved Path | Single-domain scenario with default EngineConfig is the standard path |
| R15 — Open/Closed | New domain simulators can be added without modifying the engine; the coordinator interface is stable |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Simulation/000-Overview.md | System overview defining engine role in the simulation architecture |
| Bible/04-Execution/Simulation/002-Scenarios.md | Scenarios provide the input that the engine executes |
| Bible/04-Execution/Simulation/003-Validation.md | Validation consumes engine output (ExecutionFrame chain) for analysis |
| Bible/04-Execution/Security/000-Overview.md | Security Council verifies sandbox isolation and engine integrity |
| Bible/05-Platform/004-EVS.md | EVS stores engine execution frames as evidence records |
| Physics/010-Execution.md | Execution invariants governing simulation as pre-execution verification |
