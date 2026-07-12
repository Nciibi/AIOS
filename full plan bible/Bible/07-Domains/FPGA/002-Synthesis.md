# AIOS Bible â€” Domains
## FPGA â€” 002: Synthesis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-FPGA-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Synthesis and Place & Route sub-doc defines the engine for RTL synthesis, technology mapping, placement, routing, timing optimization, congestion management, and multi-iteration closure. It orchestrates the most compute-intensive operations in AIOS.

## Architecture

```
RTL
 |
 v
Synthesis (elaboration + logic optimization)
 |
 v
Technology Mapping
 |
 v
Placement
 |
 v
Routing
 |
 v
Timing Analysis
 |
 v
Optimization
 |
 v
Closure (iterative loop)
```

## Data Model (TypeScript)

```typescript
interface SynthesisConfig {
  id: string;
  deviceFamilyId: string;
  partNumber: string;
  toolchain: string;
  toolVersion: string;
  optimizationGoal: "area" | "speed" | "power" | "balanced";
  frequencyTargetMHz: number;
  preserveHierarchy: boolean;
  flattenNets: boolean;
  retiming: boolean;
  fanoutLimit: number;
  jobId: string;
}

interface TechnologyMap {
  synthesisId: string;
  luts: number;
  lutType: "lut5" | "lut6" | "lut7" | "mixed";
  flipFlops: number;
  dspSlices: number;
  blockRams: number;
  bramUsedBits: number;
  ultrarams: number;
  carryChains: number;
  muxf7: number;
  muxf8: number;
  ioRegs: number;
  utilizationPercent: number;
}

interface PlacementResult {
  placementId: string;
  status: "completed" | "partial" | "failed";
  cellUtilization: number;
  pinDensity: number;
  wireLengthEstimate: number;
  congestionScore: number;
  iterations: number;
  durationSeconds: number;
  warnings: string[];
  errors: string[];
}

interface RoutingResult {
  routingId: string;
  status: "completed" | "partial" | "failed";
  totalWires: number;
  routedWires: number;
  unroutedNets: number;
  maxFanout: number;
  totalWireLength: number;
  worstNegativeSlack: number;
  totalNegativeSlack: number;
  violators: number;
  congestion: CongestionReport;
}

interface TimingReport {
  timingId: string;
  fmaxMHz: number;
  setupPaths: TimingPathSummary;
  holdPaths: TimingPathSummary;
  clockDomains: ClockDomainReport[];
  violatingPaths: ViolatingPath[];
}

interface CongestionReport {
  averageCongestion: number;
  maxCongestion: number;
  congestedRegions: CongestedRegion[];
  overflowNets: number;
  routingTrialCount: number;
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| run_synthesis | Elaborate and optimize RTL into gate-level netlist | RTL, SynthesisConfig | TechnologyMap |
| map_technology | Map optimized logic to target device primitives | netlist, device | TechnologyMap |
| place_design | Assign logic elements to physical sites on device | TechnologyMap, constraints | PlacementResult |
| route_design | Connect placed elements using routing fabric | PlacementResult, constraints | RoutingResult |
| optimize_timing | Apply retiming, duplication, or restructuring to meet timing | TimingReport, options | OptimizationResult |
| close_timing | Iterate P&R with progressively tighter constraints | design, constraints | ClosureReport |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| SynthesisEngine | SynthesisWorker | Orchestrates synthesis tool execution |
| Mapper | SynthesisEngine | Handles technology mapping logic |
| Placer | SynthesisEngine | Manages physical placement algorithms |
| Router | SynthesisEngine | Executes routing passes |
| TimingAnalyzer | SynthesisEngine, HDLWorker | Runs static timing analysis |
| Optimizer | SynthesisEngine | Applies timing/area/power optimizations |

## Events

| FPGA.EventType |     Produced When | Fields |
|-------|----------|---------|
| FPGA.SynthesisStarted |     SynthesisEngine: synth_id, device, goal, frequency | Fired when synthesis job begins |
| FPGA.SynthesisCompleted |     SynthesisEngine: synth_id, tech_map, utilization, duration | Fired after synthesis finishes |
| FPGA.MappingDone |     Mapper: synth_id, lut_type, dsp, bram, util | Fired when technology mapping completes |
| FPGA.PlacementDone |     Placer: placement_id, cell_util, congestion, iter | Fired when placement finishes |
| FPGA.RoutingDone |     Router: routing_id, wires_routed, unrouted, slack | Fired when routing completes |
| FPGA.TimingAnalyzed |     TimingAnalyzer: timing_id, fmax, violators, paths | Fired after timing analysis |
| FPGA.TimingClosed |     Optimizer: closure_id, iterations, final_slack, status | Fired when timing closure is achieved or abandoned |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| FPGA-SYN-001 | Synthesis failure â€” tool exits with non-zero code or internal error | HIGH | Return full tool log, preserve intermediate files, trigger debug workflow |
| FPGA-SYN-002 | Mapping overflow â€” technology mapping exceeds device LUT or FF capacity | HIGH | Report overflow by resource type, suggest device upgrade, abort P&R |
| FPGA-SYN-003 | Placement congestion â€” placement fails to legalize all cells within density limits | HIGH | Run congestion-aware placement pass, relax density target, report if still failing |
| FPGA-SYN-004 | Routing unroutable â€” routing fails to complete all net connections | HIGH | Identify unroutable nets, suggest floorplan changes, escalate to HDL redesign |
| FPGA-SYN-005 | Timing violation â€” worst negative slack below threshold after optimization | MEDIUM | Report violating paths, attempt constraint relaxation, trigger RTL redesign if persistent |
| FPGA-SYN-006 | Toolchain version mismatch â€” installed tool version differs from pinned version | HIGH | Block execution, trigger toolchain verification workflow |
| FPGA-SYN-007 | License unavailable â€” EDA tool license cannot be acquired | MEDIUM | Queue job, retry with backoff, fail after TTL expiry |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| FPGA-SYN-INV-001 | Every synthesis run must have completed RTL simulation on the same design | Precondition check in SynthesisEngine; block synthesis without simulation event |
| FPGA-SYN-INV-002 | All EDA tool versions must match the pinned version in the Toolchain Registry | Version check at SynthesisConfig creation; reject mismatch |
| FPGA-SYN-INV-003 | P&R must achieve positive worst negative slack before bitstream generation | Postcondition check after RoutingDone; block bitstream on negative slack |
| FPGA-SYN-INV-004 | Congestion score must be below 90% for a design to proceed to bitstream | Threshold check in PlaceRouteCompleted handler |
| FPGA-SYN-INV-005 | Synthesis results must be bit-identical for identical RTL and toolchain | Determinism check via checksum on TechnologyMap; regression test enforcement |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Compliant |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Compliant |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Compliant |
| R10 - Simpler Over Complex | Compliant |
| R13 - Design for Failure | Compliant |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

## Cross-Cutting Concerns

### Security

FPGA operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), FPGA emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), FPGA instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), FPGA declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/FPGA/000-Overview.md | Base FPGA domain overview |
| Bible/07-Domains/FPGA/001-Architecture.md | Architecture defines device constraints for synthesis |
| Bible/07-Domains/FPGA/003-Verification.md | Verification validates synthesis output |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” synthesis job event transport |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” EDA tool adapter interface |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” design confidence scoring |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” compute budgets for P&R operations |
