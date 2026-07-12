# AIOS Bible — Domains
## FPGA — 002: Synthesis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-FPGA-002 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
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

| Event | Producer | Payload | Description |
|-------|----------|---------|-------------|
| FPGA.SynthesisStarted | SynthesisEngine | synth_id, device, goal, frequency | Fired when synthesis job begins |
| FPGA.SynthesisCompleted | SynthesisEngine | synth_id, tech_map, utilization, duration | Fired after synthesis finishes |
| FPGA.MappingDone | Mapper | synth_id, lut_type, dsp, bram, util | Fired when technology mapping completes |
| FPGA.PlacementDone | Placer | placement_id, cell_util, congestion, iter | Fired when placement finishes |
| FPGA.RoutingDone | Router | routing_id, wires_routed, unrouted, slack | Fired when routing completes |
| FPGA.TimingAnalyzed | TimingAnalyzer | timing_id, fmax, violators, paths | Fired after timing analysis |
| FPGA.TimingClosed | Optimizer | closure_id, iterations, final_slack, status | Fired when timing closure is achieved or abandoned |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| FPGA-SYN-001 | Synthesis failure — tool exits with non-zero code or internal error | HIGH | Return full tool log, preserve intermediate files, trigger debug workflow |
| FPGA-SYN-002 | Mapping overflow — technology mapping exceeds device LUT or FF capacity | HIGH | Report overflow by resource type, suggest device upgrade, abort P&R |
| FPGA-SYN-003 | Placement congestion — placement fails to legalize all cells within density limits | HIGH | Run congestion-aware placement pass, relax density target, report if still failing |
| FPGA-SYN-004 | Routing unroutable — routing fails to complete all net connections | HIGH | Identify unroutable nets, suggest floorplan changes, escalate to HDL redesign |
| FPGA-SYN-005 | Timing violation — worst negative slack below threshold after optimization | MEDIUM | Report violating paths, attempt constraint relaxation, trigger RTL redesign if persistent |
| FPGA-SYN-006 | Toolchain version mismatch — installed tool version differs from pinned version | HIGH | Block execution, trigger toolchain verification workflow |
| FPGA-SYN-007 | License unavailable — EDA tool license cannot be acquired | MEDIUM | Queue job, retry with backoff, fail after TTL expiry |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| FPGA-SYN-INV-001 | Every synthesis run must have completed RTL simulation on the same design | Precondition check in SynthesisEngine; block synthesis without simulation event |
| FPGA-SYN-INV-002 | All EDA tool versions must match the pinned version in the Toolchain Registry | Version check at SynthesisConfig creation; reject mismatch |
| FPGA-SYN-INV-003 | P&R must achieve positive worst negative slack before bitstream generation | Postcondition check after RoutingDone; block bitstream on negative slack |
| FPGA-SYN-INV-004 | Congestion score must be below 90% for a design to proceed to bitstream | Threshold check in PlaceRouteCompleted handler |
| FPGA-SYN-INV-005 | Synthesis results must be bit-identical for identical RTL and toolchain | Determinism check via checksum on TechnologyMap; regression test enforcement |

## Design DNA (R1-R6,R9,R10,R13-R15)

- **R1 — Single Source of Truth**: SynthesisConfig is the sole configuration source for all P&R operations.
- **R2 — Immutable Event Log**: Every synthesis, placement, routing, and timing event is recorded immutably.
- **R3 — Capability-Based Authorization**: Only SynthesisWorker capability may invoke SynthesisEngine operations.
- **R4 — Law of Diminishing Returns**: P&R stops after 5 iterations with less than 1% improvement; premature closure avoided.
- **R5 — Deterministic Computation**: Same RTL, toolchain, and seed produces identical routed netlist.
- **R6 — Bounded Context**: Synthesis owns the P&R pipeline; timing analysis results are shared via Events.
- **R9 — Fail-Fast**: Toolchain mismatch and license errors are detected pre-execution, not mid-synthesis.
- **R10 — Audit Trail**: Every P&R iteration, timing analysis, and optimization step is logged with timestamps.
- **R13 — Defensive Design**: DRC and LVS checks run between P&R stages; partial results preserved on failure.
- **R14 — Self-Healing**: On placement congestion, Placer retries with relaxed density target up to 3 times.
- **R15 — Backward Compatibility**: Synthesis configs from older toolchain versions have migration paths documented.

## Related Documents

- Bible/07-Domains/FPGA/000-Overview.md
- Bible/07-Domains/FPGA/001-Architecture.md
- Bible/07-Domains/FPGA/003-Verification.md
- Bible/06-Services/ACF/000-Overview.md
- Bible/08-Interfaces/SDK/003-Provider-SDK.md
- Bible/02-Core/DTS/000-Overview.md
- Bible/02-Core/ROS/000-Overview.md
