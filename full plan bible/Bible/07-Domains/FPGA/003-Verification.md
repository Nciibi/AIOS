# AIOS Bible â€” Domains
## FPGA â€” 003: Verification

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-FPGA-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The FPGA Verification sub-doc defines the verification pipeline â€” RTL simulation, gate-level simulation, formal verification, assertion checking, coverage analysis, bitstream verification, and readback verification. It ensures that every design meets functional, temporal, and integrity requirements before deployment.

## Architecture

```
RTL Simulation
    |
    v
Gate-Level Simulation
    |
    v
Formal Verification
    |
    v
Assertion Checking
    |
    v
Coverage Analysis
    |
    v
Bitstream Verification
    |
    v
Readback Verification
```

## Data Model (TypeScript)

```typescript
interface SimulationConfig {
  id: string;
  designId: string;
  language: "vhdl" | "verilog" | "systemverilog" | "mixed";
  simulator: string;
  simulatorVersion: string;
  testbenchId: string;
  testCases: string[];
  timeScale: string;
  resolution: string;
  coverageEnabled: boolean;
  assertionsEnabled: boolean;
  maxSimTime: number;
  seed: number;
  jobId: string;
}

interface FormalVerificationPlan {
  id: string;
  designId: string;
  tool: string;
  mode: "equivalence" | "property" | "fpv" | "connective";
  properties: PropertySpec[];
  comparePoint: "rtl_to_rtl" | "rtl_to_gate" | "gate_to_gate";
  depth: number;
  engines: string[];
  timeoutMinutes: number;
}

interface AssertionSpec {
  id: string;
  module: string;
  type: "immediate" | "concurrent" | "property" | "coverage";
  expression: string;
  severity: "fatal" | "error" | "warning" | "info";
  category: "protocol" | "fsm" | "data" | "interface" | "timing";
  clockDomain: string;
  enabled: boolean;
}

interface CoverageResult {
  simId: string;
  lineCoverage: number;
  toggleCoverage: number;
  fsmCoverage: number;
  branchCoverage: number;
  expressionCoverage: number;
  assertionCoverage: number;
  totalFunctionalCoverage: number;
  uncoveredItems: CoverageGap[];
  timestamp: Timestamp;
}

interface BitstreamVerification {
  id: string;
  bitstreamId: string;
  checksum: string;
  checksumAlgorithm: string;
  signatureValid: boolean;
  signatureAlgorithm: string;
  encryptionVerified: boolean;
  bitstreamSize: number;
  deviceId: string;
  programmedAt: Timestamp;
  verifiedAt: Timestamp;
}

interface ReadbackResult {
  readbackId: string;
  deviceId: string;
  bitstreamId: string;
  readbackData: string;
  match: boolean;
  mismatches: ReadbackMismatch[];
  durationSeconds: number;
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| run_simulation | Execute RTL or gate-level simulation with testbench | SimulationConfig | SimulationResult |
| run_formal | Execute formal verification on design properties | FormalVerificationPlan | FormalResult |
| check_assertions | Evaluate assertion set during or post-simulation | AssertionSpec[], scope | AssertionResult |
| analyze_coverage | Compute functional coverage metrics | SimulationResult | CoverageResult |
| verify_bitstream | Checksum and signature verification of bitstream | BitstreamArtifact | BitstreamVerification |
| verify_readback | Compare readback data against programmed bitstream | device, bitstream | ReadbackResult |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| SimulationRunner | SimulationWorker | Orchestrates simulator execution |
| FormalEngine | SimulationWorker | Manages formal verification tools |
| AssertionChecker | SimulationWorker | Evaluates assertions against simulation traces |
| CoverageAnalyzer | SimulationWorker | Computes coverage metrics from simulation data |
| BitstreamVerifier | SynthesisWorker | Verifies bitstream integrity and signature |
| ReadbackController | SynthesisWorker | Manages device readback and comparison |

## Events

| FPGA.EventType |  Produced When | Fields |
|-------|----------|---------|
| FPGA.SimulationPassed |  SimulationRunner: sim_id, test_cases, passed, coverage | Fired when simulation completes with all tests passing |
| FPGA.FormalVerified |  FormalEngine: formal_id, properties, proven, inconclusive | Fired when formal verification completes |
| FPGA.AssertionChecked |  AssertionChecker: module, assertions_fired, passed, failed | Fired after assertion evaluation |
| FPGA.CoverageAnalyzed |  CoverageAnalyzer: sim_id, total_coverage, gaps, threshold | Fired when coverage analysis finishes |
| FPGA.BitstreamVerified |  BitstreamVerifier: bitstream_id, checksum, signature_valid | Fired after bitstream integrity check |
| FPGA.ReadbackVerified |  ReadbackController: readback_id, match, mismatches | Fired after readback comparison |
| FPGA.SimulationFailed |  SimulationRunner: sim_id, failing_tests, logs, assertions | Fired when simulation fails |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| FPGA-VRF-001 | Simulation assertion failure â€” an assertion evaluates false during simulation | HIGH | Record assertion with stimulus, halt simulation, return waveform at failure point |
| FPGA-VRF-002 | Formal verification inconclusive â€” tool cannot prove or disprove properties within depth or time | MEDIUM | Increase depth or time limit, switch engine, report unbounded proof unavailable |
| FPGA-VRF-003 | Coverage below threshold â€” functional coverage is less than 80% minimum | MEDIUM | Return coverage gap report, identify uncovered regions, trigger testbench expansion |
| FPGA-VRF-004 | Bitstream integrity failure â€” checksum mismatch after bitstream generation | HIGH | Regenerate bitstream, verify toolchain integrity, compare with prior build |
| FPGA-VRF-005 | Readback mismatch â€” programmed device readback does not match source bitstream | CRITICAL | Report mismatch addresses, trigger device reprogram, isolate hardware fault |
| FPGA-VRF-006 | Gate-level simulation mismatch â€” gate sim results differ from RTL sim results | HIGH | Compare RTL vs gate waveforms, identify synthesis artifacts, resynthesize with constraints |
| FPGA-VRF-007 | Formal engine timeout â€” verification exceeds configured time limit | MEDIUM | Partition properties, run with bounded proof, report as partial verification |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| FPGA-VRF-INV-001 | RTL simulation must pass before gate-level simulation or synthesis | Precondition check in SimulationWorker; block gate sim without RTL sim pass event |
| FPGA-VRF-INV-002 | Formal verification is required on all clock-domain crossing and reset logic | Cross-reference check in FormalEngine against CDC/RDC property registry |
| FPGA-VRF-INV-003 | Bitstream must pass integrity verification before device programming | Postcondition check in BitstreamVerifier; block program on integrity failure |
| FPGA-VRF-INV-004 | Coverage must meet minimum threshold of 80% for functional verification signoff | Threshold gate in CoverageAnalyzer; block handoff on below-threshold coverage |
| FPGA-VRF-INV-005 | All assertion violations must be resolved or explicitly waived before bitstream generation | Waiver registry check in BitstreamVerifier; enforce zero unresolved violations |

## Design DNA (R1-R6,R9,R10,R13-R15)

- **R1 â€” Single Source of Truth**: SimulationConfig and FormalVerificationPlan are the sole sources for verification setup.
- **R2 â€” Immutable Event Log**: Every simulation, formal run, assertion check, and verification produces an immutable event.
- **R3 â€” Capability-Based Authorization**: Only SimulationWorker and SynthesisWorker capabilities may invoke verification engines.
- **R4 â€” Law of Diminishing Returns**: Coverage above 95% triggers diminishing returns; focus shifts to directed testing.
- **R5 â€” Deterministic Computation**: Same testbench, seed, and design produces identical simulation results.
- **R6 â€” Bounded Context**: Verification owns the sim-to-bitstream pipeline; results are broadcast via Events.
- **R9 â€” Fail-Fast**: Assertion failures stop simulation immediately; formal inconclusive results block signoff.
- **R10 â€” Audit Trail**: Every verification step, coverage metric, and waiver is logged with timestamp and worker identity.
- **R13 â€” Defensive Design**: Simulation checkpoints at every assertion boundary; partial coverage results preserved.
- **R14 â€” Self-Healing**: On formal timeout, FormalEngine retries with partitioned property sets automatically.
- **R15 â€” Backward Compatibility**: Verification configs maintain versioned migration paths across tool updates.



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
| Bible/07-Domains/FPGA/001-Architecture.md | Architecture defines verification constraints |
| Bible/07-Domains/FPGA/002-Synthesis.md | Synthesis output is the subject of verification |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” verification event transport |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” EDA tool adapter interface |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” verification confidence scoring |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” compute budgets for simulation and formal verification |
