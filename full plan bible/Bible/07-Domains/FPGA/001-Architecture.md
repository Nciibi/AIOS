# AIOS Bible â€” Domains
## FPGA â€” 001: Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-FPGA-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The FPGA Architecture sub-doc defines the device architecture layer â€” device family registry, logic fabric model, IP core catalog, constraint definition, resource estimation, and device selection. It provides the structural foundation upon which RTL design, synthesis, and verification are built.

## Architecture

```
Requirements
    |
    v
Device Family Selection
    |
    v
Fabric Resource Estimation
    |
    v
IP Core Instantiation
    |
    v
Constraint Generation
    |
    v
Implementation Handoff
```

## Data Model (TypeScript)

```typescript
interface DeviceFamily {
  id: string;
  vendor: "xilinx" | "intel" | "lattice" | "microchip" | "custom";
  family: string;
  processNode: number;
  supportedTools: string[];
  status: "supported" | "deprecated" | "experimental";
  registeredAt: Timestamp;
}

interface LogicFabric {
  deviceFamilyId: string;
  partNumber: string;
  packageType: string;
  speedGrade: string;
  resources: FabricResources;
  temperatureRange: "commercial" | "industrial" | "military";
}

interface FabricResources {
  logicCells: number;
  luts: number;
  flipFlops: number;
  dspSlices: number;
  blockRams: number;
  bramTotalBits: number;
  ultraRams: number;
  plls: number;
  mmcms: number;
  transceivers: number;
  ioPins: number;
  ioBanks: number;
}

interface IPCore {
  id: string;
  name: string;
  vendor: string;
  version: string;
  category: "clocking" | "interface" | "dsp" | "memory" | "protocol" | "processing" | "io";
  supportedFamilies: string[];
  resourceUsage: Partial<FabricResources>;
  license: "open" | "purchased" | "subscription" | "evaluation";
  licenseExpiry: Timestamp | null;
  source: "academy" | "vendor" | "custom";
}

interface DesignConstraint {
  id: string;
  deviceFamilyId: string;
  type: "timing" | "pin" | "area" | "power" | "placement" | "routing";
  target: string;
  value: string | number;
  priority: "critical" | "high" | "medium" | "low";
  source: "requirements" | "inferred" | "manual";
}

interface ResourceEstimate {
  deviceFamilyId: string;
  partNumber: string;
  luts: number;
  lutPercent: number;
  flipFlops: number;
  ffPercent: number;
  dspSlices: number;
  dspPercent: number;
  blockRams: number;
  bramPercent: number;
  totalPercent: number;
  ioPins: number;
  ioPercent: number;
  confidence: "low" | "medium" | "high";
}

interface DeviceSelector {
  requirements: DeviceRequirements;
  candidates: DeviceFamily[];
  selected: DeviceFamily | null;
  rationale: string;
  alternatives: DeviceFamily[];
}
```

## Core Concepts / Operations

| Operation | Description | Input | Output |
|-----------|-------------|-------|--------|
| select_device | Match requirements against device registry and select optimal family | DeviceRequirements | DeviceSelector |
| estimate_resources | Compute expected resource utilization from design metadata | module_list, device_family | ResourceEstimate |
| instantiate_ip | Load and configure an IP core for the target device | ip_core_id, configuration | IPCoreInstance |
| define_constraints | Generate constraint set from requirements and device spec | requirements, device | DesignConstraint[] |
| model_fabric | Build logic fabric model for a specific part number | part_number | LogicFabric |

## Internal Interfaces

| Interface | Consumer | Description |
|-----------|----------|-------------|
| DeviceRegistry | HDLWorker, SynthesisWorker | Provides device family lookup and validation |
| FabricModeler | HDLWorker | Supplies logic fabric resource models |
| IPCatalog | HDLWorker, SimulationWorker | Manages IP core discovery and instantiation |
| ConstraintEngine | SynthesisWorker | Generates and validates design constraints |
| ResourceEstimator | Sou Planner, HDLWorker | Pre-synthesis resource utilization estimates |

## Events

| FPGA.EventType |     Produced When | Fields |
|-------|----------|---------|
| FPGA.DeviceSelected |     DeviceRegistry: device_id, part_number, rationale | Fired when a target device is selected |
| FPGA.ResourcesEstimated |     ResourceEstimator: estimate_id, total_percent, confidence | Fired after resource estimation completes |
| FPGA.IPCoresInstantiated |     IPCatalog: core_id, name, version, device | Fired when an IP core is instantiated |
| FPGA.ConstraintsDefined |     ConstraintEngine: constraint_ids, types, count | Fired when constraints are generated |
| FPGA.DeviceValidated |     DeviceRegistry: device_id, validation_status | Fired after device compatibility check |
| FPGA.FabricModeled |     FabricModeler: part_number, resource_summary | Fired when fabric model is constructed |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| FPGA-ARC-001 | Device family mismatch â€” selected device does not match family in requirements | HIGH | Reject selection, present compatible alternatives from registry |
| FPGA-ARC-002 | Resource overestimation â€” estimated utilization exceeds 100% of device capacity | HIGH | Return overflow report, suggest larger device, trigger replan |
| FPGA-ARC-003 | IP core license unavailable â€” required IP core license is expired or missing | MEDIUM | Queue license acquisition, fall back to open-source alternative if available |
| FPGA-ARC-004 | Constraint conflict â€” two constraints target same path with incompatible values | MEDIUM | Report conflict with priority resolution, require manual override |
| FPGA-ARC-005 | Device not in registry â€” specified device part number is unknown | HIGH | Query vendor database, escalate to registry update if verified |
| FPGA-ARC-006 | IP core incompatible â€” IP core does not support selected device family | MEDIUM | Search compatible variants, suggest alternative IP core |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| FPGA-ARC-INV-001 | Every design must target a device registered in the DeviceRegistry | Precondition check in select_device; block implementation on unregistered device |
| FPGA-ARC-INV-002 | Resource estimates must be deterministic for identical design metadata | Hash comparison on ResourceEstimator output; unit test enforcement |
| FPGA-ARC-INV-003 | All IP cores must have verified device family compatibility before instantiation | Cross-reference check in IPCatalog instantiate method |
| FPGA-ARC-INV-004 | Constraint generation must produce at least one timing constraint per clock domain | Postcondition check in ConstraintEngine; warn on missing domain |
| FPGA-ARC-INV-005 | Device selection must consider power, thermal, and package constraints from requirements | Multi-field filter in DeviceSelector; rejection on any unmet constraint |

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
| Bible/07-Domains/FPGA/002-Synthesis.md | Synthesis consumes architecture constraints for P&R |
| Bible/07-Domains/FPGA/003-Verification.md | Verification validates architecture compliance |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” device selection event transport |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” EDA provider adapter interface |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” design confidence scoring |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” compute budgets for device estimation |
