# AIOS Bible — Domains
## Embedded — 002: Firmware

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-EMB-002 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Provide the firmware generation engine that produces production-ready embedded binaries from board profiles, HAL configurations, driver templates, and application logic while enforcing resource constraints and toolchain correctness.

## Architecture

```mermaid
flowchart LR
    Profile[Board Profile] --> HAL[HAL Generation]
    HAL --> Driver[Driver Generation]
    Driver --> App[Application Logic]
    App --> Linker[Linker Configuration]
    Linker --> Startup[Startup Code Generation]
    Startup --> Build[Cross-Compilation]
    Build --> Binary[Binary Output]
```

The pipeline ingests a board profile and produces HAL abstraction layer code, device driver implementations, the user application skeleton, a tailored linker script, startup code with vector tables, and finally compiles everything into a flashable binary.

## Data Model (TypeScript)

```typescript
interface FirmwareProject {
  id: string;
  boardId: string;
  name: string;
  halConfig: HALConfig;
  drivers: DriverTemplate[];
  application: ApplicationCode;
  linker: LinkerScript;
  startup: StartupCode;
  toolchain: ToolchainConfig;
  outputBinary: BinaryArtifact;
}

interface HALConfig {
  mcuFamily: string;
  core: string;
  clockConfig: ClockConfig;
  peripheralDrivers: string[];
  interruptTable: InterruptEntry[];
  halVersion: string;
  rtosConfig?: RTOSConfig;
}

interface ClockConfig {
  source: 'HSI' | 'HSE' | 'PLL' | 'LSI' | 'LSE';
  sysclk: number;
  hclk: number;
  apb1: number;
  apb2: number;
  pllSource?: string;
  pllMul?: number;
  pllDiv?: number;
}

interface InterruptEntry {
  irq: number;
  name: string;
  priority: number;
  handler: string;
  enabled: boolean;
}

interface DriverTemplate {
  name: string;
  type: 'USART' | 'SPI' | 'I2C' | 'GPIO' | 'ADC' | 'DAC' | 'PWM' | 'CAN' | 'USB' | 'DMA' | 'TIMER' | 'EXTI';
  instance: number;
  api: string[];
  dependencies: string[];
  resourceUsage: ResourceEstimate;
  configParams: Record<string, DriverParam>;
}

interface DriverParam {
  type: 'int' | 'float' | 'bool' | 'enum' | 'string';
  default: string;
  min?: number;
  max?: number;
  enumValues?: string[];
}

interface ApplicationCode {
  entryPoint: string;
  sourceFiles: SourceFile[];
  includePaths: string[];
  defines: Record<string, string>;
  stackSize: number;
  heapSize: number;
}

interface SourceFile {
  path: string;
  language: 'c' | 'cpp' | 'asm';
  content: string;
  dependencies: string[];
}

interface LinkerScript {
  template: string;
  memoryRegions: MemoryRegion[];
  sectionPlacement: SectionPlacement[];
  symbols: Record<string, number>;
}

interface SectionPlacement {
  section: string;
  region: string;
  attributes: string[];
  alignment?: number;
}

interface StartupCode {
  vectorTable: VectorEntry[];
  resetHandler: string;
  systemInit: string;
  stackPointerInitial: number;
}

interface VectorEntry {
  position: number;
  name: string;
  handler: string;
  defaultHandler: string;
}

interface ToolchainConfig {
  compiler: string;
  arch: string;
  floatABI?: 'soft' | 'softfp' | 'hard';
  optimization: '-O0' | '-O1' | '-O2' | '-O3' | '-Os';
  cStandard: 'c99' | 'c11' | 'c17' | 'c23';
  cppStandard?: 'c++11' | 'c++14' | 'c++17' | 'c++20';
  flags: string[];
  linkerFlags: string[];
}

interface BinaryArtifact {
  path: string;
  format: 'elf' | 'hex' | 'bin';
  size: number;
  checksum: string;
  buildTimestamp: string;
  sections: SectionInfo[];
}

interface SectionInfo {
  name: string;
  address: number;
  size: number;
  type: 'text' | 'data' | 'bss' | 'rodata' | 'stack' | 'heap';
}

interface ResourceEstimate {
  flashEstimate: number;
  ramEstimate: number;
  stackEstimate: number;
}

interface RTOSConfig {
  type: 'FreeRTOS' | 'Zephyr' | 'RT-Thread' | 'ThreadX' | 'none';
  tickRate: number;
  heapSize: number;
  maxTasks: number;
  configOptions: Record<string, string | number>;
}
```

## Core Concepts / Operations

| Concept | Operation | Description |
|---------|-----------|-------------|
| HAL Generation | generate_hal | Produce hardware abstraction layer from board profile |
| Driver Creation | create_driver | Instantiate a device driver from a typed template |
| Application | write_application | Generate application entry point and task skeleton |
| Linker Config | configure_linker | Tailor linker script to target memory map |
| Startup Code | generate_startup | Create vector table and reset sequence |
| Build | build_firmware | Invoke cross-compiler toolchain to produce binary |

## Internal Interfaces

```typescript
interface FirmwareEngineAPI {
  generate_hal(profile: BoardProfile): Result<HALConfig>;
  create_driver(driverId: string, config: Record<string, any>): Result<DriverTemplate>;
  write_application(spec: ApplicationSpec): Result<ApplicationCode>;
  configure_linker(boardId: string, memory: MemoryMap): Result<LinkerScript>;
  generate_startup(profile: BoardProfile): Result<StartupCode>;
  build_firmware(project: FirmwareProject): Result<BinaryArtifact>;
}

interface BoardProfile {
  boardId: string;
  mcuFamily: string;
  core: string;
  flashOrigin: number;
  flashSize: number;
  ramOrigin: number;
  ramSize: number;
  peripheralList: string[];
  clockTree: ClockTree;
}

interface ClockTree {
  sources: ClockSource[];
  dividers: ClockDivider[];
  outputs: ClockOutput[];
}

interface ClockSource {
  name: string;
  type: 'internal' | 'external' | 'pll';
  frequency: number;
}

interface ApplicationSpec {
  name: string;
  entryPoint: string;
  tasks: TaskSpec[];
  globals: Record<string, string>;
  includes: string[];
}

interface TaskSpec {
  name: string;
  stackSize: number;
  priority: number;
  period?: number;
  dependencies: string[];
}

interface BuildResult {
  success: boolean;
  binary: BinaryArtifact;
  warnings: BuildWarning[];
  errors: BuildError[];
  sections: SectionInfo[];
}

interface BuildWarning {
  code: string;
  message: string;
  file?: string;
  line?: number;
}

interface BuildError {
  code: string;
  message: string;
  file?: string;
  line?: number;
  fatal: boolean;
}
```

## Events

| Event Type | Produced When | Fields |
|-------|---------|-------------|
| Embedded.FirmwareProjectCreated | { projectId: string, boardId: string } | New firmware project initialized from board profile |
| Embedded.HALGenerated | { projectId: string, halVersion: string } | HAL abstraction layer code has been generated |
| Embedded.DriverWritten | { projectId: string, driverName: string } | A device driver was instantiated from template |
| Embedded.LinkerConfigured | { projectId: string, regionCount: number } | Linker script tailored to target memory map |
| Embedded.BuildStarted | { projectId: string, toolchain: string } | Cross-compilation process has begun |
| Embedded.BuildCompleted | { projectId: string, binarySize: number } | Build finished with or without errors |
| Embedded.BuildFailed | { projectId: string, errorCount: number } | Build terminated due to compilation or linking errors |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| EMB-FW-001 | HAL generation incompatibility between MCU family and selected HAL version | error | Roll back to compatible HAL version or select different profile |
| EMB-FW-002 | Driver resource conflict where two drivers claim the same peripheral instance | error | Reassign peripheral instances or merge driver configurations |
| EMB-FW-003 | Linker overflow where total sections exceed flash or RAM boundaries | error | Reduce code size, enable optimization, or shrink driver set |
| EMB-FW-004 | Startup code misconfiguration with invalid vector table entry | error | Validate interrupt numbers and handler symbols before assembly |
| EMB-FW-005 | Toolchain not found or version mismatch with MCU architecture | error | Install correct toolchain version or update project configuration |
| EMB-FW-006 | Stack size estimate exceeds available RAM after application generation | warning | Increase RAM allocation or reduce stack depth via static analysis |
| EMB-FW-007 | Undefined symbol reference during linking phase | error | Check driver dependencies and include paths for missing implementations |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| EMB-FW-INV-001 | Build output must be byte-identical for identical inputs and toolchain versions | Hash-based build cache prevents non-deterministic artifacts |
| EMB-FW-INV-002 | Every driver must declare its resource usage before integration | ResourceEstimate is validated against available flash and RAM |
| EMB-FW-INV-003 | Each generated binary must pass toolchain verification post-build | objdump and nm checksums validate section addresses and sizes |
| EMB-FW-INV-004 | Application entry point must exist in exactly one source file | Duplicate symbol detection runs before linking |
| EMB-FW-INV-005 | Interrupt vector table must cover all IRQs defined by the MCU profile | Generation uses the profile's IRQ count to size the table |
| EMB-FW-INV-006 | Linker script memory regions must match the board's memory map exactly | Region bounds are validated against BoardDefinition before script output |

## Design DNA (R1-R6,R9,R10,R13-R15)

| Rule | Application |
|------|-------------|
| R1 — Target Bounded | Firmware generation is scoped to a single board profile; no multi-target abstractions leak |
| R2 — Interchangeable Architecture | Board profiles can be swapped to produce firmware for different hardware without changing application logic |
| R3 — Generic Operations | HAL, driver, and linker generation follow the same pipeline for all MCU families |
| R4 — Composition over Inheritance | Drivers are composed of typed templates rather than inheriting from base classes |
| R5 — Stable Intermediate Representation | FirmwareProject is the canonical IR passed between pipeline stages |
| R6 — Temporal Synchronization | Each stage emits an event; downstream stages wait for prerequisite events before executing |
| R9 — Stateless Verification | BuildCompleted and BuildFailed are deterministic for the same project and toolchain |
| R10 — Capability-Based Routing | Driver selection and optimization level adapt based on available flash and RAM |
| R13 — Event-Driven Consistency | BuildFailed events trigger automatic rollback to last known good configuration |
| R14 — Code as Law | Linker script generation programmatically enforces memory region boundaries |
| R15 — Provably Deterministic | SHA-256 of inputs matches SHA-256 of binary output across all runs |

## Related Documents

- Bible/00-Overview.md
- Bible/07-Domains/Embedded/000-Overview.md
- Bible/07-Domains/Embedded/001-Devices.md
- Bible/07-Domains/Embedded/003-Constraints.md
- Bible/90-ACF/ACF-000-Core.md
- Bible/80-Provider-SDK/Provider-SDK-000.md
