# AIOS Bible â€” Domains
## Embedded â€” 001: Devices

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-EMB-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Manage the device support registry that maps physical embedded targets to reusable board support packages, enabling deterministic pin assignments, peripheral configuration, and device tree generation.

## Architecture

```mermaid
flowchart LR
    Detection[Device Detection] --> Matching[Profile Matching]
    Matching --> BSP[Board Support Package Generation]
    BSP --> DTC[Device Tree Compilation]
    DTC --> Verify[Pin Verification]
    Verify --> Register[Device Registration]
```

Detection identifies MCU parameters via probe or manifest. Profile matching selects the closest board definition. BSP generation produces HAL-level configuration files. Device tree compilation generates DTS/DTSI artifacts. Pin verification validates no conflicts exist. Registration commits the device into the active pool.

## Data Model (TypeScript)

```typescript
interface MCUProfile {
  id: string;
  family: string;
  manufacturer: string;
  core: 'Cortex-M0' | 'Cortex-M3' | 'Cortex-M4' | 'Cortex-M7' | 'RV32' | 'RV64';
  flashSize: number;       // bytes
  ramSize: number;         // bytes
  clockMax: number;        // Hz
  packages: string[];      // e.g. ['LQFP64', 'QFN32']
  voltageRange: [number, number];
  tempRange: [number, number];
}

interface BoardDefinition {
  id: string;
  name: string;
  mcuProfileId: string;
  formFactor: string;
  peripherals: PeripheralConfig[];
  pinMappings: PinMapping[];
  memoryMap: MemoryMap;
  deviceTreePath?: string;
}

interface PeripheralConfig {
  name: string;
  type: 'USART' | 'SPI' | 'I2C' | 'GPIO' | 'ADC' | 'DAC' | 'PWM' | 'CAN' | 'USB' | 'DMA' | 'TIMER';
  instance: number;
  pins: string[];
  config: Record<string, string | number>;
}

interface PinMapping {
  pin: string;
  signal: string;
  peripheral: string;
  altFunction: number;
  voltage: number;
  driveStrength?: 'low' | 'medium' | 'high';
  pull?: 'none' | 'up' | 'down';
}

interface MemoryMap {
  regions: MemoryRegion[];
  aliases: Record<string, string>;
}

interface MemoryRegion {
  name: string;
  type: 'flash' | 'ram' | 'peripheral' | 'sram' | 'backup';
  base: number;
  size: number;
  attributes: string[];
}

interface DeviceTree {
  version: number;
  include: string[];
  nodes: DeviceTreeNode[];
  bindings: Record<string, string>;
}

interface DeviceTreeNode {
  label: string;
  compatible: string[];
  reg?: number[];
  interrupts?: number[];
  status: 'okay' | 'disabled';
  properties: Record<string, string | number | string[]>;
}
```

## Core Concepts / Operations

| Concept | Operation | Description |
|---------|-----------|-------------|
| Registration | register_device | Add a detected device to the active registry |
| Detection | detect_mcu | Probe MCU identifiers and match against profiles |
| BSP Generation | generate_bsp | Produce board support package from matched profile |
| Device Tree | compile_devicetree | Convert internal representation to DTS output |
| Verification | verify_pins | Validate no pin conflicts or electrical violations |

## Internal Interfaces

```typescript
interface DeviceRegistryAPI {
  register_device(device: MCUProfile): Result<BoardDefinition>;
  detect_mcu(probe: MCUProbe): Result<MCUProfile>;
  generate_bsp(profile: MCUProfile, board: BoardDefinition): Result<BSPPackage>;
  compile_devicetree(bsp: BSPPackage): Result<DeviceTree>;
  verify_pins(board: BoardDefinition): Result<PinVerificationReport>;
}

interface MCUProbe {
  method: 'jtag' | 'swd' | 'uart' | 'manifest';
  identifiers: Record<string, string>;
  voltage?: number;
}

interface BSPPackage {
  boardId: string;
  halHeaders: string[];
  linkerScript: string;
  startupFile: string;
  deviceTree: DeviceTree;
  pinConfig: Record<string, PinMapping>;
  clockConfig: ClockConfiguration;
}

interface PinVerificationReport {
  passed: boolean;
  conflicts: PinConflict[];
  warnings: PinWarning[];
}

interface PinConflict {
  pin: string;
  signals: string[];
  severity: 'error' | 'warning';
}

interface ClockConfiguration {
  source: 'HSI' | 'HSE' | 'PLL' | 'LSI' | 'LSE';
  frequency: number;
  dividers: Record<string, number>;
  pllConfig?: PLLConfig;
}
```

## Events

| EMB.EventType |      Produced When | Fields |
|-----------|---------------|--------|
| EMB.DeviceRegistered |      A new device is added to the registry | deviceId, boardId, registeredAt, registeredBy |
| EMB.MCUDetected |      An MCU is detected and profile-matched | profileId, method, confidence, detectedAt |
| EMB.BSPGenerated |      A board support package is generated | boardId, artifactCount, generationDuration |
| EMB.PinConflictDetected |      A pin assignment conflict is found | pin, conflictCount, peripheralList |
| EMB.DeviceTreeCompiled |      Device tree compilation completes | boardId, nodeCount, validationStatus |
| EMB.PeripheralMismatch |      A peripheral type mismatch is detected | peripheral, expected, actual, severity |
| EMB.BSPCacheHit |      BSP is retrieved from cache instead of regenerated | boardId, cacheAge, cacheKey |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| EMB-DEV-001 | Unknown device detected with no matching MCU profile | error | Request manual profile creation or update database |
| EMB-DEV-002 | Pin conflict detected between two peripherals | error | Reassign affected pins or disable conflicting peripheral |
| EMB-DEV-003 | Peripheral type mismatch in board definition | error | Correct peripheral type in board definition manifest |
| EMB-DEV-004 | BSP generation failure due to missing HAL templates | error | Verify HAL template repository is accessible and complete |
| EMB-DEV-005 | Device tree compilation syntax error | error | Validate generated DTS against schema before recompilation |
| EMB-DEV-006 | Clock configuration out-of-range for target MCU | warning | Clamp to valid range and regenerate clock tree |
| EMB-DEV-007 | Voltage mismatch between pin mapping and peripheral spec | warning | Adjust drive strength or pull configuration |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| EMB-DEV-INV-001 | Every registered device must map to exactly one MCU profile | Registration rejects devices with zero or multiple profile matches |
| EMB-DEV-INV-002 | No two active peripherals may share the same pin at the same time | Pin verification raises conflict before BSP generation |
| EMB-DEV-INV-003 | BSP output must be deterministic for identical inputs | Hash-based cache key enforces reproducibility |
| EMB-DEV-INV-004 | Device tree nodes must satisfy all referenced bindings | Compilation step validates each node against binding schema |
| EMB-DEV-INV-005 | Memory map regions must not overlap | Region insertion checks for intersection before commit |
| EMB-DEV-INV-006 | Clock frequency must stay within MCU profile limits | Generation clamps PLL output and divider ratios |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | All device generation is bounded to the target MCU profile; no generic defaults |
| R2 - Dependency Order | Board definitions can be swapped without changing application logic |
| R3 - DRY | Device detection and BSP generation follow the same pipeline for all families |
| R4 - Builder Pattern | Peripheral configs are composed into board definitions rather than subclassed |
| R5 - Liskov Substitution | DeviceTree is the canonical IR passed between stages |
| R6 - DI over Singletons | Events fire after each stage completes; downstream stages await their prerequisites |
| R9 - Deterministic | Pin verification produces the same result for the same board definition every time |
| R10 - Simpler Over Complex | BSP generation adapts based on available flash, RAM, and peripheral resources |
| R13 - Design for Failure | PinConflictDetected events trigger automatic reassignment workflows |
| R14 - Paved Path | Device tree compilation enforces binding rules programmatically |
| R15 - Open/Closed | MD5 of inputs matches MD5 of BSP output across all runs |

## Cross-Cutting Concerns

### Security

Embedded operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Embedded emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Embedded instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Embedded declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/0000-Master-Architecture-Plan.md | Master Architecture Plan â€” device support in AIOS context |
| Bible/07-Domains/Embedded/000-Overview.md | Base Embedded domain overview |
| Bible/07-Domains/Embedded/002-Firmware.md | Firmware generation downstream consumer of device data |
| Bible/07-Domains/Embedded/003-Constraints.md | Resource constraint analysis depends on device profiles |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” device discovery event transport |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” hardware probe adapter interface |
