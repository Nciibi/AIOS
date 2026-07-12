# AIOS Bible — Domains
## Embedded — 001: Devices

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-EMB-001 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
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

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| Embedded.DeviceRegistered | A new device is added to the registry | deviceId, boardId, registeredAt, registeredBy |
| Embedded.MCUDetected | An MCU is detected and profile-matched | profileId, method, confidence, detectedAt |
| Embedded.BSPGenerated | A board support package is generated | boardId, artifactCount, generationDuration |
| Embedded.PinConflictDetected | A pin assignment conflict is found | pin, conflictCount, peripheralList |
| Embedded.DeviceTreeCompiled | Device tree compilation completes | boardId, nodeCount, validationStatus |
| Embedded.PeripheralMismatch | A peripheral type mismatch is detected | peripheral, expected, actual, severity |
| Embedded.BSPCacheHit | BSP is retrieved from cache instead of regenerated | boardId, cacheAge, cacheKey |

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

## Design DNA (R1-R6,R9,R10,R13-R15)

| Rule | Application |
|------|-------------|
| R1 — Target Bounded | All device generation is bounded to the target MCU profile; no generic defaults |
| R2 — Interchangeable Architecture | Board definitions can be swapped without changing application logic |
| R3 — Generic Operations | Device detection and BSP generation follow the same pipeline for all families |
| R4 — Composition over Inheritance | Peripheral configs are composed into board definitions rather than subclassed |
| R5 — Stable Intermediate Representation | DeviceTree is the canonical IR passed between stages |
| R6 — Temporal Synchronization | Events fire after each stage completes; downstream stages await their prerequisites |
| R9 — Stateless Verification | Pin verification produces the same result for the same board definition every time |
| R10 — Capability-Based Routing | BSP generation adapts based on available flash, RAM, and peripheral resources |
| R13 — Event-Driven Consistency | PinConflictDetected events trigger automatic reassignment workflows |
| R14 — Code as Law | Device tree compilation enforces binding rules programmatically |
| R15 — Provably Deterministic | MD5 of inputs matches MD5 of BSP output across all runs |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/0000-Master-Architecture-Plan.md | Master Architecture Plan — device support in AIOS context |
| Bible/07-Domains/Embedded/000-Overview.md | Base Embedded domain overview |
| Bible/07-Domains/Embedded/002-Firmware.md | Firmware generation downstream consumer of device data |
| Bible/07-Domains/Embedded/003-Constraints.md | Resource constraint analysis depends on device profiles |
| Bible/06-Services/ACF/000-Overview.md | ACF — device discovery event transport |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK — hardware probe adapter interface |
