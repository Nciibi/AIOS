# AIOS Bible — Domains
## Embedded — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-EMB-000 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Embedded domain enables AIOS to develop, compile, flash, test, and monitor firmware and software for embedded systems — microcontrollers, RTOS-based devices, IoT endpoints, and system-on-chip (SoC) platforms. It provides the capability set for bare-metal and RTOS development, hardware abstraction layer (HAL) generation, peripheral configuration, and resource-constrained optimization.

Embedded development differs fundamentally from application-level coding: resources are severely constrained (KB of RAM, MHz of clock), cross-compilation toolchains are required, hardware-in-the-loop testing is often necessary, and the impact of bugs can be physical (bricked devices, safety hazards). The Embedded domain accounts for these constraints in its capability profiles and safety protocols.

## Domain Entities

The Embedded domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| FirmwareWorker | A Worker specialized for embedded firmware development | AGS: Embedded/FirmwareWorker |
| HardwareTester | A Worker that interfaces with hardware test fixtures | AGS: Embedded/HardwareTester |
| BuildCross | A cross-compilation sandbox for target architectures | AGS: Embedded/BuildCross |
| BoardSupport | A knowledge artifact for a specific board or MCU | Academy: Knowledge |

## Capabilities

The Embedded domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Firmware Development | `write_hal`, `configure_peripheral`, `manage_interrupts`, `optimize_memory` | Medium token, low compute |
| Cross-Compilation | `compile_arm`, `compile_riscv`, `compile_xtensa`, `link_libraries` | Low token, high compute (per compile) |
| Hardware Interface | `flash_device`, `read_register`, `probe_pins`, `monitor_serial` | Low token, low compute (I/O bound) |
| Resource Analysis | `analyze_ram_usage`, `estimate_power`, `compute_flash_footprint` | Low token, medium compute |
| RTOS Configuration | `configure_scheduler`, `manage_tasks`, `set_up_ipc`, `tune_latency` | Medium token, low compute |
| Testing | `run_hil_test`, `simulate_input`, `log_analysis`, `scope_decode` | Low token, high I/O |

## Embedded-Specific Constraints

The Embedded domain operates under constraints not present in other domains:

| Constraint | Typical Range | Impact on Capabilities |
|------------|--------------|----------------------|
| Flash Memory | 16 KB – 2 MB | Code size must be optimized; dead code elimination required |
| RAM | 2 KB – 512 KB | Stack and heap are tightly bounded; dynamic allocation discouraged |
| Clock Speed | 8 MHz – 400 MHz | Algorithm choice affects timing; real-time guarantees needed |
| Power Budget | µW – mW | Sleep modes, clock gating, and duty cycling may be required |
| Peripheral Count | 2–50 | Driver generation must match exact hardware configuration |
| Toolchain Diversity | ARM GCC, RISC-V GCC, IAR, Keil | Multiple compiler backends with different optimizations |

## Development Flow

Embedded development in AIOS follows this workflow:

```
1. Requirements received (board, peripherals, firmware features)
2. Sou Planner decomposes into firmware plan
3. Board-support knowledge retrieved from Academy
4. FirmwareWorker instantiated with appropriate toolchain
5. HAL and driver code generated
6. Application logic generated
7. Cross-compilation in BuildCross sandbox
8. Static analysis (stack depth, memory bounds, timing)
9. If hardware available → flash and HIL test
10. If hardware unavailable → simulation testing
11. DTS confidence evaluation
12. Firmware artifact signed and published
13. Academy indexes new board-support knowledge
```

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Embedded.FirmwareGenerated` | Firmware source is generated | worker_id, target_mcu, platform, lines_of_code |
| `Embedded.CrossCompileCompleted` | Cross-compilation finishes | build_id, target_arch, outcome, binary_size, ram_estimate |
| `Embedded.HardwareProbed` | Hardware is detected and probed | board_id, mcu_type, peripherals_found, firmware_version |
| `Embedded.FlashCompleted` | Firmware is flashed to device | flash_id, target_device, protocol, duration |
| `Embedded.HILTestCompleted` | Hardware-in-the-loop test run finishes | test_id, test_suite, passed, failed, signal_quality |
| `Embedded.ResourceReportGenerated` | Resource utilization report is produced | report_id, flash_usage, ram_usage, stack_depth, power_estimate |

## Cross-Cutting Concerns

### Security

Firmware Workers operate in sandboxed build environments. Cross-compilation toolchains are verified and pinned to known-good versions. Flashed firmware is cryptographically signed. Hardware test fixtures are access-controlled per Organization. No embedded operation may alter hardware beyond its defined capability scope. (Physics/008-Security.md)

### Evidence

Every embedded operation produces an Event — code generation, compilation, flashing, testing. Build artifacts are stored with their source Event chain. Hardware probe results are recorded for audit and reproducibility. (PHI-008)

### Lifecycle

Firmware Workers follow the canonical lifecycle. Hardware sessions are ephemeral — created for a test session and destroyed. Board-support knowledge follows the Academy knowledge lifecycle. Firmware releases follow versioning per Foundations/009-Versioning.md. (Physics/006-Lifecycles.md)

### Capability Bounds

Embedded capabilities are bounded by the available toolchains, hardware targets, and resource budgets. A FirmwareWorker cannot target an MCU for which no toolchain is registered. Cross-compilation is bounded by compute resource allocation. Hardware-in-the-loop testing requires physical device availability. (Physics/007-Capabilities.md)

### Communication

All Embedded domain communication flows through ACF. Hardware test fixtures communicate through serial adapters abstracted as resource providers. Flash operations use provider-specific protocols abstracted through the Provider SDK. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each embedded capability (firmware, cross-compile, HIL, analysis) is a separate concern |
| R5 (Liskov) | All toolchain adapters implement the CrossCompiler interface |
| R9 (Deterministic) | Same source and toolchain version produces identical binaries |
| R10 (Simpler Over Complex) | Firmware uses linear build pipelines — no branching complexity |
| R13 (Design for Failure) | HIL test failures preserve partial results; build failures return complete logs |
| R14 (Paved Path) | Paved path: generate → cross-compile → test → flash → verify |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — Embedded domain structure |
| Physics/005-Events.md | Evidence — Embedded operations produce Events |
| Physics/007-Capabilities.md | Capabilities — Embedded capability bounds and resource profiles |
| Physics/010-Execution.md | Execution — Embedded build pipeline execution model |
| Bible/02-Core/Sou/002-Planner.md | Planner — Sou produces firmware development plans |
| Bible/02-Core/AGS/000-Overview.md | AGS — FirmwareWorker and BuildCross Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — Board-support knowledge management |
| Bible/02-Core/ROS/000-Overview.md | ROS — Compute and storage budget for cross-compilation |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK — Hardware adapter provider interface |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
