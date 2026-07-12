# AIOS Bible â€” Domains
## Embedded â€” 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-EMB-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Embedded domain enables AIOS to develop, compile, flash, test, and monitor firmware and software for embedded systems â€” microcontrollers, RTOS-based devices, IoT endpoints, and system-on-chip (SoC) platforms. It provides the capability set for bare-metal and RTOS development, hardware abstraction layer (HAL) generation, peripheral configuration, and resource-constrained optimization.

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
| Flash Memory | 16 KB â€“ 2 MB | Code size must be optimized; dead code elimination required |
| RAM | 2 KB â€“ 512 KB | Stack and heap are tightly bounded; dynamic allocation discouraged |
| Clock Speed | 8 MHz â€“ 400 MHz | Algorithm choice affects timing; real-time guarantees needed |
| Power Budget | ÂµW â€“ mW | Sleep modes, clock gating, and duty cycling may be required |
| Peripheral Count | 2â€“50 | Driver generation must match exact hardware configuration |
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
9. If hardware available â†’ flash and HIL test
10. If hardware unavailable â†’ simulation testing
11. DTS confidence evaluation
12. Firmware artifact signed and published
13. Academy indexes new board-support knowledge
```

## Invariants

1. **EMB-I-001 â€” Target-Bounded**: A FirmwareWorker may only generate code for MCU targets that are registered and verified in its Genome. Cross-target code generation is prohibited.

2. **EMB-I-002 â€” Toolchain Verified**: Every cross-compilation uses a pinned, verified toolchain. Toolchains are cryptographically hashed and compared against known-good hashes before use.

3. **EMB-I-003 â€” Resource-Constrained Design**: Generated firmware must not exceed the target device's flash and RAM bounds. Violations cause build failure.

4. **EMB-I-004 â€” Hardware Safety**: Hardware-in-the-loop tests require physical safety verification before execution. High-power or hazardous hardware tests require Security Council authorization.

5. **EMB-I-005 â€” Deterministic Build**: Same source, toolchain, and configuration always produces identical binary output. Build reproducibility is verified by checksum.

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Toolchain not available for target MCU | Build fails with toolchain-not-found error. Academy queried for alternative toolchain. |
| Generated firmware exceeds flash budget | Optimize-for-size flag applied. If still exceeding, refactoring plan generated. |
| Hardware probe finds unexpected MCU revision | Probe data captured as knowledge artifact. Firmware parameters adjusted for detected revision. |
| Flash programming fails mid-write | Device may be in unknown state. Recovery procedure: re-flash with verified binary. |
| HIL test fixture unavailable | Test queued. If fixture remains unavailable for TTL, test is skipped with warning and simulation results used. |

## Events

| EMB.EventType |      Produced When | Fields |
|-----------|--------------|--------|
| EMB.FirmwareGenerated |      Firmware source is generated | worker_id, target_mcu, platform, lines_of_code, hal_version |
| EMB.CrossCompileCompleted |      Cross-compilation finishes | build_id, target_arch, outcome, binary_size, ram_estimate, flash_estimate |
| EMB.HardwareProbed |      Hardware is detected and probed | board_id, mcu_type, revision, peripherals_found, firmware_version |
| EMB.FlashCompleted |      Firmware is flashed to device | flash_id, target_device, protocol, duration, verification_status |
| EMB.HILTestCompleted |      Hardware-in-the-loop test run finishes | test_id, test_suite, passed, failed, signal_quality, duration_ms |
| EMB.ResourceReportGenerated |      Resource utilization report is produced | report_id, flash_usage, ram_usage, stack_depth, power_estimate, mips_estimate |


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

Firmware Workers operate in sandboxed build environments. Cross-compilation toolchains are verified and pinned to known-good versions. Flashed firmware is cryptographically signed. Hardware test fixtures are access-controlled per Organization. No embedded operation may alter hardware beyond its defined capability scope. (Physics/008-Security.md)

### Evidence

Every embedded operation produces an Event â€” code generation, compilation, flashing, testing. Build artifacts are stored with their source Event chain. Hardware probe results are recorded for audit and reproducibility. (PHI-008)

### Lifecycle

Firmware Workers follow the canonical lifecycle. Hardware sessions are ephemeral â€” created for a test session and destroyed. Board-support knowledge follows the Academy knowledge lifecycle. Firmware releases follow versioning per Foundations/009-Versioning.md. (Physics/006-Lifecycles.md)

### Capability Bounds

Embedded capabilities are bounded by the available toolchains, hardware targets, and resource budgets. A FirmwareWorker cannot target an MCU for which no toolchain is registered. Cross-compilation is bounded by compute resource allocation. Hardware-in-the-loop testing requires physical device availability. (Physics/007-Capabilities.md)

### Communication

All Embedded domain communication flows through ACF. Hardware test fixtures communicate through serial adapters abstracted as resource providers. Flash operations use provider-specific protocols abstracted through the Provider SDK. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each embedded capability (firmware, cross-compile, HIL, analysis) is a separate concern |
| R5 (Liskov) | All toolchain adapters implement the CrossCompiler interface |
| R9 (Deterministic) | Same source and toolchain version produces identical binaries |
| R10 (Simpler Over Complex) | Firmware uses linear build pipelines â€” no branching complexity |
| R13 (Design for Failure) | HIL test failures preserve partial results; build failures return complete logs |
| R14 (Paved Path) | Paved path: generate â†’ cross-compile â†’ test â†’ flash â†’ verify |

## Component Map

| Component | Document | Function |
|-----------|----------|----------|
| Firmware Generator | Embedded/001-Firmware.md | HAL and application code generation for embedded targets |
| Cross-Compiler Manager | Embedded/002-Compiler.md | Toolchain management, multi-arch compilation, linker scripts |
| Hardware Interface Layer | Embedded/003-Hardware.md | Probe, flash, debug, and monitor hardware targets |
| Board Support Registry | Embedded/004-Boards.md | Board definitions, pin mappings, peripheral configurations |

## Performance Characteristics

| Metric | Target | Hard Limit |
|--------|--------|------------|
| Firmware generation (simple peripheral) | < 10 seconds | 30 seconds |
| Firmware generation (full application) | < 60 seconds | 5 minutes |
| Cross-compilation (small MCU) | < 30 seconds | 2 minutes |
| Cross-compilation (large MCU) | < 5 minutes | 15 minutes |
| Flash firmware (JTAG/SWD) | < 10 seconds | 30 seconds |
| HIL test execution | < 2 minutes | 10 minutes |
| Resource analysis report | < 10 seconds | 30 seconds |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture â€” Embedded domain structure |
| Physics/005-Events.md | Evidence â€” Embedded operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” Embedded capability bounds and resource profiles |
| Physics/010-Execution.md | Execution â€” Embedded build pipeline execution model |
| Bible/02-Core/Sou/002-Planner.md | Planner â€” Sou produces firmware development plans |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” FirmwareWorker and BuildCross Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” Board-support knowledge management |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” Firmware quality confidence scoring |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” Compute and storage budget for cross-compilation |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” Communication for hardware adapter control |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK â€” Hardware adapter provider interface |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
