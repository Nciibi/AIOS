# AIOS Bible — Domains
## FPGA — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-FPGA-000 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The FPGA domain enables AIOS to design, simulate, synthesize, place-and-route, and verify digital logic for Field-Programmable Gate Arrays. It provides the capability set for hardware description language (HDL) development — VHDL, Verilog, SystemVerilog — as well as high-level synthesis (HLS), timing closure, and bitstream generation.

FPGA development sits at the intersection of software and hardware engineering. Unlike software domains where the output is executable code, FPGA output is a hardware configuration bitstream that implements digital circuits. The design flow involves synthesis, mapping, placement, routing, and timing analysis — each step with its own toolchain, constraints, and failure modes.

## Domain Entities

The FPGA domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| HDLWorker | A Worker specialized for HDL design and RTL development | AGS: FPGA/HDLWorker |
| SynthesisWorker | A Worker that manages synthesis, P&R, and bitstream generation | AGS: FPGA/SynthesisWorker |
| SimulationWorker | A Worker that runs RTL simulation and waveform analysis | AGS: FPGA/SimulationWorker |
| IPCore | A knowledge artifact for a reusable intellectual property core | Academy: Knowledge |
| BitstreamArtifact | A signed and verified FPGA configuration artifact | Storage: Registered |

## Capabilities

The FPGA domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| RTL Design | `write_hdl`, `design_fsm`, `create_datapath`, `instantiate_ip` | High token, medium compute |
| Simulation | `run_rtl_sim`, `run_gate_sim`, `analyze_waveform`, `check_coverage` | Low token, very high compute |
| Synthesis | `synthesize_design`, `optimize_area`, `optimize_speed`, `infer_rams` | Low token, very high compute |
| Place & Route | `run_placement`, `run_routing`, `optimize_timing`, `manage_congestion` | Low token, very high compute |
| Timing Analysis | `run_sta`, `analyze_paths`, `check_setup_hold`, `generate_constraints` | Low token, high compute |
| Verification | `run_lint`, `run_formal`, `run_assertions`, `bitstream_verify` | Medium token, high compute |
| Device Programming | `flash_bitstream`, `verify_bitstream`, `readback_verify` | Low token, I/O bound |

## FPGA Design Flow

The canonical FPGA design flow within AIOS:

```
1. Requirements received (device family, interfaces, performance targets)
2. Sou Planner decomposes into design plan
3. IP core knowledge retrieved from Academy
4. HDLWorker generates RTL design
5. SimulationWorker runs behavioral simulation
6. If simulation fails → revise RTL
7. SynthesisWorker synthesizes design
8. Place & Route on target device
9. Static Timing Analysis (STA)
10. If timing fails → revise constraints or RTL
11. Formal verification (RTL vs. netlist)
12. Bitstream generation
13. Bitstream verification and signing
14. Device programming (if hardware available)
15. Academy indexes new IP core knowledge
```

## Synthesis and P&R Resource Profiles

FPGA toolchain operations are among the most compute-intensive in AIOS:

| Operation | Typical Duration | Compute Profile | Memory Footprint |
|-----------|-----------------|----------------|-----------------|
| RTL Simulation (small design) | 1–30 seconds | 1–4 cores | 256 MB – 1 GB |
| RTL Simulation (large design) | 1–60 minutes | 4–16 cores | 1–16 GB |
| Synthesis (small design) | 30 seconds – 5 minutes | 2–8 cores | 512 MB – 2 GB |
| Synthesis (large design) | 10–120 minutes | 8–32 cores | 4–32 GB |
| Place & Route (small) | 1–10 minutes | 2–4 cores | 1–4 GB |
| Place & Route (large) | 30 minutes – 12 hours | 8–32 cores | 4–64 GB |
| Static Timing Analysis | 1–30 minutes | 2–8 cores | 1–8 GB |
| Formal Verification | 5–60 minutes | 4–16 cores | 2–16 GB |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `FPGA.RTLGenerated` | HDL code is generated | worker_id, module_name, language, lines, ports |
| `FPGA.SimulationRun` | RTL simulation completes | sim_id, test_name, passed, coverage_pct, duration |
| `FPGA.SynthesisCompleted` | Synthesis finishes | synth_id, device, lut_usage, ff_usage, bram_usage, freq_achieved |
| `FPGA.PlaceRouteCompleted` | P&R finishes | par_id, cell_utilization, wire_length, congestion, duration |
| `FPGA.TimingAnalyzed` | STA completes | sta_id, fmax, setup_slack_worst, hold_slack_worst, violating_paths |
| `FPGA.BitstreamGenerated` | Bitstream is produced | bitstream_id, device, checksum, size_bytes |
| `FPGA.DeviceProgrammed` | FPGA is programmed | program_id, device_id, protocol, verification_status |

## Cross-Cutting Concerns

### Security

HDL Workers operate in sandboxed environments. Synthesis toolchains are verified and pinned to known-good versions. Bitstreams are cryptographically signed before programming. IP cores retrieved from Academy are verified for provenance. Readback verification ensures programmed bitstream integrity. (Physics/008-Security.md)

### Evidence

Every FPGA operation produces an Event — RTL generation, simulation, synthesis, P&R, timing analysis, bitstream generation, and programming. Complete design provenance is maintained from requirements through bitstream. Simulation waveforms and timing reports are stored as evidence artifacts. (PHI-008)

### Lifecycle

HDL Workers and Simulation Workers follow the canonical Worker lifecycle. Synthesis and P&R jobs are batch operations that may run for hours — they follow a job lifecycle (Submitted → Queued → Running → Completed → Archived). IP Cores follow the Academy knowledge lifecycle. (Physics/006-Lifecycles.md)

### Capability Bounds

FPGA capabilities are bounded by available toolchains, target device libraries, and compute resource budgets. A SynthesisWorker may only target devices for which a toolchain is registered. P&R is bounded by runtime limits — designs exceeding the time budget return partial results. (Physics/007-Capabilities.md)

### Communication

All FPGA domain communication flows through ACF. Synthesis and P&R jobs are submitted through batch queues managed via ACF. Device programmers communicate through JTAG or USB adapters abstracted as resource providers. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each FPGA capability (HDL design, simulation, synthesis, P&R, analysis) is separate |
| R5 (Liskov) | All EDA tool adapters implement the SynthesisTool or SimulationTool interface |
| R9 (Deterministic) | Same RTL and toolchain version produces identical synthesis results |
| R10 (Simpler Over Complex) | Design flow is linear with feedback loops — no unbounded iteration |
| R13 (Design for Failure) | Synthesis failures return complete logs; partial P&R results preserved |
| R14 (Paved Path) | Paved path: RTL → simulate → synthesize → P&R → analyze → program |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — FPGA domain structure |
| Physics/005-Events.md | Evidence — FPGA operations produce Events |
| Physics/007-Capabilities.md | Capabilities — FPGA capability bounds and compute profiles |
| Physics/010-Execution.md | Execution — FPGA batch job execution model |
| Bible/02-Core/Sou/002-Planner.md | Planner — Sou produces FPGA design plans |
| Bible/02-Core/AGS/000-Overview.md | AGS — HDLWorker and SynthesisWorker Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — IP core knowledge management |
| Bible/02-Core/ROS/000-Overview.md | ROS — Compute budgets for synthesis and P&R |
| Bible/08-Interfaces/SDK/003-Provider-SDK.md | Provider SDK — EDA tool adapter provider interface |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
