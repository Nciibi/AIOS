# Integration, Attack, Chaos, and Benchmarking Plan (Sections 5-8)

This plan outlines the final testing phase for the AIOS security architecture. Now that unit tests and property tests are passing for individual crates, we will build a unified pipeline to test how `aios_context_resolver`, `aios_policy`, and `aios_execution` interact together under normal operations, attack simulations, and chaotic failures. We will also introduce performance benchmarks.

## User Review Required

> [!IMPORTANT]
> To test the entire pipeline end-to-end without creating circular dependencies, I propose creating a new top-level workspace crate specifically for integration tests: `aios_integration_tests`. This is a standard Rust practice for multi-crate workspaces. Let me know if you prefer this or if we should squeeze these tests inside the `aios_execution` crate.

## Proposed Changes

---

### Integration Test Crate

This new crate will house the cross-layer tests. It will use a unified `TestPipeline` mock harness.

#### [NEW] [aios_integration_tests/Cargo.toml](file:///c:/Users/ncibi/Desktop/aios/aios_integration_tests/Cargo.toml)
- Define the new crate and add it to the workspace root `Cargo.toml`.
- Add dependencies for `tokio`, `uuid`, and our core crates (`aios_core`, `aios_context_resolver`, `aios_policy`, `aios_execution`).

#### [NEW] [aios_integration_tests/tests/common.rs](file:///c:/Users/ncibi/Desktop/aios/aios_integration_tests/tests/common.rs)
- Implement `TestPipeline`: A harness that strings together `DefaultContextResolver -> DefaultPolicyEvaluator -> DefaultExecutor`.
- Embed `MockSandbox` and `MockAuditLog` specifically designed to throw errors during chaos testing.

#### [NEW] [aios_integration_tests/tests/pipeline_tests.rs](file:///c:/Users/ncibi/Desktop/aios/aios_integration_tests/tests/pipeline_tests.rs)
- Implements **Section 5 (Cross-Layer Integration)**.
- Validates low-risk queries succeeding end-to-end and critical resource deletions being blocked securely.

#### [NEW] [aios_integration_tests/tests/attack_simulation.rs](file:///c:/Users/ncibi/Desktop/aios/aios_integration_tests/tests/attack_simulation.rs)
- Implements **Section 6 (Attack Simulation)**.
- Integrates the 500+ path traversal corpus strings, ensuring no bypasses reach the executor.
- Connects the LLM prompt injection corpus to ensure the scanner rejects them correctly.

#### [NEW] [aios_integration_tests/tests/chaos_tests.rs](file:///c:/Users/ncibi/Desktop/aios/aios_integration_tests/tests/chaos_tests.rs)
- Implements **Section 7 (Chaos Tests)**.
- Simulates Audit sink unreachability, context resolver crashes, and random executor panics to verify fail-closed architecture blockages.

---

### Context Resolver

We will implement the performance assertions defined in the guide using the `criterion` benchmarking framework.

#### [MODIFY] [aios_context_resolver/Cargo.toml](file:///c:/Users/ncibi/Desktop/aios/aios_context_resolver/Cargo.toml)
- Add `criterion = "0.5"` to `[dev-dependencies]`.
- Add the `[[bench]]` configuration to register `resolver_bench`.

#### [NEW] [aios_context_resolver/benches/resolver_bench.rs](file:///c:/Users/ncibi/Desktop/aios/aios_context_resolver/benches/resolver_bench.rs)
- Implements **Section 8 (Performance Benchmarks)**.
- Adds micro-benchmarks for `validate_raw_path_string`, `injection_scan`, and full resolution path, explicitly enforcing the p50 < 500μs requirements.

## Open Questions

- We need a minimal "MockSandbox" for the `TestPipeline`. Should I migrate the one I built in `executor_tests.rs` into a shared utilities crate, or simply copy it to `aios_integration_tests/tests/common.rs` for isolation? (I recommend copying/adapting it for isolation).

## Verification Plan

### Automated Tests
- `cargo test -p aios_integration_tests`
- `cargo bench -p aios-context-resolver`
- Ensure 0 failed runs under attack simulations.
