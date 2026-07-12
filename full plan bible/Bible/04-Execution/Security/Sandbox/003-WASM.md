# AIOS Bible — Sandbox (SAN)
## 003 — WebAssembly Sandbox

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-003 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

WebAssembly sandbox provides lightweight, capability-based isolation for plugin execution and policy evaluation within AIOS. Unlike operating system sandboxes that enforce boundaries via kernel mechanisms (syscall filtering, namespaces), WebAssembly enforces isolation at the module boundary — WASM modules execute in a sandboxed virtual machine with no direct access to host resources unless explicitly granted through imported functions.

WASM serves three primary roles: plugin execution where third-party code runs with fine-grained capability grants, policy evaluation where untrusted policy expressions are executed without OS sandbox overhead, and high-frequency low-latency Workers where MicroVM or container startup costs are prohibitive. WASM sandboxes achieve sub-millisecond startup and deterministic resource accounting.

## Architecture

WebAssembly modules are loaded and instantiated by a WASM runtime (Wasmtime or WAMR) embedded in the Sandbox service. Each module declares its imports explicitly — the runtime provides only those imports that correspond to the Worker's granted capabilities. Memory, CPU, and instance counts are bounded at instantiation time, and host functions are wrapped with capability checks.

```
Module Load → Compile → Cache → Instantiate → Execute → Unload
```

### WASM Runtime Integration

| Runtime | Role | Characteristics |
|---------|------|-----------------|
| Wasmtime | Primary runtime | Cranelift compiler, WASI preview 2, component model support |
| WAMR | Embedded/fallback | Interpreter + fast JIT, smaller footprint, embedded device support |

### Module Loading and Instantiation

| Phase | Description | Resource Accounting |
|-------|-------------|-------------------|
| Load | Module bytes read from store (file or cache) | Bytes loaded |
| Compile | Module compiled to native code (Cranelift JIT) | CPU time, memory for compiled code |
| Cache | Compiled module stored in ModuleCache | Cache storage bytes |
| Instantiate | Module instantiated with import resolver | Memory for linear memory, instance struct |
| Execute | Module functions called via runtime API | CPU time, memory operations |

## Data Model

```typescript
interface WasmModule {
  id: string;
  name: string;
  version: string;
  sha256: string;
  bytes: Uint8Array;
  compiled: CompiledModule;
  imports: ImportDeclaration[];
  exports: ExportDeclaration[];
  metadata: ModuleMetadata;
}

interface ImportDeclaration {
  module: string;
  field: string;
  type: ImportType;                 // "function" | "memory" | "table" | "global"
  signature?: FunctionSignature;
  requiredCapability?: string;      // Capability key required to satisfy this import
}

interface ExportDeclaration {
  name: string;
  type: ExportType;
  signature?: FunctionSignature;
}

interface FunctionSignature {
  params: ValueType[];
  results: ValueType[];
}

type ValueType = "i32" | "i64" | "f32" | "f64" | "externref" | "funcref";

interface ModuleMetadata {
  source: "file" | "store" | "stream";
  language: string;                 // Source language (Rust, C, TinyGo, etc.)
  wasiVersion: string;             // "preview1" | "preview2"
  componentModel: boolean;
  entryPoint: string;               // Export name to call on execute
}

interface CompiledModule {
  bytes: Uint8Array;
  compilationTimeMs: number;
  compilationMemoryBytes: number;
  codeSizeBytes: number;
}

interface WasmInstance {
  id: string;
  moduleId: string;
  sandboxId: string;
  state: InstanceState;            // "created" | "instantiated" | "running" | "trapped" | "destroyed"
  linearMemory: MemoryInfo;
  capabilities: CapabilityGrant[];
  resourceUsage: InstanceResourceUsage;
  createdAt: string;
  destroyedAt?: string;
}

type InstanceState = "created" | "instantiated" | "running" | "trapped" | "destroyed";

interface MemoryInfo {
  initialPages: number;             // Initial linear memory size (64KB per page)
  maximumPages: number;             // Maximum linear memory size
  currentPages: number;             // Currently allocated pages
  peakPages: number;                // Peak allocated pages
}

interface InstanceResourceUsage {
  cpuCycles: bigint;                // Accumulated CPU cycles
  memoryBytes: number;              // Current memory allocation
  peakMemoryBytes: number;          // Peak memory allocation
  hostFunctionCalls: number;        // Count of host function invocations
  totalHostFunctionCalls: number;   // Lifetime count
  executionTimeNs: bigint;          // Accumulated execution time
}

interface ModuleConfig {
  maxMemoryPages: number;           // Memory limit per instance (default: 256 = 16MB)
  maxTableSize: number;             // Table size limit (default: 1024)
  maxInstances: number;             // Max concurrent instances of this module
  maxCPUPerInstance: number;        // CPU time limit per call (ns, default: 10^9)
  maxTotalCPUPerSecond: number;     // Total CPU per second across all instances
  allowWasi: boolean;               // Enable WASI preview 2
  allowComponentModel: boolean;     // Enable component model
  cacheEnabled: boolean;            // Enable module caching
  fuelEnabled: boolean;             // Enable fuel-based metering
  fuelPerInstruction: number;       // Fuel cost per WASM instruction
  initialFuel: number;              // Initial fuel per instance call
}

interface ImportResolver {
  module: string;
  imports: HostFunction[];
  capabilities: string[];           // Capabilities required to use this resolver
}

interface HostFunction {
  name: string;
  callback: Function;
  capabilityCheck: (grant: CapabilityGrant) => boolean;
  auditLog: boolean;                // Log every call to EAS
}

interface CapabilityGrant {
  capability: string;               // e.g., "fs.read.self"
  scope: string;                    // e.g., "/workspace/worker-123"
  constraints: CapabilityConstraint[];
  expiresAt?: string;               // TTL for time-limited grants
}

interface CapabilityConstraint {
  type: "rate" | "quota" | "scope" | "time";
  value: string;
}

interface ModuleCache {
  maxEntries: number;
  maxSizeBytes: number;
  ttlMs: number;                    // Time-to-live for cached entries
  entries: Map<string, CacheEntry>;
  stats: CacheStats;
}

interface CacheEntry {
  moduleId: string;
  compiled: CompiledModule;
  cachedAt: string;
  accessCount: number;
  lastAccessed: string;
  sizeBytes: number;
}

interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  totalSizeBytes: number;
  hitRate: number;
}
```

## Core Concepts / Operations

### Capability-Based Security Model

The WASM sandbox uses a capability-based security model derived from WASI preview 2's component model. Each WASM module declares its required capabilities as imports. The resolver satisfies only those imports that correspond to the Worker's granted capabilities:

| WASI Import | Capability Required | Description |
|-------------|---------------------|-------------|
| `wasi:io/streams` | `fs.read.self` | Read from input streams |
| `wasi:filesystem/types` | `fs.read.self` | File system type operations |
| `wasi:filesystem/directory` | `fs.write.self` | Directory listing |
| `wasi:http/handler` | `network.egress.api` | HTTP request/response handling |
| `wasi:random/random` | `env.random` | Cryptographically secure random |
| `wasi:cli/environment` | `env.variables` | Environment variable access |
| `wasi:cli/exit` | `sys.exit` | Process exit |

### Import Resolution

The ImportResolver maps WASM module imports to host functions. Each host function carries a capability check that runs before execution:

1. Module declares import: `(import "wasi:filesystem" "read-file")`
2. Resolver looks up the import in its registry: `{module: "wasi:filesystem", field: "read-file"}`
3. Resolver checks the Worker's capability grants: does the Worker have `fs.read.self`?
4. If granted: resolver provides the host function wrapper with capability scope applied.
5. If denied: instantiation fails with a CapabilityDenied error.

### Module Cache

The ModuleCache stores compiled WASM modules to avoid recompilation on repeated instantiation:

| Operation | Cache Hit | Cache Miss |
|-----------|-----------|------------|
| Module load | Return cached compiled module | Compile module, store in cache |
| Memory management | No allocation | Allocate compiled code memory |
| Typical latency | <10µs | <10ms (Cranelift JIT) |

Cache eviction follows LRU with TTL expiry. Modules with high access counts are promoted to permanent cache entries.

### Resource Limits

| Resource | Limit Field | Enforcement | Violation Action |
|----------|-------------|-------------|------------------|
| Memory pages | `maxMemoryPages` | Runtime memory limit per instance | Trap on memory.grow beyond limit |
| CPU cycles | `maxCPUPerInstance` | Fuel metering (instructions executed) | Trap when fuel exhausted |
| Instance count | `maxInstances` | Instance pool tracking | Deny instantiation |
| Table size | `maxTableSize` | Table growth limit | Trap on table.grow beyond limit |
| Call depth | Runtime default | Stack overflow detection | Trap on call stack overflow |
| Execution time | `maxCPUPerInstance` | Wall-clock timeout | Trap on timeout expiry |

### Plugin Lifecycle

```
Load → Compile → Cache → Instantiate → Execute → Unload
```

| Phase | Operation | Resource Check |
|-------|-----------|----------------|
| Load | Read module bytes from file/store | File size limit (default: 10MB compiled, 50MB raw) |
| Compile | Cranelift JIT compilation | Compilation CPU time (default: 500ms limit) |
| Cache | Store compiled module in ModuleCache | Cache size limit (default: 256MB) |
| Instantiate | Create instance with import resolver | Instance count check against maxInstances |
| Execute | Call exported function | Fuel check before each instruction |
| Unload | Drop instance, release memory | Resource accounting snapshot for EAS |

### Host Function Sandboxing

Host functions are the bridge between WASM and the host system. They are sandboxed at three levels:

| Level | Check | Implementation |
|-------|-------|---------------|
| Capability | Does the Worker have the required capability? | CapabilityGrant check before function execution |
| Scope | Does the operation target an allowed resource? | Path prefix check for filesystem, URL allowlist for network |
| Rate | Is the Worker within rate limits? | Token bucket rate limiter per host function |

### Instance Pool Management

A pool of pre-instantiated WASM instances is maintained for low-latency Worker startup:

| Pool Type | Size | Refresh Strategy |
|-----------|------|------------------|
| Hot pool | 10–50 instances per active module | Maintained at configured minimum; replenished on consumption |
| Warm pool | 50–200 compiled modules | Compiled modules ready for instantiation; no pre-running instances |
| Cold | All cached modules | Compiled and cached; instantiated on demand |

### WASI Preview 2 Component Model

The component model allows composable WASM modules with shared-nothing linking:

| Feature | Benefit | Security Implication |
|---------|---------|---------------------|
| Component-level imports | Explicit dependency declaration | Every dependency is audited and capability-gated |
| Shared-nothing linking | No shared linear memory between components | Isolation between plugin components |
| Interface types | Automatic serialization/deserialization at boundaries | Data validation at component boundaries |
| Asynchronous calls | Non-blocking component interactions | Prevents blocking host function DoS |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| Runtime API | Wasmtime/WAMR | Sandbox Service | FFI (C API) |
| Import Resolver | Sandbox Service | WASM Instance | Host function registration |
| Module Cache | Sandbox Service | WASM Runtime | In-memory key-value store |
| Capability Store | AZS Capability Service | Import Resolver | Internal gRPC |
| Fuel Meter | WASM Runtime | Instance | Instruction-level accounting |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.WASM.ModuleLoaded` | Module bytes loaded from store | module_id, name, version, size_bytes, source |
| `SAN.WASM.ModuleCached` | Module compiled and cached | module_id, compilation_time_ms, code_size_bytes, cache_key |
| `SAN.WASM.InstanceCreated` | Module instance created | instance_id, module_id, capability_grants[], initial_memory_pages |
| `SAN.WASM.InstanceDestroyed` | Instance destroyed | instance_id, module_id, cpu_cycles, peak_memory_bytes, host_function_calls |
| `SAN.WASM.CapabilityDenied` | Import resolution denied due to missing capability | module_id, instance_id, import_module, import_field, missing_capability |
| `SAN.WASM.MemoryLimitExceeded` | Instance exceeded memory limit | instance_id, module_id, requested_pages, max_pages, current_pages |
| `SAN.WASM.CPULimitExceeded` | Instance fuel exhausted | instance_id, module_id, fuel_consumed, max_fuel, execution_time_ns |
| `SAN.WASM.HostFunctionCalled` | Host function invoked | instance_id, host_function, capability_grant, duration_ns, audit_log_payload |
| `SAN.WASM.TrapEncountered` | WASM trap (runtime error) | instance_id, module_id, trap_code, instruction_offset, call_stack |
| `SAN.WASM.InstancePoolExhausted` | Instance pool exhausted, new instances may be delayed | module_id, hot_pool_size, warm_pool_size, current_load, queue_depth |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SAN_WASM_001 | Module validation failure: module bytes fail WASM spec validation | Medium | Reject module; log validation errors for developer feedback |
| SAN_WASM_002 | Import resolution failure: required capability not granted or import not found | High | Fail instantiation; report missing capability to caller with resolution hint |
| SAN_WASM_003 | Fuel exhaustion: CPU limit exceeded during execution | Medium | Trap execution; return partial results if available; log overage |
| SAN_WASM_004 | Memory allocation failure: linear memory growth beyond configured limit | High | Trap on memory.grow; log allocation attempt with requested size |
| SAN_WASM_005 | Instance pool exhausted: maximum instances reached for the module | Medium | Block instantiation; wait for pool replenishment; surface queue depth to scheduler |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SAN-WASM-001 | Every WASM instance must be initialized with exactly the imports declared in its module — no additional imports, no missing imports | Runtime validates import resolution completeness before instantiation |
| SAN-WASM-002 | No WASM instance may access host memory outside its allocated linear memory | WASM runtime enforces memory bounds on every load/store instruction |
| SAN-WASM-003 | Every host function call must pass a capability check before execution | ImportResolver wraps each host function with capability grant validation |
| SAN-WASM-004 | Fuel metering must account for every executed WASM instruction — fuel exhaustion always traps | Runtime injects fuel accounting at the basic block or instruction level |
| SAN-WASM-005 | Cached compiled modules must be invalidated when the source module changes (SHA-256 mismatch) | ModuleCache checks SHA-256 of incoming module against cached entry before reuse |

## Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | WASM sandbox does one thing: lightweight capability-isolated module execution |
| R2 — Dependency Order | Compliant | WASM sandbox depends on Wasmtime/WAMR runtime; Sandbox Service depends on WASM driver |
| R3 — DRY | Compliant | Module templates and capability grant sets defined once per plugin type |
| R4 — Builder Pattern | Compliant | WasmInstance constructed by InstanceBuilder with validated import resolver |
| R5 — Liskov Substitution | Compliant | WASM sandbox conforms to SandboxDriver interface (load, instantiate, execute, unload) |
| R6 — DI over Singletons | Compliant | WASM runtime driver injected into SandboxService via runtime abstraction |
| R7 — Tests Exist | Compliant | Unit tests for import resolution, fuel metering, capability checks; integration tests with Wasmtime |
| R8 — Tests Fast | Compliant | Unit tests complete in <1ms; integration suite <5s with module cache pre-warmed |
| R9 — Deterministic Tests | Compliant | Same module + same capability grants always produces identical execution behavior |
| R10 — Prefer Simpler | Compliant | Five lifecycle phases; capability model maps directly to WASM import model |
| R11 — Refactor over Rewrite | Compliant | Capability model updates through import resolver changes, not runtime modification |
| R12 — Embrace Errors | Compliant | Every error identifies the module, instance, instruction, and capability context |
| R13 — Design for Failure | Compliant | Instance trap does not affect runtime; other instances continue unaffected |
| R14 — Paved Path | Compliant | All plugin Workers execute through the paved load→instantiate→execute→unload path |
| R15 — Open/Closed | Compliant | New capabilities added via ImportResolver registrations, not core sandbox changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Isolation.md | Base sandbox architecture; WASM is the lightweight sandbox driver |
| 004-Seccomp.md | Seccomp profiles applied to WASM runtime process for self-isolation |
| 001-Firecracker.md | Alternative sandbox driver for high-isolation tiers (complementary to WASM) |
| 002-gVisor.md | Alternative sandbox driver for container workloads (complementary to WASM) |
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; WASM sandbox enforces at capability import boundary |
| ../AZS/002-Capability.md | Capability grants derived from capability bounds; WASM imports mapped to capabilities |
| ../Audit/000-EAS.md | Module load/instantiate/host-call events recorded by EAS |
| Physics/007-Capabilities.md | Capability Bound invariants enforced by import resolution and capability checks |
| Physics/008-Security.md | Capability-based isolation satisfies security verification for plugin execution |
| Physics/010-Execution.md | WASM lifecycle conforms to execution tenure invariants |
