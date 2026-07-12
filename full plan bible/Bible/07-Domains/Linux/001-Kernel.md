# AIOS Bible — Domains
## Linux — 001: Kernel Configuration & Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-LNX-001 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to configure, compile, load, and tune the Linux kernel across a fleet — treating kernel state as a versioned, auditable, and idempotent resource.

## Architecture

Kernel configuration follows a lifecycle: baseline profile is selected → config is generated from fragments → optionally compiled → modules loaded → runtime parameters applied → boot entry updated. The lifecycle is driven by a KernelConfigurator agent that reconciles desired state against live kernel state. Compilation runs in isolated build contexts; artifacts are signed and versioned. Boot entries are managed via bootloader abstraction (GRUB, systemd-boot).

## Data Model (TypeScript interfaces)

```typescript
interface KernelConfig {
  id: string;
  profileName: string;
  configFragments: ConfigFragment[];
  targetVersion: string;
  buildFlags: Record<string, string>;
  artifactHash?: string;
  signKeyId?: string;
  lastApplied: string;
}

interface ConfigFragment {
  path: string;
  content: string;
  enabled: boolean;
  priority: number;
}

interface KernelModule {
  name: string;
  path: string;
  version: string;
  license: string;
  dependencies: string[];
  parameters: Record<string, string>;
  state: 'loaded' | 'unloaded' | 'blacklisted';
}

interface KernelParameter {
  key: string;
  value: string;
  scope: 'runtime' | 'persistent';
  sourceFile?: string;
}

interface BootEntry {
  id: string;
  label: string;
  kernelVersion: string;
  initrdPath?: string;
  cmdline: string;
  default: boolean;
  timeout: number;
}
```

## Core Concepts / Operations

- **configure_kernel(id, profileName, fragments)** — generates kernel .config from profile and overlay fragments
- **compile_kernel(configId, buildFlags)** — compiles kernel source, returns artifact reference with hash
- **load_module(name, parameters)** — inserts kernel module with optional parameters
- **unload_module(name)** — removes kernel module
- **set_sysctl(key, value, scope)** — sets kernel parameter at runtime or writes to sysctl.conf
- **manage_boot_entry(entry)** — creates, updates, or removes a bootloader entry
- **get_kernel_info()** — returns running kernel version, build info, and live parameters

## Internal Interfaces (table)

| Interface | Provider | Consumer | Purpose |
|-----------|----------|----------|---------|
| IKernelConfig | KernelConfigurator | SysAdminWorker | Apply kernel config profiles |
| IBuildExecutor | BuildIsolation | KernelConfigurator | Execute kernel compiles |
| IModuleManager | ModuleHandler | KernelConfigurator | Load/unload kernel modules |
| ISysctlService | SysctlManager | KernelConfigurator | Get/set kernel parameters |
| IBootManager | BootEntryManager | KernelConfigurator | Manage boot entries |

## Events (table)

| Event | Emitter | Payload | Meaning |
|-------|---------|---------|---------|
| Linux.KernelConfigured | KernelConfigurator | { configId, profileName } | Kernel config applied successfully |
| Linux.KernelCompiled | KernelConfigurator | { configId, version, hash } | Kernel compilation completed |
| Linux.KernelCompileFailed | KernelConfigurator | { configId, errorCode, logRef } | Kernel compilation failed |
| Linux.ModuleLoaded | ModuleHandler | { moduleName, version } | Module loaded into kernel |
| Linux.ModuleUnloaded | ModuleHandler | { moduleName } | Module removed from kernel |
| Linux.SysctlApplied | SysctlManager | { key, value, scope } | Kernel parameter changed |
| Linux.BootEntryChanged | BootEntryManager | { entryId, action } | Boot entry created, updated, or removed |

## Error Cases (table with Code, Condition, Severity, Recovery)

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| KRN-001 | Config fragment conflict (same param in two fragments) | Error | Reject and report conflicting fragments |
| KRN-002 | Kernel compilation failure | Error | Return build log, suggest dependency check |
| KRN-003 | Module version incompatible with running kernel | Warning | Block load, suggest rebuild or version match |
| KRN-004 | Sysctl key not found or read-only | Warning | Log and skip, return available values |
| KRN-005 | Boot entry already exists with different cmdline | Error | Require explicit update or confirmation |
| KRN-006 | Artifact hash mismatch after compilation | Critical | Discard artifact, recompile with verification |
| KRN-007 | Module dependency unsatisfied | Warning | List missing dependencies, fail load |

## Invariants (table with ID, Rule, Enforcement)

| ID | Rule | Enforcement |
|----|------|-------------|
| KRN-INV-01 | Kernel config application is idempotent | Configurator compares current vs desired before applying |
| KRN-INV-02 | Every compiled kernel artifact has a verified hash | Build pipeline rejects unhashed or mismatched artifacts |
| KRN-INV-03 | Only one default boot entry exists at a time | Boot manager enforces single default; previous default demoted |
| KRN-INV-04 | Module load respects dependency ordering | ModuleHandler resolves DAG and loads in topological order |
| KRN-INV-05 | Kernel parameters are validated against allowed list before apply | SysctlManager rejects unknown or dangerous parameter names |

## Design DNA (table with Rule, Assessment — include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 — Composition over Inheritance | Kernel configuration uses fragment composition; operations composed via agent orchestration |
| R2 — Explicit over Implicit | All kernel config fragments and build flags are explicitly declared in desired state |
| R3 — Immutable Artifacts | Kernel build outputs are immutable, content-addressed by hash |
| R4 — Stateless Workers | KernelConfigurator agent is stateless; state stored in KernelConfig resource |
| R5 — Idempotency | Every kernel operation is idempotent — configure, load, and param-set are safe to retry |
| R6 — Observability | Every kernel mutation emits an event; sysctl reads are exposed via capability API |
| R9 — Fail Closed | Compile failure or hash mismatch prevents deployment of untrusted kernel |
| R10 — Least Privilege | Module loading and sysctl writes require explicit capability grants per host |
| R13 — Graceful Degradation | If boot manager is unavailable, runtime sysctl changes still succeed |
| R14 — Data Immutability | KernelConfig records are append-only; history preserved for audit |
| R15 — Explicit Errors | Every failure mode has a typed error code and structured recovery |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Bible/07-Laws/Law-004-Evidence.md | Audit trail for all kernel operations |
| Bible/07-Laws/Law-007-Capability-Bounds.md | Capability scoping for kernel actions |
| Bible/Physics/005-Events.md | Event schema lineage |
| Bible/Physics/007-Capabilities.md | Capability model for kernel operations |
| Bible/Physics/010-Execution.md | Execution lifecycle for compile tasks |
