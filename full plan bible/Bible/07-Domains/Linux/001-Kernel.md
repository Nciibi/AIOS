# AIOS Bible â€” Domains
## Linux â€” 001: Kernel Configuration & Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-LNX-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to configure, compile, load, and tune the Linux kernel across a fleet â€” treating kernel state as a versioned, auditable, and idempotent resource.

## Architecture

Kernel configuration follows a lifecycle: baseline profile is selected â†’ config is generated from fragments â†’ optionally compiled â†’ modules loaded â†’ runtime parameters applied â†’ boot entry updated. The lifecycle is driven by a KernelConfigurator agent that reconciles desired state against live kernel state. Compilation runs in isolated build contexts; artifacts are signed and versioned. Boot entries are managed via bootloader abstraction (GRUB, systemd-boot).

### Architecture Flow

```text
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                    KernelConfigurator Agent                      â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”        â”‚
â”‚  â”‚ Config    â”‚  â”‚ Build    â”‚  â”‚ Module   â”‚  â”‚ Sysctl   â”‚        â”‚
â”‚  â”‚ Resolver  â”‚  â”‚ Executor â”‚  â”‚ Manager  â”‚  â”‚ Manager  â”‚        â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜        â”‚
â”‚        â”‚             â”‚             â”‚             â”‚              â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚              Desired State Reconciliation             â”‚       â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚       â”‚
â”‚  â”‚  â”‚ KernelConfigâ”‚  â”‚ Modules    â”‚  â”‚ BootEntry     â”‚  â”‚       â”‚
â”‚  â”‚  â”‚ Resource    â”‚  â”‚ Resource   â”‚  â”‚ Resource      â”‚  â”‚       â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â”‚                          â”‚                                      â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚              Live Kernel State                        â”‚       â”‚
â”‚  â”‚  /proc/sys   /sys/module   /boot/   /lib/modules/    â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

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

interface KernelBuildArtifact {
  id: string;
  configId: string;
  version: string;
  hash: string;
  signature?: string;
  path: string;
  buildLogRef: string;
  buildTimestamp: string;
  sizeBytes: number;
}

interface ConfigFragmentOverride {
  fragmentPath: string;
  paramKey: string;
  paramValue: string;
  overridePriority: number;
  reason: string;
}

interface KernelVersion {
  fullVersion: string;
  major: number;
  minor: number;
  patch: number;
  extra?: string;
  buildUser: string;
  buildDate: string;
  architecture: string;
  configHash: string;
}
```

## Core Concepts / Operations

- **configure_kernel(id, profileName, fragments)** â€” generates kernel .config from profile and overlay fragments
- **compile_kernel(configId, buildFlags)** â€” compiles kernel source, returns artifact reference with hash
- **load_module(name, parameters)** â€” inserts kernel module with optional parameters
- **unload_module(name)** â€” removes kernel module
- **set_sysctl(key, value, scope)** â€” sets kernel parameter at runtime or writes to sysctl.conf
- **manage_boot_entry(entry)** â€” creates, updates, or removes a bootloader entry
- **get_kernel_info()** â€” returns running kernel version, build info, and live parameters

### Operations Table

| Operation | Description | Preconditions | Postconditions |
|-----------|-------------|---------------|----------------|
| configure_kernel | Generates kernel .config from profile and overlay fragments | Valid profileName, non-conflicting fragments | KernelConfig updated; .config written |
| compile_kernel | Compiles kernel source into bootable image | configId exists; build environment ready | Artifact produced with verified hash; build log recorded |
| load_module | Inserts kernel module into running kernel | Module file exists; dependencies loaded | Module loaded and visible in lsmod; parameters applied |
| unload_module | Removes kernel module from running kernel | Module loaded; no dependent modules active | Module unloaded; resources released |
| set_sysctl | Sets kernel parameter at runtime or persists to sysctl.conf | Key is valid and writable; value in allowed range | Parameter applied at runtime; optionally persisted |
| manage_boot_entry | Creates, updates, or removes a bootloader entry | Bootloader accessible | Boot entry added/updated/removed; single default enforced |
| get_kernel_info | Returns running kernel version and live parameters | Kernel is running | Structured kernel info returned; no state change |
| sign_kernel_artifact | Signs compiled kernel image with specified key | Artifact exists; signKeyId is valid | Artifact signed; signature file produced |
| verify_kernel_image | Validates kernel image integrity and signature | Artifact path and expected hash provided | Integrity result reported; boot blocked on mismatch |
| rollback_kernel | Reverts to previous kernel version and boot entry | Prior kernel artifact available | Previous kernel set as default; config archived |
| list_available_profiles | Enumerates all kernel config profiles in inventory | Profile store accessible | Profile list returned with metadata; no state change |

## Internal Interfaces (table)

| Interface | Provider | Consumer | Purpose |
|-----------|----------|----------|---------|
| IKernelConfig | KernelConfigurator | SysAdminWorker | Apply kernel config profiles |
| IBuildExecutor | BuildIsolation | KernelConfigurator | Execute kernel compiles |
| IModuleManager | ModuleHandler | KernelConfigurator | Load/unload kernel modules |
| ISysctlService | SysctlManager | KernelConfigurator | Get/set kernel parameters |
| IBootManager | BootEntryManager | KernelConfigurator | Manage boot entries |
| ISigningService | ArtifactSigner | KernelConfigurator | Sign kernel build artifacts |
| IVersionResolver | VersionHandler | KernelConfigurator | Resolve and track kernel versions |
| IConfigValidator | ConfigValidator | KernelConfigurator | Validate config fragments for conflicts |

## Events (table)

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| Linux.KernelConfigured | KernelConfigurator applies a kernel config profile | configId, profileName, appliedAt |
| Linux.KernelCompiled | KernelConfigurator finishes a kernel build | configId, version, hash, compileDuration |
| Linux.KernelCompileFailed | KernelConfigurator encounters a build error | configId, errorCode, logRef, failedAt |
| Linux.ModuleLoaded | ModuleHandler inserts a kernel module | moduleName, version, dependencies |
| Linux.ModuleUnloaded | ModuleHandler removes a kernel module | moduleName, refCount, removedBy |
| Linux.SysctlApplied | SysctlManager changes a kernel parameter | key, value, scope, persisted |
| Linux.BootEntryChanged | BootEntryManager creates, updates, or removes a boot entry | entryId, action, bootloader, previousEntryId |

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

## Design DNA (table with Rule, Assessment â€” include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 â€” Composition over Inheritance | Kernel configuration uses fragment composition; operations composed via agent orchestration |
| R2 â€” Explicit over Implicit | All kernel config fragments and build flags are explicitly declared in desired state |
| R3 â€” Immutable Artifacts | Kernel build outputs are immutable, content-addressed by hash |
| R4 â€” Stateless Workers | KernelConfigurator agent is stateless; state stored in KernelConfig resource |
| R5 â€” Idempotency | Every kernel operation is idempotent â€” configure, load, and param-set are safe to retry |
| R6 â€” Observability | Every kernel mutation emits an event; sysctl reads are exposed via capability API |
| R9 â€” Fail Closed | Compile failure or hash mismatch prevents deployment of untrusted kernel |
| R10 â€” Least Privilege | Module loading and sysctl writes require explicit capability grants per host |
| R13 â€” Graceful Degradation | If boot manager is unavailable, runtime sysctl changes still succeed |
| R14 â€” Data Immutability | KernelConfig records are append-only; history preserved for audit |
| R15 â€” Explicit Errors | Every failure mode has a typed error code and structured recovery |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Physics/000-Laws.md | Audit trail for all kernel operations |
| Physics/000-Laws.md | Capability scoping for kernel actions |
| Physics/005-Events.md | Event schema lineage |
| Physics/007-Capabilities.md | Capability model for kernel operations |
| Physics/010-Execution.md | Execution lifecycle for compile tasks |
