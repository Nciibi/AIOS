# AIOS Bible — Sandbox (SAN)
## 004 — Seccomp Profile Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-004 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Seccomp Profile Management provides systemic system call filtering across all AIOS sandbox types through seccomp-bpf (Berkeley Packet Filter). Seccomp is the last line of defense at the kernel boundary — it restricts which Linux system calls a process may issue, even if the process is compromised. Every sandboxed process, sandbox infrastructure process (Sentry, Gofer, jailer), and the Sandbox service itself operates under a seccomp-bpf profile that whitelists only the syscalls required for its function.

Seccomp Profile Management serves three functions: generation of seccomp profiles from capability declarations, management of a profile registry with versioning and distribution, and enforcement of profiles across all sandbox types with audit logging for denied syscalls.

## Architecture

Seccomp profiles are seccomp-bpf programs — small BPF bytecode programs loaded into the kernel that inspect each syscall's number and arguments before execution. The kernel executes the BPF program and takes the specified action (allow, deny, trace, or kill) before the syscall is processed.

```
Profile Definition → BPF Compilation → Kernel Load → Syscall Interception → Action
```

### Seccomp-bpf Architecture

| Layer | Component | Role |
|-------|-----------|------|
| Definition | ProfileGenerator | Converts capability declarations to syscall allowlists |
| Compilation | BPF Compiler | Translates allowlist rules to seccomp-bpf bytecode |
| Loading | ProfileLoader | Loads BPF program via `prctl(PR_SET_SECCOMP)` or `seccomp(SECCOMP_SET_MODE_FILTER)` |
| Interception | Kernel seccomp module | Evaluates each syscall against loaded BPF program |
| Action | Kernel | Executes specified action: ALLOW, KILL, TRACE, LOG, ERRNO |
| Audit | ProfileRegistry | Logs denied syscalls to EAS with full context |

### Profile Structure

```
Profile
├── Default action (what happens when no rule matches)
│   ├── ALLOW (whitelist mode — deny all not explicitly allowed)
│   └── KILL (blacklist mode — allow all not explicitly denied)
├── Rules[]
│   ├── Syscall name/number
│   ├── Argument filters (optional — check arg0..arg5)
│   │   ├── Mask (bitmask for comparison)
│   │   ├── Value (expected value after mask)
│   │   └── Comparator (EQ, NE, LT, LE, GT, GE, MASKED_EQ)
│   └── Action on match
│       ├── ALLOW
│       ├── KILL (immediate SIGSYS termination)
│       ├── TRACE (notify ptracer)
│       ├── LOG (log violation, continue)
│       └── ERRNO (return specific errno)
└── Flags
    ├── SECCOMP_FILTER_FLAG_TSYNC (apply to all threads)
    ├── SECCOMP_FILTER_FLAG_LOG (log all actions)
    └── SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (wait for killable recv)
```

## Data Model

```typescript
interface SeccompProfile {
  id: string;
  name: string;
  version: number;
  sandboxType: "firecracker" | "gvisor" | "wasm" | "process" | "container";
  target: "sandbox" | "sentry" | "gofer" | "jailer" | "runtime";
  defaultAction: SeccompAction;
  rules: SyscallRule[];
  flags: SeccompFlag[];
  architectures: string[];           // e.g., ["SCMP_ARCH_X86_64"]
  metadata: ProfileMetadata;
}

type SeccompAction = "ALLOW" | "KILL" | "TRACE" | "LOG" | "ERRNO";

type SeccompFlag = "TSYNC" | "LOG" | "WAIT_KILLABLE_RECV";

interface SyscallRule {
  syscall: string;                   // Syscall name (e.g., "read", "write")
  syscallNumber?: number;            // Architecture-specific syscall number
  argumentFilters?: ArgFilter[];
  action: SeccompAction;
  comment?: string;                  // Why this syscall is allowed/denied
}

interface ArgFilter {
  index: number;                     // Argument index (0–5)
  mask: number;                      // Bitmask applied before comparison
  value: number;                     // Expected value after masking
  comparator: "EQ" | "NE" | "LT" | "LE" | "GT" | "GE" | "MASKED_EQ";
}

interface ProfileGenerator {
  id: string;
  capabilitySource: string;          // Reference to AZS capability declaration
  target: string;                    // Target process type
  baseProfile: string;               // Reference to base SeccompProfile ID
  generatedProfile: string;          // Reference to generated SeccompProfile ID
  generationRules: GenerationRule[];
  lastGenerated: string;
  generationCount: number;
}

interface GenerationRule {
  capability: string;                // e.g., "fs.read.self"
  syscalls: string[];               // Syscalls to add when capability is granted
  argumentFilters?: ArgFilter[];
  condition?: string;                // Conditional expression
}

interface ProfileRegistry {
  id: string;
  storePath: string;                 // Filesystem path for profile storage
  profiles: Map<string, SeccompProfile>;
  templates: Map<string, SeccompProfile>;
  versions: Map<string, number[]>;   // Profile ID → version list
  generated: Map<string, ProfileGenerator>;
  stats: RegistryStats;
}

interface RegistryStats {
  totalProfiles: number;
  totalVersions: number;
  totalGenerators: number;
  lastSync: string;
  storageBytes: number;
}

interface AuditRecord {
  id: string;
  timestamp: string;
  sandboxId: string;
  processId: number;
  threadId: number;
  syscallNumber: number;
  syscallName: string;
  arguments: number[];               // Raw argument values
  instructionPointer: number;        // Address of syscall instruction
  profileId: string;
  profileVersion: number;
  action: SeccompAction;
  stackTrace?: string[];            // Userspace stack trace (if available)
}

interface ProfileLayer {
  base: string;                      // Base profile ID (default for sandbox type)
  capabilities: string[];           // Capability-specific profile additions
  custom?: string;                   // Custom overrides (restricted to Operator role)
  composite: string;                 // Resolved composite profile ID
}
```

## Core Concepts / Operations

### Profile Generation from Capability Declarations

Seccomp profiles are generated automatically from Worker capability declarations. Each capability maps to a set of required syscalls:

| Capability | Required Syscalls |
|-----------|------------------|
| `fs.read.self` | read, pread64, preadv, lseek, stat, fstat, lstat, newfstatat, readlink, readlinkat, getdents, getdents64, openat, close |
| `fs.write.self` | write, pwrite64, pwritev, truncate, ftruncate, mkdir, mkdirat, rename, renameat, renameat2, unlink, unlinkat, rmdir |
| `fs.exec` | execve, execveat, mmap (PROT_EXEC), mprotect (PROT_EXEC), access, faccessat, faccessat2 |
| `network.egress.api` | socket, connect, bind, listen, accept, accept4, sendto, sendmsg, recvfrom, recvmsg, setsockopt, getsockopt, getsockname, getpeername, shutdown, poll, ppoll, epoll_create, epoll_ctl, epoll_wait, epoll_pwait |
| `network.ingress.callback` | (same as egress) + listen, accept, accept4 |
| `process.spawn` | clone, fork, vfork, wait4, waitid, exit, exit_group |
| `sys.time` | clock_gettime, clock_settime, gettimeofday, settimeofday, nanosleep, clock_nanosleep |
| `sys.random` | getrandom |
| `env.variables` | getenv (via prctl or /proc), not a syscall — requires procfs access |

### Profile Layering

Profiles are composed in layers to provide appropriate isolation without excessive restriction:

```
Layer 0: Default (sandbox-type base)
  └── Always applied — provides baseline for each sandbox type
Layer 1: Capability-specific
  └── Adds syscalls for each granted capability
Layer 2: Custom overrides
  └── Operator-defined additions or modifications (audited)
```

| Profile Level | Scope | Author | Override Policy |
|--------------|-------|--------|-----------------|
| Default | Per sandbox type (Firecracker, gVisor, WASM, Process) | Platform team | Immutable in production |
| Capability-specific | Per Worker capability set | Generated from AZS | Automatic, no manual override |
| Custom | Per Worker or per organization | Operator | Manual, requires RFC approval |

### Profile Registry

The ProfileRegistry stores, versions, and distributes seccomp profiles:

| Operation | Description | Frequency |
|-----------|-------------|-----------|
| Store | Save profile to registry with version number | On create/update |
| Retrieve | Load profile by ID and version | On sandbox creation |
| List | List all profiles and versions | On demand |
| Diff | Compare two profile versions | On audit |
| Sync | Synchronize registry across cluster nodes | Periodic (30s) |

### Audit Logging for Denied Syscalls

Every denied syscall produces an AuditRecord with full forensic context:

| Audit Field | Source | Retention |
|-------------|--------|-----------|
| Timestamp | System clock | 1 year |
| Sandbox ID | Sandbox service | 1 year |
| Process/Thread ID | Kernel (via PTRACE_GETEVENTMSG) | 1 year |
| Syscall number + name | Audit record based on seccomp_data | 1 year |
| Arguments | seccomp_data structure | 1 year |
| Instruction pointer | seccomp_data structure | 1 year |
| Profile ID + version | Registry lookup from loaded filter | 1 year |
| Stack trace | /proc/pid/maps + unwind | 90 days |

### Profile Testing (Syscall Tracing Mode)

Before a profile is deployed to production, it is tested in trace mode:

| Phase | Mode | Behavior | Duration |
|-------|------|----------|----------|
| Development | LOG only | Denied syscalls are logged but the process continues | Developer iteration |
| Staging | TRACE | Denied syscalls are forwarded to a tracer process for analysis | CI/CD pipeline |
| Canary | KILL (low-priority Workers) | Denied syscalls terminate the process; low-impact Workers only | 24 hours |
| Production | KILL | Full enforcement across all Workers | Permanent |

### Integration with Sandbox Types

| Sandbox Type | Target Process | Profile Source | Typical Profile Size |
|-------------|---------------|----------------|---------------------|
| Firecracker | Jailer | Hardcoded (immutable) | ~50 syscalls |
| Firecracker | Guest kernel | Seccomp within guest (guest OS concern) | Guest-configured |
| gVisor | Sentry | Hardcoded Sentry profile (immutable) | ~40 syscalls |
| gVisor | Gofer | Generated from Gofer capability config | ~30 syscalls |
| gVisor | Sandbox application | Generated from Worker capability declaration | ~50–200 syscalls |
| WASM | Runtime (Wasmtime/WAMR) | Generated from runtime requirements | ~60 syscalls |
| Process | Worker process | Generated from Worker capability declaration | ~30–150 syscalls |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| Profile Generation | ProfileGenerator | Seccomp Service | Internal API |
| Profile Loading | ProfileLoader | Sandbox Processes | prctl/seccomp syscall |
| Profile Registry | ProfileRegistry | Seccomp Service | Key-value store |
| Audit Ingestion | Seccomp Service | EAS | Event stream |
| Profile Testing | Seccomp Service | CI/CD system | HTTP API |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.SEC.ProfileCreated` | New seccomp profile created | profile_id, name, version, sandbox_type, target, default_action, rule_count |
| `SAN.SEC.ProfileUpdated` | Existing profile updated with new version | profile_id, name, old_version, new_version, changelog, diff_summary |
| `SAN.SEC.ProfileApplied` | Profile loaded into a process | profile_id, version, sandbox_id, process_pid, thread_id, result |
| `SAN.SEC.SyscallDenied` | Syscall denied by seccomp filter | sandbox_id, process_pid, syscall_number, syscall_name, arguments[], profile_id, action_taken |
| `SAN.SEC.SyscallAllowed` | Syscall allowed by seccomp filter (recorded only when audit flag set) | sandbox_id, process_pid, syscall_number, syscall_name, profile_id |
| `SAN.SEC.ProfileGenerated` | Profile generated from capability declaration | generator_id, capability_source, base_profile, generated_profile, rule_count |
| `SAN.SEC.ProfileTested` | Profile tested in trace mode | profile_id, version, test_duration, denied_count, allowed_count, test_result |
| `SAN.SEC.ProfileLayered` | Profile layers composed into composite profile | profile_id, base_layer, capability_layers[], custom_layer, composite_id |
| `SAN.SEC.ProfileConflict` | Conflicting rules detected between layers | profile_id, layer_a, layer_b, conflicting_syscall, resolution_strategy |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SAN_SEC_001 | Profile generation failure: capability declaration contains unrecognized syscall names | Medium | Log generation error; fall back to base profile for unrecognized capabilities |
| SAN_SEC_002 | Profile loading failure: kernel does not support seccomp or BPF program is invalid | Critical | Fall back to ALLOW (dangerous — escalate to Security Council immediately) |
| SAN_SEC_003 | Profile registry corruption: profile store inconsistent or version mismatch | High | Restore from backup; trigger profile regeneration from capability sources |
| SAN_SEC_004 | Profile conflict: two layers define different actions for the same syscall | Medium | Apply resolution strategy (most restrictive wins); log conflict for audit |
| SAN_SEC_005 | Audit overflow: too many denied syscalls causing audit system backpressure | Medium | Sample denied syscalls (log every Nth); alert Operator of potential runaway process |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SAN-SEC-001 | Every seccomp profile must specify a default action — no profile can leave any syscall unhandled | ProfileGenerator validates that defaultAction is set before compilation |
| SAN-SEC-002 | Every sandbox process must have a seccomp profile loaded before it begins execution of Worker code | Sandbox lifecycle enforces profile loading in the Initialize phase, before Execute phase |
| SAN-SEC-003 | A profile loaded into a process must be immutable for the lifetime of that process | seccomp-bpf filters are immutable after loading; no mechanism exists to relax a loaded filter |
| SAN-SEC-004 | All denied syscalls must be recorded with sufficient context for forensic analysis | AuditRecord includes sandbox_id, process_pid, syscall_number, arguments, instruction_pointer, and profile_id |

## Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | Seccomp Profile Management does one thing: syscall-level access control |
| R2 — Dependency Order | Compliant | Seccomp depends on kernel seccomp module; Sandbox drivers depend on Seccomp Service |
| R3 — DRY | Compliant | Base profiles defined once per sandbox type; capability-to-syscall mapping defined once per capability |
| R4 — Builder Pattern | Compliant | SeccompProfile built by ProfileBuilder with validated generation rules |
| R5 — Liskov Substitution | Compliant | Any profile (Firecracker/gVisor/WASM/Process) conforms to SeccompProfile interface |
| R6 — DI over Singletons | Compliant | ProfileGenerator injected into SandboxService for profile creation |
| R7 — Tests Exist | Compliant | Unit tests for generation rules, BPF compilation; integration tests for profile loading |
| R8 — Tests Fast | Compliant | Profile generation unit tests complete in <50ms; BPF compilation tests <100ms |
| R9 — Deterministic Tests | Compliant | Same capability declaration always produces identical seccomp profile |
| R10 — Prefer Simpler | Compliant | Three-layer profile model; linear generation→load→audit pipeline |
| R11 — Refactor over Rewrite | Compliant | Profile improvements through generation rule updates, not seccomp infrastructure changes |
| R12 — Embrace Errors | Compliant | Every denied syscall is recorded with full forensic context, never silently ignored |
| R13 — Design for Failure | Compliant | Profile load failure does not prevent process start (falls back to ALLOW but escalates); audit overflow sampled |
| R14 — Paved Path | Compliant | All sandbox processes execute through the paved generate→layer→load→audit path |
| R15 — Open/Closed | Compliant | New syscall rules added via GenerationRule registrations, not profile structure changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Isolation.md | Base sandbox architecture; seccomp profiles enforce syscall isolation |
| 001-Firecracker.md | Firecracker jailer uses seccomp Level 2 profile; seccomp defined in this document |
| 002-gVisor.md | gVisor Sentry and Gofer use seccomp profiles for self-isolation |
| 003-WASM.md | WASM runtime uses seccomp profile for process-level self-isolation |
| 005-Namespaces.md | Namespaces provide process isolation; seccomp provides syscall isolation (complementary) |
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; seccomp enforces at kernel syscall boundary |
| ../AZS/002-Capability.md | Capability declarations drive seccomp profile generation |
| ../Audit/000-EAS.md | Denied syscall audit records ingested by EAS |
| Physics/007-Capabilities.md | Capability Bound invariants enforced at syscall granularity |
| Physics/008-Security.md | Seccomp satisfies syscall-level security verification |
| Physics/010-Execution.md | Profile loading lifecycle conforms to execution tenure invariants |
