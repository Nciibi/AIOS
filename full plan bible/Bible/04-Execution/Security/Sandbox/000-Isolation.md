# AIOS Bible — Sandbox (SAN)
## 000 — Execution Sandboxing

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-000 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Execution Sandboxing provides the runtime isolation boundary for all Worker execution within AIOS. Under Law 7 (Capability Bounds), every Worker operates within declared capability bounds. Sandboxing is the mechanism that enforces these bounds at the operating system and runtime level — ensuring that a Worker cannot access resources, execute operations, or consume capacity beyond its declared capability envelope.

Sandboxing serves three constitutional functions. First, containment: a compromised or misbehaving Worker is contained within its sandbox and cannot affect other Workers, the host system, or the broader AIOS platform. Second, enforcement: resource limits (CPU, memory, network, storage, tokens) are enforced at the sandbox boundary, not by the Worker's cooperation. Third, audit: every resource access, system call, and network operation is observable from the sandbox boundary for evidence collection.

Sandboxing is not optional. Every Worker executes within a sandbox. There is no "unsandboxed" execution mode. The Sandbox service is part of the Security Council's execution infrastructure — it is invoked by the Runtime Engine after the verification pipeline authorizes execution. The sandbox is created before the Worker starts and is destroyed when the Worker terminates, in accordance with Law 10 (Tenure).

## Sandbox Architecture

### Sandbox Types

| Type | Isolation Level | Overhead | Use Case |
|------|----------------|----------|----------|
| Process | OS-level process isolation | Low (<5ms startup) | Simple tool execution, stateless actions |
| Container | Container-level (OCI/Docker) | Medium (<100ms startup) | Standard Worker execution |
| MicroVM | Hardware-virtualized (Firecracker) | High (<500ms startup) | High-risk Workers, multi-tenant isolation |
| Wasm | WebAssembly sandbox | Very Low (<1ms startup) | Plugin execution, policy evaluation |

### Sandbox Selection

The appropriate sandbox type is selected based on the Worker's capability declaration:

| Autonomy Level | Risk Tier | Default Sandbox | Allow Override |
|---------------|-----------|-----------------|----------------|
| L0 | Any | MicroVM | No |
| L1 | L0–L2 | Container | Yes (upgraded to MicroVM, never downgraded) |
| L1 | L3–L4 | MicroVM | No |
| L2 | L0–L2 | Container | Yes |
| L2 | L3–L4 | MicroVM | No |
| L3 | Any | Container | Yes (to MicroVM, not Process) |
| L4 | L0–L1 | Process | Yes (to Container, not MicroVM) |
| L4 | L2–L4 | Container | No |

### Sandbox Lifecycle

```
Request → Create → Initialize → Execute → Monitor → Destroy
```

1. **Request**: Runtime Engine requests sandbox creation for a verified Worker (authorization token must be presented)
2. **Create**: Sandbox service provisions the isolation boundary with declared resource limits
3. **Initialize**: Worker binary/environment is loaded into the sandbox
4. **Execute**: Worker process runs inside the sandbox
5. **Monitor**: Sandbox monitors resource consumption, system calls, and network activity
6. **Destroy**: Sandbox is torn down, resources released, evidence collected

## Resource Enforcement

### Resource Limits

| Resource | Enforcement Mechanism | Granularity | Violation Action |
|----------|----------------------|-------------|------------------|
| CPU | CFS quota (cgroups) | 1% increments | Throttled, violation logged after 10s sustained overage |
| Memory | cgroups memory limit | 1 MB increments | OOM kill, violation event |
| Disk (ephemeral) | tmpfs size limit | 1 MB increments | Write denied, violation event |
| Network | iptables/nftables + rate limit | Per-connection | Connection blocked, violation event |
| Processes | PID limit (cgroups) | 1 process | Fork denied, violation event |
| System calls | Seccomp-bpf filter | Per-syscall | Syscall denied, violation event |
| File system | Bind mount + overlayfs | Read-only/read-write paths | Access denied, violation event |
| Tokens | Application-level (ACF token budget) | Per-message | Token denial at Stage 5 |

### Enforcement Implementation

```typescript
interface SandboxLimits {
  cpu: {
    maxCores: number;           // Fractional, e.g., 0.5 for half a core
    maxFrequency: string;       // e.g., "2.4GHz"
    quotaPeriodUs: number;      // CFS period in microseconds
  };
  memory: {
    maxBytes: number;
    swapMaxBytes: number;       // 0 for no swap
    oomScoreAdj: number;        // OOM killer priority
  };
  network: {
    egressBandwidthBps: number;
    ingressBandwidthBps: number;
    allowedEndpoints: string[]; // Only these destinations
    allowedPorts: number[];
    denyAll: boolean;           // No network access
  };
  fs: {
    readOnlyPaths: string[];    // Read-only access
    readWritePaths: string[];   // Read-write access
    writableTmpfs: boolean;     // Ephemeral scratch space
    tmpfsSizeBytes: number;
  };
  syscalls: {
    allowedSyscalls: string[];  // Whitelist
    denyOnViolation: boolean;   // Kill or log
  };
}
```

### Resource Accounting

Resource consumption is accounted at the sandbox boundary and reported to ROS:

- **CPU**: Accumulated CPU time, measured in millicore-seconds
- **Memory**: Peak memory usage, measured in MB-seconds
- **Network**: Bytes transferred, measured per-endpoint
- **Disk**: Total bytes written to tmpfs
- **System calls**: Count of syscalls by type
- **Elapsed time**: Wall clock time from start to termination

Accounting data is published to EAS as evidence at sandbox teardown.

## Security Controls

### Seccomp Profile

Each sandbox type has a default seccomp-bpf profile that whitelists only the system calls required for the Worker's declared capabilities:

| Worker Type | Allowed Syscalls (subset) | Denied Syscalls |
|-------------|--------------------------|-----------------|
| Text/Code Worker | read, write, openat, close, mmap, munmap, exit_group, nanosleep | clone (CLONE_NEW*), mount, umount, pivot_root, kexec |
| Tool Executor | + execve, wait4, dup2, pipe2, socket, connect | + bpf, perf_event_open, process_vm_writev |
| Network Worker | + socket, connect, sendto, recvfrom, bind, listen, accept | + iptables, nf_tables, raw socket creation |
| Full Worker | Based on declared tool set | All syscalls not in whitelist |

### Network Policy

Network access is restricted by capabilities:

| Capability | Network Access | Example |
|-----------|---------------|---------|
| `network.none` | No network access | Data processing |
| `network.egress.api` | HTTP/S to registered API endpoints | Model API calls |
| `network.egress.all` | Full egress (rate-limited) | General tool execution |
| `network.ingress.none` | No inbound connections | Default |
| `network.ingress.callback` | One established callback channel | Async execution |

### Filesystem Policy

| Capability | Filesystem Access |
|-----------|------------------|
| `fs.read.self` | Read own workspace |
| `fs.read.org` | Read organization-scoped data |
| `fs.write.self` | Write to own workspace |
| `fs.write.tmp` | Write to ephemeral tmpfs (destroyed with sandbox) |
| `fs.exec` | Execute files within sandbox |

## Observability

### System Call Monitoring

All system calls are monitored at the sandbox boundary:
- Permitted syscalls are counted and attributed
- Denied syscalls produce immediate violation events
- Syscall frequency anomalies trigger alerts
- Syscall traces are available for forensic investigation (retained 7 days)

### Network Flow Monitoring

All network connections are logged:
- Source sandbox, destination address, port, protocol
- Bytes transferred, connection duration
- TLS handshake metadata (SNI, certificate fingerprint)
- DNS query log

### Audit Events

| Event | Frequency | Retention |
|-------|-----------|-----------|
| Sandbox create/destroy | Per lifecycle | 90 days |
| Resource limit hit | Per violation | 1 year |
| Denied syscall | Per violation | 1 year |
| Network connection | Per connection (summarized) | 30 days |
| OOM event | Per event | 1 year |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.SandboxCreated` | A sandbox is created | sandbox_id, worker_id, sandbox_type, resource_limits, started_at |
| `SAN.SandboxDestroyed` | A sandbox is destroyed | sandbox_id, worker_id, uptime_ms, peak_memory, total_cpu_ms |
| `SAN.ResourceViolation` | A resource limit is exceeded | sandbox_id, resource_type, limit_value, actual_value, duration |
| `SAN.SyscallDenied` | A system call is denied | sandbox_id, syscall_number, syscall_name, process_pid |
| `SAN.NetworkBlocked` | A network connection is blocked | sandbox_id, destination, port, protocol, blocked_rule |
| `SAN.OOMKilled` | A sandbox process is OOM-killed | sandbox_id, process_pid, process_name, memory_usage_at_kill |
| `SAN.SandboxTimeout` | A sandbox exceeds its maximum runtime | sandbox_id, max_runtime, actual_runtime |
| `SAN.SandboxHealth` | Sandbox resource health snapshot | sandbox_id, cpu_usage, memory_usage, network_io, uptime |

## Cross-Cutting Concerns

### Security

- Sandbox escape is treated as a critical security incident. Any detected escape attempt triggers immediate Worker termination, sandbox destruction, and Security Council escalation.
- Sandbox configurations are immutable after creation. A running Worker cannot modify its sandbox limits.
- The Sandbox service itself runs in a privileged MicroVM to prevent escape from below.

### Evidence

- Every sandbox lifecycle event is recorded as evidence in EAS.
- Resource accounting data is published at sandbox teardown for post-execution audit.
- Denied syscalls and network blocks are recorded with full context for forensic analysis.

### Lifecycle

- Sandbox lifetime is bounded by the Worker's tenure (Law 10). When the Worker terminates, the sandbox is destroyed.
- Sandboxes exceeding their maximum runtime (configurable per Worker, default 24 hours) are force-destroyed.
- Resource limits are snapshotted at sandbox creation and restored at sandbox destroy for accounting.

### Capability Bounds

- Sandbox resource limits are derived from the Worker's declared capability bounds (Stage 5).
- A Worker may not request more resources than its capability bounds allow.
- Capability bounds are enforced at the OS level — a Worker cannot bypass capability verification by consuming resources directly.

### Communication

- Sandbox services communicate through ACF for lifecycle management.
- Network traffic from the sandbox flows through ACF-managed proxies for observability.
- The Sandbox service publishes health metrics through ACF.

### Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | Sandbox does one thing: isolate Worker execution |
| R2 — Dependency Order | Compliant | Sandbox depends on OS primitives; Runtime Engine depends on Sandbox |
| R3 — DRY | Compliant | Sandbox type configurations defined once per type |
| R4 — Builder Pattern | Compliant | Sandbox constructed by SandboxBuilder with validated resource limits |
| R5 — Liskov Substitution | Compliant | Any sandbox implementation (Process, Container, MicroVM) conforms to Sandbox interface |
| R6 — DI over Singletons | Compliant | Sandbox service injected into Runtime Engine |
| R7 — Tests Exist | Compliant | Unit tests for limit enforcement, integration tests for sandbox lifecycle |
| R8 — Tests Fast | Compliant | Process sandbox tests complete in <5s; full suite <60s |
| R9 — Deterministic Tests | Compliant | Same limits + same Worker always produces same resource enforcement |
| R10 — Prefer Simpler | Compliant | 4 sandbox types, linear lifecycle — no complex orchestration |
| R11 — Refactor over Rewrite | Compliant | Sandbox improvements through driver updates, not architecture rewrites |
| R12 — Embrace Errors | Compliant | Every violation identifies the resource, limit, and offending process |
| R13 — Design for Failure | Compliant | Sandbox failure does not affect host; sandbox crash is contained |
| R14 — Paved Path | Compliant | All Workers execute through the paved Sandbox create→run→destroy path |
| R15 — Open/Closed | Compliant | New sandbox types added via SandboxDriver interface, not core changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; Sandbox enforces at OS level |
| ../AZS/002-Capability.md | Resource limits derived from capability bounds |
| ../Audit/000-EAS.md | Sandbox evidence recorded by EAS |
| ../SSM/000-SSM.md | Session secrets injected into sandbox at initialization |
| Physics/007-Capabilities.md | Capability Bound invariants |
| Physics/008-Security.md | Security verification invariants |
| Physics/010-Execution.md | Execution invariants |
