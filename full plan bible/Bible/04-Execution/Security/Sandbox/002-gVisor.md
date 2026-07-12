# AIOS Bible — Sandbox (SAN)
## 002 — gVisor Container Sandbox

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-002 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

gVisor container sandbox provides application-kernel isolation for standard Worker execution. Unlike hardware-virtualized sandboxes (Firecracker) that run a full guest kernel, gVisor intercepts application system calls at the user-space boundary and implements Linux kernel semantics in a specialized sandbox kernel (Sentry). This provides strong isolation with lower overhead than hardware virtualization, suitable for L1–L4 Workers in the standard risk tiers.

gVisor serves three primary roles: sandboxed execution for Workers whose capability declarations require kernel-level isolation but do not justify Firecracker overhead, high-density Worker hosting where multiple sandboxes share a single host kernel with Sentry-enforced boundaries, and compatibility with OCI container workflows where existing container images are executed within a gVisor-managed sandbox.

## Architecture

gVisor intercepts all application system calls at the user-space boundary. The interception is performed by one of three platform implementations (KVM, ptrace, or systrap), which traps the application's syscall and redirects it to the Sentry process. The Sentry implements Linux syscall semantics in user-space Go code, effectively acting as the application's kernel. File system operations are proxied through a Gofer process that performs host file I/O with reduced privilege.

```
Container → Platform (KVM/ptrace) → Sentry → Gofer → Host OS
```

### gVisor Architecture Components

| Component | Role | Implementation |
|-----------|------|----------------|
| Sentry | Application kernel in user space | Go process; implements ~300 Linux syscalls |
| Gofer | File system proxy with reduced privileges | Go process; 9P2000.L protocol over vsock |
| Platform | Syscall interception mechanism | KVM (hardware), ptrace (software), or systrap |
| Netstack | User-space TCP/IP network stack | Go implementation; no host network stack dependency |

### Sentry Configuration

The Sentry is the core of gVisor isolation. It intercepts every application syscall and either implements it or denies it. The Sentry configuration determines which syscalls are permitted, what security checks are applied, and how resources are accounted.

| Parameter | Description | Default | Range |
|-----------|-------------|---------|-------|
| SyscallFilter | Whitelist of permitted syscalls | Default whitelist (~150 syscalls) | Configurable per capability |
| SeccompProfile | Host seccomp-bpf filter for Sentry process | Strict Sentry profile | Default only (immutable) |
| MaxThreads | Maximum threads in sandbox | 1000 | 1–10000 |
| MaxFDs | Maximum open file descriptors | 1000 | 1–100000 |
| NetworkMode | Network stack mode | "sandwich" (netstack) | "sandwich", "host", "none" |
| FileAccess | File access mode | "proxy" (Gofer) | "proxy", "direct", "exclusive" |
| OverlayFS | Root overlay filesystem | Read-only + tmpfs | Enabled/disabled |

## Data Model

```typescript
interface SandboxConfig {
  id: string;
  containerID: string;
  spec: OCIRuntimeSpec;
  sentry: SentryConfig;
  gofer: GoferConfig;
  platform: PlatformConfig;
  filesystem: FilesystemConfig;
  network: NetworkConfig;
  resourceLimits: ResourceLimits;
  seccomp: SeccompConfig;
}

interface SentryConfig {
  syscallFilter: SyscallFilter;
  seccompProfile: string;           // Built-in Sentry seccomp profile
  maxThreads: number;
  maxFDs: number;
  maxCaps: number;
  allowSetuid: boolean;
  allowSetgid: boolean;
  userLog: string;                  // Path for Sentry debug logs
  strace: boolean;                  // Enable syscall tracing
  straceSize: number;               // Max bytes to log per syscall
  straceEventSize: number;          // Max event bytes in strace output
}

interface SyscallFilter {
  mode: "whitelist" | "blacklist";
  syscalls: string[];
  denyOnViolation: boolean;         // Kill process or log only
}

interface GoferConfig {
  fsgoferHostUDS: string;           // Host-side Unix domain socket path
  fsgoferGuestPath: string;         // Guest mount point
  cachePolicy: GoferCachePolicy;
  cacheSize: number;                // Inode cache size (entries)
  cacheHighWaterMark: number;       // Cache eviction threshold
  cacheLowWaterMark: number;        // Cache fill threshold
  overlay: OverlayConfig;
}

interface GoferCachePolicy {
  revalidate: "never" | "open" | "always";
  writeback: "sync" | "async" | "direct";
  attrCache: boolean;
  dentryCache: boolean;
  pageCache: boolean;
}

interface OverlayConfig {
  enabled: boolean;
  upperDir: string;                 // tmpfs mount for upper layer
  workDir: string;                  // OverlayFS work directory
  lowerDir: string;                 // Read-only lower layer
}

interface PlatformConfig {
  type: "kvm" | "ptrace" | "systrap";
  kvmPath: string;                  // Path to /dev/kvm (for KVM platform)
  ptraceAddr: number;               // ptrace address to attach (for ptrace platform)
  systrapAddr: string;              // Systrap socket path (for systrap platform)
}

interface FilesystemConfig {
  rootfs: RootfsConfig;
  mounts: MountConfig[];
  tmpfs: TmpfsConfig;
}

interface RootfsConfig {
  type: "overlayfs" | "bind" | "tmpfs";
  source: string;
  readonly: boolean;
}

interface MountConfig {
  source: string;
  destination: string;
  type: string;
  options: string[];
  readonly: boolean;
}

interface TmpfsConfig {
  sizeBytes: number;
  mountPoint: string;
}

interface NetworkConfig {
  mode: "sandwich" | "host" | "none";
  interface: NetworkInterface;
  dns: DNSConfig;
  forwarding: boolean;
}

interface NetworkInterface {
  name: string;
  mtu: number;
  macAddress: string;
  addresses: string[];
  routes: Route[];
}

interface Route {
  destination: string;
  gateway: string;
  metric: number;
}

interface DNSConfig {
  servers: string[];
  searches: string[];
  options: string[];
}

interface ResourceLimits {
  cpu: CPULimit;
  memory: MemoryLimit;
  processes: ProcessLimit;
}

interface CPULimit {
  maxCores: number;
  quotaUs: number;
  periodUs: number;
  shares: number;
}

interface MemoryLimit {
  maxBytes: number;
  swapBytes: number;
  reservationBytes: number;
  kernelBytes: number;
  oomScoreAdj: number;
}

interface ProcessLimit {
  maxProcesses: number;
  maxThreads: number;
}

interface SeccompConfig {
  sentryProfile: string;            // Reference to SeccompProfile for Sentry self-isolation
  sandboxProfile: string;           // Reference to SeccompProfile for sandbox syscall filter
  auditOnly: boolean;               // Log violations instead of killing
}
```

## Core Concepts / Operations

### Sentry Syscall Filtering

The Sentry maintains a whitelist of permitted Linux syscalls. Any syscall not on the whitelist is denied and the calling process is terminated (or logged in audit mode). The whitelist is derived from the Worker's capability declaration:

| Capability | Allowed Syscalls (additional) |
|-----------|------------------------------|
| `fs.read.self` | open, read, pread64, lseek, stat, fstat, readlink |
| `fs.write.self` | write, pwrite64, truncate, ftruncate, mkdir, rename |
| `fs.exec` | execve, execveat, mmap (PROT_EXEC) |
| `network.egress.api` | socket, connect, sendto, recvfrom, bind (ephemeral), getsockopt, setsockopt |
| `network.ingress.callback` | listen, accept, poll, epoll_wait |

### Gofer Filesystem Proxy

The Gofer process handles all host file system I/O on behalf of the sandbox. It communicates with the Sentry over a Unix domain socket using the 9P2000.L protocol. The Gofer has reduced privileges compared to the Sentry — it does not have the Sentry's syscall interception capability.

| Operation | Mechanism | Cache Policy |
|-----------|-----------|-------------|
| File open | Gofer opens file descriptor on host, sends fd to Sentry | On open: check attr cache |
| File read | Sentry reads from fd (no host syscall for subsequent reads) | Page cache hit: no host I/O |
| File write | Sentry writes to fd, Gofer flushes based on writeback policy | Async writeback: deferred flush |
| Directory read | Gofer reads directory entries, sends to Sentry | Dentry cache: TTL-based expiry |
| Metadata lookup | Gofer stats file, sends to Sentry | Attr cache: 1s default TTL |

### Platform Selection

| Platform | Mechanism | Overhead | Requirements | Use Case |
|----------|-----------|----------|-------------|----------|
| KVM | Hardware virtualization extensions for syscall trapping | Lowest | `/dev/kvm` access, `CONFIG_KVM=y` | Production, highest throughput |
| ptrace | `ptrace(PTRACE_SYSEMU)` for syscall interception | Moderate | No special hardware | Development, testing |
| systrap | Lightweight syscall interception via stub process | Low | Linux 5.11+ (`sched_setattr`) | Production when KVM unavailable |

### Network Stack

gVisor's user-space network stack (netstack) implements TCP/IP semantics entirely in the Sentry. This eliminates host network stack exposure — even if the application generates malicious network packets, they are processed by the Sentry's netstack, not the host kernel.

| Feature | Implementation | Isolation Benefit |
|---------|---------------|-------------------|
| TCP/IP | Full TCP state machine in Go | No host TCP stack processing |
| UDP | Datagram handling in user space | No host UDP stack processing |
| DNS | DNS resolver in netstack | No host resolver dependency |
| Socket filtering | Sentry applies iptables rules in user space | Host iptables bypass not possible |

### OCI Runtime Integration

gVisor integrates with the container runtime via the OCI runtime specification. When a container is created with `runtime=runsc` (gVisor's OCI runtime), the container's OCI spec is translated into a SandboxConfig:

1. The OCI spec's `rootfs` is mounted as the Gofer's root filesystem.
2. Mount points in the OCI spec are translated to MountConfig entries.
3. Resource limits from the OCI spec's Linux resources are mapped to Sentry resource limits.
4. The container's process becomes the init process in the gVisor sandbox.

### Filesystem Isolation

Filesystem isolation is achieved through overlayfs and mount namespace separation:

| Layer | Type | Contents | Persistence |
|-------|------|----------|-------------|
| Lower (rootfs) | Read-only overlay | Container image | Immutable during sandbox lifetime |
| Upper | tmpfs overlay | Container modifications | Destroyed on sandbox teardown |
| Scratch | tmpfs mount | Worker scratch space (writable) | Destroyed on sandbox teardown |
| Data | bind mount | Host directories (read-write) | Persists beyond sandbox lifetime |

### Performance Characteristics vs Native

| Operation | Native | gVisor (KVM) | gVisor (ptrace) | Overhead vs Native |
|-----------|--------|--------------|------------------|-------------------|
| Syscall (getpid) | ~100ns | ~1µs | ~5µs | 10–50x |
| File read (4KB) | ~500ns | ~3µs | ~8µs | 6–16x |
| Network (TCP echo) | ~5µs | ~20µs | ~50µs | 4–10x |
| Memory allocation | ~50ns | ~50ns | ~50ns | 1x (direct hardware access) |
| Thread creation | ~10µs | ~50µs | ~100µs | 5–10x |
| Container startup | ~50ms | ~150ms | ~300ms | 3–6x |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| Sentry API | Sentry Process | Sandbox Service | gRPC (control socket) |
| Gofer API | Gofer Process | Sentry Process | 9P2000.L (Unix socket) |
| Platform | KVM/ptrace/Systrap | Sentry Process | /dev/kvm, ptrace, or vsock |
| Netstack | Sentry Process | Application | In-process function calls |
| Prometheus | Sentry Process | Metrics System | HTTP (metrics endpoint) |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.GV.SandboxCreated` | gVisor sandbox created | sandbox_id, container_id, platform_type, sentry_pid, gofer_pid |
| `SAN.GV.SandboxStarted` | Sandbox init process started | sandbox_id, started_at, rootfs_type, network_mode |
| `SAN.GV.SandboxStopped` | Sandbox stopped | sandbox_id, uptime_ms, exit_code, termination_signal |
| `SAN.GV.SandboxDestroyed` | Sandbox destroyed, resources released | sandbox_id, uptime_ms, peak_memory_bytes, total_cpu_ns, total_syscalls |
| `SAN.GV.SyscallDenied` | Sentry denied a syscall | sandbox_id, syscall_number, syscall_name, pid, thread_id, instruction_pointer |
| `SAN.GV.SentryCrash` | Sentry process crashed | sandbox_id, sentry_pid, signal, stack_trace, core_pattern |
| `SAN.GV.GoferError` | Gofer encountered an I/O error | sandbox_id, gofer_pid, operation, path, errno, cache_state |
| `SAN.GV.PlatformSwitch` | Platform mode switched at runtime | sandbox_id, old_platform, new_platform, reason |
| `SAN.GV.ContainerOOM` | Container process OOM-killed by Sentry | sandbox_id, pid, oom_score, memory_usage_bytes, memory_limit_bytes |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SAN_GV_001 | Platform initialization failure: KVM not available or ptrace denied | Critical | Fall back to ptrace → systrap chain; if all fail, escalate to container sandbox fallback |
| SAN_GV_002 | Gofer mount failure: rootfs could not be mounted or overlayfs setup failed | Critical | Sandbox creation fails; container image or mount config reviewed for misconfiguration |
| SAN_GV_003 | Sentry crash due to unhandled syscall or kernel panic | Critical | Auto-restart sandbox up to 3 times with exponential backoff; escalate if persistent |
| SAN_GV_004 | Resource limit exceeded: CPU quota, memory limit, or process count | High | Throttle CPU, OOM-kill offending process, or deny fork; violation event logged |
| SAN_GV_005 | Netstack error: TCP connection failure or DNS resolution error | Medium | Retry with degraded network; fall back to host network if sandwich mode fails |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SAN-GV-001 | The Sentry must never execute a host syscall directly on behalf of the sandbox application — all host syscalls are proxied through Gofer or handled by Sentry implementation | Sentry code statically analyzed for syscall instructions; runtime seccomp enforces Sentry-only syscall whitelist |
| SAN-GV-002 | The Gofer process must have strictly fewer capabilities than the Sentry — it can only perform file I/O, not syscall interception | Gofer seccomp profile denies ptrace, seccomp, and process-control syscalls |
| SAN-GV-003 | Sandbox network traffic must not bypass the netstack — raw socket creation is denied by Sentry | Sentry whitelist excludes socket(AF_PACKET), socket(AF_NETLINK), and netfilter syscalls |
| SAN-GV-004 | Sandbox filesystem writes to the lower overlay layer must never persist across sandbox restarts | OverlayFS upper directory is tmpfs mounted at sandbox create, unmounted and discarded at destroy |

## Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | gVisor module does one thing: application-kernel isolation for container workloads |
| R2 — Dependency Order | Compliant | gVisor depends on platform (KVM/ptrace); Sandbox Service depends on runsc OCI runtime |
| R3 — DRY | Compliant | SandboxConfig templates defined once per capability tier; reused across Workers of same tier |
| R4 — Builder Pattern | Compliant | SandboxConfig built by SandboxConfigBuilder with validated OCI spec translation |
| R5 — Liskov Substitution | Compliant | gVisor sandbox conforms to SandboxDriver interface (create, start, stop, destroy) |
| R6 — DI over Singletons | Compliant | gVisor driver injected into SandboxService via platform abstraction layer |
| R7 — Tests Exist | Compliant | Unit tests for syscall filter generation, integration tests for gVisor sandbox lifecycle with runsc |
| R8 — Tests Fast | Compliant | Unit tests complete in <100ms; integration suite <30s with pre-booted Sentry pool |
| R9 — Deterministic Tests | Compliant | Same OCI spec + same image always produces identical Sentry filtering behavior |
| R10 — Prefer Simpler | Compliant | Five configuration components; linear lifecycle; OCI runtime handles container management |
| R11 — Refactor over Rewrite | Compliant | gVisor improvements through runsc version upgrades and Sentry filter configuration |
| R12 — Embrace Errors | Compliant | Every error identifies the component (Sentry/Gofer/Platform), operation, and sandbox state |
| R13 — Design for Failure | Compliant | Sentry crash does not affect host kernel; Gofer failure contained; other sandboxes unaffected |
| R14 — Paved Path | Compliant | All standard Workers execute through the paved gVisor create→start→stop→destroy path |
| R15 — Open/Closed | Compliant | New gVisor features added via Sentry filter rules and Gofer cache policy, not sandbox service changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Isolation.md | Base sandbox architecture; gVisor is the container sandbox driver |
| 004-Seccomp.md | Seccomp profiles applied to Sentry and Gofer processes |
| 005-Namespaces.md | Linux namespaces created by runsc for sandbox isolation |
| 001-Firecracker.md | Alternative sandbox driver for higher isolation tiers |
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; gVisor enforces at application-kernel boundary |
| ../AZS/002-Capability.md | Syscall filters derived from capability bounds; OCI limits mapped to Sentry resources |
| ../Audit/000-EAS.md | Sandbox lifecycle and syscall violations recorded by EAS |
| ../SSM/000-SSM.md | Session secrets injected into sandbox via Gofer file mount or vsock |
| Physics/007-Capabilities.md | Capability Bound invariants enforced by Sentry syscall filtering |
| Physics/008-Security.md | Application-kernel isolation satisfies security verification for standard risk tiers |
| Physics/010-Execution.md | Sandbox lifecycle conforms to execution tenure invariants |
