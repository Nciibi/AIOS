# AIOS Bible — Sandbox (SAN)
## 001 — Firecracker MicroVM

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-001 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Firecracker MicroVM sandbox provides hardware-virtualized isolation for Worker execution under the highest-risk tiers (L0 Workers, L3–L4 risk-tier Workers). Under Law 7 (Capability Bounds), Firecracker enforces the strictest resource and security boundaries — each MicroVM runs a minimal Linux guest with no shared kernel surface, eliminating container escape as a threat vector. Firecracker is designed for multi-tenant workloads where Workers must be isolated at the hardware level with cryptographic guarantee.

Firecracker serves three specific roles: high-isolation Worker execution requiring guaranteed tenant separation, execution of Workers with elevated or dangerous capability declarations that demand kernel-level isolation, and sandboxing for adversarial or untrusted Workers whose compromise must not affect any other tenant or the host system.

## Architecture

Firecracker instances are managed by the Sandbox service through the Firecracker VMM API. Each MicroVM runs a stripped Linux kernel (5.10+ with virtio drivers) inside a jailer-managed process with seccomp-bpf filters. The host communicates with the guest via virtio-mmio devices: block devices for root filesystem and scratch storage, vsock for control plane signaling, and virtio-net for network I/O.

### MicroVM Lifecycle

```
Request → Create → Configure → Start → Monitor → Stop → Destroy
```

1. **Request**: Sandbox service evaluates Worker capability declaration and selects Firecracker when isolation policy requires hardware-level separation.
2. **Create**: The jailer spawns a Firecracker VMM process in a dedicated chroot with dropped capabilities. A unique MicroVM ID is assigned.
3. **Configure**: MicroVM resources are configured via the VMM API — CPU template, memory size, boot source, block devices, network interfaces, vsock.
4. **Start**: The guest kernel boots from the configured rootfs. The Worker binary is loaded via vsock after boot completion signal.
5. **Monitor**: Resource consumption, guest health, and jailer violations are monitored continuously. Metrics are collected every 100ms.
6. **Stop**: A graceful shutdown signal is sent via vsock. If the guest does not respond within the configured timeout (default 30s), a forceful halt is issued.
7. **Destroy**: The MicroVM is destroyed, all resources released, and accounting evidence collected for EAS.

## Data Model

```typescript
interface MicroVMConfig {
  id: string;
  vmID: string;
  jailer: JailerConfig;
  bootSource: BootSource;
  machineConfig: MachineConfig;
  blockDevices: BlockDevice[];
  networkInterfaces: NetworkInterface[];
  vsock: VsockConfig;
  metrics: MetricsConfig;
  logging: LoggingConfig;
}

interface JailerConfig {
  chrootBaseDir: string;
  execFile: string;
  uid: number;
  gid: number;
  cgroupVersion: string;
  numCgroups: number;
  daemonize: boolean;
  node: number;                    // NUMA node
  seccompLevel: number;           // 0=none, 1=basic, 2=advanced
  extraArgs: string[];
  resourceLimits: ResourceLimits;
}

interface BootSource {
  kernelImagePath: string;
  bootArgs: string;
  initrdPath?: string;
}

interface MachineConfig {
  vcpuCount: number;
  memSizeMib: number;
  htEnabled: boolean;
  trackDirtyPages: boolean;
  cpuTemplate: CpuTemplate;
}

type CpuTemplate = "C3" | "T2" | "T2S" | "T2CL" | "T2A" | "V1N1";

interface BlockDevice {
  driveId: string;
  pathOnHost: string;
  isRootDevice: boolean;
  isReadOnly: boolean;
  partUuid?: string;
  rateLimiter?: RateLimiter;
  cacheType: "Sync" | "Unsafe" | "Writeback";
  ioEngine: "Sync" | "Async";
}

interface NetworkInterface {
  ifaceId: string;
  hostDevName: string;
  guestMAC: string;
  rxRateLimiter?: RateLimiter;
  txRateLimiter?: RateLimiter;
  allowMmdsRequests: boolean;
}

interface RateLimiter {
  bandwidth: {
    size: number;                  // Bytes
    oneTimeBurst: number;          // Bytes
    refillTime: number;            // Milliseconds
  };
  ops: {
    size: number;                  // Ops count
    oneTimeBurst: number;
    refillTime: number;
  };
}

interface VsockConfig {
  vsockId: string;
  guestCid: number;
  udsPath: string;
}

interface VMMAction {
  actionType: "InstanceStart" | "InstanceHalt" | "SendCtrlAltDel" |
              "FlushMetrics" | "CreateSnapshot" | "LoadSnapshot" |
              "ResumeVM" | "PauseVM";
  snapshotPath?: string;
  memFilePath?: string;
}

interface MetricsConfig {
  metricsPath: string;
  metricsPeriodMs: number;
}

interface LoggingConfig {
  logPath: string;
  level: "Error" | "Warning" | "Info" | "Debug";
  showLevel: boolean;
  showLogOrigin: boolean;
}

interface Snapshot {
  snapshotId: string;
  vmID: string;
  snapshotType: "Full" | "Diff";
  snapshotPath: string;
  memFilePath: string;
  createdAt: string;
  sizeBytes: number;
  checksum: string;
  bootSource: BootSource;
}

interface NetworkMetrics {
  ifaceId: string;
  rxBytes: number;
  rxPackets: number;
  txBytes: number;
  txPackets: number;
  rxDropped: number;
  txDropped: number;
  rxErrors: number;
  txErrors: number;
  rxRateLimitedCount: number;
  txRateLimitedCount: number;
}

interface BlockMetrics {
  driveId: string;
  readBytes: number;
  readCount: number;
  writeBytes: number;
  writeCount: number;
  readRateLimitedCount: number;
  writeRateLimitedCount: number;
}

interface Metrics {
  vmID: string;
  timestamp: string;
  network: NetworkMetrics[];
  block: BlockMetrics[];
  vsock: {
    txBytes: number;
    rxBytes: number;
    connections: number;
  };
  apiServer: {
    requestsCount: number;
    failsCount: number;
  };
}
```

## Core Concepts / Operations

### Firecracker VMM Integration

The Sandbox service communicates with each Firecracker instance over a local Unix socket using the Firecracker VMM HTTP API. The API exposes endpoints for configuring the MicroVM, starting/stopping the instance, attaching block devices and network interfaces, and retrieving metrics. The VMM API is authenticated by the sandbox service identity — only the Sandbox service has socket access within the jailer chroot.

### MicroVM Lifecycle Operations

| Operation | Description | Preconditions | Postconditions |
|-----------|-------------|---------------|----------------|
| Create | Jailer spawns Firecracker VMM process | Capability declaration reviewed, resource limits computed | VMM process running in chroot, API socket listening |
| Configure | Set machine config, boot source, devices, network, vsock | VMM process running, API socket available | All device and network configurations applied |
| Start | Boot guest kernel | Configuration complete | Guest kernel booting, vsock ready for Worker load |
| Monitor | Poll metrics, check jailer liveness | MicroVM running | Metrics collected, violations detected |
| Stop | Send halt signal, force if needed | MicroVM running | Guest halted gracefully or forcefully |
| Destroy | Kill VMM process, release resources | MicroVM stopped | Chroot removed, resources freed, evidence collected |

### Resource Limits Per MicroVM

| Resource | Configuration Field | Enforcement | Default |
|----------|-------------------|-------------|---------|
| vCPU Count | `machineConfig.vcpuCount` | Hardware virtualization | 1 (range: 1–32) |
| Memory Size | `machineConfig.memSizeMib` | Hardware MMU | 512 MiB (range: 128–65536) |
| CPU Template | `machineConfig.cpuTemplate` | CPU feature masking | T2 (range: C3, T2, T2S, T2CL, T2A, V1N1) |
| Block Device | `blockDevices[]` | virtio-blk rate limiter | 1 rootfs (RO) + 1 scratch (RW, 1 GiB) |
| Network | `networkInterfaces[]` | virtio-net rate limiter | 1 interface, 100 Mbps cap |
| Seccomp | `jailer.seccompLevel` | seccomp-bpf filter | Level 2 (advanced) |

### Network Configuration

Each MicroVM receives a dedicated TAP device on the host, bridged to the ACF network proxy. MAC addresses are assigned from a managed pool based on the MicroVM ID. Rate limiting is enforced at the virtio-net layer using token bucket filters.

| Parameter | Configuration | Purpose |
|-----------|--------------|---------|
| Host Device | `hostDevName` | TAP device name on host |
| Guest MAC | `guestMAC` | Unique MAC from managed pool |
| RX Rate | `rxRateLimiter` | Ingress bandwidth limit |
| TX Rate | `txRateLimiter` | Egress bandwidth limit |

### Block Device Mapping

| Device | Role | Type | Size | Caching |
|--------|------|------|------|---------|
| Rootfs | Guest OS root | Read-only | 512 MiB | Unsafe |
| Scratch | Worker scratch space | Read-write | 1–10 GiB | Writeback |
| Data | Optional data volume | Read-only | Configurable | Unsafe |

### Snapshot/Restore

Snapshots enable fast MicroVM startup by saving and restoring the guest memory and disk state:

- **Full snapshot**: Complete guest memory + disk state. Used for baseline saves.
- **Diff snapshot**: Memory pages changed since last snapshot. Used for incremental saves.
- **Restore**: Load a saved snapshot and resume execution. Used for hot-start pools.

A pre-booted MicroVM pool maintains 5–10 instances in memory-suspended state for sub-second Worker startup.

### Security Hardening

| Control | Implementation | Effect |
|---------|---------------|--------|
| Seccomp (Jailer) | Level 2 (advanced) seccomp-bpf | All syscalls filtered except minimum VMM set (~50 syscalls) |
| Dropped Capabilities | `capabilities(7)` drop all except CAP_NET_ADMIN, CAP_SYS_ADMIN | Least privilege for VMM process |
| Readonly Root | Root filesystem mounted readonly | Prevents guest modification of OS |
| Chroot | Jailer chroot per MicroVM | Filesystem isolation for VMM process |
| Cgroup Assignment | Dedicated cgroup per MicroVM | Resource isolation at host level |
| NUMA Pinning | Fixed NUMA node assignment | CPU/memory locality, cache isolation |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| VMM API | Firecracker Instance | Sandbox Service | HTTP/Unix Socket |
| Jailer | Firecracker Binary | Sandbox Service | Process exec |
| Vsock | Guest Kernel | Host Agent | virtio-vsock |
| Snapshot Store | Filesystem | Sandbox Service | File I/O |
| Metrics | Firecracker Instance | Sandbox Service | File polling |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.FC.MicroVMCreated` | MicroVM created via jailer | microvm_id, worker_id, vcpu_count, mem_mib, cpu_template, jailer_pid |
| `SAN.FC.MicroVMStarted` | Guest kernel boot completed | microvm_id, boot_duration_ms, kernel_version, vsock_cid |
| `SAN.FC.MicroVMStopped` | MicroVM halted | microvm_id, uptime_ms, stop_reason, graceful_flag |
| `SAN.FC.MicroVMDestroyed` | MicroVM destroyed, resources released | microvm_id, uptime_ms, peak_memory_mib, total_cpu_ms, evidence_sent |
| `SAN.FC.ResourceLimitHit` | Resource limit exceeded | microvm_id, resource_type, limit_value, actual_value, duration_ms |
| `SAN.FC.NetworkBlocked` | Network rate limit exceeded | microvm_id, iface_id, direction, current_rate_bps, limit_bps |
| `SAN.FC.SnapshotCreated` | Snapshot created | snapshot_id, microvm_id, snapshot_type, size_bytes, duration_ms |
| `SAN.FC.SnapshotRestored` | Snapshot restored | snapshot_id, microvm_id, restore_duration_ms, resumed_flag |
| `SAN.FC.JailerViolation` | Jailer detected a security violation | microvm_id, violation_type, syscall_number, process_pid, seccomp_level |
| `SAN.FC.MetricsReported` | Metrics snapshot collected | microvm_id, network_metrics[], block_metrics[], vsock_metrics, api_metrics |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SAN_FC_001 | Jailer spawn failure: insufficient resources or permission denied | Critical | Retry with fallback to container sandbox if configured; escalate to Security Council |
| SAN_FC_002 | MicroVM configure failure: invalid device mapping or resource config | Critical | Destroy VMM process; log misconfiguration; escalate to Operator |
| SAN_FC_003 | Guest kernel boot timeout: kernel panic or driver init failure | Critical | Force halt; capture serial console output for forensic; destroy MicroVM |
| SAN_FC_004 | Snapshot load failure: corrupted snapshot or version mismatch | High | Fall back to full boot; rebuild snapshot from known-good state; alert Operator |
| SAN_FC_005 | Resource overcommit: host cannot satisfy requested resource limits | High | Reject request; surface available capacity to scheduler for re-routing |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SAN-FC-001 | Every MicroVM executes in a jailer chroot with Level 2 seccomp applied before kernel boot | Jailer startup validates chroot path; seccomp filter loaded before fork |
| SAN-FC-002 | No two MicroVMs share the same vCPU core or NUMA node without explicit affinity isolation | VMM CPU pinning ensures exclusive core assignment per MicroVM |
| SAN-FC-003 | All block devices except scratch are mounted read-only in the guest | Guest kernel enforces readonly via virtio-blk read-only flag; host ratifies by block device config |
| SAN-FC-004 | Snapshot integrity is verified by checksum before restore operation | LoadSnapshot validates SHA-256 checksum of snapshot file before memory load |
| SAN-FC-005 | MicroVM destruction is idempotent — calling destroy twice on the same MicroVM must not error | Destroy operation checks MicroVM state; already-destroyed MicroVM returns success without action |

## Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | Firecracker module does one thing: hardware-isolated MicroVM management |
| R2 — Dependency Order | Compliant | Firecracker depends on KVM and jailer; Sandbox Service depends on Firecracker API |
| R3 — DRY | Compliant | MicroVM templates defined once per CPU/memory profile; reused across instances |
| R4 — Builder Pattern | Compliant | MicroVMConfig built by MicroVMBuilder with validated resource envelopes |
| R5 — Liskov Substitution | Compliant | MicroVM sandbox conforms to SandboxDriver interface (create, start, stop, destroy, metrics) |
| R6 — DI over Singletons | Compliant | Firecracker driver injected into SandboxService via platform abstraction |
| R7 — Tests Exist | Compliant | Unit tests for config validation, integration tests for VM lifecycle with real Firecracker binary |
| R8 — Tests Fast | Compliant | Snapshot restore tests complete in <500ms; full lifecycle suite <10s |
| R9 — Deterministic Tests | Compliant | Same config + same kernel image always produces identical MicroVM behavior |
| R10 — Prefer Simpler | Compliant | Four lifecycle states; VMM API is a single HTTP endpoint; no orchestration layer |
| R11 — Refactor over Rewrite | Compliant | Sandbox improvements through Firecracker version upgrades and driver config changes |
| R12 — Embrace Errors | Compliant | Every error identifies the MicroVM ID, operation, and kernel state at failure |
| R13 — Design for Failure | Compliant | MicroVM failure contained within jailer chroot; host unaffected; neighbor MicroVMs unaffected |
| R14 — Paved Path | Compliant | All high-isolation Workers execute through the paved MicroVM create→configure→start→destroy path |
| R15 — Open/Closed | Compliant | New Firecracker features added via VMM API extension, not sandbox service modification |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Isolation.md | Base sandbox architecture; Firecracker is the MicroVM sandbox driver |
| 004-Seccomp.md | Seccomp profiles applied to Firecracker jailer and guest kernel |
| 005-Namespaces.md | Linux namespaces used by jailer for MicroVM process isolation |
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; MicroVM enforces at hardware level |
| ../AZS/002-Capability.md | Resource limits derived from capability bounds; MicroVM templates selected by risk tier |
| ../Audit/000-EAS.md | MicroVM lifecycle evidence recorded by EAS |
| ../SSM/000-SSM.md | Session secrets injected into guest via vsock channel |
| Physics/007-Capabilities.md | Capability Bound invariants enforced by MicroVM resource configuration |
| Physics/008-Security.md | Hardware isolation satisfies security verification for L0 Workers |
| Physics/010-Execution.md | MicroVM lifecycle conforms to execution tenure invariants |
