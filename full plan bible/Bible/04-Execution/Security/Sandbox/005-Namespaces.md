# AIOS Bible — Sandbox (SAN)
## 005 — Linux Namespace Configuration

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Sandbox |
| Document ID | AIOS-BBL-SAN-005 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Linux Namespace Configuration provides process-level isolation through kernel namespace primitives for container and process sandboxes. Namespaces partition kernel resources such that processes in one namespace cannot see or access resources in another namespace. Every container and process sandbox in AIOS is created within a dedicated set of namespaces, providing the foundational isolation layer upon which other security controls (seccomp, capabilities, resource limits) are applied.

Namespaces serve three functions: resource visibility isolation so a Worker cannot see host or other Workers' processes, filesystems, or network interfaces; privilege reduction through user namespace UID/GID remapping enabling rootless operation; and lifecycle scoping so that all sandbox resources are cleaned up when the namespace is destroyed.

## Architecture

Namespaces are created when a sandbox is initialized. The Sandbox service (or the container runtime on its behalf) creates a new set of namespaces and places the Worker process inside them. Each namespace type isolates a different kernel resource. The lifecycle of the namespace is tied to the sandbox lifecycle — when the sandbox is destroyed, its namespaces are torn down.

```
Namespace Creation → Process Entry → Resource Isolation → Namespace Destruction
```

### Namespace Types

| Namespace | Isolates | Creation Flag | Linux Support |
|-----------|----------|---------------|---------------|
| PID | Process ID numbering | `CLONE_NEWPID` | Since 2.6.24 |
| Network | Network devices, stacks, ports | `CLONE_NEWNET` | Since 2.6.29 |
| Mount | Filesystem mount points | `CLONE_NEWNS` | Since 2.4.19 |
| User | UID/GID mappings | `CLONE_NEWUSER` | Since 3.8 |
| UTS | Hostname, domain name | `CLONE_NEWUTS` | Since 2.6.19 |
| IPC | System V IPC, POSIX message queues | `CLONE_NEWIPC` | Since 2.6.19 |
| Cgroup | Cgroup root directory | `CLONE_NEWCGROUP` | Since 4.6 |

### Namespace Creation and Joining

| Operation | Function | Description |
|-----------|----------|-------------|
| Create | `clone(CLONE_NEW* | SIGCHLD)` | Create new process in new namespaces |
| Join | `setns(fd, nstype)` | Attach existing process to existing namespace |
| Unshare | `unshare(CLONE_NEW*)` | Move calling process into new namespaces |
| Query | `nsenter -t pid -n` | Execute command in target namespace |
| List | `ls -la /proc/[pid]/ns/` | List namespace inodes for a process |

## Data Model

```typescript
interface NamespaceConfig {
  id: string;
  sandboxId: string;
  types: NamespaceType[];
  userNamespace?: UserNamespaceConfig;
  networkNamespace?: NetworkNamespaceConfig;
  mountNamespace?: MountNamespaceConfig;
  pidNamespace?: PIDNamespaceConfig;
  utsNamespace?: UTSNamespaceConfig;
  ipcNamespace?: IPCNamespaceConfig;
  cgroupNamespace?: CgroupNamespaceConfig;
  cloneFlags: string[];              // Raw clone flags used for creation
  createdAt: string;
}

type NamespaceType = "pid" | "network" | "mount" | "user" | "uts" | "ipc" | "cgroup";

interface UserNamespaceConfig {
  uidMappings: IDMapping[];
  gidMappings: IDMapping[];
  owner: string;                     // Initial UID/GID owner
  enableRootless: boolean;
  enableSetgroups: boolean;
  denySetgroups: boolean;
}

interface IDMapping {
  containerID: number;               // UID/GID inside the namespace
  hostID: number;                    // UID/GID on the host
  range: number;                     // Range of IDs mapped
}

interface UserNamespaceMap {
  namespaceId: string;
  processId: number;
  uid: number;
  effectiveUID: number;
  gid: number;
  effectiveGID: number;
  supplementaryGIDs: number[];
  capabilities: string[];            // Effective capabilities after mapping
}

interface NetworkNamespaceConfig {
  vethPairs: VethPair[];
  bridgeName?: string;
  mtu: number;
  loopbackUp: boolean;
  ipForwarding: boolean;
  arpProxy: boolean;
  interfaces: NetworkInterfaceConfig[];
  routes: RouteConfig[];
  rules: RoutingPolicyRule[];
  firewall: FirewallRule[];
}

interface VethPair {
  hostName: string;                  // veth endpoint on host
  containerName: string;             // veth endpoint inside namespace
  peerIndex: number;                 // Interface index in namespace
}

interface NetworkInterfaceConfig {
  name: string;
  addresses: string[];
  mtu: number;
  hwAddress: string;
  state: "up" | "down";
  master?: string;                   // Bridge name if bridged
}

interface RouteConfig {
  destination: string;
  gateway: string;
  source: string;
  metric: number;
  table: number;
}

interface RoutingPolicyRule {
  priority: number;
  from: string;
  to: string;
  table: number;
  fwmark: number;
}

interface FirewallRule {
  table: "filter" | "nat" | "mangle";
  chain: string;
  protocol: string;
  source: string;
  destination: string;
  match: string;
  action: "ACCEPT" | "DROP" | "REJECT" | "MASQUERADE";
}

interface MountNamespaceConfig {
  mounts: MountConfig[];
  pivotRoot: PivotRootConfig;
  propagation: MountPropagation;
  sharedMounts: string[];
  slaveMounts: string[];
  privateMounts: string[];
  unbindableMounts: string[];
}

interface MountConfig {
  source: string;
  destination: string;
  type: string;
  options: string[];
  flags: MountFlag;
  bind: boolean;
  recursive: boolean;
  readonly: boolean;
}

interface MountFlag {
  bind: boolean;
  recursive: boolean;
  slave: boolean;
  shared: boolean;
  private: boolean;
  unbindable: boolean;
  nosuid: boolean;
  nodev: boolean;
  noexec: boolean;
  relatime: boolean;
  ro: boolean;
}

type MountPropagation = "shared" | "slave" | "private" | "unbindable";

interface PivotRootConfig {
  newRoot: string;                   // New root filesystem path
  putOld: string;                    // Old root placement path
  enabled: boolean;
}

interface PIDNamespaceConfig {
  initProcess: string;               // Path to init process binary
  initArgs: string[];
  enableReaping: boolean;            // Reap orphaned child processes
  maxProcesses: number;              // PID limit within namespace
}

interface UTSNamespaceConfig {
  hostname: string;
  domainname?: string;
}

interface IPCNamespaceConfig {
  enableSemaphores: boolean;
  enableMessageQueues: boolean;
  enableSharedMemory: boolean;
  shmmax: number;                    // Max shared memory segment size
  shmall: number;                    // Max total shared memory
  semmsl: number;                    // Max semaphores per array
  semmns: number;                    // Max semaphore arrays system-wide
}

interface CgroupNamespaceConfig {
  cgroupRoot: string;
  controllers: string[];             // e.g., ["cpu", "memory", "pids", "blkio"]
  cgroupVersion: "v1" | "v2";
  enableCgroupNS: boolean;
}
```

## Core Concepts / Operations

### User Namespace Mapping (UID/GID Remapping)

User namespaces allow a process to run with root privileges inside the namespace while having no privileges on the host. The UID/GID mapping defines the translation between namespace UIDs and host UIDs:

| Mapping Type | Container ID | Host ID | Range | Purpose |
|-------------|--------------|---------|-------|---------|
| UID mapping | 0 (root) | 100000 | 65536 | Root in namespace is unprivileged user on host |
| UID mapping | 1000 (app) | 101000 | 1 | Application user identity preserved |
| GID mapping | 0 (root) | 100000 | 65536 | Root group mapped to unprivileged host group |
| GID mapping | 1000 (app) | 101000 | 1 | Application group identity preserved |

Rootless operation is achieved entirely through user namespace mapping — the Worker process believes it is running as root but has no actual host privileges.

### Network Namespace Isolation (Veth Pairs, Bridge)

Each network namespace receives a virtual Ethernet (veth) pair. One end resides in the host network namespace, the other inside the sandbox namespace:

```
Host Namespace                     Sandbox Namespace
┌─────────────────┐               ┌───────────────────┐
│ veth-host-XXXX  │───────────────│ veth-sandbox-XXXX  │
│ 172.16.0.1/24   │   veth pair   │ 172.16.0.2/24      │
└────────┬────────┘               └────────┬──────────┘
         │                                   │
    ┌────┴────┐                        ┌────┴──────┐
    │ Bridge  │                        │ Loopback  │
    │ aios-br0 │                        │ lo        │
    └─────────┘                        └───────────┘
```

| Component | Configuration | Purpose |
|-----------|--------------|---------|
| Veth host | `veth-sandbox-XXXX` | Host endpoint of veth pair |
| Veth sandbox | `eth0` | Sandbox endpoint of veth pair |
| Bridge | `aios-br0` | Connects sandbox veths to ACF proxy |
| Loopback | `lo` (up) | Internal sandbox communication |
| IP assignment | DHCP or static per sandbox | Addressing within ACF network |

### Mount Namespace Setup (pivot_root, OverlayFS)

Mount namespaces provide filesystem isolation. Each sandbox gets a private mount tree:

| Layer | Type | Source | Destination | Flags | Persistence |
|-------|------|--------|-------------|-------|-------------|
| Rootfs | bind | Container image | `/` | ro, nosuid, nodev | Immutable |
| Overlay upper | tmpfs | tmpfs | `/upper` | rw, noexec | Destroyed with sandbox |
| Overlay work | tmpfs | tmpfs | `/work` | rw, noexec | Destroyed with sandbox |
| Scratch | tmpfs | tmpfs | `/scratch` | rw, noexec, size=X | Destroyed with sandbox |
| Data volumes | bind | Host paths | `/data/*` | rw or ro | Persistent |
| Proc | proc | procfs | `/proc` | rw, nosuid, nodev, noexec | Virtual |
| Sys | sysfs | sysfs | `/sys` | ro, nosuid, nodev, noexec | Virtual |
| Dev | tmpfs | tmpfs | `/dev` | rw, nosuid, strictatime | Virtual |

The `pivot_root` system call changes the root filesystem of the process, ensuring the sandbox process cannot access any host filesystem paths.

### PID Namespace (Process Isolation, Init Process)

PID namespaces provide process numbering isolation. The first process in a PID namespace becomes PID 1 (init). This init process is responsible for:

| Responsibility | Implementation | Consequence of Failure |
|---------------|---------------|----------------------|
| Reaping orphans | `waitpid()` in a loop | Zombie processes accumulate |
| Signal forwarding | Forward SIGTERM/SIGINT to child processes | Workers not cleanly terminated |
| Child exit status | Collect exit codes from children | Lost evidence data |

### Cgroup Namespace for Resource Tracking

Cgroup namespaces virtualize the cgroup filesystem so that a process inside the namespace sees only its own cgroup hierarchy. This prevents the Worker from:

- Seeing other Workers' cgroup resource usage
- Modifying its own cgroup resource limits
- Escaping resource accounting by writing to cgroup files

| Controller | Resource | Mount Point | Version |
|------------|----------|-------------|---------|
| cpu | CPU quota, shares, period | `/sys/fs/cgroup/cpu` | v1 or v2 |
| memory | Memory limit, OOM control | `/sys/fs/cgroup/memory` | v1 or v2 |
| pids | Process count limit | `/sys/fs/cgroup/pids` | v1 or v2 |
| blkio | Block I/O limits | `/sys/fs/cgroup/blkio` | v1 or v2 (io) |
| cpuset | CPU/memory node assignment | `/sys/fs/cgroup/cpuset` | v1 or v2 |

### Namespace Lifecycle Tied to Sandbox Lifecycle

| Sandbox Phase | Namespace Operation | Actions |
|---------------|--------------------|---------|
| Create | Namespace creation | Create all configured namespaces via `clone(CLONE_NEW*)` |
| Initialize | Process entry | Move Worker process into namespaces via `setns()` |
| Execute | Namespace active | Process operates within namespace isolation |
| Destroy | Namespace cleanup | Terminate all processes in namespace; release namespace references |

When a sandbox is destroyed, all processes in its namespaces are killed, and the namespace references are released. The kernel automatically cleans up namespace resources when the last process exits and the last file descriptor referencing the namespace is closed.

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| Namespace Creation | Sandbox Service (via `clone`) | Workers | System call |
| Namespace Joining | Sandbox Service (via `setns`) | Workers | System call |
| UID/GID Mapping | Sandbox Service (via `/proc/[pid]/uid_map`) | Kernel | File write |
| Veth Setup | Sandbox Service (via `ip link`) | Kernel | Netlink |
| Bridge Setup | Sandbox Service (via `ip link`, `brctl`) | Kernel | Netlink |
| Mount Setup | Sandbox Service (via `mount`) | Kernel | System call |
| Cgroup Assignment | Sandbox Service (via cgroupfs) | Kernel | File write |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `SAN.NS.NamespaceCreated` | New namespace set created | namespace_id, sandbox_id, types[], clone_flags, init_pid |
| `SAN.NS.NamespaceJoined` | Process entered existing namespace | namespace_id, process_pid, nstype, fd |
| `SAN.NS.UserMapped` | UID/GID mapping written | namespace_id, uid_mappings[], gid_mappings[], enable_rootless |
| `SAN.NS.NetworkSetup` | Network namespace configured | namespace_id, veth_host, veth_sandbox, bridge_name, addresses[], routes[] |
| `SAN.NS.MountSetup` | Mount namespace configured | namespace_id, mounts[], pivot_root_enabled, propagation_type |
| `SAN.NS.PIDInitStarted` | PID namespace init process started | namespace_id, pid_ns_init_pid, init_process_path, max_processes |
| `SAN.NS.CgroupAttached` | Process attached to cgroup controllers | namespace_id, process_pid, cgroup_path, controllers[] |
| `SAN.NS.NamespaceDestroyed` | Namespace destroyed | namespace_id, sandbox_id, process_count, remaining_pids |
| `SAN.NS.EscalationAttempt` | Process attempted to escape namespace by joining host namespace | namespace_id, process_pid, target_ns_type, target_ns_inode, denied_reason |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SAN_NS_001 | Namespace creation failure: kernel not configured for requested namespace type | Critical | Fall back to container sandbox without affected namespace; escalate to Operator |
| SAN_NS_002 | UID/GID mapping rejection: kernel denied mapping due to `max_user_namespaces` limit | High | Reduce sandbox count; increase `max_user_namespaces` sysctl; re-queue request |
| SAN_NS_003 | Veth pair creation failure: exhausted network interfaces or kernel module not loaded | High | Re-use existing namespace network stack if compatible; escalate to Operator |
| SAN_NS_004 | Mount setup failure: overlayfs or tmpfs mount failed | High | Bind-mount rootfs without overlay; log degraded isolation; escalate to Operator |
| SAN_NS_005 | PID namespace init process crash: PID 1 process died unexpectedly | Critical | Terminate all processes in namespace; destroy sandbox; capture init crash log for forensic |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SAN-NS-001 | No process inside a sandbox namespace may have more capabilities on the host than an unprivileged user | User namespace UID mapping ensures all container UIDs map to unprivileged host UIDs |
| SAN-NS-002 | A process inside a mount namespace must not be able to access files outside its root | pivot_root changes the process root; all host mounts are made private or slave before pivot |
| SAN-NS-003 | Network traffic from a sandbox namespace must pass through the ACF network proxy | veth host endpoint is bridged to ACF proxy bridge; no direct host network access |
| SAN-NS-004 | All processes in a PID namespace must be terminated before the namespace is destroyed | Sandbox destroy sends SIGKILL to each process; waits for process exit before namespace release |
| SAN-NS-005 | The cgroup namespace must prevent the sandbox process from viewing or modifying host cgroup hierarchies | Cgroup namespace virtualizes `/sys/fs/cgroup` root; process sees only its own cgroup subtree |

## Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | Namespace configuration does one thing: kernel resource isolation through namespaces |
| R2 — Dependency Order | Compliant | Namespace creation depends on kernel namespace support; Sandbox Service depends on namespace config |
| R3 — DRY | Compliant | Namespace templates defined once per sandbox type; reused across sandboxes of same type |
| R4 — Builder Pattern | Compliant | NamespaceConfig built by NamespaceBuilder with validated UID/GID mappings and mount layout |
| R5 — Liskov Substitution | Compliant | Any namespace configuration (PID/Network/Mount) conforms to NamespaceConfig interface |
| R6 — DI over Singletons | Compliant | Namespace service injected into SandboxService for namespace lifecycle management |
| R7 — Tests Exist | Compliant | Unit tests for UID/GID mapping validation, mount configuration; integration tests for namespace lifecycle |
| R8 — Tests Fast | Compliant | Unit tests complete in <10ms; integration tests <2s with unprivileged user namespace support |
| R9 — Deterministic Tests | Compliant | Same namespace config always produces identical process isolation behavior |
| R10 — Prefer Simpler | Compliant | Seven namespace types with straightforward create→join→destroy lifecycle; no complex orchestration |
| R11 — Refactor over Rewrite | Compliant | Namespace configuration improvements through kernel parameter tuning, not isolation model changes |
| R12 — Embrace Errors | Compliant | Every namespace operation error identifies the namespace type, operation, and affected process |
| R13 — Design for Failure | Compliant | Namespace creation failure does not affect host; failed sandbox namespace is cleaned up completely |
| R14 — Paved Path | Compliant | All container and process sandboxes execute through the paved create→join→isolate→destroy path |
| R15 — Open/Closed | Compliant | New namespace types added via kernel updates, not sandbox service modification |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Isolation.md | Base sandbox architecture; namespaces provide OS-level process isolation |
| 001-Firecracker.md | Firecracker jailer uses Linux namespaces for MicroVM process isolation |
| 002-gVisor.md | runsc OCI runtime creates namespaces for gVisor sandbox isolation |
| 003-WASM.md | WASM runtime uses namespaces when running in container mode |
| 004-Seccomp.md | Seccomp provides syscall-level isolation complementing namespace resource isolation |
| ../Execution-Auth/000-EAS.md | Pipeline authorizes execution; namespaces enforce at kernel resource boundary |
| ../AZS/002-Capability.md | Namespace isolation parameters derived from capability bounds |
| ../Audit/000-EAS.md | Namespace lifecycle events recorded by EAS |
| Physics/007-Capabilities.md | Capability Bound invariants enforced by namespace resource isolation |
| Physics/008-Security.md | Namespace isolation satisfies process-level security verification |
| Physics/010-Execution.md | Namespace lifecycle conforms to execution tenure invariants |
