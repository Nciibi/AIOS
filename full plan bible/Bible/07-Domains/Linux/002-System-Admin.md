# AIOS Bible — Domains
## Linux — 002: System Administration

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-LNX-002 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to manage Linux system state — users, services, packages, and filesystems — across single nodes or fleets via declarative, idempotent operations.

## Architecture

System administration follows a playbook-driven model. Desired state is defined in resource manifests (UserAccount, SystemService, etc.) which are reconciled by the SysAdminWorker agent. A playbook is an ordered collection of operations that can target one or many hosts. Each operation is dry-run before apply to verify correctness. Execution reports are stored as RunbookRecord entries for audit compliance.

### Architecture Flow

```text
┌─────────────────────────────────────────────────────────────────┐
│                     SysAdminWorker Agent                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ User     │  │ Service  │  │ Package  │  │ Filesys  │        │
│  │ Handler  │  │ Handler  │  │ Handler  │  │ Handler  │        │
│  └─────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│        │             │             │             │              │
│  ┌─────▼─────────────▼─────────────▼─────────────▼─────┐       │
│  │              Playbook Engine                          │       │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │       │
│  │  │ Dry-Run    │  │ Execution  │  │ Rollback      │  │       │
│  │  │ Validator  │  │ Runner     │  │ Manager       │  │       │
│  │  └────────────┘  └────────────┘  └───────────────┘  │       │
│  └───────────────────────┬──────────────────────────────┘       │
│                          │                                      │
│  ┌───────────────────────▼──────────────────────────────┐       │
│  │              Live System State                        │       │
│  │  /etc/passwd   systemctl   dpkg/rpm   /etc/fstab     │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model (TypeScript interfaces)

```typescript
interface UserAccount {
  username: string;
  uid?: number;
  gid?: number;
  groups: string[];
  shell: string;
  homeDir: string;
  sshKeys: string[];
  passwordHash?: string;
  state: 'present' | 'absent';
}

interface SystemService {
  name: string;
  state: 'running' | 'stopped' | 'restarted' | 'reloaded';
  enabled: boolean;
  unitFile?: string;
  environment: Record<string, string>;
  dropIns: Record<string, string>;
}

interface PackageManifest {
  name: string;
  version?: string;
  repository: string;
  state: 'installed' | 'absent' | 'latest';
  holds: boolean;
  architecture?: string;
}

interface FileSystemConfig {
  mountPoint: string;
  device: string;
  fstype: string;
  options: string[];
  dump: number;
  pass: number;
  state: 'mounted' | 'unmounted' | 'absent';
}

interface CronJob {
  name: string;
  command: string;
  schedule: string;
  user: string;
  state: 'present' | 'absent';
  environment: Record<string, string>;
}

interface LogrotateConfig {
  path: string;
  rotationInterval: 'daily' | 'weekly' | 'monthly';
  rotate: number;
  compress: boolean;
  delayCompress: boolean;
  postrotateScript?: string;
  state: 'present' | 'absent';
}

interface SelinuxContext {
  path: string;
  user?: string;
  role?: string;
  type?: string;
  level?: string;
  recursive: boolean;
  state: 'applied' | 'absent';
}
```

## Core Concepts / Operations

- **manage_user(user)** — creates or removes user account with groups, shell, and SSH keys
- **configure_service(service)** — ensures service is in desired run state and enablement
- **install_package(manifest)** — installs, removes, or updates a package from repository
- **mount_filesystem(config)** — mounts or unmounts filesystem per fstab specification
- **run_playbook(operations, targets)** — executes sequence of operations across hosts with dry-run
- **dry_run_playbook(operations, targets)** — previews changes without applying them

### Operations Table

| Operation | Description | Preconditions | Postconditions |
|-----------|-------------|---------------|----------------|
| manage_user | Creates or removes user account with groups, shell, SSH keys | Valid username; sudo/capability for useradd/usermod | User created/removed; SSH keys deployed; groups assigned |
| configure_service | Ensures service is in desired run state and enablement | Service unit file exists; systemd accessible | Service started/stopped/restarted; enable symlink set |
| install_package | Installs, removes, or updates package from repository | Package repository reachable; dpkg/rpm available | Package installed/removed/updated; holds preserved |
| mount_filesystem | Mounts or unmounts filesystem per fstab specification | Device accessible; fstab entry valid | Filesystem mounted/unmounted; fstab updated |
| run_playbook | Executes sequence of operations across hosts with dry-run | Playbook validated; all targets reachable | Operations applied in order; RunbookRecord created |
| dry_run_playbook | Previews changes without applying them | Playbook parsed; targets accessible | Diff output produced; no system state changed |
| schedule_cron_job | Creates, updates, or removes cron job entry | cron daemon running; crontab accessible | Cron entry added/removed; next run scheduled |
| configure_logrotate | Sets log rotation policy for a service | Logrotate installed; log directory exists | Logrotate config written; rotation schedule active |
| manage_selinux_context | Applies SELinux file context to path | SELinux enabled; restorecon/semanage available | File context applied; SELinux policy updated |
| set_firewalld_zone | Assigns firewalld zone to interfaces | firewalld running; zone exists | Interface assigned to zone; firewall rules reloaded |

## Internal Interfaces (table)

| Interface | Provider | Consumer | Purpose |
|-----------|----------|----------|---------|
| IUserManager | UserHandler | SysAdminWorker | CRUD user accounts |
| IServiceManager | ServiceHandler | SysAdminWorker | Start/stop/enable services |
| IPackageManager | PackageHandler | SysAdminWorker | Install/remove packages |
| IFilesystemManager | FsHandler | SysAdminWorker | Mount/unmount filesystems |
| IPlaybookEngine | PlaybookRunner | SysAdminWorker | Execute ordered operation sets |
| ICronManager | CronHandler | SysAdminWorker | Manage cron job entries |
| ILogrotateManager | LogrotateHandler | SysAdminWorker | Configure log rotation policies |
| ISelinuxManager | SelinuxHandler | SysAdminWorker | Apply SELinux file contexts |

## Events (table)

| Event | Emitter | Payload | Meaning |
|-------|---------|---------|---------|
| Linux.UserCreated | UserHandler | { username, uid, groups } | User account created |
| Linux.UserDeleted | UserHandler | { username } | User account removed |
| Linux.UserModified | UserHandler | { username, changes } | User account attributes changed |
| Linux.ServiceRestarted | ServiceHandler | { serviceName, reason } | Service restarted |
| Linux.ServiceFailed | ServiceHandler | { serviceName, error } | Service failed to start/stop |
| Linux.PackageOperation | PackageHandler | { packageName, operation, version } | Package installed/removed/updated |
| Linux.FilesystemMounted | FsHandler | { mountPoint, device, fstype } | Filesystem mounted |
| Linux.FilesystemUnmounted | FsHandler | { mountPoint } | Filesystem unmounted |

## Error Cases (table with Code, Condition, Severity, Recovery)

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SYS-001 | Service dependency cycle detected | Error | Reject playbook, report dependency graph cycle |
| SYS-002 | Package dependency conflict | Error | Report conflicting packages, suggest resolution |
| SYS-003 | Permission denied on system operation | Warning | Log failure, verify capability grants and sudoers |
| SYS-004 | Mount point already in use | Error | Unmount active mount or choose different path |
| SYS-005 | User already exists with conflicting UID | Warning | Skip user creation, log conflict for review |
| SYS-006 | Playbook operation timeout | Error | Halt playbook, roll back completed ops if configured |
| SYS-007 | Package repository unreachable | Warning | Log, attempt to use local cache or mirror fallback |

## Invariants (table with ID, Rule, Enforcement)

| ID | Rule | Enforcement |
|----|------|-------------|
| SYS-INV-01 | Every system mutation is preceded by a dry-run | Playbook engine rejects apply without prior dry-run |
| SYS-INV-02 | All system operations are idempotent | Handlers compare current vs desired state before acting |
| SYS-INV-03 | Service enablement state is persisted across reboots | ServiceHandler manages enable symlinks or preset |
| SYS-INV-04 | Package holds are preserved across operations | PackageHandler checks hold flag before upgrade/remove |
| SYS-INV-05 | Filesystem state is reconciled against fstab | FsHandler ensures fstab is updated before mount |
| SYS-INV-06 | Playbook execution produces an auditable RunbookRecord | Engine records every operation outcome with timestamp |

## Design DNA (table with Rule, Assessment — include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 — Composition over Inheritance | Playbooks compose individual operations; handlers delegate to platform-specific implementations |
| R2 — Explicit over Implicit | All desired state is declared in resource manifests; no magic defaults |
| R3 — Immutable Artifacts | Package versions pinned by hash or explicit version; playbooks immutable after execution |
| R4 — Stateless Workers | SysAdminWorker is stateless; state lives in resource manifests |
| R5 — Idempotency | Every operation checks current state before applying change |
| R6 — Observability | Every mutation emits a typed event; dry-run provides full diff |
| R9 — Fail Closed | Playbook halts on first error; partial apply requires explicit rollback config |
| R10 — Least Privilege | Each operation runs with minimum required privileges; escalation explicit |
| R13 — Graceful Degradation | If package repo is down, system still serves already-deployed configs |
| R14 — Data Immutability | RunbookRecords are append-only; past operations never mutated |
| R15 — Explicit Errors | Every failure returns structured error code and recovery hint |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Bible/07-Domains/Linux/001-Kernel.md | Kernel operations sibling |
| Bible/07-Laws/Law-004-Evidence.md | Audit trail requirements |
| Bible/07-Laws/Law-007-Capability-Bounds.md | Capability scoping |
| Bible/Physics/005-Events.md | Event schema lineage |
| Bible/Physics/007-Capabilities.md | Capability model |
| Bible/Physics/010-Execution.md | Execution lifecycle |
