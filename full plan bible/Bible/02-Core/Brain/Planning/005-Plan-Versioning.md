# AIOS Bible — Brain
## 005 — Plan Versioning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-005 |
| Source Laws | Law 4 — Law of Evidence, Law 6 — Law of Lifecycle |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Plan Versioning manages the lifecycle of plan revisions — from initial draft through approval, execution, and eventual completion or cancellation. Every modification to a plan creates a new version, preserving a complete audit trail of changes. This module supports approval workflows (Sou must approve before execution), version diffing (to review what changed between revisions), plan rollback (to revert to a previous approved state), and concurrent modification prevention (optimistic locking). Versioning ensures that Sou never executes an unapproved plan and can always trace how a plan evolved over time.

## Data Model

### PlanVersion

```typescript
PlanVersion {
  version_id: string
  plan_id: string
  version_number: number            // Monotonically increasing, per-plan
  status: PlanVersionStatus
  plan_snapshot: PlanSnapshot       // Full copy of the plan at this version
  parent_version_id?: string        // Previous version (linear history)
  diff_from_parent?: PlanDiff       // Changes from parent version
  approval: ApprovalInfo
  metadata: VersionMetadata
  created_at: timestamp
}
```

### PlanVersionStatus

```typescript
type PlanVersionStatus = "draft" | "approved" | "active" | "completed" | "failed" | "cancelled"
```

### Status Transitions

```
             ┌───────┐
             │ Draft │
             └───┬───┘
                 │ Sou approves
                 ▼
           ┌──────────┐
           │ Approved  │
           └────┬─────┘
                │ execution starts
                ▼
            ┌────────┐
            │ Active  │
            └───┬────┘
                │
      ┌─────────┼─────────┐
      ▼         ▼         ▼
 ┌─────────┐ ┌─────────┐ ┌──────────┐
 │Complete │ │ Failed  │ │ Cancelled │
 └─────────┘ └─────────┘ └──────────┘
```

Transition rules:
- `draft` → `approved`: Sou explicitly approves via `approvePlan()`
- `approved` → `active`: Execution begins (Institution OS picks up the plan)
- `active` → `completed`: All milestones finished successfully
- `active` → `failed`: A milestone failed with no recovery path
- `active` → `cancelled`: Sou cancels the plan mid-execution
- `draft` → `cancelled`: Plan abandoned before approval
- `approved` → `cancelled`: Plan abandoned after approval but before execution
- No transitions out of `completed`, `failed`, or `cancelled` (terminal states)

### PlanSnapshot

```typescript
PlanSnapshot {
  goal: string
  milestones: Milestone[]
  dependencies: Dependency[]
  resource_estimates: ResourceEstimate
  session_id: string
  sou_approved: boolean
  approved_at?: timestamp
}
```

### PlanDiff

```typescript
PlanDiff {
  added_milestones: Milestone[]
  removed_milestone_ids: string[]
  modified_milestones: {
    milestone_id: string
    field_changes: Record<string, { old: unknown; new: unknown }>
  }[]
  added_dependencies: Dependency[]
  removed_dependency_ids: string[]
  modified_dependencies: {
    dependency_id: string
    field_changes: Record<string, { old: unknown; new: unknown }>
  }[]
  goal_changed?: { old: string; new: string }
  resource_estimates_changed: boolean
  summary: string                   // Human-readable change description
}
```

### ApprovalInfo

```typescript
ApprovalInfo {
  approved_by: string               // "sou" (only Sou can approve)
  approved_at?: timestamp
  approval_notes?: string
  rejection_reason?: string
  rejection_at?: timestamp
}
```

### VersionMetadata

```typescript
VersionMetadata {
  created_by: string                // "sou" | "planner" | "system"
  change_description: string
  trigger: "manual" | "decomposition" | "replan" | "rollback"
  tags: string[]
  locked: boolean                   // Prevents further modifications
  checksum: string                  // Hash of PlanSnapshot for integrity
}
```

### PlanVersionHistory

```typescript
PlanVersionHistory {
  plan_id: string
  versions: PlanVersion[]
  current_version_id: string
  active_version_id?: string        // Version currently executing
  total_versions: number
  last_modified: timestamp
}
```

## Version Creation & Modification Workflow

### Creating a New Version

Every modification to a plan creates a new draft version:

```typescript
function modifyPlan(plan_id: string, modifications: PlanModification): PlanVersion {
  const currentVersion = getCurrentVersion(plan_id)

  // Lock check
  if (currentVersion.metadata.locked) {
    throw new Error("PLN_VER_PLAN_LOCKED")
  }

  // Concurrent modification check
  if (modifications.expected_version_id !== currentVersion.version_id) {
    throw new Error("PLN_VER_CONCURRENT_MODIFICATION")
  }

  // Create new version from current snapshot
  const newSnapshot = applyModifications(currentVersion.plan_snapshot, modifications)
  const diff = computeDiff(currentVersion.plan_snapshot, newSnapshot)

  const newVersion: PlanVersion = {
    version_id: generateId(),
    plan_id,
    version_number: currentVersion.version_number + 1,
    status: "draft",
    plan_snapshot: newSnapshot,
    parent_version_id: currentVersion.version_id,
    diff_from_parent: diff,
    approval: {},
    metadata: {
      created_by: modifications.created_by,
      change_description: modifications.description,
      trigger: modifications.trigger,
      tags: modifications.tags ?? [],
      locked: false,
      checksum: hash(newSnapshot),
    },
    created_at: now(),
  }

  emit PLN.VER.VersionCreated(newVersion)
  return newVersion
}
```

### Approval Workflow

```
Draft version created
    │
    ▼
Sou reviews plan (via diff from parent if available)
    │
    ├── Approve → status = "approved"
    │   ├── Lock the version
    │   ├── Emit PLN.VER.PlanApproved
    │   └── (if previous active exists, it remains active until new execution starts)
    │
    └── Reject → status remains "draft"
        ├── Sou provides rejection reason
        ├── Emit PLN.VER.PlanRejected
        └── Sou may modify and resubmit
```

### Concurrent Modification Prevention

Optimistic locking via expected version ID:

```typescript
// Client reads current version:
const current = getCurrentVersion(plan_id)
// Client submits modification with expected version:
submitModification(plan_id, {
  expected_version_id: current.version_id,  // Lock token
  modifications: {...}
})
// Server checks:
if (modification.expected_version_id !== getCurrentVersion(plan_id).version_id) {
  throw new Error("PLN_VER_CONCURRENT_MODIFICATION")
  // Client must re-read and re-apply changes
}
```

## Internal Interface

```typescript
interface PlanVersionManager {
  createVersion(plan_id: string, snapshot: PlanSnapshot, metadata: Partial<VersionMetadata>): PlanVersion
  getVersion(version_id: string): PlanVersion | null
  getCurrentVersion(plan_id: string): PlanVersion | null
  getActiveVersion(plan_id: string): PlanVersion | null
  getVersionHistory(plan_id: string): PlanVersionHistory
  listVersions(plan_id: string, status?: PlanVersionStatus): PlanVersion[]

  approvePlan(version_id: string, notes?: string): PlanVersion
  rejectPlan(version_id: string, reason: string): PlanVersion
  activatePlan(version_id: string): PlanVersion               // status: draft → active
  completePlan(plan_id: string): PlanVersion                  // status: active → completed
  failPlan(plan_id: string, reason: string): PlanVersion      // status: active → failed
  cancelPlan(plan_id: string, reason: string): PlanVersion    // any → cancelled

  diffVersions(version_a_id: string, version_b_id: string): PlanDiff
  rollback(plan_id: string, target_version_id: string, reason: string): PlanVersion

  lockVersion(version_id: string): void
  unlockVersion(version_id: string): void

  verifyIntegrity(version_id: string): boolean                // Snapshot checksum check
  compareSnapshots(snapshot_a: PlanSnapshot, snapshot_b: PlanSnapshot): PlanDiff
}

interface PlanModification {
  created_by: string
  description: string
  trigger: "manual" | "decomposition" | "replan" | "rollback"
  expected_version_id: string       // Optimistic lock token
  changes: {
    milestones_to_add?: Milestone[]
    milestone_ids_to_remove?: string[]
    milestone_updates?: Record<string, Partial<Milestone>>
    dependencies_to_add?: Dependency[]
    dependency_ids_to_remove?: string[]
    dependency_updates?: Record<string, Partial<Dependency>>
    goal?: string
    resource_estimates?: ResourceEstimate
  }
  tags?: string[]
}
```

## Lifecycle

```
Plan Created (initial decomposition)
    │
    ▼
Version 1 (draft)
    │
    ├── Sou reviews plan
    ├── Sou requests changes
    │   └── Version 2 (draft) — diff: modified milestones
    │       └── Sou requests more changes
    │           └── Version 3 (draft) — diff: added dependencies
    │
    ▼
Sou approves (Version 3 → approved)
    │
    ├── Version 3 locked
    └── Emit PLN.VER.PlanApproved
    │
    ▼
Execution starts (Version 3 → active)
    │
    ├── Institution OS begins milestone execution
    ├── Progress Tracking starts monitoring
    │
    ├── ISSUE: mid-execution replan needed
    │   └── Version 4 (draft) — based on active snapshot
    │       ├── Sou reviews diff
    │       ├── Sou approves → Version 4 (approved → active)
    │       └── Old Version 3 archived
    │
    ├── Plan completed
    │   └── Version 4 → completed
    │       ├── Emit PLN.PlanCompleted
    │       └── Final version locked
    │
    ├── Plan failed
    │   └── Version 4 → failed
    │       ├── Emit PLN.PlanFailed
    │       └── Sou may create new plan based on failed version
    │
    └── Plan cancelled
        └── Version 4 → cancelled
            ├── Emit PLN.PlanCancelled
            └── Version remains for audit
```

### Rollback

```typescript
function rollback(plan_id: string, target_version_id: string, reason: string): PlanVersion {
  const targetVersion = getVersion(target_version_id)
  if (!targetVersion) throw new Error("PLN_VER_VERSION_NOT_FOUND")

  const currentVersion = getCurrentVersion(plan_id)
  if (!currentVersion) throw new Error("PLN_VER_PLAN_NOT_FOUND")

  // Only rollback if plan is active or in draft
  if (currentVersion.status === "completed") throw new Error("PLN_VER_COMPLETED_NO_ROLLBACK")

  const newSnapshot = clone(targetVersion.plan_snapshot)
  const diff = computeDiff(currentVersion.plan_snapshot, newSnapshot)

  const rollbackVersion: PlanVersion = {
    version_id: generateId(),
    plan_id,
    version_number: currentVersion.version_number + 1,
    status: "draft",                 // Rollback creates a new draft
    plan_snapshot: newSnapshot,
    parent_version_id: currentVersion.version_id,
    diff_from_parent: diff,
    approval: {},
    metadata: {
      created_by: "system",
      change_description: `Rollback to version ${targetVersion.version_number}: ${reason}`,
      trigger: "rollback",
      tags: ["rollback"],
      locked: false,
      checksum: hash(newSnapshot),
    },
    created_at: now(),
  }

  emit PLN.VER.VersionCreated(rollbackVersion)
  emit PLN.VER.PlanRolledBack({ plan_id, from_version: currentVersion.version_id, to_version: targetVersion.version_id })

  return rollbackVersion
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.VER.VersionCreated` | version_id, plan_id, version_number, status | New plan version created |
| `PLN.VER.PlanApproved` | version_id, plan_id, approved_at | Plan version approved by Sou |
| `PLN.VER.PlanRejected` | version_id, plan_id, rejection_reason | Plan version rejected by Sou |
| `PLN.VER.PlanActivated` | version_id, plan_id | Plan version moved to active execution |
| `PLN.VER.PlanCompleted` | version_id, plan_id, duration_ms | Plan version completed |
| `PLN.VER.PlanFailed` | version_id, plan_id, reason | Plan version failed |
| `PLN.VER.PlanCancelled` | version_id, plan_id, reason | Plan version cancelled |
| `PLN.VER.PlanRolledBack` | plan_id, from_version, to_version | Plan rolled back to earlier version |
| `PLN.VER.VersionDiffComputed` | version_id, parent_id, change_count | Diff calculated between versions |
| `PLN.VER.ConcurrentModification` | plan_id, expected_version, actual_version | Concurrent edit prevented |
| `PLN.VER.VersionLocked` | version_id, plan_id | Version locked (no further modifications) |
| `PLN.VER.VersionUnlocked` | version_id, plan_id | Version unlocked |
| `PLN.VER.IntegrityCheckFailed` | version_id, expected_checksum, actual_checksum | Snapshot checksum mismatch |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VER-001 | Version numbers are monotonically increasing per plan | Algorithmic — checked on `createVersion` |
| VER-002 | Only one version can be `active` per plan at any time | Algorithmic — `activatePlan` deactivates previous |
| VER-003 | A draft version must be approved before it can become active | Algorithmic — `activatePlan` requires `approved` status |
| VER-004 | Terminal statuses (`completed`, `failed`, `cancelled`) are irreversible | Algorithmic — state machine enforces no outgoing transitions |
| VER-005 | Every version is a complete snapshot of the plan at a point in time | Schema — `plan_snapshot` is required, never partial |
| VER-006 | Concurrent modifications are prevented via optimistic locking | Algorithmic — `expected_version_id` validated on write |
| VER-007 | Only Sou can approve a plan | API-level — `approved_by` must be "sou" |
| VER-008 | Rollback always creates a new draft version (history is append-only) | Algorithmic — rollback never mutates existing versions |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Version not found | `PLN_VER_VERSION_NOT_FOUND` | Return error; no version data |
| Plan not found | `PLN_VER_PLAN_NOT_FOUND` | Return error; no plan data |
| Concurrent modification detected | `PLN_VER_CONCURRENT_MODIFICATION` | Return error; client must re-read and retry |
| Approve already-approved version | `PLN_VER_ALREADY_APPROVED` | OK; idempotent (no state change) |
| Transition from terminal state | `PLN_VER_TERMINAL_STATE` | Return error; plan already completed/failed/cancelled |
| Rollback on completed plan | `PLN_VER_COMPLETED_NO_ROLLBACK` | Return error; cannot rollback a completed plan |
| Locked version modification | `PLN_VER_PLAN_LOCKED` | Return error; unlock before modifying |
| Non-Sou approval attempt | `PLN_VER_UNAUTHORIZED_APPROVAL` | Deny; log security event |
| Snapshot checksum mismatch | `PLN_VER_INTEGRITY_FAILURE` | Return error; data corruption detected |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Plan Versioning handles only version lifecycle and history |
| R2 — Dependency Order | Depends on snapshot of full plan; no upward deps |
| R3 — DRY | Diff algorithm defined once; reused for rollback and review |
| R4 — Builder Pattern | Versions built by snapshot → diff → metadata → storage |
| R5 — Liskov Substitution | Any VersionStore implements the storage interface |
| R6 — DI over Singletons | Diff strategy and lock mechanism injectable |
| R9 — Deterministic | Same snapshots produce same diffs |
| R10 — Simpler Over Complex | Linear version history, not branching/merging |
| R13 — Design for Failure | Concurrent modification detection prevents data loss; integrity checksums catch corruption |
| R14 — Paved Path | All changes flow through createVersion → approve → activate |
| R15 — Open/Closed | New version statuses added via state machine extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Plan Versioning governs the plan lifecycle end-to-end |
| Planning/001-Goal-Decomposition.md | Decomposition triggers initial version creation |
| Planning/002-Milestones.md | Milestone changes tracked across versions |
| Planning/003-Dependencies.md | Dependency changes tracked across versions |
| Planning/004-Progress-Tracking.md | Active version supplies state for progress tracking |
| Brain/Sou/000-Overview.md | Sou approves, rejects, and cancels plan versions |
| Bible/05-Platform/004-EVS.md | All version events recorded in Event Store |
