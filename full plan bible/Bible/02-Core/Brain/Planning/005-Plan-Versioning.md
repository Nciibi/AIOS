# AIOS Bible â€” Brain
## 005 â€” Plan Versioning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-005 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Plan Versioning manages the lifecycle of plan revisions â€” from initial draft through approval, execution, and eventual completion or cancellation. Every modification to a plan creates a new version, preserving a complete audit trail of changes. This module supports approval workflows (Sou must approve before execution), version diffing (to review what changed between revisions), plan rollback (to revert to a previous approved state), and concurrent modification prevention (optimistic locking). Versioning ensures that Sou never executes an unapproved plan and can always trace how a plan evolved over time.

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
             â”Œâ”€â”€â”€â”€â”€â”€â”€â”
             â”‚ Draft â”‚
             â””â”€â”€â”€â”¬â”€â”€â”€â”˜
                 â”‚ Sou approves
                 â–¼
           â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
           â”‚ Approved  â”‚
           â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
                â”‚ execution starts
                â–¼
            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”
            â”‚ Active  â”‚
            â””â”€â”€â”€â”¬â”€â”€â”€â”€â”˜
                â”‚
      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
      â–¼         â–¼         â–¼
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚Complete â”‚ â”‚ Failed  â”‚ â”‚ Cancelled â”‚
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Transition rules:
- `draft` â†’ `approved`: Sou explicitly approves via `approvePlan()`
- `approved` â†’ `active`: Execution begins (Institution OS picks up the plan)
- `active` â†’ `completed`: All milestones finished successfully
- `active` â†’ `failed`: A milestone failed with no recovery path
- `active` â†’ `cancelled`: Sou cancels the plan mid-execution
- `draft` â†’ `cancelled`: Plan abandoned before approval
- `approved` â†’ `cancelled`: Plan abandoned after approval but before execution
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
    â”‚
    â–¼
Sou reviews plan (via diff from parent if available)
    â”‚
    â”œâ”€â”€ Approve â†’ status = "approved"
    â”‚   â”œâ”€â”€ Lock the version
    â”‚   â”œâ”€â”€ Emit PLN.VER.PlanApproved
    â”‚   â””â”€â”€ (if previous active exists, it remains active until new execution starts)
    â”‚
    â””â”€â”€ Reject â†’ status remains "draft"
        â”œâ”€â”€ Sou provides rejection reason
        â”œâ”€â”€ Emit PLN.VER.PlanRejected
        â””â”€â”€ Sou may modify and resubmit
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
  activatePlan(version_id: string): PlanVersion               // status: draft â†’ active
  completePlan(plan_id: string): PlanVersion                  // status: active â†’ completed
  failPlan(plan_id: string, reason: string): PlanVersion      // status: active â†’ failed
  cancelPlan(plan_id: string, reason: string): PlanVersion    // any â†’ cancelled

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
    â”‚
    â–¼
Version 1 (draft)
    â”‚
    â”œâ”€â”€ Sou reviews plan
    â”œâ”€â”€ Sou requests changes
    â”‚   â””â”€â”€ Version 2 (draft) â€” diff: modified milestones
    â”‚       â””â”€â”€ Sou requests more changes
    â”‚           â””â”€â”€ Version 3 (draft) â€” diff: added dependencies
    â”‚
    â–¼
Sou approves (Version 3 â†’ approved)
    â”‚
    â”œâ”€â”€ Version 3 locked
    â””â”€â”€ Emit PLN.VER.PlanApproved
    â”‚
    â–¼
Execution starts (Version 3 â†’ active)
    â”‚
    â”œâ”€â”€ Institution OS begins milestone execution
    â”œâ”€â”€ Progress Tracking starts monitoring
    â”‚
    â”œâ”€â”€ ISSUE: mid-execution replan needed
    â”‚   â””â”€â”€ Version 4 (draft) â€” based on active snapshot
    â”‚       â”œâ”€â”€ Sou reviews diff
    â”‚       â”œâ”€â”€ Sou approves â†’ Version 4 (approved â†’ active)
    â”‚       â””â”€â”€ Old Version 3 archived
    â”‚
    â”œâ”€â”€ Plan completed
    â”‚   â””â”€â”€ Version 4 â†’ completed
    â”‚       â”œâ”€â”€ Emit PLN.PlanCompleted
    â”‚       â””â”€â”€ Final version locked
    â”‚
    â”œâ”€â”€ Plan failed
    â”‚   â””â”€â”€ Version 4 â†’ failed
    â”‚       â”œâ”€â”€ Emit PLN.PlanFailed
    â”‚       â””â”€â”€ Sou may create new plan based on failed version
    â”‚
    â””â”€â”€ Plan cancelled
        â””â”€â”€ Version 4 â†’ cancelled
            â”œâ”€â”€ Emit PLN.PlanCancelled
            â””â”€â”€ Version remains for audit
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
| PLN.PLN.VER.VersionCreated | version_id, plan_id, version_number, status | New plan version created |
| PLN.PLN.VER.PlanApproved | version_id, plan_id, approved_at | Plan version approved by Sou |
| PLN.PLN.VER.PlanRejected | version_id, plan_id, rejection_reason | Plan version rejected by Sou |
| PLN.PLN.VER.PlanActivated | version_id, plan_id | Plan version moved to active execution |
| PLN.PLN.VER.PlanCompleted | version_id, plan_id, duration_ms | Plan version completed |
| PLN.PLN.VER.PlanFailed | version_id, plan_id, reason | Plan version failed |
| PLN.PLN.VER.PlanCancelled | version_id, plan_id, reason | Plan version cancelled |
| PLN.PLN.VER.PlanRolledBack | plan_id, from_version, to_version | Plan rolled back to earlier version |
| PLN.PLN.VER.VersionDiffComputed | version_id, parent_id, change_count | Diff calculated between versions |
| PLN.PLN.VER.ConcurrentModification | plan_id, expected_version, actual_version | Concurrent edit prevented |
| PLN.PLN.VER.VersionLocked | version_id, plan_id | Version locked (no further modifications) |
| PLN.PLN.VER.VersionUnlocked | version_id, plan_id | Version unlocked |
| PLN.PLN.VER.IntegrityCheckFailed | version_id, expected_checksum, actual_checksum | Snapshot checksum mismatch |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VER-001 | Version numbers are monotonically increasing per plan | Algorithmic â€” checked on `createVersion` |
| VER-002 | Only one version can be `active` per plan at any time | Algorithmic â€” `activatePlan` deactivates previous |
| VER-003 | A draft version must be approved before it can become active | Algorithmic â€” `activatePlan` requires `approved` status |
| VER-004 | Terminal statuses (`completed`, `failed`, `cancelled`) are irreversible | Algorithmic â€” state machine enforces no outgoing transitions |
| VER-005 | Every version is a complete snapshot of the plan at a point in time | Schema â€” `plan_snapshot` is required, never partial |
| VER-006 | Concurrent modifications are prevented via optimistic locking | Algorithmic â€” `expected_version_id` validated on write |
| VER-007 | Only Sou can approve a plan | API-level â€” `approved_by` must be "sou" |
| VER-008 | Rollback always creates a new draft version (history is append-only) | Algorithmic â€” rollback never mutates existing versions |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
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


## Cross-Cutting Concerns

### Security

Planning System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Planning System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Planning System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Planning System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Plan Versioning handles only version lifecycle and history |
| R2 â€” Dependency Order | Depends on snapshot of full plan; no upward deps |
| R3 â€” DRY | Diff algorithm defined once; reused for rollback and review |
| R4 â€” Builder Pattern | Versions built by snapshot â†’ diff â†’ metadata â†’ storage |
| R5 â€” Liskov Substitution | Any VersionStore implements the storage interface |
| R6 â€” DI over Singletons | Diff strategy and lock mechanism injectable |
| R9 â€” Deterministic | Same snapshots produce same diffs |
| R10 â€” Simpler Over Complex | Linear version history, not branching/merging |
| R13 â€” Design for Failure | Concurrent modification detection prevents data loss; integrity checksums catch corruption |
| R14 â€” Paved Path | All changes flow through createVersion â†’ approve â†’ activate |
| R15 â€” Open/Closed | New version statuses added via state machine extension |

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
