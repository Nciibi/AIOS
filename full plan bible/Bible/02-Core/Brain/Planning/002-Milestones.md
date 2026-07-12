# AIOS Bible — Brain
## 002 — Milestone Planning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-002 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 2 — Law of Non-Execution |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Milestone Planning takes the decomposed goal tree from Goal Decomposition and produces an ordered, sequenced collection of milestones ready for dependency resolution and execution. This module manages the full milestone lifecycle — creation, status transitions, hierarchical structuring, parallelization support, and metadata enrichment (effort estimates, risk scores, capability requirements). Milestones are the atomic units of execution in the Planning System; each milestone maps to exactly one mission when delegated to Institution OS. The Milestone Planner provides tree traversal, reordering, and status aggregation capabilities used by Progress Tracking and the Context System.

## Data Model

### Milestone

```typescript
Milestone {
  milestone_id: string
  plan_id: string
  name: string
  description: string
  order: number                     // Display/execution sequence
  level: number                     // Depth in milestone tree (0 = root-level)
  parent_id?: string                // Parent milestone for hierarchy
  children: string[]                // Child milestone IDs
  status: MilestoneStatus
  dependencies: string[]            // Milestone IDs that must complete first
  parallelizable: boolean           // Can run concurrently with siblings
  assigned_mission_id?: string      // Set when delegated to Institution OS
  estimated_effort: EffortEstimate
  metadata: MilestoneMetadata
  created_at: timestamp
  updated_at: timestamp
  completed_at?: timestamp
  started_at?: timestamp
  result?: MilestoneResult
}
```

### MilestoneStatus

```typescript
type MilestoneStatus = "pending" | "in_progress" | "completed" | "blocked" | "failed"
```

### MilestoneState Transitions

```
               ┌─────────┐
               │ Pending │
               └────┬────┘
                    │ mission assigned
                    ▼
             ┌────────────┐
             │ In Progress │
             └──────┬─────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
   ┌─────────┐ ┌─────────┐ ┌────────┐
   │ Blocked │ │Complete │ │ Failed │
   └─────────┘ └─────────┘ └────────┘
         │
         │ dependency resolved
         ▼
     (back to In Progress)
```

Blocked milestones automatically return to `in_progress` when the blocking dependency resolves. `completed` and `failed` are terminal states for a milestone.

### EffortEstimate

```typescript
EffortEstimate {
  estimated_tokens: number
  estimated_duration_ms: number
  required_capabilities: string[]
  estimated_cost: number
  risk_score: number                // 0.0–1.0
  confidence_interval: {
    low: number                     // Pessimistic estimate
    high: number                    // Optimistic estimate
  }
}
```

### MilestoneMetadata

```typescript
MilestoneMetadata {
  source: string                    // "decomposition" | "template" | "manual"
  tags: string[]
  priority: number                  // 0.0–1.0, relative importance
  effort_level: "trivial" | "small" | "medium" | "large" | "epic"
  risk_factors: string[]
  success_criteria: string[]        // Objective pass/fail conditions
  notes: string[]
  locked: boolean                   // Prevents modification when set
}
```

### MilestoneResult

```typescript
MilestoneResult {
  output: unknown                   // Mission output artifact
  actual_tokens_used: number
  actual_duration_ms: number
  actual_cost: number
  errors?: string[]
  artifacts: string[]               // References to produced artifacts
}
```

### MilestoneTree

```typescript
MilestoneTree {
  plan_id: string
  root_milestones: string[]         // Top-level milestone IDs (level 0)
  milestones: Record<string, Milestone>
  total_count: number
  completed_count: number
  blocked_count: number
  failed_count: number
  depth: number
  last_updated: timestamp
}
```

## Hierarchy & Sequencing

### Parent-Child Hierarchy

Milestones form a tree where parent milestones represent higher-level objectives and children are sub-tasks:

```
Milestone: "Implement Auth System" (level 0)
├── Milestone: "Design Auth Architecture" (level 1)
│   ├── "Research auth patterns" (level 2)
│   └── "Design database schema" (level 2)
├── Milestone: "Build Backend Auth" (level 1)
│   ├── "User model & migrations" (level 2)
│   ├── "Registration endpoint" (level 2)
│   └── "Login endpoint" (level 2)
└── Milestone: "Build Frontend Auth" (level 1)
    ├── "Login form component" (level 2)
    └── "Registration form component" (level 2)
```

Rules:
- Parent milestone status is derived from children: `completed` when all children complete, `failed` if any child fails, `blocked` if any child is blocked.
- Leaf milestones (no children) are executable — they receive mission assignments.
- Parent milestones are not directly executable; they serve as groupings.

### Ordering & Sequencing

Milestones at the same level are ordered by their `order` field. The `order` field determines display sequence and, in the absence of explicit dependencies, suggests execution order:

```typescript
sortByOrder(milestones: Milestone[]): Milestone[]
  return milestones.sort((a, b) => a.order - b.order)
```

Dependencies override order-based sequencing. If milestone B depends on A, B runs after A regardless of order values.

### Parallel Milestone Support

Milestones marked `parallelizable: true` can execute concurrently with their siblings:

```
Sequential (parallelizable = false):
  M1 → M2 → M3 → Done

Parallel (M2 and M3 parallelizable):
  M1 ─┬→ M2 ─┬→ Done
       └→ M3 ┘
```

Parallel execution requires:
1. No dependency path between parallel milestones
2. No shared singleton resources (checked by Resource Estimator)
3. Sufficient worker capacity (checked at mission dispatch)

## Internal Interface

```typescript
interface MilestonePlanner {
  createMilestone(plan_id: string, input: CreateMilestoneInput): Milestone
  createMilestoneBatch(plan_id: string, inputs: CreateMilestoneInput[]): Milestone[]
  updateStatus(milestone_id: string, status: MilestoneStatus, result?: MilestoneResult): Milestone
  updateMilestone(milestone_id: string, updates: Partial<Milestone>): Milestone

  getMilestone(milestone_id: string): Milestone | null
  getMilestoneTree(plan_id: string): MilestoneTree
  getMilestonesByStatus(plan_id: string, status: MilestoneStatus): Milestone[]
  getChildMilestones(parent_id: string): Milestone[]
  getLeafMilestones(plan_id: string): Milestone[]            // Executable milestones

  setParentChild(parent_id: string, child_id: string): void
  reorderMilestones(plan_id: string, ordered_ids: string[]): void
  setParallelizable(milestone_id: string, parallelizable: boolean): void

  lockMilestone(milestone_id: string): void
  unlockMilestone(milestone_id: string): void

  assignMission(milestone_id: string, mission_id: string): void
  unassignMission(milestone_id: string): void

  aggregateStatus(plan_id: string): MilestoneStatus          // Rollup of root milestones
  countByStatus(plan_id: string): Record<MilestoneStatus, number>
}

interface CreateMilestoneInput {
  name: string
  description: string
  order: number
  parent_id?: string
  parallelizable?: boolean
  estimated_effort?: Partial<EffortEstimate>
  metadata?: Partial<MilestoneMetadata>
}
```

## Lifecycle

```
Milestone Created (createMilestone)
    │
    ▼
┌─────────┐
│ Pending │ ← status: "pending"
└────┬────┘
     │ Sou approves plan
     ▼
┌────────────┐
│ Pending    │ (ready for execution)
└────┬───────┘
     │ mission assigned via Institution OS
     ▼
┌────────────┐
│ In Progress│ ← status: "in_progress"
└──────┬─────┘
       │
       ├── dependency blocks → "blocked" → dependency resolved → back to "in_progress"
       ├── completed → "completed" → emit PLN.MilestoneCompleted
       └── failed → "failed" → emit PLN.MilestoneFailed
```

### Parent Status Aggregation

```
Parent status is derived from children:
  - Any child failed → parent = "failed"
  - Any child blocked → parent = "blocked"
  - Any child in_progress → parent = "in_progress"
  - All children completed → parent = "completed"
  - No children → parent = "pending" (leaf, executable)
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.MS.MilestoneCreated` | milestone_id, plan_id, name, parent_id | New milestone added to plan |
| `PLN.MS.MilestoneUpdated` | milestone_id, plan_id, updated_fields | Milestone metadata or order changed |
| `PLN.MS.MilestoneDeleted` | milestone_id, plan_id | Milestone removed from plan |
| `PLN.MS.StatusChanged` | milestone_id, old_status, new_status, reason | Milestone status transitioned |
| `PLN.MS.MilestoneStarted` | milestone_id, plan_id, mission_id | Mission assigned; execution begins |
| `PLN.MS.MilestoneCompleted` | milestone_id, plan_id, result, duration_ms | Milestone finished successfully |
| `PLN.MS.MilestoneBlocked` | milestone_id, blocking_milestone_id | Milestone blocked on dependency |
| `PLN.MS.MilestoneUnblocked` | milestone_id, resolved_milestone_id | Blocking dependency resolved |
| `PLN.MS.MilestoneFailed` | milestone_id, plan_id, error | Milestone execution failed |
| `PLN.MS.ParentStatusUpdated` | milestone_id, derived_status, child_summary | Parent status recalculated from children |
| `PLN.MS.Reordered` | plan_id, previous_order, new_order | Milestone execution order changed |
| `PLN.MS.MissionAssigned` | milestone_id, mission_id | Milestone bound to a mission |
| `PLN.MS.MissionUnassigned` | milestone_id, mission_id | Mission unbound from milestone |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MS-001 | Every milestone belongs to exactly one plan | Schema — `plan_id` is required |
| MS-002 | Milestone IDs are unique within a plan | Schema — primary key constraint |
| MS-003 | A milestone's parent must exist in the same plan | Referential — checked on `setParentChild` |
| MS-004 | Only leaf milestones (no children) are directly executable | Algorithmic — `getLeafMilestones` enforced at mission assignment |
| MS-005 | `completed` and `failed` are terminal states — no further transitions | Algorithmic — `updateStatus` rejects transitions out of terminal states |
| MS-006 | Parent milestone status is always derived from children, never set directly | Algorithmic — `updateStatus` on parent returns error |
| MS-007 | Parallelizable milestones must have no dependency path between them | Validation — checked on `setParallelizable` |
| MS-008 | Order values within the same parent are unique | Validation — checked on `reorderMilestones` |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Parent milestone not found | `PLN_MS_PARENT_NOT_FOUND` | Return error; create parent first |
| Status transition to terminal from terminal | `PLN_MS_TERMINAL_STATE` | Return error; milestone already completed/failed |
| Set status on parent milestone | `PLN_MS_PARENT_STATUS_IMMUTABLE` | Return error; parent status is derived |
| Duplicate order value in siblings | `PLN_MS_DUPLICATE_ORDER` | Return error; reorder with unique values |
| Assign mission to non-leaf milestone | `PLN_MS_NOT_LEAF` | Return error; only leaf milestones executable |
| Locked milestone modification attempt | `PLN_MS_MILESTONE_LOCKED` | Return error; unlock before modifying |
| Cyclic parent-child relationship | `PLN_MS_CYCLIC_HIERARCHY` | Return error; cannot set child as ancestor |
| Milestone not found for status update | `PLN_MS_MILESTONE_NOT_FOUND` | Return error; no state change |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Milestone Planner handles only milestone CRUD and lifecycle |
| R2 — Dependency Order | Depends on Goal Decomposition for input; no upward deps |
| R3 — DRY | Status transition logic defined once in state machine |
| R4 — Builder Pattern | Milestones built via CreateMilestoneInput → validation → storage |
| R5 — Liskov Substitution | Any MilestoneStore implements the storage interface |
| R6 — DI over Singletons | Storage backend and state machine injectable |
| R9 — Deterministic | Same inputs produce same milestone structure |
| R10 — Simpler Over Complex | Tree hierarchy with parent rollup, not generalized work breakdown |
| R13 — Design for Failure | Blocked status automatically resolves; failed children propagate to parent |
| R14 — Paved Path | All operations through createMilestone → updateStatus → aggregateStatus |
| R15 — Open/Closed | New milestone metadata fields added via schema extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Milestone Planning is the second stage of planning |
| Planning/001-Goal-Decomposition.md | Milestones created from decomposition output |
| Planning/003-Dependencies.md | Dependencies connect milestones into execution graph |
| Planning/004-Progress-Tracking.md | Milestone status drives progress metrics |
| Brain/Context/000-Overview.md | Milestone status changes pushed to Context System |
| Institution OS | Milestones delegated as missions for execution |
