# AIOS Bible — Institutions
## 002 — Mission Execution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-MSN-002 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Manage active Mission execution — worker dispatch, progress tracking, evidence collection, runtime adaptation, and check-in management.

## Architecture

Execution is driven by the LMS in coordination with ROS and Workers. The execution flow follows a cyclic monitor-and-adapt pattern:

```
Running State Entry
    │
    ▼
Dispatch Workers (LMS → ROS → Worker)
    │
    ▼
[Monitor Progress ← Check-in Collection ← Execute Tasks ← Evidence Recording]
    │                                      │
    └── Adaptation Loop ──────────────────┘
    │
    ▼
All Milestones Complete → Transition to Review
```

Checkpoints are taken at every check-in to enable recovery. The adaptation loop adjusts resources and timelines based on actual progress vs. planned milestones.

## Data Model

```typescript
interface ExecutionState {
  mission_id: UUID;
  active_workers: WorkerAssignment[];
  current_progress: ProgressSnapshot;
  evidence_packages: EvidencePackage[];
  adaptations: RuntimeAdaptation[];
  check_in_schedule: CheckInSchedule;
  started_at: Timestamp;
  last_heartbeat: Timestamp;
}

interface WorkerAssignment {
  worker_id: UUID;
  assigned_milestones: UUID[];
  status: AssignmentStatus;
  started_at: Timestamp;
  completed_at?: Timestamp;
}

interface ProgressSnapshot {
  mission_id: UUID;
  milestone_progress: Map<UUID, MilestoneProgress>;
  overall_completion: number;
  timestamp: Timestamp;
}

interface EvidencePackage {
  package_id: UUID;
  action_ref: UUID;
  evidence_type: EvidenceType;
  payload: Blob;
  hash: string;
  timestamp: Timestamp;
}

interface RuntimeAdaptation {
  adaptation_id: UUID;
  type: AdaptationType;
  previous_value: any;
  new_value: any;
  reason: string;
  authorized_by: UUID;
  timestamp: Timestamp;
}

interface CheckInRecord {
  check_in_id: UUID;
  type: CheckInType;
  status: CheckInStatus;
  submitted_by: UUID;
  evidence: EvidencePackage[];
  timestamp: Timestamp;
}
```

## Core Concepts / Operations

### Worker Dispatch Flow (LMS → ROS → Worker)
LMS identifies the need for worker dispatch when a Mission enters Running state. LMS requests resources from ROS. ROS allocates Workers from the Organization pool. LMS assigns Workers to milestones and dispatches execution instructions.

```
LMS: dispatch request → ROS: allocate worker → Worker: acknowledge → LMS: confirm
```

### Progress Tracking at Milestone Granularity
Each milestone tracks independent progress. Completion is reported by Workers with evidence. Progress snapshots are taken at configurable intervals. Overall completion is the weighted sum of milestone completions.

### Evidence Collection per Action
Every action by a Worker produces an EvidencePackage. Evidence is hashed and stored immutably. Evidence packages are linked to the Event chain. Evidence integrity is verified at each check-in.

### Runtime Adaptation
Two adaptation types:
- **Resource Reallocation**: Shift resources between milestones based on progress data. Requires supervisor authorization.
- **Timeline Adjustment**: Shift milestone dates based on actual vs. estimated progress. Requires revalidation if critical path changes.

### Check-In Management
Three check-in types:
- **Periodic**: Scheduled at regular intervals. Status report + evidence submission.
- **Near-Milestone**: Triggered when a milestone approaches completion. Acceptance criteria verification.
- **On-Failure**: Triggered automatically when a Worker reports failure or error. Escalation evaluation.

### Checkpointing
Execution state is checkpointed at every check-in. Checkpoints enable recovery from failure (see 004-Failure-Recovery.md). Checkpoint format matches ExecutionState schema.

## Lifecycle

Execution occurs in the **Running** state (000-Lifecycle.md). Transitions from Running to Waiting, Paused, Blocked, or Review are managed by this subsystem. Execution terminates when all milestones are complete (transition to Review) or a failure triggers an alternative transition.

## Internal Interfaces

| Method | Input | Output | Consumed By |
|--------|-------|--------|-------------|
| dispatchWorker(mission, milestone, worker) | MissionPlan, Milestone, WorkerID | WorkerAssignment | LMS |
| recordProgress(mission, snapshot) | UUID, ProgressSnapshot | ConfirmedSnapshot | Sou |
| recordEvidence(action, package) | ActionRef, EvidencePackage | EvidenceReceipt | ACL |
| reallocateResources(mission, adaptation) | UUID, RuntimeAdaptation | AdaptationConfirmation | ROS |
| adjustTimeline(mission, new_timeline) | UUID, Timeline | TimelineConfirmation | Planner |
| createCheckIn(mission, type, evidence) | UUID, CheckInType, Evidence[] | CheckInRecord | LMS |
| checkpoint(execution_state) | ExecutionState | CheckpointID | Recovery |

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.Exec.WorkerDispatched | mission_id, worker_id, milestone_id, instruction_hash | Worker dispatched |
| MSN.Exec.WorkerCompleted | mission_id, worker_id, milestone_id, result_hash | Worker finishes milestone |
| MSN.Exec.ProgressUpdated | mission_id, overall_completion, milestone_progress | Progress snapshot taken |
| MSN.Exec.EvidenceRecorded | mission_id, package_id, evidence_type, hash | Evidence collected |
| MSN.Exec.ResourceReallocated | mission_id, adaptation_id, resource_delta | Resources reallocated |
| MSN.Exec.TimelineAdjusted | mission_id, old_timeline, new_timeline | Timeline adjusted |
| MSN.Exec.CheckInRequired | mission_id, check_in_id, type, deadline | Check-in triggered |
| MSN.Exec.CheckInCompleted | mission_id, check_in_id, status, evidence_count | Check-in completed |
| MSN.Exec.EscalationTriggered | mission_id, reason, escalation_level | Escalation triggered |
| MSN.Exec.Heartbeat | mission_id, worker_id, timestamp, status | Periodic heartbeat |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_EXEC_001 | Worker dispatch failed — no available Worker with required capability |
| MSN_EXEC_002 | Evidence integrity check failed — hash mismatch |
| MSN_EXEC_003 | Resource allocation exceeded — no budget remaining |
| MSN_EXEC_004 | Timeline adjustment violates dependency constraints |
| MSN_EXEC_005 | Check-in deadline missed — no response within SLA |
| MSN_EXEC_006 | Heartbeat timeout — worker unreachable |

## Invariants

| ID | Invariant |
|----|-----------|
| MSN-EXEC-001 | Every dispatched worker must be assigned to at least one milestone |
| MSN-EXEC-002 | Evidence chain must be append-only and immutable |
| MSN-EXEC-003 | Total resource consumption must not exceed allocated budget |
| MSN-EXEC-004 | Timeline adjustments must preserve milestone DAG ordering |
| MSN-EXEC-005 | Missed check-in must trigger escalation within SLA timeout |

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Execution is a single focused subsystem of the Mission lifecycle |
| R3 (DRY) | Execution reuses types from Physics/002-Missions.md |
| R9 (Deterministic) | Same worker dispatch with same input produces same execution |
| R10 (Simpler Over Complex) | Linear progress model with clear check-in gates |
| R12 (Embrace Errors) | All execution errors have unique codes (MSN_EXEC_001–006) |
| R13 (Design for Failure) | Checkpoints enable recovery; heartbeat detects failure |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/001-Planning.md | Sibling — execution consumes the plan |
| Missions/003-Delegation.md | Sibling — execution may involve delegation |
| Missions/004-Failure-Recovery.md | Sibling — failures during execution trigger recovery |
| Bible/02-Core/ROS/005-Budget.md | Resource budget allocation |
| Bible/03-Institutions/Workers/000-Overview.md | Worker lifecycle and dispatch |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
