# AIOS Bible â€” Brain
## 004 â€” Progress Tracking

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-004 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Progress Tracking monitors the execution status of approved plans in real-time. It aggregates milestone status events from Institution OS into meaningful progress metrics â€” completion percentage, blocked count, resource consumption vs estimates, and timeline variance. Progress snapshots are periodically pushed to the Context System so Sou maintains situational awareness. The Progress Tracker is stateless (state lives in Event Store) â€” it reads events to compute metrics on demand or on schedule. It also produces progress visualization data for the plan rendering pipeline, enabling Sou to assess plan health at a glance.

## Data Model

### PlanProgress

```typescript
PlanProgress {
  plan_id: string
  session_id: string
  metrics: ProgressMetrics
  milestone_states: Record<string, MilestoneState>
  timeline: TimelineInfo
  resource_consumption: ResourceConsumption
  risk_indicators: RiskIndicator[]
  history: ProgressSnapshot[]       // Recent snapshots for trend analysis
  last_updated: timestamp
}
```

### ProgressMetrics

```typescript
ProgressMetrics {
  completion_percentage: number     // 0.0â€“100.0
  total_milestones: number
  completed_milestones: number
  in_progress_milestones: number
  pending_milestones: number
  blocked_milestones: number
  failed_milestones: number
  parallel_execution_count: number  // Currently executing in parallel
  active_dependencies: number       // Dependencies yet to resolve
}
```

### MilestoneState

```typescript
MilestoneState {
  milestone_id: string
  name: string
  status: MilestoneStatus
  assigned_mission_id?: string
  started_at?: timestamp
  completed_at?: timestamp
  estimated_duration_ms: number
  actual_duration_ms?: number
  estimated_tokens: number
  actual_tokens_used?: number
  estimated_cost: number
  actual_cost?: number
  blocking_dependencies: string[]   // Currently blocking this milestone
  last_event: string                // Most recent event name
  last_event_at: timestamp
}
```

### TimelineInfo

```typescript
TimelineInfo {
  plan_created_at: timestamp
  plan_approved_at?: timestamp
  plan_started_at?: timestamp
  estimated_total_duration_ms: number
  elapsed_ms: number                // Since plan_started_at
  remaining_ms: number              // Estimated remaining duration
  timeline_variance_ms: number      // Positive = behind schedule, negative = ahead
  timeline_variance_percentage: number
  milestones_on_schedule: number
  milestones_behind_schedule: number
  milestones_ahead_of_schedule: number
  projected_completion_at?: timestamp
}
```

### ResourceConsumption

```typescript
ResourceConsumption {
  total_tokens_budgeted: number
  total_tokens_consumed: number
  token_consumption_percentage: number
  total_cost_budgeted: number
  total_cost_incurred: number
  cost_consumption_percentage: number
  per_milestone: Record<string, {
    tokens_budgeted: number
    tokens_consumed: number
    cost_budgeted: number
    cost_incurred: number
  }>
}
```

### RiskIndicator

```typescript
RiskIndicator {
  level: "low" | "medium" | "high" | "critical"
  category: "schedule" | "budget" | "blockage" | "quality" | "dependency"
  message: string
  source: string                    // Which component flagged this
  milestone_id?: string
  detected_at: timestamp
}
```

### ProgressSnapshot

```typescript
ProgressSnapshot {
  snapshot_id: string
  plan_id: string
  timestamp: timestamp
  metrics: ProgressMetrics
  timeline_variance_ms: number
  resource_consumption_percentage: number
  active_risk_count: number
}
```

### ProgressVisualization

```typescript
ProgressVisualization {
  plan_id: string
  gantt_data: GanttBar[]            // For rendering milestone timeline
  critical_path_highlight: string[]
  risk_heatmap: { milestone_id: string; risk_level: string }[]
  completion_trend: { timestamp: timestamp; percentage: number }[]
  block_chain: { milestone_id: string; blocked_by: string }[]
}
```

### GanttBar

```typescript
GanttBar {
  milestone_id: string
  name: string
  level: number
  start: timestamp                  // Actual or estimated start
  end: timestamp                    // Actual or estimated end
  status: MilestoneStatus
  on_critical_path: boolean
  progress_percentage: number       // For in_progress milestones
}
```

## Metrics Aggregation

### Completion Percentage

Calculated as the ratio of completed milestones to total executable milestones:

```typescript
function calculateCompletion(progress: PlanProgress): number {
  const executable = progress.total_milestones  // Leaf milestones only
  if (executable === 0) return 0
  return (progress.completed_milestones / executable) * 100
}
```

Parent milestones are excluded from the denominator since they are groupings, not executable units.

### Timeline Variance

Compares actual elapsed time against the estimated duration of completed milestones:

```typescript
function calculateTimelineVariance(progress: PlanProgress): number {
  const completed = Object.values(progress.milestone_states)
    .filter(m => m.status === "completed" && m.actual_duration_ms != null)

  if (completed.length === 0) return 0

  const totalEstimated = completed.reduce((sum, m) => sum + m.estimated_duration_ms, 0)
  const totalActual = completed.reduce((sum, m) => sum + (m.actual_duration_ms ?? 0), 0)

  return totalActual - totalEstimated  // Positive = behind schedule
}
```

### Resource Consumption

Compares actual token/cost usage against estimates:

```
per_milestone variance = actual - estimated
total variance = sum(per_milestone variance)
consumption_percentage = (total_tokens_consumed / total_tokens_budgeted) * 100
```

### Blocked Count & Chain Analysis

Tracks which milestones are blocked and why. Block chains are computed by following `blocking_dependencies` recursively:

```
Milestone C blocked by B â†’ B blocked by A â†’ A blocked by (missing resource)
Chain visualization: C â†’ B â†’ A â†’ root cause
```

## Progress Events & Context System Integration

Progress events are pushed to the Context System on:
1. Every milestone status change
2. Periodic heartbeat (configurable interval)
3. Risk threshold breach
4. Upon explicit `getProgress()` request

The Context System maintains the latest `PlanProgress` in Working Memory for Sou to query:

```typescript
// Context System stores progress for active plans
WorkingMemorySlot "active_plan_progress" {
  capacity: 3                        // Track up to 3 active plans
  eviction_policy: "fifo"
  items: PlanProgress[]
}
```

## Internal Interface

```typescript
interface ProgressTracker {
  getProgress(plan_id: string): PlanProgress
  getMetrics(plan_id: string): ProgressMetrics
  getMilestoneState(milestone_id: string): MilestoneState | null

  updateMilestoneStatus(milestone_id: string, status: MilestoneStatus, result?: MilestoneResult): MilestoneState
  processMilestoneEvent(event: MilestoneEvent): void

  getTimelineVariance(plan_id: string): number
  getResourceConsumption(plan_id: string): ResourceConsumption
  getRiskIndicators(plan_id: string): RiskIndicator[]

  computeCompletion(plan_id: string): number
  computeBlockChain(plan_id: string): { milestone_id: string; blocked_by: string }[]

  takeSnapshot(plan_id: string): ProgressSnapshot
  getSnapshotHistory(plan_id: string, limit?: number): ProgressSnapshot[]

  getVisualization(plan_id: string): ProgressVisualization
  getGanttData(plan_id: string): GanttBar[]

  pushToContext(plan_id: string): void           // Emit progress to Context System
  startHeartbeat(plan_id: string, interval_ms: number): void
  stopHeartbeat(plan_id: string): void
}

interface MilestoneEvent {
  plan_id: string
  milestone_id: string
  event_type: "started" | "completed" | "failed" | "blocked" | "unblocked" | "progress"
  timestamp: timestamp
  data?: Partial<MilestoneResult | { blocking_milestone_id: string }>
}
```

## Lifecycle

```
Plan Approved
    â”‚
    â–¼
Initialize Progress (first snapshot)
    â”‚
    â”œâ”€â”€ Set initial metrics (0% complete)
    â”œâ”€â”€ Compute estimated timeline
    â”œâ”€â”€ Start heartbeat timer
    â””â”€â”€ Push initial state to Context System
    â”‚
    â–¼
Active Monitoring (event-driven + heartbeat)
    â”‚
    â”œâ”€â”€ Milestone started â†’ update milestone state, recalculate metrics
    â”œâ”€â”€ Milestone completed â†’ record actual duration, update %, check timeline
    â”œâ”€â”€ Milestone blocked â†’ flag risk, compute block chain
    â”œâ”€â”€ Milestone failed â†’ flag risk, check plan health
    â”œâ”€â”€ Heartbeat tick â†’ take snapshot, check thresholds
    â””â”€â”€ Push updates to Context System
    â”‚
    â–¼
Risk Detection
    â”‚
    â”œâ”€â”€ Timeline variance > threshold â†’ generate risk indicator
    â”œâ”€â”€ Resource consumption > 80% â†’ generate risk indicator
    â”œâ”€â”€ Blocked count > 3 â†’ generate risk indicator
    â””â”€â”€ Failed milestone â†’ generate risk indicator
    â”‚
    â–¼
Plan Completed / Failed / Cancelled
    â”‚
    â”œâ”€â”€ Take final snapshot
    â”œâ”€â”€ Stop heartbeat
    â”œâ”€â”€ Compute final metrics and variance
    â”œâ”€â”€ Emit PLN.PlanCompleted or PLN.PlanFailed
    â”œâ”€â”€ Push final state to Episodic Memory
    â””â”€â”€ Remove from active tracking
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.PT.ProgressUpdated` | plan_id, completion_percentage, timestamp | Progress metrics recalculated |
| `PLN.PT.MilestoneStateChanged` | milestone_id, new_status, old_status | Individual milestone state update |
| `PLN.PT.SnapshotTaken` | snapshot_id, plan_id, metrics | Periodic progress snapshot recorded |
| `PLN.PT.TimelineVarianceUpdated` | plan_id, variance_ms, variance_pct | Timeline variance recalculated |
| `PLN.PT.ResourceAlert` | plan_id, resource_type, consumption_pct | Resource consumption exceeded threshold |
| `PLN.PT.RiskIndicatorRaised` | plan_id, level, category, message | New risk indicator generated |
| `PLN.PT.RiskIndicatorResolved` | plan_id, risk_id | Risk condition cleared |
| `PLN.PT.BlockChainUpdated` | plan_id, blocked_count, chain | Blocked milestone chain changed |
| `PLN.PT.HeartbeatTick` | plan_id, elapsed_ms, metrics | Periodic heartbeat event |
| `PLN.PT.PushedToContext` | plan_id, context_slot | Progress snapshot sent to Context System |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| PT-001 | Completion percentage is always 0.0â€“100.0 | Algorithmic â€” clamped on calculation |
| PT-002 | Timeline variance is computed only from completed milestones | Algorithmic â€” excludes in-progress estimates |
| PT-003 | The progress tracker is stateless â€” all state derived from Event Store | Architectural â€” no internal persistence |
| PT-004 | A plan's progress is monotonically non-decreasing (completion never goes down) | Algorithmic â€” checked on each update |
| PT-005 | Each milestone has exactly one status at any time | Schema â€” union type constraint |
| PT-006 | Risk indicators are automatically resolved when condition clears | Algorithmic â€” evaluated on each snapshot |
| PT-007 | Heartbeat timer is stopped when plan reaches terminal state | Algorithmic â€” checked on plan completion/failure |
| PT-008 | Resource consumption ratios never exceed 100% of budget | Algorithmic â€” hard cap; further consumption flagged separately |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Plan not found for progress query | `PLN_PT_PLAN_NOT_FOUND` | Return error; no progress data |
| Milestone not found for status update | `PLN_PT_MILESTONE_NOT_FOUND` | Return error; no state change |
| Empty plan query (no milestones) | `PLN_PT_EMPTY_PLAN` | Return 0% completion, empty timeline |
| Negative duration in event data | `PLN_PT_NEGATIVE_DURATION` | Clamp to 0; log warning |
| Stale heartbeat on cancelled plan | `PLN_PT_STALE_HEARTBEAT` | Stop heartbeat; log cleanup |
| Context System push failure | `PLN_PT_CONTEXT_PUSH_FAILED` | Retry with backoff; log error |
| Snapshot storage failure | `PLN_PT_SNAPSHOT_FAILED` | Log error; continue monitoring |
| Invalid milestone event sequence | `PLN_PT_INVALID_EVENT_SEQUENCE` | Reject event; log with context for debugging |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Progress Tracking handles only monitoring and metrics |
| R2 â€” Dependency Order | Depends on Event Store for state; Context System for push |
| R3 â€” DRY | Metric calculations defined once in ProgressMetrics |
| R4 â€” Builder Pattern | Progress built from events â†’ aggregation â†’ snapshot |
| R5 â€” Liskov Substitution | Any ProgressStore implements the storage interface |
| R6 â€” DI over Singletons | Event source and context pusher injectable |
| R9 â€” Deterministic | Same events produce same metrics |
| R10 â€” Simpler Over Complex | Uses flat progress metrics, not earned value management |
| R13 â€” Design for Failure | Risk indicators raised proactively; stale heartbeat detection |
| R14 â€” Paved Path | All tracking flows through milestone events â†’ getProgress |
| R15 â€” Open/Closed | New metrics added by extending ProgressMetrics schema |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Progress Tracking is the fourth stage of planning |
| Planning/002-Milestones.md | Milestone status drives all progress metrics |
| Planning/003-Dependencies.md | Block chains computed from dependency graph |
| Planning/005-Plan-Versioning.md | Plan versions capture progress at approval points |
| Brain/Context/000-Overview.md | Progress snapshots pushed to Context System |
| Memory/002-Episodic-Memory.md | Final snapshots promoted to Episodic Memory |
| Institution OS | Milestone events received from Institution OS |
