# AIOS Bible — Institutions
## 001 — Mission Planning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-MSN-001 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Decompose Human Intent into structured Mission plans with goals, milestones, resources, dependencies, timeline, and risk assessment.

## Architecture

The Planning subsystem follows a linear pipeline architecture that transforms raw Intent into a validated Mission plan. Each stage produces a validated artifact consumed by the next stage.

```
Intent → Goal Decomposition → Milestone Definition → Resource Estimation
    → Dependency Mapping → Timeline Estimation → Risk Assessment → Plan
```

Validation gates exist between each stage — a stage cannot proceed until its output passes validation. The completed plan is submitted to DGP + Security Council for approval before the Mission transitions from Planned to Assigned.

## Data Model

```typescript
interface MissionPlan {
  mission_id: UUID;
  goals: Goal[];
  milestones: Milestone[];
  resource_requirements: ResourceRequirement[];
  dependencies: Dependency[];
  timeline: Timeline;
  risk_assessment: RiskAssessment;
  created_at: Timestamp;
  version: number;
}

interface Goal {
  goal_id: UUID;
  description: string;
  priority: Priority;
  parent_goal?: UUID;
  success_criteria: string[];
}

interface Milestone {
  milestone_id: UUID;
  goal_id: UUID;
  description: string;
  acceptance_criteria: string[];
  estimated_effort: Effort;
  depends_on: UUID[];
}

interface ResourceRequirement {
  resource_type: ResourceType;
  quantity: number;
  unit: string;
  allocation_window: TimeRange;
}

interface Dependency {
  dependency_id: UUID;
  type: DependencyType;
  target_mission_id?: UUID;
  condition?: string;
  description: string;
  resolution_criteria: string[];
}

interface Timeline {
  start_date: Timestamp;
  end_date: Timestamp;
  milestones: MilestoneSchedule[];
  critical_path: UUID[];
  buffer_days: number;
}

interface RiskAssessment {
  risks: Risk[];
  overall_score: number;
  mitigation_plan: MitigationAction[];
}
```

## Core Concepts / Operations

### Goal Decomposition from Intent
Sou decomposes Human Intent into hierarchically structured Goals. Each Goal maps to a subset of Intent and carries measurable success criteria. Goals form a tree — leaf goals are directly executable, non-leaf goals are composite.

### Milestone Ordering (DAG)
Milestones must form a Directed Acyclic Graph (DAG). Circular dependencies are rejected at validation. The critical path is computed from the DAG structure. Each milestone is assigned to a specific Goal.

### Milestone Acceptance Criteria Format
Each milestone defines acceptance criteria as a list of boolean-evaluable conditions. Format: `<metric> <operator> <value> [unit]`. Example: `accuracy >= 0.95`, `latency < 200ms`.

### Resource Estimation per Milestone
Resource requirements are estimated from milestone scope. Resource types include compute, tokens, storage, network, and human review. Estimates are aggregated into a total Mission budget.

### Dependency Types
- **Hard**: Must be resolved before milestone can start. Blocks execution.
- **Soft**: Should be resolved but execution can proceed with degraded capability.
- **Temporal**: Time-based constraint (must start after date X, must complete before date Y).

### Timeline Estimation per Milestone
Timeline is derived from milestone DAG order, estimated effort, and resource allocation. Buffer days are added for critical-path milestones. Timeline is expressed as earliest/latest start and end dates.

### Risk Categories and Scoring
| Category | Score Range | Description |
|----------|-------------|-------------|
| Technical | 1–5 | Feasibility, complexity, unknown unknowns |
| Resource | 1–5 | Availability, contention, budget constraints |
| Dependency | 1–5 | External dependency reliability |
| Timeline | 1–5 | Schedule pressure, buffer adequacy |
| Constitutional | 1–5 | Compliance, authorization, legal risk |

Overall risk score is the weighted sum. Scores ≥ 4 require mitigation plan before plan approval.

## Lifecycle

Planning occurs in the **Planned** state (000-Lifecycle.md). The plan is produced by Sou, validated, and submitted for approval. Approved plans transition the Mission from Planned to Assigned.

## Internal Interfaces

| Method | Input | Output | Consumed By |
|--------|-------|--------|-------------|
| createPlan(intent, context) | Intent, Context | MissionPlan | Sou |
| validatePlan(plan) | MissionPlan | ValidationResult | DGP |
| approvePlan(plan, approver) | MissionPlan, Approver | ApprovalRecord | Security Council |
| rejectPlan(plan, reason) | MissionPlan, Reason | RejectionRecord | Sou |

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.Plan.Created | mission_id, plan_hash, version | Plan created |
| MSN.Plan.Validated | mission_id, validation_result, passed | Plan validated |
| MSN.Plan.GoalDecomposed | mission_id, goal_count, hierarchy | Goals decomposed |
| MSN.Plan.MilestoneDefined | mission_id, milestone_count, dag_hash | Milestones defined |
| MSN.Plan.ResourceEstimated | mission_id, resource_budget | Resources estimated |
| MSN.Plan.DependencyMapped | mission_id, dependency_count, types | Dependencies mapped |
| MSN.Plan.TimelineEstimated | mission_id, start_date, end_date, critical_path | Timeline estimated |
| MSN.Plan.RiskAssessed | mission_id, overall_score, top_risks | Risk assessed |
| MSN.Plan.Approved | mission_id, approved_by, approval_hash | Plan approved |
| MSN.Plan.Rejected | mission_id, rejected_by, reasons | Plan rejected |
| MSN.Plan.Versioned | mission_id, old_version, new_version | Plan updated |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_PLN_001 | No goals defined — plan must contain at least one goal |
| MSN_PLN_002 | Circular milestone dependency detected — DAG violation |
| MSN_PLN_003 | Resource estimate exceeds available budget |
| MSN_PLN_004 | Timeline constraint violation — end date before start date |
| MSN_PLN_005 | Risk score exceeds threshold — mandatory mitigation required |
| MSN_PLN_006 | Plan validation failed — constitutional compliance check |

## Invariants

| ID | Invariant |
|----|-----------|
| MSN-PLN-001 | Every plan must contain at least one Goal |
| MSN-PLN-002 | Milestone dependency graph must be a DAG |
| MSN-PLN-003 | Resource requirements must not exceed Organization allocation |
| MSN-PLN-004 | Timeline must be internally consistent (start ≤ end for all segments) |
| MSN-PLN-005 | All milestones must be associated with a Goal |

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Planning is a single focused concern within the Mission lifecycle |
| R3 (DRY) | Plans reference canonical types from Physics/002-Missions.md |
| R9 (Deterministic) | Same Intent and context produces same plan structure |
| R10 (Simpler Over Complex) | Linear planning flow with clear validation gates |
| R12 (Embrace Errors) | All planning errors have unique codes (MSN_PLN_001–006) |
| R14 (Paved Path) | Intent → Goals → Milestones → Resources → Dependencies → Timeline → Risk |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/002-Execution.md | Sibling — execution consumes the plan |
| Missions/003-Delegation.md | Sibling — delegation may result from planning |
| Missions/004-Failure-Recovery.md | Sibling — risk assessment informs recovery |
| Bible/02-Core/Sou/002-Planner.md | Sou produces Mission plans |
| Bible/02-Core/Sou/003-Missions.md | Sou's view of Missions |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
