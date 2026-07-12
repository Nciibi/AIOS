# AIOS Bible â€” Institutions
## 001 â€” Mission Planning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Institutions |
| Document ID | AIOS-BBL-003-MSN-001 |
| Source Laws | Law 1 â€” Law of Origin, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Decompose Human Intent into structured Mission plans with goals, milestones, resources, dependencies, timeline, and risk assessment.

## Architecture

The Planning subsystem follows a linear pipeline architecture that transforms raw Intent into a validated Mission plan. Each stage produces a validated artifact consumed by the next stage.

```
Intent â†’ Goal Decomposition â†’ Milestone Definition â†’ Resource Estimation
    â†’ Dependency Mapping â†’ Timeline Estimation â†’ Risk Assessment â†’ Plan
```

Validation gates exist between each stage â€” a stage cannot proceed until its output passes validation. The completed plan is submitted to DGP + Security Council for approval before the Mission transitions from Planned to Assigned.

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
Sou decomposes Human Intent into hierarchically structured Goals. Each Goal maps to a subset of Intent and carries measurable success criteria. Goals form a tree â€” leaf goals are directly executable, non-leaf goals are composite.

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
| Technical | 1â€“5 | Feasibility, complexity, unknown unknowns |
| Resource | 1â€“5 | Availability, contention, budget constraints |
| Dependency | 1â€“5 | External dependency reliability |
| Timeline | 1â€“5 | Schedule pressure, buffer adequacy |
| Constitutional | 1â€“5 | Compliance, authorization, legal risk |

Overall risk score is the weighted sum. Scores â‰¥ 4 require mitigation plan before plan approval.

## Lifecycle

Planning occurs in the **Planned** state (000-Lifecycle.md). The plan is produced by Sou, validated, and submitted for approval. Approved plans transition the Mission from Planned to Assigned.

## Internal Interfaces

```typescript
interface MissionPlanner {
  createPlan(intent: Intent, context: Context): Promise<MissionPlan>;
  validatePlan(plan: MissionPlan): Promise<ValidationResult>;
  approvePlan(plan: MissionPlan, approver: Approver): Promise<ApprovalRecord>;
  rejectPlan(plan: MissionPlan, reason: string): Promise<RejectionRecord>;
}
```

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.MSN.Plan.Created | mission_id, plan_hash, version | Plan created |
| MSN.MSN.Plan.Validated | mission_id, validation_result, passed | Plan validated |
| MSN.MSN.Plan.GoalDecomposed | mission_id, goal_count, hierarchy | Goals decomposed |
| MSN.MSN.Plan.MilestoneDefined | mission_id, milestone_count, dag_hash | Milestones defined |
| MSN.MSN.Plan.ResourceEstimated | mission_id, resource_budget | Resources estimated |
| MSN.MSN.Plan.DependencyMapped | mission_id, dependency_count, types | Dependencies mapped |
| MSN.MSN.Plan.TimelineEstimated | mission_id, start_date, end_date, critical_path | Timeline estimated |
| MSN.MSN.Plan.RiskAssessed | mission_id, overall_score, top_risks | Risk assessed |
| MSN.MSN.Plan.Approved | mission_id, approved_by, approval_hash | Plan approved |
| MSN.MSN.Plan.Rejected | mission_id, rejected_by, reasons | Plan rejected |
| MSN.MSN.Plan.Versioned | mission_id, old_version, new_version | Plan updated |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_PLN_001 | No goals defined â€” plan must contain at least one goal |
| MSN_PLN_002 | Circular milestone dependency detected â€” DAG violation |
| MSN_PLN_003 | Resource estimate exceeds available budget |
| MSN_PLN_004 | Timeline constraint violation â€” end date before start date |
| MSN_PLN_005 | Risk score exceeds threshold â€” mandatory mitigation required |
| MSN_PLN_006 | Plan validation failed â€” constitutional compliance check |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MSN-PLN-001 | Every plan must contain at least one Goal | Architectural â€” Schema validation rejects empty goal sets |
| MSN-PLN-002 | Milestone dependency graph must be a DAG | Algorithmic â€” Cycle detection on dependency graph |
| MSN-PLN-003 | Resource requirements must not exceed Organization allocation | Algorithmic â€” Budget validation against ROS allocation |
| MSN-PLN-004 | Timeline must be internally consistent (start â‰¤ end for all segments) | Algorithmic â€” Timeline cross-validation on creation |
| MSN-PLN-005 | All milestones must be associated with a Goal | Architectural â€” Milestone.goal_id references must resolve |


## Cross-Cutting Concerns

### Security

Missions operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Missions emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Missions instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Missions declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Planning is a single focused concern within the Mission lifecycle |
| R3 â€” DRY | Plans reference canonical types from Physics/002-Missions.md |
| R9 â€” Deterministic | Same Intent and context produces same plan structure |
| R10 â€” Simpler Over Complex | Linear planning flow with clear validation gates |
| R12 â€” Embrace Errors | All planning errors have unique codes (MSN_PLN_001â€“006) |
| R14 â€” Paved Path | Intent â†’ Goals â†’ Milestones â†’ Resources â†’ Dependencies â†’ Timeline â†’ Risk |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/002-Execution.md | Sibling â€” execution consumes the plan |
| Missions/003-Delegation.md | Sibling â€” delegation may result from planning |
| Missions/004-Failure-Recovery.md | Sibling â€” risk assessment informs recovery |
| Bible/02-Core/Sou/002-Planner.md | Sou produces Mission plans |
| Bible/02-Core/Sou/003-Missions.md | Sou's view of Missions |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
