# AIOS Bible — Brain
## 000 — Planning System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-000 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 2 — Law of Non-Execution, Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Planning System enables Sou to decompose strategic goals into actionable plans. It handles goal decomposition, milestone definition, dependency mapping, resource estimation, and progress tracking. When Sou decides WHAT to do, the Planning System figures out HOW to do it — breaking high-level objectives into concrete, ordered steps that can be executed as missions.

The Planning System does not execute plans. Execution is delegated to Institution OS (missions, workers). The Planning System produces plan blueprints that Sou approves before execution begins.

## Architecture

```
Sou (approves plan, monitors progress)
   ▲
   │
   ▼
┌────────────────────────────────────────────┐
│           Planning System                   │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Goal     │  │ Milestone│  │ Dependency│ │
│  │ Decompose│─►│ Planner  │─►│ Resolver  │ │
│  └──────────┘  └──────────┘  └────┬─────┘ │
│                                    │       │
│  ┌──────────┐  ┌──────────┐       │       │
│  │ Resource │  │ Progress │       │       │
│  │ Estimator│  │ Tracker  │       │       │
│  └──────────┘  └──────────┘       │       │
└────────────────────────────────────┼───────┘
                                     │
                                     ▼
                            ┌──────────────┐
                            │  Event Store │
                            │ (evidence)   │
                            └──────────────┘
```

## Core Concepts

### Plan Model

```
Plan {
  plan_id: string
  session_id: string
  goal: string                     // High-level objective
  milestones: Milestone[]
  dependencies: Dependency[]
  resource_estimates: ResourceEstimate
  status: "draft" | "approved" | "active" | "completed" | "failed" | "cancelled"
  sou_approved: boolean
  created_at: timestamp
  approved_at?: timestamp
  completed_at?: timestamp
}

Milestone {
  milestone_id: string
  name: string
  description: string
  order: number                    // Sequential position in plan
  parent_milestone?: string        // For hierarchical decomposition
  dependencies: string[]           // Milestone IDs that must complete first
  estimated_effort: ResourceEstimate
  status: "pending" | "in_progress" | "completed" | "blocked" | "failed"
  assigned_mission_id?: string     // Set when delegated to Institution OS
}

Dependency {
  from: string                     // Milestone ID (prerequisite)
  to: string                       // Milestone ID (dependent)
  type: "sequential" | "parallel" | "conditional"
  condition?: string               // For conditional deps
}

ResourceEstimate {
  estimated_tokens: number
  estimated_duration_ms: number
  required_capabilities: string[]
  estimated_cost: number
  risk_score: number               // 0.0–1.0
}
```

### 1. Goal Decomposition

The Goal Decomposer breaks a high-level goal into a hierarchy of milestones:

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| Top-down | Start with goal, recursively decompose | Well-understood domains |
| Bottom-up | Identify concrete steps, group into milestones | Novel or exploratory tasks |
| Template-based | Use predefined plan templates | Repetitive goals with known structure |
| Mixed | Combination of strategies | Complex, partially-known goals |

Decomposition produces a milestone tree:

```
Goal: "Implement user authentication system"
├── Milestone 1: Design auth architecture
│   ├── Subtask 1.1: Research auth patterns
│   └── Subtask 1.2: Design database schema
├── Milestone 2: Implement backend
│   ├── Subtask 2.1: Create user model
│   ├── Subtask 2.2: Implement registration endpoint
│   └── Subtask 2.3: Implement login endpoint
└── Milestone 3: Implement frontend
    ├── Subtask 3.1: Build login form
    └── Subtask 3.2: Build registration form
```

### 2. Milestone Planning

Each milestone is assigned metadata that Sou uses for resource allocation and sequencing:

| Property | Description |
|----------|-------------|
| `order` | Position in execution sequence |
| `estimated_effort` | Time, tokens, cost projection |
| `dependencies` | Prerequisites that must complete |
| `required_capabilities` | Worker capabilities needed |
| `risk_score` | Likelihood of issues (0.0–1.0) |
| `parallelizable` | Can this run in parallel with siblings? |

### 3. Dependency Resolution

The Dependency Resolver analyzes milestone dependencies and produces an execution graph:

| Dependency Type | Meaning | Example |
|----------------|---------|---------|
| Sequential | B cannot start until A completes | Design → Implement → Test |
| Parallel | A and B can run simultaneously | Frontend + Backend development |
| Conditional | B starts only if A produces result X | If design approved, then implement |

The resolver detects cycles and reports them as errors. All plans must be DAGs (Directed Acyclic Graphs).

### 4. Resource Estimation

Before Sou approves a plan, the Planning System estimates required resources:

| Resource | Estimation Basis |
|----------|-----------------|
| Tokens | Estimated LLMOS usage per milestone |
| Duration | Historical data from similar milestones |
| Cost | Token cost + resource reservation via ROS |
| Capabilities | Worker capabilities required |
| Risk | Complexity, novelty, dependencies, known issues |

### 5. Progress Tracking

Once a plan is approved and execution begins, the Progress Tracker monitors:

| Metric | Source | Description |
|--------|--------|-------------|
| Milestone status | Institution OS | Current status of each milestone |
| Completion % | Completed / total milestones | Overall plan progress |
| Blocked milestones | Dependency failures | Milestones waiting on dependencies |
| Resource consumption | ROS / Event Store | Actual vs estimated resources |
| Timeline variance | Actual vs estimated duration | Schedule deviation |

Progress events are pushed to the Context System so Sou remains aware of execution status.

## Interfaces

### Planning System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `createPlan(goal, context)` | Sou only | Decompose a goal into a plan |
| `approvePlan(plan_id)` | Sou only | Approve a plan for execution |
| `getPlan(plan_id)` | Sou only | Retrieve a plan by ID |
| `listPlans(session_id, status?)` | Sou only | List plans for a session |
| `updateMilestoneStatus(milestone_id, status, result?)` | Institution OS | Report milestone completion |
| `cancelPlan(plan_id)` | Sou only | Cancel an active plan |
| `getProgress(plan_id)` | Sou only | Get execution progress |
| `estimateResources(goal, context)` | Sou only | Estimate resources without creating a plan |

### Internal Interfaces

```
interface DecompositionStrategy {
  decompose(goal: string, context: DecisionContext): Milestone[]
}

ExecutionGraph {
  nodes: ExecutionNode[]
  edges: Dependency[]
  entry_nodes: string[]            // Milestone IDs with no prerequisites
  critical_path: string[]          // Longest dependency chain
  estimated_total_duration_ms: number
}

ExecutionNode {
  milestone_id: string
  name: string
  estimated_duration_ms: number
  level: number                    // Depth in dependency tree (0 = root)
}

interface DependencyResolver {
  resolve(milestones: Milestone[]): ExecutionGraph
}

interface ResourceEstimator {
  estimate(plan: Plan): ResourceEstimate
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.PlanCreated` | plan_id, goal, milestone_count | Plan created but not yet approved |
| `PLN.PlanApproved` | plan_id, resource_estimate | Sou approved the plan |
| `PLN.PlanCancelled` | plan_id, reason | Plan cancelled before/during execution |
| `PLN.PlanCompleted` | plan_id, duration_ms | All milestones completed |
| `PLN.PlanFailed` | plan_id, failed_milestone, reason | Plan failed at a milestone |
| `PLN.MilestoneStarted` | milestone_id, plan_id | Milestone execution began |
| `PLN.MilestoneCompleted` | milestone_id, plan_id, result | Milestone finished |
| `PLN.MilestoneBlocked` | milestone_id, blocking_dependency | Milestone waiting on dependency |
| `PLN.MilestoneFailed` | milestone_id, error | Milestone failed |
| `PLN.DependencyCycleDetected` | cycle_nodes | Dependency cycle prevented |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| PLN-001 | Plans must be DAGs — no circular dependencies | Algorithmic — checked on create |
| PLN-002 | Plans require Sou approval before execution | API-level — milestones not created until `approvePlan` |
| PLN-003 | Milestone status is reported by Institution OS | API-level — only Institution OS can update |
| PLN-004 | The Planning System is stateless — plans live in Memory OS | Architectural — no internal persistence |
| PLN-005 | Every plan milestone maps to exactly one mission | Architectural — verified on approval |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Planning System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou creates, approves, and monitors plans |
| Brain/Decision/000-Overview.md | Decisions inform plan creation and milestone sequencing |
| Brain/Context/000-Overview.md | Progress events pushed to Context System |
| Brain/Tools/000-Overview.md | Tool System provides capabilities estimated during planning |
| Institution OS | Milestones delegated as missions for execution |
| Bible/02-Core/ROS/ | Resource estimation uses ROS for cost projection |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Dependency cycle detected | `PLN_CYCLE_DETECTED` | Reject plan; return cycle nodes for resolution |
| Unknown milestone_id on update | `PLN_MILESTONE_NOT_FOUND` | Return error; no state change |
| Approve already-approved plan | `PLN_ALREADY_APPROVED` | OK; idempotent |
| Update from unauthorized source | `PLN_UNAUTHORIZED_SOURCE` | Deny update; log security event |
| Goal too vague to decompose | `PLN_DECOMPOSITION_FAILED` | Return error with suggestions |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Planning System does one thing: plan creation and tracking |
| R2 — Dependency Order | Depends on Event Store, ROS; no upward deps |
| R3 — DRY | Plan templates defined once in Template Registry |
| R4 — Builder Pattern | Plan built by Decomposer → Planner → Resolver |
| R5 — Liskov Substitution | Any DecompositionStrategy implements the interface |
| R6 — DI over Singletons | Strategies injected at plan creation |
| R9 — Deterministic | Same goal + context produces same plan (unless strategy includes randomness) |
| R10 — Simpler Over Complex | Uses milestone tree, not generalized PERT/CPM |
| R13 — Design for Failure | Planning System degrades gracefully — resource estimates use cached data when ROS is unavailable |
| R14 — Paved Path | All planning flows through `createPlan` → `approvePlan` |
| R15 — Open/Closed | New decomposition strategies added via Registry |