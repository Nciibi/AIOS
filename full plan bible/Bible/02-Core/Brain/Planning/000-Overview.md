# AIOS Bible â€” Brain
## 000 â€” Planning System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-000 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 2 â€” Law of Non-Execution, Law 4 â€” Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Planning System enables Sou to decompose strategic goals into actionable plans. It handles goal decomposition, milestone definition, dependency mapping, resource estimation, and progress tracking. When Sou decides WHAT to do, the Planning System figures out HOW to do it â€” breaking high-level objectives into concrete, ordered steps that can be executed as missions.

The Planning System does not execute plans. Execution is delegated to Institution OS (missions, workers). The Planning System produces plan blueprints that Sou approves before execution begins.

## Architecture

```
Sou (approves plan, monitors progress)
   â–²
   â”‚
   â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Planning System                   â”‚
â”‚                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚ Goal     â”‚  â”‚ Milestoneâ”‚  â”‚ Dependencyâ”‚ â”‚
â”‚  â”‚ Decomposeâ”‚â”€â–ºâ”‚ Planner  â”‚â”€â–ºâ”‚ Resolver  â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜ â”‚
â”‚                                    â”‚       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚       â”‚
â”‚  â”‚ Resource â”‚  â”‚ Progress â”‚       â”‚       â”‚
â”‚  â”‚ Estimatorâ”‚  â”‚ Tracker  â”‚       â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”˜
                                     â”‚
                                     â–¼
                            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                            â”‚  Event Store â”‚
                            â”‚ (evidence)   â”‚
                            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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
  risk_score: number               // 0.0â€“1.0
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
â”œâ”€â”€ Milestone 1: Design auth architecture
â”‚   â”œâ”€â”€ Subtask 1.1: Research auth patterns
â”‚   â””â”€â”€ Subtask 1.2: Design database schema
â”œâ”€â”€ Milestone 2: Implement backend
â”‚   â”œâ”€â”€ Subtask 2.1: Create user model
â”‚   â”œâ”€â”€ Subtask 2.2: Implement registration endpoint
â”‚   â””â”€â”€ Subtask 2.3: Implement login endpoint
â””â”€â”€ Milestone 3: Implement frontend
    â”œâ”€â”€ Subtask 3.1: Build login form
    â””â”€â”€ Subtask 3.2: Build registration form
```

### 2. Milestone Planning

Each milestone is assigned metadata that Sou uses for resource allocation and sequencing:

| Property | Description |
|----------|-------------|
| `order` | Position in execution sequence |
| `estimated_effort` | Time, tokens, cost projection |
| `dependencies` | Prerequisites that must complete |
| `required_capabilities` | Worker capabilities needed |
| `risk_score` | Likelihood of issues (0.0â€“1.0) |
| `parallelizable` | Can this run in parallel with siblings? |

### 3. Dependency Resolution

The Dependency Resolver analyzes milestone dependencies and produces an execution graph:

| Dependency Type | Meaning | Example |
|----------------|---------|---------|
| Sequential | B cannot start until A completes | Design â†’ Implement â†’ Test |
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
| PLN-001 | Plans must be DAGs â€” no circular dependencies | Algorithmic â€” checked on create |
| PLN-002 | Plans require Sou approval before execution | API-level â€” milestones not created until `approvePlan` |
| PLN-003 | Milestone status is reported by Institution OS | API-level â€” only Institution OS can update |
| PLN-004 | The Planning System is stateless â€” plans live in Memory OS | Architectural â€” no internal persistence |
| PLN-005 | Every plan milestone maps to exactly one mission | Architectural â€” verified on approval |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
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
| R1 â€” Modulsingularity | Planning System does one thing: plan creation and tracking |
| R2 â€” Dependency Order | Depends on Event Store, ROS; no upward deps |
| R3 â€” DRY | Plan templates defined once in Template Registry |
| R4 â€” Builder Pattern | Plan built by Decomposer â†’ Planner â†’ Resolver |
| R5 â€” Liskov Substitution | Any DecompositionStrategy implements the interface |
| R6 â€” DI over Singletons | Strategies injected at plan creation |
| R9 â€” Deterministic | Same goal + context produces same plan (unless strategy includes randomness) |
| R10 â€” Simpler Over Complex | Uses milestone tree, not generalized PERT/CPM |
| R13 â€” Design for Failure | Planning System degrades gracefully â€” resource estimates use cached data when ROS is unavailable |
| R14 â€” Paved Path | All planning flows through `createPlan` â†’ `approvePlan` |
| R15 â€” Open/Closed | New decomposition strategies added via Registry |
