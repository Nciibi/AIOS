# AIOS Bible â€” Brain
## 003 â€” Dependency Resolution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-003 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 2 â€” Law of Non-Execution, Law 4 â€” Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Dependency Resolution analyzes milestone dependencies and produces a validated execution graph. This module enforces DAG (Directed Acyclic Graph) structure, detects and reports cycles, calculates the critical path, and validates that all dependency constraints are satisfiable. Conditional dependencies are evaluated against the current decision context to determine which branches are active. The resolved ExecutionGraph is the authoritative execution blueprint â€” it determines milestone ordering, parallel execution opportunities, and schedule-critical paths. Dependency visualization data is also produced for the Context System to render plan structure to Sou.

## Data Model

### Dependency

```typescript
Dependency {
  dependency_id: string
  plan_id: string
  from: string                      // Prerequisite milestone ID
  to: string                        // Dependent milestone ID
  type: DependencyType
  condition?: string                // Evaluable expression for conditional deps
  label?: string                    // Human-readable description
  metadata: {
    weight: number                  // 0.0â€“1.0, influence on critical path
    optional: boolean               // If true, soft dependency (advisory only)
    created_at: timestamp
  }
}
```

### DependencyType

```typescript
type DependencyType = "sequential" | "parallel" | "conditional"
```

### ExecutionGraph

```typescript
ExecutionGraph {
  plan_id: string
  nodes: Record<string, ExecutionNode>
  edges: Dependency[]
  entry_nodes: string[]             // Milestone IDs with no prerequisites
  exit_nodes: string[]              // Milestone IDs with no dependents
  critical_path: CriticalPath
  parallel_groups: ParallelGroup[]
  total_estimated_duration_ms: number
  depth: number                     // Longest path length in nodes
  validated: boolean
  cycle_info?: CycleInfo            // Present if cycle detected
}
```

### ExecutionNode

```typescript
ExecutionNode {
  milestone_id: string
  name: string
  level: number                     // Depth in dependency tree (0 = root)
  estimated_duration_ms: number
  earliest_start: number            // Calculated via forward pass
  earliest_finish: number
  latest_start: number              // Calculated via backward pass
  latest_finish: number
  slack: number                     // Float â€” delay without affecting critical path
  dependencies: string[]            // Incoming edge milestone IDs
  dependents: string[]              // Outgoing edge milestone IDs
  on_critical_path: boolean
  parallel_group_id?: string
}
```

### CriticalPath

```typescript
CriticalPath {
  path: string[]                    // Ordered milestone IDs forming the critical path
  total_duration_ms: number
  critical_nodes: ExecutionNode[]
  parallelizable_segments: { start: number; end: number; duration_ms: number }[]
}
```

### ParallelGroup

```typescript
ParallelGroup {
  group_id: string
  milestone_ids: string[]
  estimated_duration_ms: number     // Max of group members
  description: string
}
```

### CycleInfo

```typescript
CycleInfo {
  cycle_nodes: string[]             // Milestone IDs involved in the cycle
  cycle_edges: Dependency[]         // Dependencies forming the cycle
  suggested_resolution: string      // Which edge to remove or reverse
}
```

### ConditionalDependencyEvaluation

```typescript
ConditionalDependencyEvaluation {
  dependency_id: string
  condition: string
  evaluated: boolean
  result: boolean                   // True = dependency is active
  context_snapshot: Record<string, unknown>
  evaluated_at: timestamp
}
```

## Dependency Types

### Sequential Dependency

B cannot start until A completes. This is the default dependency type:

```
A â”€â”€â†’ B â”€â”€â†’ C

Meaning: A must finish before B starts; B must finish before C starts.
Enforced at execution by Institution OS â€” missions scheduled in order.
```

### Parallel Dependency

A and B have no ordering constraint and may execute concurrently:

```
A â”€â”€â”
    â”œâ”€â”€â†’ C
B â”€â”€â”˜

Meaning: A and B run in parallel; C waits for both.
Allows the scheduler to maximize resource utilization.
```

### Conditional Dependency

B starts only if A produces a result that satisfies a condition:

```
A â”€â”€[if result.passed]â”€â”€â†’ B
  â””â”€[if result.failed]â”€â”€â†’ C

Meaning: If A's output passes validation, execute B; otherwise execute C.
Condition is evaluated as an expression against the source milestone's result.
```

Condition expressions use a restricted DSL:

```typescript
// Supported condition expressions:
condition := field comparator value
field := /result\.\w+/             // e.g., result.status, result.validation_score
comparator := "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "matches"
value := string | number | boolean
```

## DAG Enforcement & Cycle Detection

### Cycle Detection Algorithm (DFS-based)

```typescript
function detectCycle(graph: ExecutionGraph): CycleInfo | null {
  const WHITE = 0  // Unvisited
  const GRAY = 1   // In current DFS path
  const BLACK = 2  // Fully explored

  const color: Record<string, number> = {}
  const parent: Record<string, string | null> = {}
  const cycle_nodes: string[] = []

  function dfs(node_id: string): boolean {
    color[node_id] = GRAY
    const node = graph.nodes[node_id]

    for (const dep_id of node.dependents) {
      if (color[dep_id] === GRAY) {
        // Back edge found â€” cycle detected
        let current = node_id
        while (current !== dep_id) {
          cycle_nodes.unshift(current)
          current = parent[current]!
        }
        cycle_nodes.unshift(dep_id)
        cycle_nodes.push(dep_id)
        return true
      }
      if (color[dep_id] === WHITE) {
        parent[dep_id] = node_id
        if (dfs(dep_id)) return true
      }
    }

    color[node_id] = BLACK
    return false
  }

  for (const node_id of graph.entry_nodes) {
    if (color[node_id] === WHITE) {
      if (dfs(node_id)) {
        return {
          cycle_nodes,
          cycle_edges: extractCycleEdges(cycle_nodes, graph),
          suggested_resolution: `Remove dependency from ${cycle_nodes[0]} to ${cycle_nodes[1]}`,
        }
      }
    }
  }

  return null
}
```

The algorithm is O(V + E) and runs on every `resolve()` call. Cycles are rejected before the plan is approved.

### Critical Path Calculation

Uses forward pass (earliest start/finish) and backward pass (latest start/finish):

```typescript
function calculateCriticalPath(graph: ExecutionGraph): CriticalPath {
  // Forward pass: compute earliest start/finish
  topologicalSort(graph).forEach(node => {
    if (node.dependencies.length === 0) {
      node.earliest_start = 0
    } else {
      node.earliest_start = Math.max(
        ...node.dependencies.map(depId => graph.nodes[depId].earliest_finish)
      )
    }
    node.earliest_finish = node.earliest_start + node.estimated_duration_ms
  })

  // Backward pass: compute latest start/finish
  topologicalSort(graph, true).forEach(node => {
    if (node.dependents.length === 0) {
      node.latest_finish = node.earliest_finish
    } else {
      node.latest_finish = Math.min(
        ...node.dependents.map(depId => graph.nodes[depId].latest_start)
      )
    }
    node.latest_start = node.latest_finish - node.estimated_duration_ms
    node.slack = node.latest_start - node.earliest_start
    node.on_critical_path = node.slack === 0
  })

  // Extract critical path
  const criticalPath = topologicalSort(graph).filter(n => n.on_critical_path)
  return {
    path: criticalPath.map(n => n.milestone_id),
    total_duration_ms: criticalPath[criticalPath.length - 1]?.earliest_finish ?? 0,
    critical_nodes: criticalPath,
    parallelizable_segments: findParallelSegments(criticalPath),
  }
}
```

## Internal Interface

```typescript
interface DependencyResolver {
  resolve(milestones: Milestone[], dependencies: Dependency[], context?: DecisionContext): ExecutionGraph
  detectCycle(graph: ExecutionGraph): CycleInfo | null
  getCriticalPath(graph: ExecutionGraph): CriticalPath
  validate(graph: ExecutionGraph): DependencyValidationResult

  addDependency(plan_id: string, dependency: CreateDependencyInput): Dependency
  removeDependency(dependency_id: string): void
  updateDependency(dependency_id: string, updates: Partial<Dependency>): Dependency

  evaluateConditional(dependency: Dependency, result: MilestoneResult): ConditionalDependencyEvaluation
  getDependenciesForMilestone(milestone_id: string): Dependency[]
  getDependentsForMilestone(milestone_id: string): Dependency[]

  visualizeGraph(plan_id: string): GraphVisualization
  getParallelGroups(graph: ExecutionGraph): ParallelGroup[]
}

interface CreateDependencyInput {
  from: string
  to: string
  type: DependencyType
  condition?: string
  label?: string
  optional?: boolean
}

interface DependencyValidationResult {
  valid: boolean
  cycle_info?: CycleInfo
  orphaned_milestones: string[]     // Not connected to any dependency
  unsatisfiable_conditions: string[]
  warnings: string[]                // E.g., redundant dependencies
}

interface GraphVisualization {
  nodes: { id: string; label: string; level: number; on_critical_path: boolean }[]
  edges: { from: string; to: string; type: DependencyType; label?: string }[]
  critical_path_highlighted: boolean
}
```

## Lifecycle

```
Milestones + Raw Dependencies (from planner / user)
    â”‚
    â–¼
Build ExecutionGraph (resolve)
    â”‚
    â”œâ”€â”€ Create nodes from milestones
    â”œâ”€â”€ Add edges from dependencies
    â””â”€â”€ Identify entry/exit nodes
    â”‚
    â–¼
Cycle Detection (detectCycle)
    â”‚
    â”œâ”€â”€ DFS over graph
    â”œâ”€â”€ If cycle found â†’ return CycleInfo with suggestion
    â””â”€â”€ If no cycle â†’ proceed
    â”‚
    â–¼
Validation (validate)
    â”‚
    â”œâ”€â”€ Check all milestones are reachable
    â”œâ”€â”€ Evaluate conditional conditions if context available
    â”œâ”€â”€ Detect orphaned milestones
    â””â”€â”€ Check for redundant/contradictory edges
    â”‚
    â–¼
Critical Path Calculation (getCriticalPath)
    â”‚
    â”œâ”€â”€ Forward pass (earliest times)
    â”œâ”€â”€ Backward pass (latest times)
    â”œâ”€â”€ Compute slack for each node
    â””â”€â”€ Identify critical path nodes (slack = 0)
    â”‚
    â–¼
Parallel Group Detection (getParallelGroups)
    â”‚
    â”œâ”€â”€ Group independent sibling chains
    â””â”€â”€ Label groups for scheduler
    â”‚
    â–¼
Validated ExecutionGraph (output to Progress Tracker, Institution OS)
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| PLN.PLNEvent |      plan_id, node_count, edge_count, depth | Execution graph constructed |
| PLN.PLNEvent |      plan_id, cycle_nodes, suggested_resolution | Dependency cycle found and blocked |
| PLN.PLNEvent |      plan_id, removed_dependency_id | Cycle resolved by user |
| PLN.PLNEvent |      plan_id, path, total_duration_ms | Critical path identified |
| PLN.PLNEvent |      plan_id, valid, warnings | Dependency validation finished |
| PLN.PLNEvent |      dependency_id, from, to, type | New dependency created |
| PLN.PLNEvent |      dependency_id, from, to | Dependency deleted |
| PLN.PLNEvent |      dependency_id, updated_fields | Dependency type or condition changed |
| PLN.PLNEvent |      dependency_id, condition, result | Conditional dependency evaluated |
| PLN.PLNEvent |      dependency_id, condition, reason | Condition cannot be evaluated with current context |
| PLN.PLNEvent |      group_id, milestone_ids, duration_ms | Parallel execution opportunity identified |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEP-001 | The execution graph is always a DAG â€” no cycles allowed | Algorithmic â€” checked on every `resolve()` |
| DEP-002 | Every non-entry milestone has at least one incoming dependency | Validation â€” flagged as orphan |
| DEP-003 | Every non-exit milestone has at least one outgoing dependency | Validation â€” flagged as dangling |
| DEP-004 | Conditional dependencies are only traversed if condition evaluates to true | Algorithmic â€” evaluated in `getCriticalPath` |
| DEP-005 | Parallel dependency implies neither Aâ†’B nor Bâ†’A ordering | Validation â€” cross-checked |
| DEP-006 | The critical path is unique and deterministic for a given graph | Algorithmic â€” forward/backward pass is deterministic |
| DEP-007 | Optional dependencies do not block execution when unsatisfied | Algorithmic â€” excluded from critical path |
| DEP-008 | A milestone cannot depend on itself | Schema â€” `from !== to` enforced |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Dependency cycle detected | `PLN_DEP_CYCLE_DETECTED` | Return CycleInfo; reject graph until resolved |
| Self-referencing dependency | `PLN_DEP_SELF_REFERENCE` | Return error; from and to must differ |
| Milestone in dependency not found | `PLN_DEP_MILESTONE_NOT_FOUND` | Return error; create milestone first |
| Conditional expression parse failure | `PLN_DEP_INVALID_CONDITION` | Return error with parser details |
| Unsatisfiable conditional (missing context) | `PLN_DEP_CONDITION_UNSATISFIABLE` | Log warning; treat as blocking |
| Redundant parallel dependency | `PLN_DEP_REDUNDANT` | Warning; parallel parallel to sibling is implied |
| Orphaned milestone (no connections) | `PLN_DEP_ORPHAN_MILESTONE` | Warning; milestone excluded from schedule |
| Modification of resolved graph during execution | `PLN_DEP_GRAPH_LOCKED` | Return error; plan must be paused |


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
| R1 â€” Modulsingularity | Dependency Resolver handles only graph analysis; no execution |
| R2 â€” Dependency Order | Depends on Milestone Planner for nodes; no upward deps |
| R3 â€” DRY | Graph algorithms (DFS, topological sort) defined once |
| R4 â€” Builder Pattern | Graph built in stages: nodes â†’ edges â†’ validate â†’ critical path |
| R5 â€” Liskov Substitution | Any cycle detection strategy implements the interface |
| R6 â€” DI over Singletons | Condition evaluator injectable |
| R9 â€” Deterministic | Same milestones + dependencies produce same graph |
| R10 â€” Simpler Over Complex | Uses CPM (Critical Path Method), not generalized PERT |
| R13 â€” Design for Failure | Cycles caught early; orphan detection prevents stalled execution |
| R14 â€” Paved Path | All dependency analysis flows through resolve() â†’ validate() |
| R15 â€” Open/Closed | New dependency types added via registry |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Dependency Resolution is the third stage of planning |
| Planning/002-Milestones.md | Dependencies connect milestones into execution graph |
| Planning/004-Progress-Tracking.md | Progress tracker monitors blocked status from dependency failures |
| Planning/005-Plan-Versioning.md | Dependency changes create new plan versions |
| Brain/Context/000-Overview.md | Visualization data pushed for plan rendering |
| Institution OS | ExecutionGraph consumed for mission scheduling |
