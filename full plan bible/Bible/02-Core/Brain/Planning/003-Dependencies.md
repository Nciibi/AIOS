# AIOS Bible — Brain
## 003 — Dependency Resolution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-003 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 2 — Law of Non-Execution, Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Dependency Resolution analyzes milestone dependencies and produces a validated execution graph. This module enforces DAG (Directed Acyclic Graph) structure, detects and reports cycles, calculates the critical path, and validates that all dependency constraints are satisfiable. Conditional dependencies are evaluated against the current decision context to determine which branches are active. The resolved ExecutionGraph is the authoritative execution blueprint — it determines milestone ordering, parallel execution opportunities, and schedule-critical paths. Dependency visualization data is also produced for the Context System to render plan structure to Sou.

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
    weight: number                  // 0.0–1.0, influence on critical path
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
  slack: number                     // Float — delay without affecting critical path
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
A ──→ B ──→ C

Meaning: A must finish before B starts; B must finish before C starts.
Enforced at execution by Institution OS — missions scheduled in order.
```

### Parallel Dependency

A and B have no ordering constraint and may execute concurrently:

```
A ──┐
    ├──→ C
B ──┘

Meaning: A and B run in parallel; C waits for both.
Allows the scheduler to maximize resource utilization.
```

### Conditional Dependency

B starts only if A produces a result that satisfies a condition:

```
A ──[if result.passed]──→ B
  └─[if result.failed]──→ C

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
        // Back edge found — cycle detected
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
    │
    ▼
Build ExecutionGraph (resolve)
    │
    ├── Create nodes from milestones
    ├── Add edges from dependencies
    └── Identify entry/exit nodes
    │
    ▼
Cycle Detection (detectCycle)
    │
    ├── DFS over graph
    ├── If cycle found → return CycleInfo with suggestion
    └── If no cycle → proceed
    │
    ▼
Validation (validate)
    │
    ├── Check all milestones are reachable
    ├── Evaluate conditional conditions if context available
    ├── Detect orphaned milestones
    └── Check for redundant/contradictory edges
    │
    ▼
Critical Path Calculation (getCriticalPath)
    │
    ├── Forward pass (earliest times)
    ├── Backward pass (latest times)
    ├── Compute slack for each node
    └── Identify critical path nodes (slack = 0)
    │
    ▼
Parallel Group Detection (getParallelGroups)
    │
    ├── Group independent sibling chains
    └── Label groups for scheduler
    │
    ▼
Validated ExecutionGraph (output to Progress Tracker, Institution OS)
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.DEP.GraphBuilt` | plan_id, node_count, edge_count, depth | Execution graph constructed |
| `PLN.DEP.CycleDetected` | plan_id, cycle_nodes, suggested_resolution | Dependency cycle found and blocked |
| `PLN.DEP.CycleResolved` | plan_id, removed_dependency_id | Cycle resolved by user |
| `PLN.DEP.CriticalPathCalculated` | plan_id, path, total_duration_ms | Critical path identified |
| `PLN.DEP.ValidationComplete` | plan_id, valid, warnings | Dependency validation finished |
| `PLN.DEP.DependencyAdded` | dependency_id, from, to, type | New dependency created |
| `PLN.DEP.DependencyRemoved` | dependency_id, from, to | Dependency deleted |
| `PLN.DEP.DependencyUpdated` | dependency_id, updated_fields | Dependency type or condition changed |
| `PLN.DEP.ConditionalEvaluated` | dependency_id, condition, result | Conditional dependency evaluated |
| `PLN.DEP.ConditionUnsatisfiable` | dependency_id, condition, reason | Condition cannot be evaluated with current context |
| `PLN.DEP.ParallelGroupDetected` | group_id, milestone_ids, duration_ms | Parallel execution opportunity identified |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEP-001 | The execution graph is always a DAG — no cycles allowed | Algorithmic — checked on every `resolve()` |
| DEP-002 | Every non-entry milestone has at least one incoming dependency | Validation — flagged as orphan |
| DEP-003 | Every non-exit milestone has at least one outgoing dependency | Validation — flagged as dangling |
| DEP-004 | Conditional dependencies are only traversed if condition evaluates to true | Algorithmic — evaluated in `getCriticalPath` |
| DEP-005 | Parallel dependency implies neither A→B nor B→A ordering | Validation — cross-checked |
| DEP-006 | The critical path is unique and deterministic for a given graph | Algorithmic — forward/backward pass is deterministic |
| DEP-007 | Optional dependencies do not block execution when unsatisfied | Algorithmic — excluded from critical path |
| DEP-008 | A milestone cannot depend on itself | Schema — `from !== to` enforced |

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

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Dependency Resolver handles only graph analysis; no execution |
| R2 — Dependency Order | Depends on Milestone Planner for nodes; no upward deps |
| R3 — DRY | Graph algorithms (DFS, topological sort) defined once |
| R4 — Builder Pattern | Graph built in stages: nodes → edges → validate → critical path |
| R5 — Liskov Substitution | Any cycle detection strategy implements the interface |
| R6 — DI over Singletons | Condition evaluator injectable |
| R9 — Deterministic | Same milestones + dependencies produce same graph |
| R10 — Simpler Over Complex | Uses CPM (Critical Path Method), not generalized PERT |
| R13 — Design for Failure | Cycles caught early; orphan detection prevents stalled execution |
| R14 — Paved Path | All dependency analysis flows through resolve() → validate() |
| R15 — Open/Closed | New dependency types added via registry |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Dependency Resolution is the third stage of planning |
| Planning/002-Milestones.md | Dependencies connect milestones into execution graph |
| Planning/004-Progress-Tracking.md | Progress tracker monitors blocked status from dependency failures |
| Planning/005-Plan-Versioning.md | Dependency changes create new plan versions |
| Brain/Context/000-Overview.md | Visualization data pushed for plan rendering |
| Institution OS | ExecutionGraph consumed for mission scheduling |
