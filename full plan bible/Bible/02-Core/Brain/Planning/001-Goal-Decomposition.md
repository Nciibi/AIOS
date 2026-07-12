# AIOS Bible — Brain
## 001 — Goal Decomposition

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-001 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 2 — Law of Non-Execution |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Goal Decomposition is the entry point of the Planning System — it transforms a high-level strategic goal into a hierarchical tree of concrete, actionable milestones. This module applies one or more decomposition strategies (top-down, bottom-up, template-based, or mixed) to analyze the goal's structure, generate a milestone tree, and validate that the resulting decomposition is well-formed. Decomposition is recursive by nature: each milestone can itself be decomposed into sub-milestones until a configurable depth limit is reached or all nodes are primitive (directly executable). The output feeds directly into Milestone Planning and Dependency Resolution.

## Data Model

### GoalAnalysis

```typescript
GoalAnalysis {
  goal: string
  complexity: number              // 0.0–1.0, estimated complexity score
  domain_tags: string[]           // Detected domain labels (e.g., "auth", "frontend")
  suggested_strategy: "top-down" | "bottom-up" | "template" | "mixed"
  known_patterns: string[]        // Similar goals from episodic memory
  ambiguity_score: number         // 0.0–1.0, how vague the goal statement is
  missing_context: string[]       // Aspects Sou should clarify before proceeding
}
```

### DecompositionNode

```typescript
DecompositionNode {
  node_id: string
  label: string
  description: string
  parent_id?: string
  children: string[]
  depth: number                    // 0 = root goal
  is_primitive: boolean            // True if no further decomposition needed
  strategy_used: DecompositionStrategyType
  quality_score: number            // 0.0–1.0, assessed against quality criteria
  metadata: {
    estimated_complexity: number
    required_capabilities: string[]
    risk_flags: string[]
  }
}
```

### MilestoneTree

```typescript
MilestoneTree {
  root_goal: string
  nodes: Record<string, DecompositionNode>
  root_node_id: string
  max_depth: number
  total_nodes: number
  primitive_count: number
  avg_quality_score: number
  strategy: DecompositionStrategyType
  created_at: timestamp
}
```

### DecompositionConfig

```typescript
DecompositionConfig {
  max_depth: number                // Default: 5
  min_quality_threshold: number    // Default: 0.6
  max_branching_factor: number     // Default: 7
  enable_recursive: boolean        // Default: true
  strategies_priority: DecompositionStrategyType[]
}
```

### DecompositionStrategyType

```typescript
type DecompositionStrategyType = "top-down" | "bottom-up" | "template" | "mixed"
```

## Strategies

### Top-Down Decomposition

Start with the root goal and iteratively break it into smaller sub-goals:

```
Goal: "Build e-commerce platform"
├── Milestone: Payment Processing
│   ├── Integrate Stripe API
│   ├── Build checkout flow
│   └── Handle refunds
├── Milestone: Product Catalog
│   ├── Design product schema
│   ├── Build search/filter
│   └── Admin CRUD interface
└── Milestone: User Management
    ├── Registration & login
    ├── Profile management
    └── Permission system
```

Best for well-understood domains where the overall structure is known in advance.

### Bottom-Up Decomposition

Identify concrete atomic tasks first, then group them into logical milestones:

```
Atomic tasks identified:
- Write SQL schema for users table
- Write SQL schema for products table
- Implement login endpoint
- Implement registration endpoint
- Build login form component
- Build registration form component

Grouped into Milestones:
├── Milestone: Database Schema Design
│   ├── Write SQL schema for users table
│   └── Write SQL schema for products table
├── Milestone: Auth API
│   ├── Implement login endpoint
│   └── Implement registration endpoint
└── Milestone: Auth Frontend
    ├── Build login form component
    └── Build registration form component
```

Best for novel or exploratory tasks where concrete steps are easier to identify than the overall architecture.

### Template-Based Decomposition

Match the goal against a library of predefined plan templates:

```
Goal: "Implement REST API"
→ Matches template: "REST API Blueprint"
├── Milestone 1: API Design (OpenAPI spec)
├── Milestone 2: Data Layer (models, migrations)
├── Milestone 3: Business Logic (services)
├── Milestone 4: Controllers (routing)
├── Milestone 5: Tests (unit + integration)
└── Milestone 6: Documentation
```

Best for repetitive goals with known, stable structure.

### Mixed Decomposition

Combine strategies — use templates for known portions, top-down for the core structure, bottom-up for exploratory sub-components:

```
Goal: "Modernize legacy payment system"
├── [Template] Core: "Payment System Blueprint" (known structure)
│   ├── Transaction processing
│   ├── Reconciliation
│   └── Reporting
├── [Top-Down] Migration Layer
│   ├── Data migration plan
│   └── Rollback strategy
└── [Bottom-Up] New Integration
    ├── Research modern payment APIs
    └── Prototype PoC integration
```

Best for complex, partially-known goals that don't fit a single strategy.

## Recursive Decomposition

Each non-primitive node may be recursively decomposed by the same or a different strategy:

```
Algorithm: RecursiveDecompose(node, config, depth)
  if depth >= config.max_depth:
    mark node as primitive
    return

  children = selectStrategy(node).decompose(node)
  for child in children:
    quality = assessQuality(child)
    if quality < config.min_quality_threshold:
      apply refinement to child
      re-decompose if refinement fails → mark as primitive with warning

  validate tree structure
  emit PLN.GoalDecomposed event
```

Depth limits prevent infinite recursion. The branching factor cap prevents explosion.

### Quality Criteria for Well-Formed Goals

| Criterion | Description | Threshold |
|-----------|-------------|-----------|
| Atomic | Node represents a single, indivisible unit of work | No AND/OR ambiguity |
| Measurable | Completion can be objectively verified | Clear pass/fail criteria |
| Bounded | Scope is limited; no hidden expansion | Est. tokens ±20% |
| Independent | Minimal coupling to sibling nodes | Dependency count ≤ 3 |
| Valuable | Each node contributes directly to parent goal | Traceable upward |
| Actionable | A capable worker can execute it | Capabilities specified |
| Consistent | No contradictory requirements | Self-consistent |

## Internal Interface

```typescript
interface GoalDecomposer {
  decompose(goal: string, context: DecisionContext, config?: DecompositionConfig): MilestoneTree
  analyzeGoal(goal: string, context: DecisionContext): GoalAnalysis
  selectStrategy(goal: string, analysis: GoalAnalysis): DecompositionStrategyType

  refineNode(node_id: string, feedback: string): DecompositionNode
  validateTree(tree: MilestoneTree): ValidationResult
  assessQuality(node: DecompositionNode): number
  getTemplateMatches(goal: string): TemplateMatch[]
}

interface DecompositionStrategy {
  type: DecompositionStrategyType
  decompose(goal: string, context: DecisionContext): DecompositionNode[]
  canHandle(goal: string, analysis: GoalAnalysis): number   // 0.0–1.0 confidence
}

interface TemplateMatch {
  template_id: string
  name: string
  confidence: number
  nodes: DecompositionNode[]
}

interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
  warnings: string[]
  quality_summary: {
    avg_score: number
    min_score: number
    failed_criteria: string[]
  }
}

interface DecisionContext {
  session_id: string
  episodic_memory_refs: string[]
  constraints: string[]
  preferences: string[]
}
```

## Lifecycle

```
Raw Goal Input
    │
    ▼
Goal Analysis (analyzeGoal)
    │
    ├── Assess complexity, ambiguity, domain
    ├── Query episodic memory for similar patterns
    └── Determine missing context
    │
    ▼
Strategy Selection (selectStrategy)
    │
    ├── If high-confidence template match → template strategy
    ├── If well-understood domain → top-down
    ├── If exploratory → bottom-up
    └── If complex/mixed → mixed strategy
    │
    ▼
Decomposition (decompose)
    │
    ├── Apply strategy recursively
    ├── Respect depth limit & branching factor
    ├── Assess quality at each node
    ├── Flag low-quality nodes for refinement
    └── Emit PLN.GoalDecomposed
    │
    ▼
Tree Validation (validateTree)
    │
    ├── Check all quality criteria
    ├── Verify no duplicate or overlapping nodes
    ├── Confirm root-to-leaf traceability
    └── Return validated MilestoneTree
    │
    ▼
Output to Milestone Planner
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PLN.GD.AnalysisComplete` | goal, complexity, domain_tags, ambiguity_score | Goal analysis finished |
| `PLN.GD.StrategySelected` | goal, strategy_type, confidence | Decomposition strategy chosen |
| `PLN.GD.NodeCreated` | node_id, parent_id, depth, strategy_used | Single decomposition node created |
| `PLN.GD.TreeGenerated` | tree_id, node_count, max_depth, strategy | Full milestone tree built |
| `PLN.GD.RecursionStep` | parent_node_id, child_count, depth | Recursive decomposition step |
| `PLN.GD.QualityAssessment` | node_id, quality_score, failed_criteria | Node quality check completed |
| `PLN.GD.RefinementNeeded` | node_id, quality_score, suggestions | Node below quality threshold |
| `PLN.GD.TemplateMatched` | goal, template_id, confidence | Goal matched a plan template |
| `PLN.GD.DepthLimitReached` | node_id, depth, max_depth | Max depth hit; node marked primitive |
| `PLN.GD.DecompositionFailed` | goal, reason, suggestions | Goal too vague or ambiguous to decompose |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GD-001 | Every decomposition node has exactly one parent (except root) | Structural — tree model enforced |
| GD-002 | Total depth never exceeds `max_depth` | Algorithmic — checked at each recursion |
| GD-003 | Branching factor never exceeds `max_branching_factor` | Algorithmic — checked at node creation |
| GD-004 | Every node's description is traceable to the root goal | Algorithmic — validated in `validateTree` |
| GD-005 | Quality score is monotonic (initial assessment ≥ refinement score) | Algorithmic — refinement can only improve |
| GD-006 | Template matches with confidence < 0.5 are not applied | Algorithmic — threshold gating |
| GD-007 | Recursive decomposition terminates (depth limit + primitive detection) | Algorithmic — guaranteed termination |
| GD-008 | A decomposed plan is never empty — at least one milestone produced | Validation — enforced on output |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Goal statement is empty or whitespace | `PLN_GD_EMPTY_GOAL` | Return error; goal required |
| No strategy can handle the goal | `PLN_GD_NO_STRATEGY` | Return error with analysis and suggestions |
| Template match below confidence threshold | `PLN_GD_LOW_CONFIDENCE` | Fall back to top-down; log warning |
| Decomposition produces zero nodes | `PLN_GD_EMPTY_TREE` | Return error; goal may be too specific |
| Recursion exceeds max depth | `PLN_GD_DEPTH_EXCEEDED` | Mark remaining as primitive; log warning |
| Quality below threshold after refinement | `PLN_GD_LOW_QUALITY` | Return tree with flags; Sou may override |
| Goal contains contradictory constraints | `PLN_GD_CONTRADICTORY_GOAL` | Return error; list conflicting constraints |
| Duplicate node detected in tree | `PLN_GD_DUPLICATE_NODE` | Return error; merge or disambiguate |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Goal Decomposition handles only decomposition; no execution |
| R2 — Dependency Order | Depends on Episodic Memory for pattern matching; no upward deps |
| R3 — DRY | Strategy logic encapsulated per strategy; shared validation reused |
| R4 — Builder Pattern | Tree built stepwise: Analyze → Select → Decompose → Validate |
| R5 — Liskov Substitution | Any DecompositionStrategy implements the interface |
| R6 — DI over Singletons | Strategies injected via DecompositionConfig |
| R9 — Deterministic | Same goal + context + strategy produces same tree |
| R10 — Simpler Over Complex | Uses tree model, not generalized goal-net or HTN |
| R13 — Design for Failure | Low-quality nodes flagged; depth limit prevents runaway recursion |
| R14 — Paved Path | All decomposition flows through decompose() entry point |
| R15 — Open/Closed | New strategies added via registry, not by modifying decomposer |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Goal Decomposition is the first stage of planning |
| Planning/002-Milestones.md | Milestone nodes created from decomposition output |
| Planning/003-Dependencies.md | Dependencies derived from milestone tree structure |
| Memory/002-Episodic-Memory.md | Past goal patterns retrieved for strategy selection |
| Brain/Decision/000-Overview.md | Decisions inform strategy selection and refinement |
