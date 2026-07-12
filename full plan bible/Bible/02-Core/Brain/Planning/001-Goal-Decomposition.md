# AIOS Bible â€” Brain
## 001 â€” Goal Decomposition

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Planning |
| Document ID | AIOS-BBL-002-PLN-001 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 2 â€” Law of Non-Execution |
| Source Physics | Physics/005-Events.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Goal Decomposition is the entry point of the Planning System â€” it transforms a high-level strategic goal into a hierarchical tree of concrete, actionable milestones. This module applies one or more decomposition strategies (top-down, bottom-up, template-based, or mixed) to analyze the goal's structure, generate a milestone tree, and validate that the resulting decomposition is well-formed. Decomposition is recursive by nature: each milestone can itself be decomposed into sub-milestones until a configurable depth limit is reached or all nodes are primitive (directly executable). The output feeds directly into Milestone Planning and Dependency Resolution.

## Data Model

### GoalAnalysis

```typescript
GoalAnalysis {
  goal: string
  complexity: number              // 0.0â€“1.0, estimated complexity score
  domain_tags: string[]           // Detected domain labels (e.g., "auth", "frontend")
  suggested_strategy: "top-down" | "bottom-up" | "template" | "mixed"
  known_patterns: string[]        // Similar goals from episodic memory
  ambiguity_score: number         // 0.0â€“1.0, how vague the goal statement is
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
  quality_score: number            // 0.0â€“1.0, assessed against quality criteria
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
â”œâ”€â”€ Milestone: Payment Processing
â”‚   â”œâ”€â”€ Integrate Stripe API
â”‚   â”œâ”€â”€ Build checkout flow
â”‚   â””â”€â”€ Handle refunds
â”œâ”€â”€ Milestone: Product Catalog
â”‚   â”œâ”€â”€ Design product schema
â”‚   â”œâ”€â”€ Build search/filter
â”‚   â””â”€â”€ Admin CRUD interface
â””â”€â”€ Milestone: User Management
    â”œâ”€â”€ Registration & login
    â”œâ”€â”€ Profile management
    â””â”€â”€ Permission system
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
â”œâ”€â”€ Milestone: Database Schema Design
â”‚   â”œâ”€â”€ Write SQL schema for users table
â”‚   â””â”€â”€ Write SQL schema for products table
â”œâ”€â”€ Milestone: Auth API
â”‚   â”œâ”€â”€ Implement login endpoint
â”‚   â””â”€â”€ Implement registration endpoint
â””â”€â”€ Milestone: Auth Frontend
    â”œâ”€â”€ Build login form component
    â””â”€â”€ Build registration form component
```

Best for novel or exploratory tasks where concrete steps are easier to identify than the overall architecture.

### Template-Based Decomposition

Match the goal against a library of predefined plan templates:

```
Goal: "Implement REST API"
â†’ Matches template: "REST API Blueprint"
â”œâ”€â”€ Milestone 1: API Design (OpenAPI spec)
â”œâ”€â”€ Milestone 2: Data Layer (models, migrations)
â”œâ”€â”€ Milestone 3: Business Logic (services)
â”œâ”€â”€ Milestone 4: Controllers (routing)
â”œâ”€â”€ Milestone 5: Tests (unit + integration)
â””â”€â”€ Milestone 6: Documentation
```

Best for repetitive goals with known, stable structure.

### Mixed Decomposition

Combine strategies â€” use templates for known portions, top-down for the core structure, bottom-up for exploratory sub-components:

```
Goal: "Modernize legacy payment system"
â”œâ”€â”€ [Template] Core: "Payment System Blueprint" (known structure)
â”‚   â”œâ”€â”€ Transaction processing
â”‚   â”œâ”€â”€ Reconciliation
â”‚   â””â”€â”€ Reporting
â”œâ”€â”€ [Top-Down] Migration Layer
â”‚   â”œâ”€â”€ Data migration plan
â”‚   â””â”€â”€ Rollback strategy
â””â”€â”€ [Bottom-Up] New Integration
    â”œâ”€â”€ Research modern payment APIs
    â””â”€â”€ Prototype PoC integration
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
      re-decompose if refinement fails â†’ mark as primitive with warning

  validate tree structure
  emit PLN.GoalDecomposed event
```

Depth limits prevent infinite recursion. The branching factor cap prevents explosion.

### Quality Criteria for Well-Formed Goals

| Criterion | Description | Threshold |
|-----------|-------------|-----------|
| Atomic | Node represents a single, indivisible unit of work | No AND/OR ambiguity |
| Measurable | Completion can be objectively verified | Clear pass/fail criteria |
| Bounded | Scope is limited; no hidden expansion | Est. tokens Â±20% |
| Independent | Minimal coupling to sibling nodes | Dependency count â‰¤ 3 |
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
  canHandle(goal: string, analysis: GoalAnalysis): number   // 0.0â€“1.0 confidence
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
    â”‚
    â–¼
Goal Analysis (analyzeGoal)
    â”‚
    â”œâ”€â”€ Assess complexity, ambiguity, domain
    â”œâ”€â”€ Query episodic memory for similar patterns
    â””â”€â”€ Determine missing context
    â”‚
    â–¼
Strategy Selection (selectStrategy)
    â”‚
    â”œâ”€â”€ If high-confidence template match â†’ template strategy
    â”œâ”€â”€ If well-understood domain â†’ top-down
    â”œâ”€â”€ If exploratory â†’ bottom-up
    â””â”€â”€ If complex/mixed â†’ mixed strategy
    â”‚
    â–¼
Decomposition (decompose)
    â”‚
    â”œâ”€â”€ Apply strategy recursively
    â”œâ”€â”€ Respect depth limit & branching factor
    â”œâ”€â”€ Assess quality at each node
    â”œâ”€â”€ Flag low-quality nodes for refinement
    â””â”€â”€ Emit PLN.GoalDecomposed
    â”‚
    â–¼
Tree Validation (validateTree)
    â”‚
    â”œâ”€â”€ Check all quality criteria
    â”œâ”€â”€ Verify no duplicate or overlapping nodes
    â”œâ”€â”€ Confirm root-to-leaf traceability
    â””â”€â”€ Return validated MilestoneTree
    â”‚
    â–¼
Output to Milestone Planner
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| PLN.PLNEvent |      goal, complexity, domain_tags, ambiguity_score | Goal analysis finished |
| PLN.PLNEvent |      goal, strategy_type, confidence | Decomposition strategy chosen |
| PLN.PLNEvent |      node_id, parent_id, depth, strategy_used | Single decomposition node created |
| PLN.PLNEvent |      tree_id, node_count, max_depth, strategy | Full milestone tree built |
| PLN.PLNEvent |      parent_node_id, child_count, depth | Recursive decomposition step |
| PLN.PLNEvent |      node_id, quality_score, failed_criteria | Node quality check completed |
| PLN.PLNEvent |      node_id, quality_score, suggestions | Node below quality threshold |
| PLN.PLNEvent |      goal, template_id, confidence | Goal matched a plan template |
| PLN.PLNEvent |      node_id, depth, max_depth | Max depth hit; node marked primitive |
| PLN.PLNEvent |      goal, reason, suggestions | Goal too vague or ambiguous to decompose |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GD-001 | Every decomposition node has exactly one parent (except root) | Structural â€” tree model enforced |
| GD-002 | Total depth never exceeds `max_depth` | Algorithmic â€” checked at each recursion |
| GD-003 | Branching factor never exceeds `max_branching_factor` | Algorithmic â€” checked at node creation |
| GD-004 | Every node's description is traceable to the root goal | Algorithmic â€” validated in `validateTree` |
| GD-005 | Quality score is monotonic (initial assessment â‰¥ refinement score) | Algorithmic â€” refinement can only improve |
| GD-006 | Template matches with confidence < 0.5 are not applied | Algorithmic â€” threshold gating |
| GD-007 | Recursive decomposition terminates (depth limit + primitive detection) | Algorithmic â€” guaranteed termination |
| GD-008 | A decomposed plan is never empty â€” at least one milestone produced | Validation â€” enforced on output |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
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
| R1 â€” Modulsingularity | Goal Decomposition handles only decomposition; no execution |
| R2 â€” Dependency Order | Depends on Episodic Memory for pattern matching; no upward deps |
| R3 â€” DRY | Strategy logic encapsulated per strategy; shared validation reused |
| R4 â€” Builder Pattern | Tree built stepwise: Analyze â†’ Select â†’ Decompose â†’ Validate |
| R5 â€” Liskov Substitution | Any DecompositionStrategy implements the interface |
| R6 â€” DI over Singletons | Strategies injected via DecompositionConfig |
| R9 â€” Deterministic | Same goal + context + strategy produces same tree |
| R10 â€” Simpler Over Complex | Uses tree model, not generalized goal-net or HTN |
| R13 â€” Design for Failure | Low-quality nodes flagged; depth limit prevents runaway recursion |
| R14 â€” Paved Path | All decomposition flows through decompose() entry point |
| R15 â€” Open/Closed | New strategies added via registry, not by modifying decomposer |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Planning/000-Overview.md | Goal Decomposition is the first stage of planning |
| Planning/002-Milestones.md | Milestone nodes created from decomposition output |
| Planning/003-Dependencies.md | Dependencies derived from milestone tree structure |
| Memory/002-Episodic-Memory.md | Past goal patterns retrieved for strategy selection |
| Brain/Decision/000-Overview.md | Decisions inform strategy selection and refinement |
