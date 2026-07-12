# AIOS Bible — Brain
## 004 — Criteria Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-004 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Criteria Registry is the persistent store of named decision criteria that can be reused across decisions. It maintains the canonical list of criteria, their default weights, scoring function assignments, and preference directions. Sou can query the registry, override weights, register custom criteria, and compose ad-hoc criterion sets for specific decisions.

Every criterion in the registry is a reusable building block. Rather than redefining "speed" or "cost" for each decision, Sou retrieves the canonical definition, applies session-level or global overrides, and evaluates consistently.

## Data Model

### Criterion

```typescript
Criterion {
  criterion_id: string
  name: string
  weight: number               // 0.0–1.0, default weight
  scoring_function: "linear" | "threshold" | "boolean" | "custom"
  preferences: PreferenceDirection  // "maximize" | "minimize" | "target"
  category: CriterionCategory
  description: string
  metadata: {
    source: string             // "system" | "sou_registered" | "user_defined"
    created_at: timestamp
    updated_at: timestamp
    deprecated_at?: timestamp
    locked: boolean            // If true, weight cannot be overridden
    tags: string[]
  }
}
```

### CriterionSet

```typescript
CriterionSet {
  set_id: string
  name: string
  criteria: string[]           // Ordered list of criterion_ids
  is_template: boolean         // If true, criteria cannot be removed from set
  category?: string            // E.g., "tool_selection", "plan_evaluation"
  created_at: timestamp
  updated_at: timestamp
}
```

### CriterionOverride

```typescript
CriterionOverride {
  override_id: string
  criterion_id: string
  old_weight: number
  new_weight: number
  reason: string               // Why Sou changed this weight
  scope: "session" | "global"
  session_id?: string          // Present if scope = "session"
  applied_at: timestamp
}
```

### CriterionCategory

```typescript
enum CriterionCategory {
  Performance = "performance",
  Cost = "cost",
  Quality = "quality",
  Safety = "safety",
  Reliability = "reliability",
  Maintainability = "maintainability",
  Scalability = "scalability",
  Explainability = "explainability",
  UserSatisfaction = "user_satisfaction",
  Custom = "custom"
}
```

### CriterionConfig

```typescript
CriterionConfig {
  default_weights: Record<string, number>   // criterion_id → default weight
  scoring_functions: Record<string, string> // criterion_id → function name
  categories: Record<string, CriterionCategory>
  weight_constraints: {
    min: number       // 0.0
    max: number       // 1.0
    sum_target: number // 1.0
  }
  normalization_policy: "sum_to_one" | "preserve_ratios"
}
```

## Default Criteria

The Criteria Registry is initialized with the following canonical criteria:

| Criterion | Default Weight | Scoring Function | Preference | Category |
|-----------|---------------|------------------|------------|----------|
| speed | 0.10 | Linear | maximize | Performance |
| cost | 0.15 | Linear | minimize | Cost |
| quality | 0.20 | Threshold | maximize | Quality |
| safety | 0.25 | Boolean | true | Safety |
| reliability | 0.10 | Linear | maximize | Reliability |
| explainability | 0.05 | Boolean | true | Explainability |
| scalability | 0.05 | Linear | maximize | Scalability |
| maintainability | 0.05 | Linear | maximize | Maintainability |
| user_satisfaction | 0.05 | Linear | maximize | UserSatisfaction |

**Total default weight: 1.0**

## Criterion Lifecycle

```
Registered (system init or Sou add)
    │
    ▼
Available
    │
    ├── Override weight → Customized
    │       │
    │       ├── Session override → Cleared on session end
    │       └── Global override → Persists in Event Store
    │
    ├── Used in evaluation → Activated
    │       │
    │       └── Recorded in DecisionRecord.criteria
    │
    └── Deprecated → Archived
            │
            └── Suppressed by newer criterion; excluded from queries by default
```

| State | Description | Transitions |
|-------|-------------|-------------|
| Registered | Criterion added to registry (system init or Sou via `registerCriterion`) | → Available |
| Available | Criterion is queryable and usable in decisions | → Customized, → Activated, → Archived |
| Customized | Weight overridden for session or globally | → Available (revert), → Activated |
| Activated | Criterion used in at least one evaluation this session | Stays active; no special terminal state |
| Archived | Deprecated criterion, excluded from default queries | Terminal (can be restored via admin action) |

## Weight Management

### Default Weights

Default weights are defined in `CriterionConfig.default_weights` and loaded at registry initialization. They represent the neutral, unopinionated baseline.

### Session-Level Overrides

```typescript
overrideWeight(criterion_id: string, new_weight: number, reason: string, session_id: string): CriterionOverride
```

- Affects current session only
- Logged in override_history with `scope = "session"`
- Cleared when session ends
- Does not persist to Event Store

### Global Overrides

```typescript
setGlobalWeight(criterion_id: string, new_weight: number, reason: string): CriterionOverride
```

- Affects all future sessions
- Persisted in Event Store as `DEC.PreferenceOverridden`
- Loaded at registry initialization for every new session

### Weight Normalization

After any override, weights are automatically re-normalized to sum to 1.0:

```typescript
normalizeWeights(weights: Record<string, number>): Record<string, number> {
  const total = Object.values(weights).reduce((sum, w) => sum + w, 0)
  if (total === 0) return weights
  const adjusted: Record<string, number> = {}
  for (const [id, w] of Object.entries(weights)) {
    adjusted[id] = Math.round((w / total) * 100) / 100
  }
  return adjusted
}
```

### Weight Constraints

| Constraint | Value | Enforcement |
|------------|-------|-------------|
| Minimum | 0.0 | Clamped on override |
| Maximum | 1.0 | Clamped on override |
| Sum target | 1.0 | Normalized after every override |
| Locked criteria | Weight immutable | Override returns error |

## Criterion Sets

Criterion sets are named, reusable groupings of criteria for common decision types.

### Predefined Sets

| Set ID | Name | Criteria | Use Case |
|--------|------|----------|----------|
| `tool_selection` | Tool Selection | speed, cost, quality, reliability | Choosing which tool to invoke |
| `plan_evaluation` | Plan Evaluation | quality, cost, safety, scalability | Comparing alternative plans |
| `resource_allocation` | Resource Allocation | cost, speed, reliability | Deciding resource distribution |
| `quick_assessment` | Quick Assessment | speed, cost | Rapid yes/no decisions |
| `safety_check` | Safety Check | safety, reliability | Pre-execution safety gate |

### Set Operations

```typescript
createSet(name: string, criteria: string[], is_template?: boolean): CriterionSet
getSet(set_id: string): CriterionSet | null
listSets(category?: string): CriterionSet[]
updateSet(set_id: string, criteria: string[]): CriterionSet
deleteSet(set_id: string): void
```

### Template Sets

Template sets have `is_template = true`. They lock their criteria — Sou cannot remove criteria from a template set. Sou can still override individual criterion weights within a template set.

### Custom Sets

Sou can compose ad-hoc criterion sets at decision time by passing an array of criterion_ids directly to `evaluateOptions`. These are not persisted unless Sou explicitly calls `createSet`.

## Criterion Override Rules

| Rule | Description |
|------|-------------|
| R1 | Sou can override any weight except locked criteria (`metadata.locked = true`) |
| R2 | Every override is logged in `override_history` with reason |
| R3 | Session overrides are cleared automatically on session end |
| R4 | Global overrides persist in Event Store as `DEC.PreferenceOverridden` events |
| R5 | Overriding a locked criterion returns error `CR_LOCKED_CRITERION` |
| R6 | Override value outside [0.0, 1.0] is clamped silently |
| R7 | After every override, weights are automatically re-normalized to sum 1.0 |
| R8 | Session overrides take precedence over global overrides |
| R9 | Default weights are restored when all overrides of a criterion are removed |

## Criteria Query

```typescript
// By category
listByCategory(category: CriterionCategory): Criterion[]

// By scoring function
listByScoringFunction(function_name: string): Criterion[]

// By name (exact or fuzzy)
findByName(name: string): Criterion | null
searchByName(query: string): Criterion[]

// Available criteria (excludes archived)
listAvailable(): Criterion[]

// Recently used criteria (based on Activation records)
listRecentlyUsed(session_id: string, limit?: number): Criterion[]

// Recommended criteria for context
getRecommended(decision_type: string, context: DecisionContext): Criterion[]
```

### Recommendation Logic

`getRecommended` uses the decision type to suggest relevant criteria:

| Decision Type | Recommended Criteria |
|---------------|---------------------|
| `tool_selection` | speed, cost, quality, reliability |
| `plan_evaluation` | quality, cost, safety, scalability, maintainability |
| `resource_allocation` | cost, speed, reliability |
| `risk_assessment` | safety, reliability, explainability |
| `strategy_choice` | quality, scalability, user_satisfaction |

Sou may accept, modify, or ignore the recommendation.

## Internal Interface

### CriteriaRegistry

```typescript
interface CriteriaRegistry {
  // Criterion CRUD
  register(criterion: Omit<Criterion, "metadata">): Criterion
  get(criterion_id: string): Criterion | null
  update(criterion_id: string, updates: Partial<Criterion>): Criterion
  delete(criterion_id: string): void
  list(): Criterion[]
  listAvailable(): Criterion[]
  search(query: string): Criterion[]

  // Weight management
  overrideWeight(criterion_id: string, new_weight: number, reason: string, session_id: string): CriterionOverride
  setGlobalWeight(criterion_id: string, new_weight: number, reason: string): CriterionOverride
  normalizeWeights(weights: Record<string, number>): Record<string, number>
  getEffectiveWeights(session_id: string): Record<string, number>
  getDefaults(): Record<string, number>
  revertOverride(criterion_id: string, session_id: string): void
  clearSessionOverrides(session_id: string): void

  // Criterion set management
  createSet(name: string, criteria: string[], is_template?: boolean): CriterionSet
  getSet(set_id: string): CriterionSet | null
  listSets(category?: string): CriterionSet[]
  updateSet(set_id: string, criteria: string[]): CriterionSet
  deleteSet(set_id: string): void
  getRecommended(decision_type: string, context: DecisionContext): Criterion[]

  // Query helpers
  listByCategory(category: CriterionCategory): Criterion[]
  listByScoringFunction(function_name: string): Criterion[]
  listRecentlyUsed(session_id: string, limit?: number): Criterion[]

  // Lifecycle
  archive(criterion_id: string): void
  restore(criterion_id: string): void
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `DEC.CriterionRegistered` | criterion_id, name, weight, category | New criterion added to registry |
| `DEC.CriterionUpdated` | criterion_id, updated_fields | Criterion definition changed |
| `DEC.CriterionArchived` | criterion_id, timestamp | Criterion deprecated and archived |
| `DEC.CriterionRestored` | criterion_id, timestamp | Archived criterion restored |
| `DEC.PreferenceOverridden` | criterion_id, old_weight, new_weight, scope, reason | Criterion weight changed |
| `DEC.SessionOverridesCleared` | session_id, override_count | All session overrides removed |
| `DEC.CriterionSetCreated` | set_id, name, criteria_count | New criterion set registered |
| `DEC.CriterionSetUpdated` | set_id, criteria_count | Criterion set modified |
| `DEC.CriterionSetDeleted` | set_id | Criterion set removed |
| `DEC.WeightsNormalized` | affected_criteria, total_before, total_after | Weights auto-normalized |
| `DEC.OverrideReverted` | criterion_id, restored_weight, session_id | Override removed, default restored |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CR-001 | Every criterion has a unique `criterion_id` | Schema — primary key constraint |
| CR-002 | Criteria weights always sum to 1.0 after normalization | Algorithmic — `normalizeWeights` called after every override |
| CR-003 | Archived criteria are excluded from default queries | Algorithmic — `listAvailable` filters by `deprecated_at` |
| CR-004 | Session overrides are cleared on session end | Architectural — called by Session Manager lifecycle hook |
| CR-005 | Global overrides survive restarts (persisted in Event Store) | Architectural — replayed from Event Store on init |
| CR-006 | Template sets never allow criteria removal | Validation — `updateSet` rejects removal from template sets |
| CR-007 | Locked criteria reject all weight overrides | Validation — `overrideWeight` returns error |
| CR-008 | Session overrides take precedence over global overrides | Algorithmic — merge order: defaults → global → session |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Register criterion with duplicate name | `CR_DUPLICATE_NAME` | Return error; names must be unique |
| Override weight on locked criterion | `CR_LOCKED_CRITERION` | Return error; weight is immutable |
| Unknown criterion_id in set creation | `CR_CRITERION_NOT_FOUND` | Skip unknown IDs; warn in response |
| Override weight outside [0.0, 1.0] | `CR_WEIGHT_OUT_OF_RANGE` | Clamp silently to nearest bound |
| Normalization with all-zero weights | `CR_ALL_ZERO_WEIGHTS` | Return error; cannot normalize |
| Delete criterion referenced in existing sets | `CR_CRITERION_IN_USE` | Archive instead; refuse hard delete |
| Access archived criterion by default query | `CR_ARCHIVED` | Exclude from results; accessible via explicit ID query |
| Create set with no criteria | `CR_EMPTY_SET` | Return error; must include at least one criterion |
| Global override with no reason | `CR_MISSING_REASON` | Return error; reason is required |
| Restore non-archived criterion | `CR_NOT_ARCHIVED` | Return error; criterion is already active |

## Usage Patterns

### Pattern 1: Tool Selection with Custom Weights

```
1. Sou needs to choose a search tool
2. Sou loads predefined set "tool_selection": [speed, cost, quality, reliability]
3. Sou overrides speed weight to 0.30 (current task is latency-sensitive)
4. Registry normalizes other weights: cost=0.23, quality=0.23, reliability=0.23
5. Sou passes normalized criteria to evaluateOptions
6. Decision recorded with effective weights
```

### Pattern 2: Registering a Custom Criterion

```
1. Sou identifies need for "energy_efficiency" criterion
2. Sou calls register({ name: "energy_efficiency", weight: 0.10, scoring_function: "linear", ... })
3. Registry adds criterion; existing weights re-normalized to accommodate
4. Sou uses new criterion in subsequent decisions
5. If valuable, criterion can be promoted to default set via configuration
```

### Pattern 3: Safety-Critical Gate

```
1. System policy defines "safety" as a locked criterion with weight 0.25
2. Sou cannot override or remove safety from any decision
3. Before every high-risk action, Sou runs a safety_check set
4. If safety criterion scores below threshold, recommendation flags risk
5. Sou may still proceed but must provide explicit override reason in DecisionRecord
```

### Pattern 4: Session-Specific Tuning

```
1. User tells Sou "I'm on a tight budget today"
2. Sou overrides cost weight: 0.15 → 0.40 (session scope)
3. Registry normalizes: cost=0.40, speed=0.08, quality=0.17, safety=0.21, ...
4. Sou evaluates all decisions with cost-weighted lens
5. Session ends → overrides cleared → defaults restored next session
```

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Criteria Registry handles only criterion storage, query, and lifecycle |
| R2 — Dependency Order | Depends on Event Store for global overrides; no upward deps |
| R3 — DRY | Criteria defined once, reused across all decisions and sets |
| R4 — Builder Pattern | Criteria built by Config → Overrides → Normalization pipeline |
| R5 — Liskov Substitution | Any CriterionStore implements CriteriaRegistry |
| R6 — DI over Singletons | Config, override store, and normalization strategy injected |
| R9 — Deterministic | Same config + overrides = same effective weights |
| R10 — Simpler Over Complex | Weighted sum with normalization; no adaptive weighting |
| R13 — Design for Failure | Locked criteria prevent catastrophic override |
| R14 — Paved Path | All operations flow through registry interface |
| R15 — Open/Closed | New criteria, sets, and categories added without modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Decision/000-Overview.md | Criteria Registry is a subsystem of the Decision System |
| Decision/001-Scoring-Engine.md | Registry provides criteria definitions to the Scorer |
| Decision/002-Tradeoff-Analyzer.md | Trade-offs computed using criteria from Registry |
| Decision/003-Constraint-Checker.md | Constraints checked alongside criteria evaluation |
| Decision/005-History-Logger.md | Every decision record includes effective criteria snapshot |
| Brain/Memory/001-Working-Memory.md | Session overrides live in Working Memory during session |
| Bible/05-Platform/004-EVS.md | Global overrides persisted via Event Store |
| Brain/Planning/000-Overview.md | Plans reference criteria sets for evaluation |
