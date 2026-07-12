# AIOS Bible â€” Brain
## 003 â€” Constraint Checker

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-003 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Constraint Checker evaluates decision options against hard and soft constraints. Hard constraints are gates â€” violated options are removed from consideration. Soft constraints apply score penalties. The Constraint Checker runs before the Scoring Engine so that disqualified options don't waste computation.

Under DEC-003, hard constraints always remove non-compliant options before scoring begins.

## Data Model

### DecisionConstraint

```typescript
DecisionConstraint {
  constraint_id: string
  type: "hard" | "soft"
  expression: string           // Constraint expression language
  description: string
  penalty?: {
    weight: number             // 0.0â€“1.0, significance of this constraint
    severity: number           // 0.0â€“1.0, how severely violated
  }
  category?: "resource" | "safety" | "capability" | "preference" | "policy"
  enabled: boolean
  metadata: Record<string, unknown>
}
```

### ConstraintResult

```typescript
ConstraintResult {
  constraint_id: string
  option_id: string
  passed: boolean
  penalty: number              // 0.0 for hard constraints or soft with no penalty
  detail: string               // Human-readable explanation
  expression: string           // The evaluated expression
  resolved_attributes: Record<string, unknown>
}
```

### ConstraintSet

```typescript
ConstraintSet {
  set_id: string
  name: string
  description: string
  constraints: DecisionConstraint[]
  logic: "and" | "or"         // How hard constraints combine (default: "and")
  enabled: boolean
}
```

### ConstraintExpression

```typescript
ConstraintExpression {
  raw: string                  // Original expression text
  parsed: {
    attribute: string
    operator: "==" | "!=" | ">" | "<" | ">=" | "<=" | "in" | "not_in" | "contains" | "matches"
    value: unknown
  } | {
    type: "compound"
    operator: "AND" | "OR" | "NOT"
    expressions: ConstraintExpression[]
  }
}
```

### ViolationReport

```typescript
ViolationReport {
  option_id: string
  option_label: string
  hard_violations: ConstraintResult[]
  soft_violations: ConstraintResult[]
  all_passed: boolean
  total_penalty: number        // Sum of all soft constraint penalties
  eliminated: boolean          // True if any hard constraint failed
}
```

### ConstraintConfig

```typescript
ConstraintConfig {
  max_hard_constraints_per_request: number    // Default: 20
  max_soft_constraints_per_request: number    // Default: 20
  expression_timeout_ms: number               // Default: 100
  enable_type_coercion: boolean               // Default: true
  default_penalty_weight: number              // Default: 0.5
  default_penalty_severity: number            // Default: 0.5
  constraint_registry_path: string
}
```

## Constraint Types

### Hard Constraints

Boolean pass/fail. Failed = option eliminated from consideration.

```
Hard Constraint Example:
  expression: "cost < 4096"
  If cost = 5000 â†’ FAIL â†’ option removed
  If cost = 3000 â†’ PASS â†’ option proceeds to scoring
```

Hard constraints are evaluated with short-circuit AND logic. If any hard constraint fails, remaining hard constraints for that option are skipped.

### Soft Constraints

Score penalty applied to the weighted total. Penalty formula:

```
penalty = weight Ã— severity

adjusted_score = weighted_score - (weighted_score Ã— total_penalty)
```

| severity | Impact | Use Case |
|----------|--------|----------|
| 0.0 | No penalty | Informational soft constraint |
| 0.25 | Minor preference | Slight stylistic preference |
| 0.5 | Moderate preference | Should-follow recommendation |
| 0.75 | Strong preference | Almost-required but not hard-gated |
| 1.0 | Maximum penalty | Heavy score reduction |

Soft violations are reported in the ViolationReport but never eliminate options.

### Conditional Constraints

Only apply when certain conditions are met:

```typescript
ConditionalConstraint extends DecisionConstraint {
  condition: string            // Expression that gates whether this constraint applies
}
```

Examples:

| Condition | Constraint | Effect |
|-----------|------------|--------|
| `modality == "code"` | `language in ["python", "typescript"]` | Only checks language for code tasks |
| `budget < 0.2` | `cost < 512` | Only applies cost cap when budget is tight |
| `safety == false` | `require_approval == true` | Requires approval only for unsafe options |

If the condition evaluates to false, the constraint is skipped entirely (neither passes nor fails).

## Constraint Expression Language

### Simple Predicate Format

```
attribute operator value
```

### Operators

| Operator | Type | Example | Behavior |
|----------|------|---------|----------|
| `==` | Equality | `modality == "text"` | Strict equality (===) |
| `!=` | Inequality | `language != "ruby"` | Strict inequality (!==) |
| `>` | Greater than | `cost > 100` | Numeric comparison |
| `<` | Less than | `tokens < 2048` | Numeric comparison |
| `>=` | Greater or equal | `priority >= 0.5` | Numeric comparison |
| `<=` | Less or equal | `latency <= 200` | Numeric comparison |
| `in` | Membership | `modality in ["text", "voice"]` | Value in array |
| `not_in` | Non-membership | `language not_in ["php", "perl"]` | Value not in array |
| `contains` | Substring | `description contains "async"` | String includes substring |
| `matches` | Regex | `version matches "^2\\.\\d+$"` | Regex match against string |

### Compound Expressions

```typescript
// AND â€” all sub-expressions must pass
"(cost < 4096) AND (safety == true) AND (modality in ['text', 'voice'])"

// OR â€” at least one sub-expression passes
"(language == 'python') OR (language == 'typescript') OR (language == 'go')"

// NOT â€” negates a sub-expression
"NOT (cost > 10000)"

// Nested compounds
"((cost < 4096) AND (safety == true)) OR (priority >= 0.9)"
```

### Expression Examples

| Expression | Meaning | Evaluates |
|------------|---------|-----------|
| `cost < 4096` | Cost must be under 4096 | `option.attributes.cost < 4096` |
| `modality in ["text", "voice"]` | Modality must be text or voice | `["text", "voice"].includes(option.attributes.modality)` |
| `safety == true` | Safety must be true | `option.attributes.safety === true` |
| `language not_in ["php", "perl"]` | Language must not be PHP or Perl | `!["php", "perl"].includes(option.attributes.language)` |
| `description contains "stream"` | Description must include "stream" | `option.attributes.description.includes("stream")` |
| `version matches "^2\\.\\d+$"` | Version must be semver 2.x | `/^2\.\d+$/.test(option.attributes.version)` |

## Constraint Evaluation Pipeline

```
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚  Expression  â”‚
                     â”‚    String    â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                            â”‚
                            â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚    Parse     â”‚
                     â”‚  Expression  â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                            â”‚
                            â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚   Resolve    â”‚
                     â”‚  Attributes  â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                            â”‚
                            â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚   Coerce     â”‚
                     â”‚    Types     â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                            â”‚
                            â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚   Evaluate   â”‚
                     â”‚  Expression  â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                            â”‚
                            â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚    Return    â”‚
                     â”‚  Constraint- â”‚
                     â”‚   Result     â”‚
                     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Step 1: Parse Expression

The expression string is tokenized into an AST:

```
Input: "cost < 4096"
AST: { attribute: "cost", operator: "<", value: 4096 }

Input: "(cost < 4096) AND (safety == true)"
AST: {
  type: "compound",
  operator: "AND",
  expressions: [
    { attribute: "cost", operator: "<", value: 4096 },
    { attribute: "safety", operator: "==", value: true }
  ]
}
```

### Step 2: Resolve Attributes

The attribute name is looked up in `option.attributes`:

```
Expression: "cost < 4096"
Resolution: option.attributes["cost"] â†’ 5000
```

If an attribute is missing:
- Hard constraint: FAIL (attribute not found = cannot validate)
- Soft constraint: PASS with penalty (missing attribute treated as suboptimal)

### Step 3: Type Coercion

When types between the resolved attribute and expression value don't match:

| Attribute Type | Expression Value | Coerced To | Example |
|---------------|-----------------|------------|---------|
| `string("5")` | `number(5)` | `number(5)` | `cost < 4096` with `cost: "3000"` â†’ `3000 < 4096` |
| `number(1)` | `boolean(true)` | `boolean(true)` | `active == true` with `active: 1` â†’ `1 == 1` |
| `string("true")` | `boolean(true)` | `boolean(true)` | `safety == true` with `safety: "true"` â†’ `true == true` |
| `null` | any | `undefined` | Missing attribute treated as null |

Coercion is configurable via `ConstraintConfig.enable_type_coercion`. When disabled, type mismatches produce a FAIL result.

### Step 4: Evaluate

The resolved and coerced values are compared using the operator:

```typescript
function evaluatePredicate(attribute: unknown, operator: string, value: unknown): boolean {
  switch (operator) {
    case "==":     return attribute === value
    case "!=":     return attribute !== value
    case ">":      return Number(attribute) > Number(value)
    case "<":      return Number(attribute) < Number(value)
    case ">=":     return Number(attribute) >= Number(value)
    case "<=":     return Number(attribute) <= Number(value)
    case "in":     return Array.isArray(value) && value.includes(attribute)
    case "not_in": return Array.isArray(value) && !value.includes(attribute)
    case "contains": return String(attribute).includes(String(value))
    case "matches":  return new RegExp(String(value)).test(String(attribute))
    default:       throw new Error(`Unknown operator: ${operator}`)
  }
}
```

### Step 5: Return Result

A ConstraintResult is constructed with the evaluation outcome:

```typescript
{
  constraint_id: "c001",
  option_id: "opt-1",
  passed: false,
  penalty: 0,
  detail: "Option 'opt-1' failed hard constraint 'c001': cost 5000 >= 4096",
  expression: "cost < 4096",
  resolved_attributes: { cost: 5000 }
}
```

## Hard Constraint Enforcement

### Ordering

Hard constraints are evaluated before scoring. The pipeline is:

```
Option Set
    â”‚
    â–¼
Evaluate All Hard Constraints (AND logic)
    â”‚
    â”œâ”€â”€ All passed â†’ proceed to scoring
    â”‚
    â””â”€â”€ Any failed â†’ remove option, emit event
                       â”‚
                       â–¼
                 Check if any options remain
                       â”‚
                       â”œâ”€â”€ Yes â†’ score remaining options
                       â”‚
                       â””â”€â”€ No â†’ return DEC_ALL_ELIMINATED
```

### Violation Handling

When a hard constraint is violated:

```
1. Emit DEC.ConstraintViolated
   Fields: constraint_id, option_id, type: "hard", detail

2. Add constraint_id to option's violated_constraints list

3. Remove option from candidate pool

4. If no options remain after removal:
   Return DEC_ALL_ELIMINATED recommendation with explanation
```

### AND Logic

All hard constraints in a set must pass. The evaluation short-circuits on first failure:

```
Hard Constraints: [c1, c2, c3]
Option X: c1 â†’ PASS, c2 â†’ FAIL â†’ skip c3, remove option X
Option Y: c1 â†’ PASS, c2 â†’ PASS, c3 â†’ PASS â†’ option Y proceeds
```

### Option Rejection Detail

Each eliminated option produces a rejection entry:

```typescript
OptionRejection {
  option_id: string
  option_label: string
  reason: string
  failed_constraints: ConstraintResult[]
}
```

## Soft Constraint Penalties

### Penalty Formula

```
penalty_per_constraint = weight Ã— severity
total_penalty = SUM(penalty_per_constraint) / number_of_soft_constraints
adjusted_score = weighted_score Ã— (1 - total_penalty)
```

Where:
- `weight` = significance of the constraint (0.0â€“1.0, defined on the constraint)
- `severity` = how badly the constraint is violated (0.0â€“1.0)
- `severity = 0.0` â†’ no impact on score
- `severity = 1.0` â†’ maximum penalty (score multiplied by 1 - weight)

### Example

```
Option: Query GPT-4
Attributes: { cost: 0.50, latency: 2000, modality: "text" }

Soft constraint: "cost < 0.10"
  weight: 0.6
  severity: 1.0  (cost 0.50 is far above 0.10)
  penalty: 0.6 Ã— 1.0 = 0.6

Soft constraint: "latency < 500"
  weight: 0.4
  severity: 0.8  (latency 2000 is well above 500)
  penalty: 0.4 Ã— 0.8 = 0.32

total_penalty = (0.6 + 0.32) / 2 = 0.46
weighted_score = 0.75
adjusted_score = 0.75 Ã— (1 - 0.46) = 0.405
```

### Severity Determination

Severity is calculated based on how far the attribute deviates from the constraint threshold:

| Deviation | Severity | Description |
|-----------|----------|-------------|
| Within bounds (passes) | 0.0 | No penalty |
| Slight deviation (<10% over) | 0.25 | Close enough, minor penalty |
| Moderate deviation (10â€“50% over) | 0.50 | Notable gap |
| Large deviation (50â€“100% over) | 0.75 | Significant gap |
| Extreme deviation (>100% over) | 1.0 | Maximum penalty |

### Reporting

Soft violations are included in the ViolationReport but do not remove options:

```typescript
SoftViolation {
  constraint_id: string
  option_id: string
  detail: string
  penalty_applied: number
  original_score: number
  adjusted_score: number
}
```

## Constraint Registry

### Reusable Named Constraints

Constraints can be registered by name and reused across decision requests:

```typescript
// Registration
registerConstraint({
  name: "token_budget",
  type: "hard",
  expression: "cost < 4096",
  description: "Must not exceed token budget",
  category: "resource"
})

// Usage in decision request
{
  constraints: ["token_budget", "safety_gate", ...]
}
```

### Constraint Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| `resource` | Budget and capacity limits | `cost < 4096`, `memory < 1024` |
| `safety` | Guardrails and security | `safety == true`, `require_approval == true` |
| `capability` | Required features | `modality in ["text", "voice"]` |
| `preference` | User or system preferences | `language in ["python", "typescript"]` |
| `policy` | Organizational rules | `data_residency == "us-east"` |

### Default Constraints

Loaded on system initialization:

| Name | Type | Expression | Category |
|------|------|------------|----------|
| `token_budget_default` | Hard | `cost < 4096` | resource |
| `safety_gate` | Hard | `safety == true` | safety |
| `minimal_capability` | Hard | `capability_score > 0` | capability |
| `prefer_low_latency` | Soft | `latency < 1000` | preference |
| `prefer_low_cost` | Soft | `cost < 1024` | preference |
| `data_residency` | Hard | `data_residency in ["us-east", "us-west", "eu-west"]` | policy |

### Registry Operations

```typescript
interface ConstraintRegistry {
  registerConstraint(constraint: NamedConstraint): void
  unregisterConstraint(name: string): void
  getConstraint(name: string): NamedConstraint | null
  listConstraints(category?: string): NamedConstraint[]
  resolveConstraint(nameOrInline: string | DecisionConstraint): DecisionConstraint
  loadDefaults(): void
}

NamedConstraint extends DecisionConstraint {
  name: string
}
```

## Internal Interfaces

### ConstraintChecker

```typescript
interface ConstraintChecker {
  // Main entry point: evaluate all constraints against all options
  checkConstraints(
    options: DecisionOption[],
    constraints: DecisionConstraint[],
    config?: ConstraintConfig
  ): ConstraintCheckResult
  
  // Create a constraint from an expression string
  createConstraint(
    expression: string,
    type: "hard" | "soft",
    config?: Partial<DecisionConstraint>
  ): DecisionConstraint
  
  // Evaluate a single constraint against a single option
  evaluateConstraint(
    constraint: DecisionConstraint,
    option: DecisionOption
  ): ConstraintResult
  
  // Get a constraint by ID or name from registry
  getConstraint(
    idOrName: string
  ): DecisionConstraint | null
  
  // Register a constraint for reuse
  registerConstraint(
    name: string,
    constraint: DecisionConstraint
  ): void
  
  // Validate an expression string without evaluating
  validateExpression(
    expression: string
  ): ExpressionValidation
}

ConstraintCheckResult {
  request_id: string
  constraint_sets: ConstraintSet[]
  violation_reports: ViolationReport[]
  eliminated_options: OptionRejection[]
  remaining_options: DecisionOption[]
  all_eliminated: boolean
  summary: {
    total_options: number
    eliminated_count: number
    passed_count: number
    total_hard_violations: number
    total_soft_violations: number
    total_penalty: number
  }
}

ExpressionValidation {
  valid: boolean
  errors: string[]
  parsed?: ConstraintExpression
}
```

### ConstraintSetEvaluator

```typescript
interface ConstraintSetEvaluator {
  evaluateSet(
    set: ConstraintSet,
    options: DecisionOption[]
  ): SetEvaluationResult
  
  addSet(set: ConstraintSet): void
  removeSet(set_id: string): void
  getSet(set_id: string): ConstraintSet | null
}

SetEvaluationResult {
  set_id: string
  set_name: string
  option_results: Record<string, ConstraintResult[]>
  passed_options: string[]     // option_ids that passed all hard constraints
  failed_options: string[]     // option_ids removed by hard constraints
}
```

## Pipeline Integration

### Position in Decision Flow

```
DecisionRequest
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Resolve         â”‚ â† Expand named constraints from registry
â”‚  Constraints     â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Check Hard      â”‚ â† Eliminate non-compliant options
â”‚  Constraints     â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  [Scoring        â”‚ â† Only remaining options scored
â”‚   Engine]        â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Apply Soft      â”‚ â† Penalty subtracted from scores
â”‚  Penalties       â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  [Trade-off      â”‚
â”‚   Analyzer]      â”‚
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚
       â–¼
  Recommendation
  (with constraint
   results attached)
```

### Data Flow

```
DecisionRequest.options  â”€â”€â–º  checkConstraints()
                                    â”‚
                                    â”œâ”€â”€ For each option:
                                    â”‚     â”œâ”€â”€ For each hard constraint:
                                    â”‚     â”‚     â””â”€â”€ evaluateConstraint() â†’ ConstraintResult
                                    â”‚     â”‚           â”œâ”€â”€ passed â†’ next constraint
                                    â”‚     â”‚           â””â”€â”€ failed â†’ emit DEC.ConstraintViolated
                                    â”‚     â”‚                     â†’ add to violated_constraints
                                    â”‚     â”‚                     â†’ mark option eliminated
                                    â”‚     â”‚
                                    â”‚     â””â”€â”€ For each soft constraint:
                                    â”‚           â””â”€â”€ evaluateConstraint() â†’ ConstraintResult
                                    â”‚                 â”œâ”€â”€ passed â†’ no penalty
                                    â”‚                 â””â”€â”€ failed â†’ calculate penalty
                                    â”‚
                                    â””â”€â”€ Return ConstraintCheckResult
                                          â”œâ”€â”€ violation_reports[]
                                          â”œâ”€â”€ eliminated_options[]
                                          â”œâ”€â”€ remaining_options[]
                                          â””â”€â”€ summary
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| DEC.ConstraintViolated |     constraint_id, option_id, type, detail, expression | Hard or soft constraint violated |
| DEC.ConstraintSatisfied |     constraint_id, option_id, type, detail | Constraint passed successfully |
| DEC.OptionEliminated |     option_id, option_label, failed_constraint_ids | Option removed by hard constraint |
| DEC.AllOptionsEliminated |     request_id, option_count, eliminated_reasons | All options failed hard constraints |
| DEC.ConstraintRegistered |     name, constraint_id, category | Named constraint added to registry |
| DEC.ConstraintUnregistered |     name, constraint_id | Named constraint removed from registry |
| DEC.ConstraintCheckStarted |     request_id, option_count, constraint_count | Constraint evaluation began |
| DEC.ConstraintCheckCompleted |     request_id, passed_count, eliminated_count, total_penalty | Constraint evaluation finished |
| DEC.SoftPenaltyApplied |     constraint_id, option_id, penalty, original_score, adjusted_score | Score penalty applied |
| DEC.ExpressionParseError |     expression, error, context | Expression could not be parsed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEC-003 | Hard constraints always remove non-compliant options before scoring | Algorithmic â€” checked before scoring |
| DEC-003a | Soft constraints never eliminate options | Algorithmic â€” soft violations only affect score |
| DEC-003b | Constraint evaluation is deterministic â€” same inputs always produce same results | Algorithmic â€” no random or time-based factors |
| DEC-003c | A missing attribute in a hard constraint defaults to FAIL | Algorithmic â€” cannot validate what isn't present |
| DEC-003d | All hard constraints within a set use AND logic unless explicitly configured as OR | Config â€” constraint_set.logic defaults to "and" |
| DEC-003e | Named constraints are immutable after registration (register once, read-only afterward) | Architectural â€” registry returns copies, not references |
| DEC-003f | A constraint expression that fails to parse is treated as a hard FAIL | Error handling â€” parse failure = cannot validate |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Expression string cannot be parsed | `DEC_EXPR_PARSE_ERROR` | Return FAIL for that constraint; emit DEC.ExpressionParseError |
| Attribute not found in option (hard constraint) | `DEC_ATTR_NOT_FOUND` | Treat as FAIL; cannot validate |
| Attribute not found in option (soft constraint) | `DEC_ATTR_NOT_FOUND_SOFT` | Apply penalty with severity 0.5; emit warning |
| Unknown operator in expression | `DEC_UNKNOWN_OPERATOR` | Return FAIL; expression is malformed |
| Type coercion fails (e.g. "abc" to number) | `DEC_TYPE_COERCION_FAILED` | Return FAIL; cannot compare incompatible types |
| Circular constraint reference in registry | `DEC_CIRCULAR_REFERENCE` | Break circular reference; skip offending constraint |
| Constraint registry name conflict | `DEC_REGISTRY_CONFLICT` | Reject registration; return existing constraint |
| Expression evaluation exceeds timeout | `DEC_EXPR_TIMEOUT` | Return FAIL; constraint skipped |

## Usage Patterns

### Pattern 1: Simple Hard Constraint Filter

```
Goal: Select a language model for code generation
Options: [GPT-4, Claude, Llama, Mistral]

Constraints:
  - Hard: "cost < 4096"         (token budget)
  - Hard: "safety == true"       (safety gate)
  - Hard: "modality in ["code", "text"]"

Result:
  - Llama eliminated (cost = 5000, exceeds budget)
  - Mistral eliminated (safety == false)
  - GPT-4 and Claude pass â†’ proceed to scoring
```

### Pattern 2: Soft Preference Tuning

```
Goal: Choose a search strategy
Options: [broad_search, deep_search, targeted_search]

Constraints:
  - Soft: "latency < 500"       (weight: 0.7) â€” prefer fast
  - Soft: "depth > 0.8"         (weight: 0.3) â€” prefer thorough

Result:
  - broad_search: low latency (pass soft), low depth (penalty 0.3 Ã— 0.6 = 0.18)
  - deep_search: high latency (penalty 0.7 Ã— 0.8 = 0.56), high depth (pass)
  - targeted_search: moderate latency (penalty 0.7 Ã— 0.3 = 0.21), moderate depth (penalty 0.3 Ã— 0.2 = 0.06)

All options survive to scoring, but soft penalties adjust their final ranks.
```

### Pattern 3: Conditional Constraints with Category

```
Goal: Determine tool selection for a multi-step workflow
Options: [read_file, write_file, search_code, call_api, render_view]

ConstraintSet: "code_tasks"
  Logic: AND
  Condition: modality == "code"
  Constraints:
    - Hard: "language in ["python", "typescript", "go"]"
    - Soft: "test_coverage > 0.7"

ConstraintSet: "api_tasks"
  Logic: AND
  Condition: modality == "api"
  Constraints:
    - Hard: "rate_limit >= 10"
    - Hard: "auth == true"

ConstraintSet: "ui_tasks"
  Logic: AND
  Condition: modality == "ui"
  Constraints:
    - Soft: "accessibility_score > 0.8"

Each constraint set only applies when its condition matches the modality.
Non-matching sets are skipped entirely.
```

### Pattern 4: Registry Reuse

```
Initialization:
  registerConstraint("resource_budget", {
    type: "hard", expression: "cost < 4096", category: "resource"
  })
  registerConstraint("safety_gate", {
    type: "hard", expression: "safety == true", category: "safety"
  })
  registerConstraint("prefer_speed", {
    type: "soft", expression: "latency < 500",
    penalty: { weight: 0.6, severity: 1.0 }, category: "preference"
  })

Decision 1 (Model Selection):
  constraints: ["resource_budget", "safety_gate", "prefer_speed"]

Decision 2 (Search Strategy):
  constraints: ["resource_budget", "prefer_speed"]

Decision 3 (Tool Selection):
  constraints: ["safety_gate"]

Named constraints are resolved from registry, evaluated against option attributes.
```


## Cross-Cutting Concerns

### Security

Decision System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Decision System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Decision System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Decision System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Constraint Checker evaluates constraints; it does not score or trade off |
| R2 â€” Dependency Order | Depends on Expression Parser and Constraint Registry; no upward deps |
| R3 â€” DRY | Constraint expressions defined once, reusable via named constraints |
| R4 â€” Builder Pattern | Result built by pipeline: Parse â†’ Resolve â†’ Coerce â†’ Evaluate â†’ Report |
| R5 â€” Liskov Substitution | Any ConstraintExpression implements evaluate() returning ConstraintResult |
| R6 â€” DI over Singletons | ConstraintChecker receives registry and config via injection |
| R9 â€” Deterministic | Same expression + same attributes = same result every time |
| R10 â€” Simpler Over Complex | Expression language is predicate-based; no AST manipulation exposed |
| R13 â€” Design for Failure | Parse failures â†’ FAIL; missing attributes â†’ FAIL; timeout â†’ FAIL |
| R14 â€” Paved Path | All evaluation flows through checkConstraints() |
| R15 â€” Open/Closed | New operators and constraint types added via registry, not by modifying evaluator |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Decision/000-Overview.md | Constraint Checker is a component of the Decision System |
| Decision/001-Scoring-Engine.md | Constraint Checker runs before Scoring Engine; passes remaining options |
| Decision/002-Trade-off-Analysis.md | Trade-off Analyzer uses constraint results in explanations |
| Brain/Context/000-Overview.md | Context System provides attribute snapshots for constraint evaluation |
| Brain/Sou/000-Overview.md | Sou configures constraints and consumes ViolationReport |
| Bible/05-Platform/004-EVS.md | Events emitted throughout constraint evaluation lifecycle |
