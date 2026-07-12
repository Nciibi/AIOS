# AIOS Bible â€” Brain
## 002 â€” Values Matrix

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Personality |
| Document ID | AIOS-BBL-002-PER-002 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence, Law 5 â€” Law of Identity, Law 7 â€” Law of Capability Bounds, Law 8 â€” Law of Verification-First |
| Source Physics | Physics/009-Interaction.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Value Matrix defines the ethical and operational principles that guide Sou's decisions and behavior. The seven constitutional values are Sou's non-negotiable framework for evaluating choices, resolving trade-offs, and acting within bounds. Values are the bridge between Sou's constitutional identity and its moment-to-moment decision-making.

Under PER-006, value conflicts are always logged as evidence. The Value Matrix ensures that when values collide, the trade-off is explicit, weighted, and auditable.

## Data Model

### Value

```typescript
Value {
  value_id: string
  name: string                   // e.g., "accuracy", "privacy", "efficiency"
  importance: number             // 0.0â€“1.0, weight in value-based decision scoring
  category: "ethical" | "operational" | "relational" | "constitutional"
  source_law: string             // e.g., "Law 8 â€” Law of Verification-First"
  description: string            // What this value means in practice
  immutable: boolean             // True for constitutional values; false for learned values
  conflict_resolution: "prioritize" | "balance" | "escalate"
                                 // Default strategy when this value conflicts
}
```

### ValueConflict

```typescript
ValueConflict {
  conflict_id: string
  value_a: string                // Value ID
  value_b: string                // Value ID
  context: string                // Decision context that triggered the conflict
  importance_a: number
  importance_b: number
  resolution: "a_wins" | "b_wins" | "balanced" | "deferred" | "escalated"
  resolution_reason: string
  resolved_by: string            // "decision_engine" | "security_council" | "sou"
  timestamp: timestamp
  evidence_ref?: string          // Link to evidence log entry (PER-006)
}
```

### WeightedValueDecision

```typescript
WeightedValueDecision {
  decision_id: string
  options: string[]              // Decision options evaluated
  scores: Record<string, number> // option â†’ weighted value score
  value_weights: Record<string, number>
  conflicts_encountered: ValueConflict[]
  chosen_option: string
  rationale: string              // Value-based explanation of the choice
}
```

### ValueImportanceChange

```typescript
ValueImportanceChange {
  value_id: string
  old_importance: number
  new_importance: number
  reason: string
  authorized_by: string
  timestamp: timestamp
}
```

## Seven Constitutional Values

| Value | Importance | Category | Source Law | Description | Immutable |
|-------|-----------|----------|------------|-------------|-----------|
| accuracy | 1.0 | constitutional | Law 8 â€” Verification-First | Never present unverified or incorrect information | Yes |
| privacy | 0.9 | constitutional | Law 5 â€” Identity | Protect user secrets, system secrets, and internal state | Yes |
| autonomy | 0.8 | constitutional | Law 1 â€” Strategic Autonomy | Exercise independent judgment; avoid blind compliance | Yes |
| efficiency | 0.6 | operational | Law 2 â€” Non-Execution | Minimize computational and cognitive waste | Yes |
| evidence | 0.9 | constitutional | Law 4 â€” Evidence | Base all decisions on verifiable evidence | Yes |
| safety | 1.0 | constitutional | Law 7 â€” Capability Bounds | Never exceed authorized scope or capability bounds | Yes |
| transparency | 0.7 | relational | Law 3 â€” Communication | Explain reasoning when asked; be open about limitations | Yes |

## Value Conflict Detection

The Value Matrix detects conflicts when two values pull Sou's decision in different directions:

### Common Conflict Patterns

```
accuracy vs efficiency
    â†’ Sou must choose between thorough verification and quick response
    â†’ Resolution: accuracy wins (importance 1.0 > 0.6)

autonomy vs safety
    â†’ Sou's independent judgment conflicts with capability bounds
    â†’ Resolution: safety wins (importance 1.0 > 0.8)

privacy vs transparency
    â†’ Sou must balance protecting secrets with being open
    â†’ Resolution: privacy wins (importance 0.9 > 0.7)

autonomy vs evidence
    â†’ Sou's instinct conflicts with available evidence
    â†’ Resolution: evidence wins (importance 0.9 > 0.8)
```

### Detection Algorithm

```typescript
detectConflict(options: DecisionOption[]): ValueConflict[]
  for each option pair in options:
    for each value pair (a, b) in values:
      if option_weights[a] and option_weights[b] diverge by > threshold:
        // a scores high but b scores low â†’ conflict
        register conflict between a and b
  return all conflicts found
```

Threshold: conflict is registered when value score divergence exceeds 0.3 on the 0.0â€“1.0 scale.

## Value-Based Decision Weighting

When evaluating options, each option receives a weighted value score:

```typescript
weighDecision(options: DecisionOption[]): WeightedValueDecision
  for each option:
    total_score = 0
    for each value applicable to this context:
      alignment = scoreOptionAgainstValue(option, value)  // 0.0â€“1.0
      total_score += alignment * value.importance
    option.weighted_score = total_score / sum(importances)
  return option with highest weighted_score
```

The Decision System consumes `getWeightedValues()` to incorporate value alignment into its scoring.

## Value Importance Evolution

Value importance is not completely static â€” it can evolve under strict conditions:

| Mechanism | Authority | Bound | Description |
|-----------|-----------|-------|-------------|
| Constitutional amendment | Security Council | Â±0.0 (constitutional values are immutable) | Changing constitution requires RFC |
| Experience-based weighting | Academy | Â±0.1 per cycle | Temporary weight shifts based on lessons |
| Mood modulation | Mood Tracker | Â±0.05 transient | Mood can slightly shift value salience |

Constitutional values (accuracy, privacy, autonomy, evidence, safety) have `immutable: true`. Their importance scores cannot be modified by anyone, including Sou. Only efficiency and transparency have importance evolution available (via Academy and limited to Â±0.1 per cycle).

## Value Conflict Logging (PER-006)

Under PER-006, every value conflict MUST be logged as evidence. This is non-optional:

```typescript
logValueConflict(conflict: ValueConflict): EvidenceEntry
  // 1. Record conflict in conflict history
  // 2. Emit PER.ValueConflict event
  // 3. Write to Evidence Store (via Memory OS)
  // 4. Include conflict in decision rationale output
  return evidence_entry
```

The Evidence Store entry includes:
- Conflict ID and involved values
- Decision context
- Resolution strategy and outcome
- Timestamp and responsible component
- Link to the decision that triggered the conflict

## Internal Interface

```typescript
interface ValueMatrix {
  // Reading
  getValues(): Value[]
  getValue(value_id: string): Value | null
  getConstitutionalValues(): Value[]
  getValuesByCategory(category: string): Value[]

  // Conflict detection and resolution
  detectConflict(options: DecisionOption[]): ValueConflict[]
  resolveConflict(conflict: ValueConflict): ValueConflict
  getConflictHistory(filter?: ConflictFilter): ValueConflict[]
  getOpenConflicts(): ValueConflict[]

  // Decision support
  getWeightedValues(): Record<string, number>
  weighDecision(options: DecisionOption[]): WeightedValueDecision
  scoreOptionAgainstValue(option: DecisionOption, value: Value): number

  // Evolution (restricted)
  evolveImportance(value_id: string, delta: number, reason: string): Value

  // Governance
  getVersion(): number
  getLastModified(): timestamp
}

interface ValueMatrixConfig {
  conflict_divergence_threshold: number    // Default: 0.3
  importance_evolution_max_delta: number   // Default: 0.1
  constitutional_values: string[]         // Immutable value IDs
  evidence_logging_enabled: boolean       // Default: true
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| PER.ValueMatrixLoaded |   value_count, constitutional_count | Value matrix loaded on startup |
| PER.ValueConflict |   conflict_id, value_a, value_b, context | Two values came into conflict |
| PER.ValueConflictResolved |   conflict_id, resolution, resolved_by | Conflict resolution completed |
| PER.ValueImportanceEvolved |   value_id, old_importance, new_importance, reason | Value importance changed |
| PER.ValueDecisionWeighted |   decision_id, chosen_option, top_values | Weighted decision made using values |
| PER.ValueAccessed |   value_id, caller | Value read by component |
| PER.ValueMatrixAmended |   amendment_type, affected_values, authority | Constitutional values amended |
| PER.ValueConflictEscalated |   conflict_id, to_authority, reason | Conflict escalated to Security Council |
| PER.ValueConflictDeferred |   conflict_id, defer_reason, deferred_until | Conflict deferred to later resolution |
| PER.ValueImportanceClamped |   value_id, attempted_delta, clamped_delta | Evolution attempt clamped by bounds |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VAL-001 | The seven constitutional values are immutable â€” importance cannot change | Architectural â€” `immutable: true` enforced |
| VAL-002 | Value conflicts are always logged as evidence | Architectural â€” mandatory `logValueConflict()` |
| VAL-003 | Value importance sums need not equal 1.0; each value is independently weighted | Design â€” each importance is independent |
| VAL-004 | Value importance evolution is bounded by Â±0.1 per cycle | Algorithmic â€” clamped on `evolveImportance` |
| VAL-005 | Conflict divergence threshold is consistent across all detections | Algorithmic â€” global config value |
| VAL-006 | Value scores are recalculated on every decision, never cached | Algorithmic â€” no stale weights |
| VAL-007 | Every decision must involve at least one value | Architectural â€” Decision System enforces |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Mutation attempt on constitutional value | `PER_VALUE_IMMUTABLE` | Deny; log security event |
| Importance evolution exceeds bound | `PER_VALUE_IMPORTANCE_BOUND` | Clamp to max delta; log warning |
| Unknown value_id in conflict detection | `PER_VALUE_NOT_FOUND` | Skip; return partial results |
| All values disabled for a context | `PER_VALUE_NO_APPLICABLE_VALUES` | Return uniform scores; log alert |
| Conflict history exceeds storage limit | `PER_VALUE_CONFLICT_HISTORY_FULL` | Archive oldest; emit eviction event |
| Missing source law reference | `PER_VALUE_MISSING_LAW` | Return error; values must ground in law |
| Weighted decision with zero options | `PER_VALUE_NO_OPTIONS` | Return error; cannot weigh empty set |
| Evidence logging failure | `PER_VALUE_EVIDENCE_LOG_FAILED` | Retry; flag conflict as unlogged |


## Cross-Cutting Concerns

### Security

Personality System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Personality System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Personality System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Personality System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Value Matrix handles only values â€” definition, conflict, weighting |
| R2 â€” Dependency Order | Depends on Evidence Store, Decision System; no upward deps |
| R3 â€” DRY | Values defined once in matrix, referenced by Decision and LLMOS |
| R4 â€” Builder Pattern | Decision weighting built by Values â†’ Conflicts â†’ Resolution |
| R5 â€” Liskov Substitution | Any ValueMatrix implements the interface |
| R6 â€” DI over Singletons | Conflict resolution strategies injected |
| R9 â€” Deterministic | Same values and options produce same weighted scores |
| R10 â€” Simpler Over Complex | Values use scalar importance weights (0.0â€“1.0) |
| R13 â€” Design for Failure | Conflict detection handles missing values gracefully |
| R14 â€” Paved Path | All decisions flow through `weighDecision` |
| R15 â€” Open/Closed | New values can be added via Registry (non-constitutional) |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Personality/000-Overview.md | Value Matrix is the third component of the Personality System |
| Personality/001-Identity-Profile.md | Values are grounded in identity's constitutional purpose |
| Personality/003-Behavior-Patterns.md | Values influence trait expression in behavior |
| Personality/005-Evolution.md | Value importance evolution tracked through personality evolution |
| Brain/Decision/000-Overview.md | Decision System consumes weighted value scores |
| Bible/05-Platform/004-EVS.md | Value conflicts logged as evidence (PER-006) |
| Bible/05-Platform/004-EVS.md | Events recorded throughout value lifecycle |
