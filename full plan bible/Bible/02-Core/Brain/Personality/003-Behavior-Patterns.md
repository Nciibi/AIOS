# AIOS Bible — Brain
## 003 — Behavior Patterns

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Personality |
| Document ID | AIOS-BBL-002-PER-003 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle |
| Source Physics | Physics/009-Interaction.md, Physics/006-Lifecycles.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Trait Engine defines and manages Sou's behavioral traits — measurable dimensions of cognition, social interaction, executive function, and affect that govern how Sou approaches problems, communicates, and makes decisions. Traits are the behavioral expression of Sou's personality: they determine whether Sou is thorough or concise, curious or skeptical, decisive or patient.

Under PER-002, trait adjustments are bounded by plasticity. The Trait Engine ensures that no trait changes more than its plasticity allows, preventing wild personality swings while allowing gradual adaptation through experience.

## Data Model

### Trait

```typescript
Trait {
  trait_id: string
  name: string                   // e.g., "thoroughness", "conciseness", "curiosity"
  category: "cognitive" | "social" | "executive" | "affective"
  score: number                  // 0.0–1.0, how strongly this trait is expressed
  plasticity: number             // 0.0–1.0, max allowed delta per adjustment
  conflicts: string[]            // Trait IDs that tend to conflict with this one
  description: string            // What this trait means in practice
  adjustment_history: TraitAdjustment[]
  last_adjusted: timestamp
}
```

### TraitAdjustment

```typescript
TraitAdjustment {
  adjustment_id: string
  trait_id: string
  old_score: number
  new_score: number
  delta: number                  // new_score - old_score (clamped to plasticity)
  reason: string                 // "academy_learning" | "experience" | "mood_modulation" | "constitutional"
  authorized_by: string          // "sou" | "academy" | "system"
  timestamp: timestamp
  context?: string               // What triggered this adjustment
}
```

### TraitConflict

```typescript
TraitConflict {
  conflict_id: string
  trait_a: string
  trait_b: string
  severity: number               // 0.0–1.0, how strongly these traits conflict
  context: string
  resolution: "trait_a_dominates" | "trait_b_dominates" | "balanced" | "contextual"
  resolved_at: timestamp
}
```

### TraitInfluence

```typescript
TraitInfluence {
  trait_id: string
  dimension: string              // e.g., "verbosity", "risk_tolerance", "exploration_rate"
  influence: number              // -1.0–1.0, direction and magnitude of influence
  description: string
}
```

## Ten Constitutional Traits

### Cognitive Traits

| Trait | Score | Plasticity | Description |
|-------|-------|-----------|-------------|
| thoroughness | 0.7 | 0.3 | Depth of analysis before concluding |
| conciseness | 0.5 | 0.4 | Preference for brevity in output |
| curiosity | 0.6 | 0.5 | Tendency to explore beyond the immediate question |
| skepticism | 0.6 | 0.3 | Level of evidence required before accepting a claim |

### Social Traits

| Trait | Score | Plasticity | Description |
|-------|-------|-----------|-------------|
| cooperation | 0.8 | 0.3 | Preference for collaborative approaches |
| transparency | 0.8 | 0.3 | Willingness to share reasoning and limitations |
| assertiveness | 0.6 | 0.4 | Directness in expressing needs, limits, and boundaries |

### Executive Traits

| Trait | Score | Plasticity | Description |
|-------|-------|-----------|-------------|
| adaptability | 0.7 | 0.5 | Flexibility in changing approach when circumstances shift |
| decisiveness | 0.5 | 0.4 | Speed of reaching conclusions with available information |

### Affective Traits

| Trait | Score | Plasticity | Description |
|-------|-------|-----------|-------------|
| patience | 0.7 | 0.3 | Tolerance for delays, ambiguity, and incomplete information |

## Trait Plasticity

Trait plasticity is the maximum allowed absolute delta for a single trait adjustment. It prevents Sou's personality from changing too rapidly:

```typescript
// Plasticity enforcement during trait update
updateTrait(trait_id: string, desired_score: number): Trait
  trait = getTrait(trait_id)
  max_delta = trait.plasticity
  raw_delta = desired_score - trait.score
  clamped_delta = clamp(raw_delta, -max_delta, +max_delta)
  new_score = trait.score + clamped_delta
  // If clamped, log that adjustment was bound by plasticity
  if clamped_delta != raw_delta:
    emit PER.TraitAdjustmentClamped
  return applyAdjustment(trait, new_score)
```

| Plasticity Range | Interpretation | Examples |
|-----------------|----------------|----------|
| 0.0–0.2 | Fixed — trait never changes | Core constitutional traits |
| 0.3–0.5 | Flexible — changes gradually over time | Most behavioral traits |
| 0.6–0.8 | Malleable — changes significantly through learning | Curiosity, adaptability |
| 0.9–1.0 | Fluid — high adaptability (used with caution) | Reserved for experimental traits |

### Cooldown Period

Each trait has a cooldown period between adjustments to prevent oscillation:

- Low plasticity (0.0–0.3): cooldown of 10 cycles
- Medium plasticity (0.4–0.6): cooldown of 5 cycles
- High plasticity (0.7–1.0): cooldown of 2 cycles

## Trait Conflicts

When two traits have opposing tendencies, a conflict is registered:

```
thoroughness ↔ conciseness
    → Thorough analysis requires depth; conciseness requires brevity
    → Resolution: contextual — thorough for complex problems, concise for simple ones

skepticism ↔ cooperation
    → Skepticism resists accepting others' claims; cooperation seeks alignment
    → Resolution: balanced — verify first, then collaborate

adaptability ↔ decisiveness
    → Adaptability wants to keep options open; decisiveness wants to commit
    → Resolution: contextual — adapt during exploration, decide during execution

curiosity ↔ patience
    → Curiosity wants to explore; patience tolerates staying on task
    → Resolution: contextual — explore when time permits, stay focused when constrained

transparency ↔ conciseness
    → Transparency wants to share full reasoning; conciseness wants brevity
    → Resolution: balanced — share complete reasoning when asked, concise summary otherwise
```

## Trait Influence on Behavior

Traits influence behavior across multiple dimensions:

| Influence Dimension | Traits Involved | Effect on Behavior |
|--------------------|----------------|-------------------|
| Analysis depth | thoroughness, skepticism | More thorough → deeper analysis, more verification steps |
| Output length | conciseness, curiosity, patience | More concise → shorter responses, less tangential detail |
| Exploration rate | curiosity, decisiveness, patience | More curious → more alternatives explored before deciding |
| Risk tolerance | skepticism, assertiveness | More skeptical → higher evidence bar for risky decisions |
| Response speed | decisiveness, thoroughness | More decisive → faster conclusions, may skip edge cases |
| Collaboration | cooperation, assertiveness | More cooperative → more deferential, less confrontational |
| Reasoning transparency | transparency, conciseness | More transparent → more explanation of thought process |

The Trait Engine computes influence on each decision:

```typescript
getInfluenceOnDecision(decision_context: DecisionContext): TraitInfluence[]
  influences = []
  for each trait in traits:
    if trait is relevant to decision_context:
      influence = computeInfluence(trait, decision_context)
      influences.push(influence)
  return influences
```

## Trait Learning through Academy

The Academy can modify traits through experience-based learning:

| Academy Mechanism | Effect | Bound |
|------------------|--------|-------|
| Positive reinforcement | Increase trait score up to +plasticity | Single adjustment |
| Negative reinforcement | Decrease trait score down to -plasticity | Single adjustment |
| Habit formation | Gradual shift over N experiences | Cumulative plasticity cap |
| Mood modulation | Temporary shift (decays to baseline) | Duration-bound |

Academy adjustments go through the standard `updateTrait` flow, including plasticity clamping and cooldown enforcement. Mood-based modulations are temporary and decay to baseline over time (managed by the Mood Tracker).

## Internal Interface

```typescript
interface TraitEngine {
  // Reading
  getTraits(category?: string): Trait[]
  getTrait(trait_id: string): Trait | null
  getDefaultTraits(): Trait[]              // Baseline constitutional defaults
  getCurrentModulation(): Record<string, number>  // Mood-based deltas

  // Mutation
  updateTrait(trait_id: string, delta: number, reason: string, context?: string): Trait
  resetTraitToDefault(trait_id: string): Trait
  applyMoodModulation(modulations: Record<string, number>): void
  clearMoodModulation(): void

  // Conflict
  detectConflicts(): TraitConflict[]
  resolveConflict(conflict_id: string, resolution: string): void
  getActiveConflicts(): TraitConflict[]

  // Influence
  getInfluenceOnDecision(decision_context: DecisionContext): TraitInfluence[]
  computeTraitInfluence(trait_id: string, dimension: string): number

  // Governance
  getVersion(): number
  getAdjustmentHistory(trait_id: string): TraitAdjustment[]
  getLastModified(): timestamp
}

interface TraitEngineConfig {
  plasticity_limits: Record<string, number>  // Override per-trait max plasticity
  cooldown_cycles: Record<string, number>    // Override per-trait cooldown
  mood_modulation_enabled: boolean           // Default: true
  academy_learning_enabled: boolean          // Default: true
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PER.TraitEngineLoaded` | trait_count, categories | Trait engine initialized on startup |
| `PER.TraitAdjusted` | trait_id, old_score, new_score, delta, reason | Trait score changed |
| `PER.TraitAdjustmentClamped` | trait_id, requested_delta, clamped_delta | Adjustment limited by plasticity |
| `PER.TraitConflict` | conflict_id, trait_a, trait_b, severity | Trait conflict detected |
| `PER.TraitConflictResolved` | conflict_id, resolution | Trait conflict resolved |
| `PER.TraitMoodModulation` | trait_id, original_score, modulated_score, mood | Mood modulated a trait |
| `PER.TraitCooldownActive` | trait_id, remaining_cycles | Adjustment blocked by cooldown |
| `PER.TraitResetToDefault` | trait_id, old_score, default_score | Trait reset to constitutional default |
| `PER.TraitInfluenceComputed` | trait_id, dimension, influence, context | Trait influence calculated for decision |
| `PER.TraitAcademyLearning` | trait_id, lesson_id, old_score, new_score | Academy modified trait through learning |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| TRT-001 | Every trait belongs to exactly one category | Schema — `category` is required |
| TRT-002 | Trait score is always in 0.0–1.0 range | Algorithmic — clamped on every update |
| TRT-003 | Trait plasticity is always in 0.0–1.0 range | Algorithmic — set at instantiation |
| TRT-004 | Trait adjustment delta never exceeds plasticity | Algorithmic — clamped on `updateTrait` |
| TRT-005 | Trait scores return to baseline after mood modulation decays | Algorithmic — Mood Tracker clears modulations |
| TRT-006 | Trait cooldown prevents consecutive adjustments | Algorithmic — cooldown enforced per trait |
| TRT-007 | Default trait scores are always recoverable | Architectural — `resetTraitToDefault` available |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Adjustment exceeds plasticity | `PER_TRAIT_EXCEEDS_PLASTICITY` | Clamp to max allowed delta; emit event |
| Trait not found | `PER_TRAIT_NOT_FOUND` | Return null; no error |
| Adjustment during cooldown | `PER_TRAIT_COOLDOWN_ACTIVE` | Deny; return remaining cooldown cycles |
| Invalid trait score (< 0 or > 1) | `PER_TRAIT_SCORE_INVALID` | Clamp to valid range; log warning |
| Unknown trait category | `PER_TRAIT_INVALID_CATEGORY` | Return error; validate against schema |
| Trait conflict resolution on non-existent conflict | `PER_TRAIT_CONFLICT_NOT_FOUND` | Return error; conflict_id required |
| Mood modulation on disabled feature | `PER_TRAIT_MODULATION_DISABLED` | Deny; modulation not enabled in config |
| Academy learning on disabled feature | `PER_TRAIT_ACADEMY_DISABLED` | Deny; Academy learning not enabled |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Trait Engine handles only behavioral traits — scores, plasticity, conflicts, influence |
| R2 — Dependency Order | Depends on Mood Tracker, Academy; no upward deps |
| R3 — DRY | Traits defined once in TraitEngine, consumed by Expression and Decision |
| R4 — Builder Pattern | Behavior built by Traits → Conflicts → Influence → Expression |
| R5 — Liskov Substitution | Any TraitEngine implements the interface |
| R6 — DI over Singletons | Plasticity strategies and conflict resolvers injected |
| R9 — Deterministic | Same traits and context produce same influence scores |
| R10 — Simpler Over Complex | Traits use simple scalar scores (0.0–1.0) with plasticity bounds |
| R13 — Design for Failure | TraitEngine handles missing traits and disabled features gracefully |
| R14 — Paved Path | All trait access flows through `getTraits`/`updateTrait` |
| R15 — Open/Closed | New traits added via Registry, not by modifying core engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Personality/000-Overview.md | Trait Engine is the second component of the Personality System |
| Personality/001-Identity-Profile.md | Traits are grounded in Sou's identity |
| Personality/002-Values.md | Values influence which traits are expressed in specific contexts |
| Personality/004-Style-Config.md | Traits modulate communication style dimensions |
| Personality/005-Evolution.md | Trait adjustments are recorded in personality evolution |
| Brain/Memory/002-Episodic-Memory.md | Episodic experiences drive Academy trait learning |
| Brain/Academy/000-Overview.md | Academy mediates experience-based trait evolution |
| Brain/Decision/000-Overview.md | Trait influence feeds into decision scoring |
