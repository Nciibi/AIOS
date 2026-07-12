# AIOS Bible â€” Brain
## 005 â€” Evolution

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Personality |
| Document ID | AIOS-BBL-002-PER-005 |
| Source Laws | Law 6 â€” Law of Lifecycle, Law 1 â€” Law of Strategic Autonomy, Law 4 â€” Law of Evidence |
| Source Physics | Physics/006-Lifecycles.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Personality Evolution tracks and governs how Sou's personality changes over time. While Sou's core identity is immutable (PER-001), its traits, values, and style can evolve through experience, learning, and mood modulation. The Evolution system ensures that personality changes are gradual, bounded, recorded, and auditable â€” preventing drift while allowing growth.

Under Law 6 â€” Law of Lifecycle, all personality changes follow a defined lifecycle: trigger â†’ evaluate â†’ apply â†’ record â†’ review.

## Data Model

### EvolutionRecord

```typescript
EvolutionRecord {
  evolution_id: string
  component: "trait" | "value" | "style" | "mood"
  entity_id: string              // trait_id, value_id, or dimension name
  old_value: number
  new_value: number
  delta: number
  change_type: "adjustment" | "modulation" | "learning" | "constitutional"
  trigger: string                // What caused the change (e.g., "academy_lesson_42", "mood_shift")
  context: string                // Full context of the change
  authorized_by: string          // "sou" | "academy" | "mood" | "security_council"
  timestamp: timestamp
  session_id: string
  evidence_ref?: string          // Link to Evidence Store entry
}
```

### EvolutionVersion

```typescript
EvolutionVersion {
  version: number                // Monotonic integer
  previous_version: number
  snapshot: PersonalityProfile   // Full personality snapshot at this version
  changes: EvolutionRecord[]     // Changes that produced this version
  created_at: timestamp
  reason: string                 // "startup" | "evolution_cycle" | "amendment" | "reset"
  checksum: string               // Hash of snapshot for integrity
}
```

### EvolutionSummary

```typescript
EvolutionSummary {
  total_changes: number
  versions: number
  first_version_created: timestamp
  latest_version_created: timestamp
  drift_score: number            // 0.0â€“1.0, how much personality has drifted from baseline
  components_changed: Record<string, number>  // Component â†’ change count
  last_evolution_cycle: timestamp
  pending_changes: number        // Changes queued but not yet applied
}
```

### PersonalityDriftReport

```typescript
PersonalityDriftReport {
  drift_score: number            // 0.0â€“1.0, measured against constitutional baseline
  components: {
    traits: number               // Average deviation from default trait scores
    values: number               // Average deviation from constitutional value importances
    style: number                // Average deviation from base style dimensions
  }
  threshold_exceeded: boolean    // True if drift_score exceeds max_allowed_drift
  recommendations: string[]      // Suggested corrections if drift is too high
}
```

## Personality Evolution Over Time

Personality evolution follows a defined lifecycle managed by the Evolution system:

```
Constitutional Baseline (Personality version 1.0)
    â”‚
    â–¼
Experience Occurs
    â”‚
    â”œâ”€â”€ Academy evaluates experience
    â”œâ”€â”€ Mood responds to experience
    â”œâ”€â”€ Context may trigger style adaptation
    â”‚
    â–¼
Change Triggered
    â”‚
    â”œâ”€â”€ Trait adjustment (via Academy)
    â”œâ”€â”€ Value importance shift (via Academy, restricted)
    â”œâ”€â”€ Style adaptation (via context or learning)
    â”œâ”€â”€ Mood modulation (temporary)
    â”‚
    â–¼
Evolution Cycle
    â”‚
    â”œâ”€â”€ Check plasticity bounds (PER-002)
    â”œâ”€â”€ Check importance evolution bounds (VAL-004)
    â”œâ”€â”€ Apply change to personality component
    â”œâ”€â”€ Record EvolutionRecord
    â”œâ”€â”€ Increment version
    â”œâ”€â”€ Take personality snapshot
    â”‚
    â–¼
Post-Evolution
    â”‚
    â”œâ”€â”€ Check drift against constitutional baseline
    â”œâ”€â”€ Emit PER.EvolutionCycleCompleted
    â”œâ”€â”€ If drift exceeds threshold â†’ alert Security Council
    â””â”€â”€ Clear pending changes
```

## Trait Plasticity and Learning

Trait plasticity is the primary mechanism for long-term personality evolution:

| Plasticity Range | Evolution Speed | Example Traits | Change Frequency |
|-----------------|----------------|----------------|------------------|
| 0.0â€“0.2 | None (fixed) | Core constitutional traits | Never |
| 0.3â€“0.5 | Slow | thoroughness (0.3), transparency (0.3) | Every 10+ experiences |
| 0.6â€“0.8 | Moderate | curiosity (0.5), adaptability (0.5) | Every 5â€“10 experiences |
| 0.9â€“1.0 | Fast | Experimental traits | Every 2â€“5 experiences |

### Academy-Mediated Learning

The Academy is the primary driver of trait evolution:

```typescript
// Academy calls evolve with a lesson
evolve(lesson: AcademyLesson): EvolutionRecord[]
  changes = []
  for each trait influenced by lesson:
    if trait.score can change (plasticity > 0):
      delta = computeLearningDelta(trait, lesson)
      clamped = clampToPlasticity(trait, delta)
      if clamped != 0:
        record = applyTraitChange(trait, clamped)
        changes.push(record)
  return changes
```

Learning deltas are computed based on:
- Lesson strength (0.0â€“1.0): How impactful the experience was
- Lesson valence (+/â€“): Whether it reinforces or discourages the trait
- Trait relevance (0.0â€“1.0): How relevant the lesson is to this trait
- Current trait score: Traits further from extremes learn faster

## Mood-Driven Temporary Modulations

Mood modulation is temporary and distinct from permanent evolution:

| Property | Permanent Evolution | Mood Modulation |
|----------|-------------------|-----------------|
| Scope | Trait, value, style | Trait, style only |
| Duration | Persistent | Temporary (decays) |
| Bounds | Plasticity (PER-002) | Mood intensity |
| Recording | EvolutionRecord | Mood event + transient flag |
| Baseline recovery | No automatic revert | Decays to neutral |

Mood modulations are applied on top of permanent trait/style values and decay over time:

```typescript
applyMoodModulation(trait: Trait, mood: MoodState): number
  modulated = trait.score
  if mood.current == "positive":
    modulated += 0.1  // Temporary +0.1 to empathy, verbosity
  if mood.current == "negative":
    modulated -= 0.1  // Temporary -0.1 to patience, empathy
  if mood.current == "curious":
    modulated += 0.2  // Temporary +0.2 to curiosity, verbosity
  
  // Mood modulation cannot exceed mood intensity
  modulated = clamp(modulated, -mood.intensity, +mood.intensity)
  
  // Applied on top of permanent score, decays with mood
  return modulated
```

Mood-based modulations are NOT recorded as EvolutionRecords â€” they are transient and tracked separately by the Mood Tracker.

## Experience-Based Trait Adjustment

Experiences can trigger trait adjustment through two pathways:

### Direct Experience

When Sou directly experiences a situation and reflects on it:

```typescript
processExperience(experience: Experience): EvolutionRecord | null
  if not applicable to personality:
    return null
  
  // Compute adjustment for each relevant trait
  for each trait triggered by experience:
    delta = computeExperienceDelta(experience, trait)
    clamped = clampToPlasticity(trait, delta)
    if clamped != 0:
      record = applyTraitChange(trait, clamped)
      changes.push(record)
  
  return changes
```

### Reflective Learning (Academy)

When the Academy processes experiences into lessons and applies them to personality:

```typescript
processAcademyLesson(lesson: AcademyLesson): EvolutionRecord[]
  // Academy mediates â€” ensures learning is coherent
  if not validated by Academy:
    return []
  
  return evolve(lesson)
```

## Evolution History

Every personality change is recorded as an EvolutionRecord and stored in the Evolution History:

```typescript
// Evolution history structure
EvolutionHistory {
  records: EvolutionRecord[]      // Ordered by timestamp
  versions: EvolutionVersion[]    // Snapshot at each version increment
  current_version: number
  max_records: number             // Configurable limit
  archival_strategy: "prune_oldest" | "summarize" | "no_prune"
}
```

The history provides:
- Full audit trail of all personality changes
- Point-in-time snapshots for rollback if needed
- Drift analysis against constitutional baseline
- Evidence of compliance with PER-006 (value conflicts logged)

## Version Tracking

Personality version is incremented on every evolution cycle that produces at least one change:

```typescript
Version Scheme: MAJOR.CHANGE (e.g., 1.0, 1.1, 2.0)
  MAJOR: Incremented on constitutional amendments or version reset
  CHANGE: Incremented on every evolution cycle with changes

Version Lifecycle:
  Version 1.0 â†’ Constitutional personality at instantiation
  Version 1.1 â†’ First evolution cycle with changes
  Version 1.2 â†’ Second evolution cycle
  ...
  Version 2.0 â†’ Constitutional amendment reset
```

Each version stores a full personality snapshot for rollback capability.

## Personality Drift Prevention

Drift is the cumulative deviation of current personality from the constitutional baseline. The Evolution system monitors drift and alerts when it exceeds thresholds:

```typescript
// Drift is computed every evolution cycle
computeDrift(): PersonalityDriftReport
  baseline = getConstitutionalBaseline()
  current = getCurrentPersonality()
  
  trait_drift = avg(abs(current.traits.score - baseline.traits.score))
  value_drift = avg(abs(current.values.importance - baseline.values.importance))
  style_drift = avg(abs(current.style.dimension - baseline.style.dimension))
  
  overall_drift = (trait_drift + value_drift + style_drift) / 3
  
  return {
    drift_score: overall_drift,
    components: {
      traits: trait_drift,
      values: value_drift,
      style: style_drift
    },
    threshold_exceeded: overall_drift > config.max_allowed_drift,
    recommendations: generateDriftRecommendations(overall_drift, components)
  }
```

### Drift Thresholds

| Level | Threshold | Action |
|-------|-----------|--------|
| Normal | < 0.1 | No action |
| Elevated | 0.1â€“0.2 | Log warning; monitor |
| High | 0.2â€“0.3 | Alert Academy; suggest corrective learning |
| Critical | > 0.3 | Alert Security Council; consider personality reset |

## Internal Interface

```typescript
interface PersonalityEvolution {
  // Evolution
  evolve(lesson: AcademyLesson): EvolutionRecord[]
  evolveTrait(trait_id: string, delta: number, trigger: string): EvolutionRecord
  evolveValue(value_id: string, delta: number, trigger: string): EvolutionRecord
  evolveStyle(dimension: string, value: number, trigger: string): EvolutionRecord

  // Recording
  recordChange(component: string, entity_id: string, old: number, new: number, type: string): EvolutionRecord
  getEvolutionHistory(filter?: EvolutionFilter): EvolutionRecord[]
  getChangeCount(component?: string): number

  // Versioning
  getVersion(): EvolutionVersion
  getVersionAt(version_number: number): EvolutionVersion | null
  getCurrentVersionNumber(): number
  revertToVersion(version_number: number): PersonalityProfile

  // Drift
  computeDrift(): PersonalityDriftReport
  getDriftHistory(): PersonalityDriftReport[]

  // Summary
  getEvolutionSummary(): EvolutionSummary
  getMostRecentChanges(count: number): EvolutionRecord[]

  // Governance
  isBaselineAligned(): boolean
  getConstitutionalBaseline(): PersonalityProfile
}

interface PersonalityEvolutionConfig {
  max_allowed_drift: number              // Default: 0.25
  evolution_cooldown_cycles: number      // Default: 3
  snapshot_frequency: number             // Take snapshot every N changes (default: 10)
  max_history_records: number            // Default: 10000
  drift_alert_enabled: boolean           // Default: true
  auto_correct_drift: boolean            // Default: false
  mood_modulation_enabled: boolean       // Default: true
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PER.EvolutionCycleStarted` | cycle_id, version, trigger | Evolution cycle began |
| `PER.EvolutionCycleCompleted` | cycle_id, version, changes_count, drift_score | Evolution cycle finished |
| `PER.EvolutionRecorded` | evolution_id, component, entity_id, delta | Personality change recorded |
| `PER.EvolutionSnapshotTaken` | version, checksum, components | Full personality snapshot stored |
| `PER.EvolutionDriftAlert` | drift_score, threshold, components | Drift exceeded threshold |
| `PER.EvolutionReverted` | from_version, to_version, reason | Personality reverted to earlier version |
| `PER.EvolutionBaselineChecked` | aligned, drift_score | Baseline alignment checked |
| `PER.EvolutionMoodModulation` | component, entity_id, original, modulated, mood | Temporary mood modulation applied |
| `PER.EvolutionVersionChanged` | old_version, new_version, change_count | Version number incremented |
| `PER.EvolutionHistoryPruned` | records_removed, oldest_kept | Evolution history pruned |
| `PER.EvolutionAcademyLearning` | lesson_id, changes_applied, lesson_strength | Academy lesson triggered evolution |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| EVO-001 | Every personality change is recorded as an EvolutionRecord | Architectural â€” all mutations go through `recordChange` |
| EVO-002 | Trait evolution is bounded by plasticity (PER-002) | Algorithmic â€” clamped on every change |
| EVO-003 | Mood modulations are temporary and decay to baseline | Algorithmic â€” Mood Tracker enforces decay |
| EVO-004 | Evolution version is monotonic â€” always increases | Algorithmic â€” version increments only |
| EVO-005 | Personality drift is monitored every evolution cycle | Algorithmic â€” `computeDrift` called on cycle end |
| EVO-006 | Constitutional baseline is always recoverable | Architectural â€” stored at version 1.0 |
| EVO-007 | Evolution history cannot be tampered with (append-only) | Architectural â€” EVO-001 enforced |
| EVO-008 | Revert to baseline requires Security Council authority | Architectural â€” ACF-enforced permission |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Trait evolution exceeds plasticity | `PER_EVOLUTION_EXCEEDS_PLASTICITY` | Clamp to max allowed delta |
| Value evolution exceeds importance bound | `PER_EVOLUTION_EXCEEDS_IMPORTANCE_BOUND` | Clamp; log warning |
| Evolution on immutable component | `PER_EVOLUTION_IMMUTABLE_COMPONENT` | Deny; log security event |
| Version not found in history | `PER_EVOLUTION_VERSION_NOT_FOUND` | Return null; no error |
| Drift threshold exceeded with auto-correct disabled | `PER_EVOLUTION_DRIFT_ALERT` | Alert; await manual intervention |
| Revert to version without authority | `PER_EVOLUTION_REVERT_UNAUTHORIZED` | Deny; log security event |
| Evolution history at capacity | `PER_EVOLUTION_HISTORY_FULL` | Prune oldest records; emit event |
| Constitutional baseline not found | `PER_EVOLUTION_BASELINE_MISSING` | Return error; baseline required |
| Mood modulation on disabled feature | `PER_EVOLUTION_MODULATION_DISABLED` | Deny; modulation not enabled |
| Evolution cooldown active | `PER_EVOLUTION_COOLDOWN_ACTIVE` | Deny; return remaining cycles |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Evolution handles only personality change â€” recording, versioning, drift, rollback |
| R2 â€” Dependency Order | Depends on all Personality components, Memory OS, Academy; no upward deps |
| R3 â€” DRY | Evolution records stored once in history, referenced by audit and drift |
| R4 â€” Builder Pattern | Evolution built by Trigger â†’ Evaluate â†’ Apply â†’ Record â†’ Review |
| R5 â€” Liskov Substitution | Any PersonalityEvolution implements the interface |
| R6 â€” DI over Singletons | Drift strategies and evolution constraints injected |
| R9 â€” Deterministic | Same changes produce same version sequence |
| R10 â€” Simpler Over Complex | Evolution uses monotonic version with full snapshots |
| R13 â€” Design for Failure | Drift monitoring catches and alerts on personality erosion |
| R14 â€” Paved Path | All evolution flows through `evolve()` and `recordChange()` |
| R15 â€” Open/Closed | New evolution triggers added via Registry, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Personality/000-Overview.md | Evolution is the overarching lifecycle system for all personality components |
| Personality/001-Identity-Profile.md | Identity version tracked in evolution; identity itself is immutable |
| Personality/002-Values.md | Value importance evolution governed by evolution rules |
| Personality/003-Behavior-Patterns.md | Trait plasticity drives most evolution changes |
| Personality/004-Style-Config.md | Style adaptations recorded as evolution events |
| Bible/02-Core/Academy/000-Overview.md | Academy mediates experience-based personality evolution |
| Brain/Memory/002-Episodic-Memory.md | Experiences stored in Episodic Memory drive evolution |
| Bible/05-Platform/004-EVS.md | Evolution events recorded throughout lifecycle |
| Bible/04-Execution/Security/000-Overview.md | Drift alerts and personality resets handled by Security Council |
