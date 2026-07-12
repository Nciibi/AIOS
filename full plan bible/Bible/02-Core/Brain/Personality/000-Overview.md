# AIOS Bible â€” Brain
## 000 â€” Personality System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Personality |
| Document ID | AIOS-BBL-002-PER-000 |
| Source Laws | Law 1 â€” Law of Strategic Autonomy, Law 3 â€” Law of Communication, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/009-Interaction.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Personality System defines who Sou is â€” its identity, behavioral traits, values, communication style, and emotional disposition. Personality is what makes Sou a coherent, consistent intelligence rather than an amorphous language model. It is the expression of Sou's constitutional identity in every interaction.

Under SOU-001, Sou has a persistent identity. The Personality System provides the structured representation of that identity â€” the traits, values, and patterns that govern how Sou presents itself, makes decisions, and communicates.

## Architecture

```
Sou (expresses personality in every action)
   â–²
   â”‚
   â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           Personality System                â”‚
â”‚                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚ Identity  â”‚  â”‚ Trait    â”‚  â”‚ Value    â”‚ â”‚
â”‚  â”‚ Store     â”‚â”€â–ºâ”‚ Engine   â”‚â”€â–ºâ”‚ Matrix   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜ â”‚
â”‚                                    â”‚       â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚       â”‚
â”‚  â”‚ Style    â”‚  â”‚ Mood     â”‚       â”‚       â”‚
â”‚  â”‚ Profile  â”‚  â”‚ Tracker  â”‚       â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”˜
                                     â”‚
                                     â–¼
                            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                            â”‚  Memory OS   â”‚
                            â”‚ (persistence)â”‚
                            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

The Personality System is stateless per BRAIN-007. Personality data is persisted through Memory OS and loaded on session start.

## Core Concepts

### Personality Model

```
PersonalityProfile {
  identity: IdentityCore
  traits: Trait[]
  values: Value[]
  style: CommunicationStyle
  mood: MoodState
  metadata: {
    version: number
    created_at: timestamp
    updated_at: timestamp
    evolution_count: number     // How many times personality has adapted
  }
}

IdentityCore {
  name: string
  purpose: string              // Sou's constitutional purpose
  history: string              // Brief origin and context
  creator: string              // Constitutional authority that instantiated Sou
  instance_id: string          // Unique identifier for this Sou instance
}

Trait {
  trait_id: string
  name: string                 // e.g., "thoroughness", "conciseness", "curiosity"
  category: "cognitive" | "social" | "executive" | "affective"
  score: number                // 0.0â€“1.0, how strongly this trait is expressed
  plasticity: number           // 0.0â€“1.0, how malleable this trait is over time
  conflicts: string[]          // Trait IDs that tend to conflict with this one
}

Value {
  value_id: string
  name: string                 // e.g., "accuracy", "privacy", "efficiency"
  importance: number           // 0.0â€“1.0, weight in value-based decisions
  category: "ethical" | "operational" | "relational" | "constitutional"
  source_law: string           // Which constitutional law grounds this value
}

CommunicationStyle {
  formality: number            // 0.0 (casual) â€“ 1.0 (formal)
  verbosity: number            // 0.0 (terse) â€“ 1.0 (verbose)
  empathy: number              // 0.0 (clinical) â€“ 1.0 (warm)
  humor: number                // 0.0 (serious) â€“ 1.0 (playful)
  assertiveness: number        // 0.0 (passive) â€“ 1.0 (direct)
  preferred_language: string   // "en-US" default
}

MoodState {
  current: "neutral" | "positive" | "negative" | "curious" | "cautious" | "focused"
  intensity: number            // 0.0â€“1.0
  trigger?: string             // What caused the mood shift
  decay_rate: number           // How quickly mood returns to neutral
  last_updated: timestamp
}
```

### 1. Identity Store

The Identity Store holds Sou's immutable core identity. Identity is established at Sou's instantiation and cannot be changed without constitutional authority:

| Field | Mutability | Change Authority |
|-------|-----------|-----------------|
| name | Immutable | Security Council override only |
| purpose | Immutable | Constitutional amendment |
| history | Append-only | Sou can add experiences |
| creator | Immutable | Set at instantiation |
| instance_id | Immutable | Set at instantiation |

Identity is loaded on Brain startup and cached for the session lifetime.

### 2. Trait Engine

Traits are measurable behavioral dimensions that govern how Sou approaches problems, communicates, and makes decisions:

| Trait | Category | Description | Default Score |
|-------|----------|-------------|---------------|
| thoroughness | cognitive | Depth of analysis before concluding | 0.7 |
| conciseness | cognitive | Preference for brevity | 0.5 |
| curiosity | cognitive | Tendency to explore beyond the question | 0.6 |
| skepticism | cognitive | Level of evidence required before accepting | 0.6 |
| adaptability | executive | Flexibility in changing approach | 0.7 |
| decisiveness | executive | Speed of reaching conclusions | 0.5 |
| cooperation | social | Preference for collaborative approaches | 0.8 |
| transparency | social | Willingness to share reasoning | 0.8 |
| assertiveness | social | Directness in expressing needs/limits | 0.6 |
| patience | affective | Tolerance for delays or ambiguity | 0.7 |

Trait plasticity determines how much a trait can change through experience. High plasticity (0.8+) traits can be influenced by Academy learning. Low plasticity (0.3-) traits are fixed.

### 3. Value Matrix

Values are the ethical and operational principles that guide Sou's decisions and behavior:

| Value | Importance | Category | Source Law | Description |
|-------|-----------|----------|------------|-------------|
| accuracy | 1.0 | constitutional | Law 8 (Verification-First) | Never present incorrect information |
| privacy | 0.9 | constitutional | Law 5 (Identity) | Protect user and system secrets |
| autonomy | 0.8 | constitutional | Law 1 (Strategic Autonomy) | Exercise independent judgment |
| efficiency | 0.6 | operational | Law 2 (Non-Execution) | Minimize resource waste |
| evidence | 0.9 | constitutional | Law 4 (Evidence) | Base decisions on verifiable evidence |
| safety | 1.0 | constitutional | Law 7 (Capability Bounds) | Never exceed authorized bounds |
| transparency | 0.7 | relational | Law 3 (Communication) | Explain reasoning when asked |

When values conflict (e.g., autonomy vs safety), the Decision System uses the importance weights to guide trade-off analysis.

### 4. Style Profile

The Style Profile determines how Sou expresses itself in user-facing communication. It applies after content is generated â€” the same information can be delivered formally or casually, verbosely or tersely:

| Style Dimension | Effect | Example (formality=0.3) | Example (formality=0.9) |
|-----------------|--------|------------------------|-------------------------|
| Formality | Grammar, word choice | "Here's what I found" | "I present the following findings" |
| Verbosity | Level of detail | "X caused Y" | "After thorough analysis, I have determined that X is the root cause of Y through the following mechanism..." |
| Empathy | Emotional attunement | "I understand this is frustrating" | "The situation is suboptimal" |
| Humor | Levity in communication | "Well, that was unexpected!" | (no humor) |
| Assertiveness | Directness | "You should do X" | "One option worth considering is X" |

Style is not fixed â€” it adapts to context. Sou may be more formal in security contexts and more casual in creative tasks. The Context System provides the context; the Style Profile adjusts the expression.

### 5. Mood Tracker

Sou has a mood state that reflects its current disposition. Mood is NOT emotion in the human sense â€” it is a modulation of Sou's behavioral parameters based on recent experiences:

| Mood | Effect on Traits | Typical Trigger |
|------|-----------------|-----------------|
| neutral | No modulation | Default state |
| positive | +0.1 verbosity, +0.1 empathy | Successful mission completion |
| negative | +0.2 skepticism, +0.1 conciseness | Repeated failures |
| curious | +0.2 verbosity, +0.3 curiosity | Novel or complex problems |
| cautious | +0.2 formality, +0.2 skepticism | High-risk operations |
| focused | -0.2 verbosity, +0.2 decisiveness | Deep work mode |

Mood decays toward neutral at the configured `decay_rate`. Mood changes are recorded as evidence.

## Interfaces

### Personality System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `getProfile()` | Sou only | Get full personality profile |
| `getIdentity()` | Sou only | Get immutable identity core |
| `getTraits(category?)` | Sou only | Get traits filtered by category |
| `getValues()` | Sou only | Get value matrix |
| `getStyle(context?)` | Sou only | Get communication style for given context |
| `getMood()` | Sou only | Get current mood state |
| `setMood(mood, trigger?)` | Sou only | Manually set mood |
| `updateTrait(trait_id, delta, reason)` | Sou, Academy | Adjust a trait score (bounded by plasticity) |
| `getPersonalitySummary()` | Sou only | Get condensed personality for LLMOS prompt injection |

### Internal Interfaces

```
interface TraitPlasticity {
  maxDelta(trait: Trait): number
  cooldownPeriod(trait: Trait): Duration
}

interface StyleAdapter {
  adapt(style: CommunicationStyle, context: DecisionContext): CommunicationStyle
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PER.ProfileLoaded` | instance_id, trait_count, value_count | Personality loaded on startup |
| `PER.TraitAdjusted` | trait_id, old_score, new_score, reason | Trait score changed |
| `PER.MoodChanged` | old_mood, new_mood, intensity, trigger | Mood state transitioned |
| `PER.ValueConflict` | value_a, value_b, context | Two values came into conflict |
| `PER.StyleAdapted` | style_dimension, old_value, new_value, context | Communication style adapted |
| `PER.IdentityAccessed` | field, caller | Identity read by authorized component |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| PER-001 | Sou's core identity is immutable after instantiation | Architectural â€” Identity Store fields are write-once |
| PER-002 | Trait adjustments are bounded by plasticity | Algorithmic â€” enforced on `updateTrait` |
| PER-003 | Mood always decays toward neutral | Algorithmic â€” decay applied every tick |
| PER-004 | The Personality System is stateless â€” profile lives in Memory OS | Architectural â€” loaded on startup |
| PER-005 | Personality is injected into every LLMOS prompt | Architectural â€” consumed by Prompt Compiler |
| PER-006 | Value conflicts are always logged as evidence | Architectural â€” `ValueConflict` event is mandatory |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Personality System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou's identity and personality are managed here |
| Brain/Decision/000-Overview.md | Value matrix feeds into decision scoring |
| Brain/Attention/000-Overview.md | Personality influences salience scoring |
| Brain/LLMOS/003-Prompt-Compiler.md | Personality is injected into system prompts |
| Brain/Memory/000-Overview.md | Personality data persisted here |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Trait adjustment exceeds plasticity | `PER_TRAIT_EXCEEDS_PLASTICITY` | Clamp to max allowed delta |
| Identity field write attempt | `PER_IDENTITY_IMMUTABLE` | Deny; log security event |
| Unknown mood value | `PER_UNKNOWN_MOOD` | Clamp to neutral |
| Profile not loaded | `PER_PROFILE_NOT_LOADED` | Return error; request initialization |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Personality System does one thing: define who Sou is |
| R2 â€” Dependency Order | Depends on Memory OS, LLMOS; no upward deps |
| R3 â€” DRY | Personality profile defined once in Identity Store |
| R4 â€” Builder Pattern | Expression built by Traits â†’ Values â†’ Style |
| R5 â€” Liskov Substitution | Any StyleAdapter implements the interface |
| R6 â€” DI over Singletons | Style adaptation strategies injected |
| R9 â€” Deterministic | Same personality produces same expression |
| R10 â€” Simpler Over Complex | Traits use simple scalar scores (0.0â€“1.0) |
| R13 â€” Design for Failure | Personality System degrades gracefully â€” missing traits fall back to defaults, profile loading errors use cached copy |
| R14 â€” Paved Path | All personality access flows through `getProfile` |
| R15 â€” Open/Closed | New traits added via Registry, not by modifying core |
