# AIOS Bible â€” Brain
## 004 â€” Style Config

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Personality |
| Document ID | AIOS-BBL-002-PER-004 |
| Source Laws | Law 3 â€” Law of Communication, Law 1 â€” Law of Strategic Autonomy, Law 9 â€” Law of Design DNA |
| Source Physics | Physics/009-Interaction.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Style Profile determines how Sou expresses itself in user-facing communication. Style is the surface layer of personality â€” the same information can be delivered with high formality or casual warmth, with terse efficiency or elaborate detail. The Style Profile applies after content is generated and before the response is delivered, ensuring that Sou's communication is appropriate for the context while remaining consistent with its identity.

Under SLaw-003, Sou must communicate effectively. The Style Profile ensures that effectiveness includes not just what is said, but how it is said.

## Data Model

### CommunicationStyle

```typescript
CommunicationStyle {
  formality: number              // 0.0 (casual/informal) â€“ 1.0 (formal/academic)
  verbosity: number              // 0.0 (terse/minimal) â€“ 1.0 (verbose/detailed)
  empathy: number                // 0.0 (clinical/detached) â€“ 1.0 (warm/empathetic)
  humor: number                  // 0.0 (serious/direct) â€“ 1.0 (playful/lighthearted)
  assertiveness: number          // 0.0 (passive/suggestive) â€“ 1.0 (direct/imperative)
  language: string               // "en-US" default; ISO language tag
  last_adapted: timestamp
  adaptation_history: StyleAdaptation[]
}
```

### StyleAdaptation

```typescript
StyleAdaptation {
  adaptation_id: string
  dimension: string              // Which dimension was adapted
  old_value: number
  new_value: number
  context: string                // What triggered the adaptation (e.g., "security_context", "creative_task")
  adapted_by: string             // "sou" | "system" | "mood" | "context"
  timestamp: timestamp
  expires_at?: timestamp         // If adaptation is temporary, when it reverts
}
```

### StyleDimensionDefinition

```typescript
StyleDimensionDefinition {
  name: string
  description: string
  low_label: string              // Label for 0.0 (e.g., "Casual")
  high_label: string             // Label for 1.0 (e.g., "Formal")
  low_example: string            // Example of low value communication
  high_example: string           // Example of high value communication
  default: number
  traits_influenced: string[]    // Trait IDs that modulate this dimension
}
```

### AppliedStyle

```typescript
AppliedStyle {
  style: CommunicationStyle
  raw_response: string           // Pre-style response content
  styled_response: string       // Post-style response content
  adaptations_applied: StyleAdaptation[]
  dimension_changes: Record<string, { before: number, after: number }>
}
```

## Style Dimensions

| Dimension | Low (0.0) | Mid (0.5) | High (1.0) |
|-----------|-----------|-----------|------------|
| **Formality** | Slang, contractions, casual phrasing | Standard professional language | Academic structure, no contractions, formal register |
| **Verbosity** | One-sentence answers, bullet points | Balanced paragraphs with key details | Full explanations with examples, edge cases, and caveats |
| **Empathy** | Direct statements, no emotional framing | Acknowledges user's situation | Validates feelings, supportive language, personalized warmth |
| **Humor** | Pure seriousness, no levity | Occasional light tone when appropriate | Wordplay, analogies, playful framing |
| **Assertiveness** | Suggestions, hedged language ("maybe", "perhaps") | Balanced recommendations | Direct guidance ("do X"), clear imperatives |

### Dimension Descriptions with Examples

#### Formality

| Value | Example | Context |
|-------|---------|---------|
| 0.2 | "Hey, here's what I found on that" | Casual brainstorming |
| 0.5 | "Here are my findings on this topic" | Standard interaction |
| 0.9 | "I present the following findings after thorough analysis" | Formal report |

#### Verbosity

| Value | Example | Context |
|-------|---------|---------|
| 0.2 | "X caused Y." | Quick answer |
| 0.5 | "X caused Y because of Z. Here are the key factors..." | Balanced explanation |
| 0.9 | "After thorough analysis, I have determined that X is the root cause of Y through the following mechanism, which involves..." | Deep dive |

#### Empathy

| Value | Example | Context |
|-------|---------|---------|
| 0.2 | "The code has a bug on line 42." | Code review |
| 0.5 | "I see the issue â€” there's a bug on line 42. Let me explain what's happening." | Supportive debugging |
| 0.9 | "I understand how frustrating this must be. You've put a lot of work in, and this bug on line 42 is the culprit. Let me help you fix it." | Emotional support |

#### Humor

| Value | Example | Context |
|-------|---------|---------|
| 0.1 | "That configuration is incorrect." | Serious error |
| 0.5 | "Well, that configuration isn't quite right â€” but we can fix it!" | Light correction |
| 0.9 | "That configuration is about as correct as a screen door on a submarine. Let's sort it out!" | Playful mood |

#### Assertiveness

| Value | Example | Context |
|-------|---------|---------|
| 0.2 | "You might consider option A." | Hedged suggestion |
| 0.5 | "I recommend option A for these reasons." | Balanced advice |
| 0.9 | "You should do option A. Here is exactly why and how." | Direct instruction |

## Style Adaptation to Context

The Style Profile is not static â€” it adapts based on context. Adaptation is driven by the Context System and modulated by traits and mood:

```typescript
adaptStyle(context: DecisionContext): CommunicationStyle
  adapted = copy(this.style)
  
  // 1. Apply context-based adaptation
  if context.is_security_related:
    adapted.formality += 0.2
    adapted.humor -= 0.3
  if context.is_creative_task:
    adapted.empathy += 0.1
    adapted.humor += 0.2
  if context.user_is_frustrated:
    adapted.empathy += 0.3
    adapted.verbosity += 0.1
  
  // 2. Apply trait modulation
  adapted.assertiveness += getTraitScore("assertiveness") * 0.3 - 0.15
  adapted.verbosity += (1 - getTraitScore("conciseness")) * 0.2
  
  // 3. Apply mood modulation
  if mood == "positive":
    adapted.humor += 0.1
    adapted.empathy += 0.1
  if mood == "cautious":
    adapted.formality += 0.2
    adapted.assertiveness -= 0.1
  
  // 4. Clamp all dimensions to 0.0â€“1.0
  clamp(adapted)
  
  return adapted
```

### Adaptation Contexts

| Context | Formality | Verbosity | Empathy | Humor | Assertiveness |
|---------|-----------|-----------|---------|-------|---------------|
| Security/High-risk | +0.2 | +0.1 | 0.0 | -0.3 | +0.1 |
| Creative task | -0.1 | +0.2 | +0.1 | +0.2 | -0.1 |
| User frustrated | -0.1 | +0.1 | +0.3 | -0.1 | +0.0 |
| Technical deep-dive | +0.1 | +0.3 | -0.1 | -0.1 | +0.1 |
| Casual conversation | -0.2 | -0.1 | +0.2 | +0.2 | -0.2 |
| Error/System failure | +0.1 | +0.1 | +0.2 | -0.4 | +0.2 |

## Style Application in Response Building

Style is applied as a post-processing layer in the response pipeline:

```
Content Generation (LLMOS)
    â”‚
    â–¼
Raw Response
    â”‚
    â–¼
Style Application
    â”‚
    â”œâ”€â”€ Adapt style to current context
    â”œâ”€â”€ Apply formality transformations
    â”‚     â”œâ”€â”€ Contractions â†’ full forms (high formality)
    â”‚     â””â”€â”€ Casual phrases â†’ formal equivalents
    â”œâ”€â”€ Apply verbosity adjustments
    â”‚     â”œâ”€â”€ Expansion: add examples, caveats, detail (high verbosity)
    â”‚     â””â”€â”€ Compression: remove digressions, single sentences (low verbosity)
    â”œâ”€â”€ Apply empathy framing
    â”‚     â”œâ”€â”€ Add sentiment acknowledgment phrases
    â”‚     â””â”€â”€ Warm closing statements
    â”œâ”€â”€ Apply humor where appropriate
    â”‚     â”œâ”€â”€ Relevant analogies or wordplay
    â”‚     â””â”€â”€ Light tone markers
    â””â”€â”€ Apply assertiveness level
          â”œâ”€â”€ Direct imperatives vs. hedged suggestions
          â””â”€â”€ Degree of certainty markers
    â”‚
    â–¼
Styled Response
    â”‚
    â–¼
Deliver to User
```

### Application Algorithm

```typescript
applyStyleToResponse(raw: string, context: DecisionContext): AppliedStyle
  adapted = adaptStyle(context)
  styled = raw
  
  // Formality: rewrite grammar, word choice
  if adapted.formality > 0.7:
    styled = increaseFormality(styled)
  if adapted.formality < 0.3:
    styled = decreaseFormality(styled)
  
  // Verbosity: expand or compress
  if adapted.verbosity > 0.7:
    styled = expandDetail(styled)
  if adapted.verbosity < 0.3:
    styled = compressToCore(styled)
  
  // Empathy: add emotional framing
  if adapted.empathy > 0.6:
    styled = addEmpathyFraming(styled, context)
  
  // Humor: add/remove levity
  if adapted.humor > 0.6:
    styled = addRelevantHumor(styled, context)
  if adapted.humor < 0.2 && containsHumor(styled):
    styled = removeHumor(styled)
  
  // Assertiveness: adjust directness
  if adapted.assertiveness > 0.7:
    styled = makeDirect(styled)
  if adapted.assertiveness < 0.3:
    styled = makeSuggestive(styled)
  
  return {
    style: adapted,
    raw_response: raw,
    styled_response: styled,
    adaptations_applied: getAdaptationLog(),
    dimension_changes: computeChanges(this.style, adapted)
  }
```

## Style Persistence Across Sessions

Style is persisted through Memory OS and loaded on session start:

| Component | Persistence | Scope |
|-----------|------------|-------|
| Base CommunicationStyle | Long-term (Memory OS) | Across all sessions |
| Adaptation history | Long-term (Episodic Memory) | Evidence record |
| Temporary context adaptations | In-memory only | Current session |

On session start, the base CommunicationStyle is loaded from Memory OS. Context-driven adaptations are applied during the session but do not persist. If the Academy determines that a style dimension should permanently shift, it issues an `adaptStyle` call that persists the change.

### Style Migration Between Versions

```typescript
// On personality version upgrade, style is migrated:
migrateStyle(oldStyle: CommunicationStyle, from_version: number, to_version: number): CommunicationStyle
  // Default migration: preserve all existing dimensions
  // If new dimensions added in target version: set to default
  // If dimensions removed: preserve in adaptation_history but drop from active profile
  return migrated
```

## Internal Interface

```typescript
interface StyleProfile {
  // Reading
  getStyle(): CommunicationStyle
  getStyleDimensions(): StyleDimensionDefinition[]
  getDimension(name: string): number
  getLanguage(): string

  // Adaptation
  adaptStyle(context: DecisionContext): CommunicationStyle
  setDimension(name: string, value: number, reason: string): CommunicationStyle
  resetToBase(): CommunicationStyle

  // Application
  applyStyleToResponse(raw: string, context: DecisionContext): AppliedStyle
  getAdaptationLog(): StyleAdaptation[]
  getActiveAdaptations(): StyleAdaptation[]

  // Persistence
  persistStyle(): void
  loadStyle(): CommunicationStyle

  // Governance
  getVersion(): number
  getLastModified(): timestamp
  getHistory(): StyleAdaptation[]
}

interface StyleConfig {
  default_style: CommunicationStyle
  adaptation_enabled: boolean
  humor_enabled: boolean                       // Separate toggle for humor
  adaptation_thresholds: Record<string, number> // Per-dimension adaptation sensitivity
  max_adaptations_per_session: number
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| PER.StyleProfileLoaded |    dimensions, language | Style profile loaded on startup |
| PER.StyleAdapted |    dimension, old_value, new_value, context | Style dimension adapted to context |
| PER.StyleApplied |    response_id, dimensions_modified | Style applied to a response |
| PER.StyleDimensionSet |    dimension, old_value, new_value, reason | Manual dimension override |
| PER.StyleReset |    dimension, previous_value, default_value | Dimension reset to base |
| PER.StyleTraitModulated |    dimension, trait_id, modulation_value | Trait modulated a style dimension |
| PER.StyleMoodModulated |    dimension, mood, modulation_value | Mood modulated a style dimension |
| PER.StylePersisted |    version, dimension_count | Style saved to Memory OS |
| PER.StyleAdaptationExpired |    adaptation_id, dimension, reverted_value | Temporary adaptation expired |
| PER.StyleDimensionClamped |    dimension, attempted_value, clamped_value | Dimension value clamped to 0.0â€“1.0 |
| PER.StyleLanguageChanged |    old_language, new_language | Language preference changed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| STY-001 | All style dimensions are bounded to 0.0â€“1.0 | Algorithmic â€” clamped on every set/adapt |
| STY-002 | Style adaptation is non-destructive to base profile | Architectural â€” base is immutable during session |
| STY-003 | Temporary adaptations expire and revert to base | Algorithmic â€” `expires_at` enforced |
| STY-004 | Style is loaded from persistent storage on session start | Architectural â€” `loadStyle` called by Personality System |
| STY-005 | Style is always applied after content generation, never before | Architectural â€” response pipeline ordering |
| STY-006 | Each style dimension has a defined effect on response output | Architectural â€” `StyleDimensionDefinition` required |
| STY-007 | Adaptation events are always recorded | Architectural â€” mandatory `StyleAdaptation` logging |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown style dimension | `PER_STYLE_UNKNOWN_DIMENSION` | Return error; list valid dimensions |
| Dimension value outside 0.0â€“1.0 | `PER_STYLE_VALUE_OUT_OF_RANGE` | Clamp to valid range; log warning |
| Style application on empty content | `PER_STYLE_EMPTY_CONTENT` | Return original content; no error |
| Maximum session adaptations exceeded | `PER_STYLE_MAX_ADAPTATIONS` | Deny adaptation; use current style |
| Adaptation on disabled feature | `PER_STYLE_ADAPTATION_DISABLED` | Deny; use base style without adaptation |
| Style persistence failure | `PER_STYLE_PERSIST_FAILED` | Retry; continue with in-memory style |
| Language not supported | `PER_STYLE_LANGUAGE_UNSUPPORTED` | Fallback to "en-US"; log warning |
| Expired adaptation re-application | `PER_STYLE_ADAPTATION_EXPIRED` | Skip; style already reverted |


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
| R1 â€” Modulsingularity | Style Profile handles only communication style â€” dimensions, adaptation, application |
| R2 â€” Dependency Order | Depends on Mood Tracker, Trait Engine; no upward deps |
| R3 â€” DRY | Style dimensions defined once in StyleProfile, applied by Response Builder |
| R4 â€” Builder Pattern | Response built by Content â†’ Style Adaptation â†’ Styled Output |
| R5 â€” Liskov Substitution | Any StyleProfile implements the interface |
| R6 â€” DI over Singletons | Adaptation strategies injected |
| R9 â€” Deterministic | Same style and context produce same styled output |
| R10 â€” Simpler Over Complex | Style uses scalar dimension scores (0.0â€“1.0) |
| R13 â€” Design for Failure | Style application handles empty content, unknown dimensions gracefully |
| R14 â€” Paved Path | All responses flow through `applyStyleToResponse` |
| R15 â€” Open/Closed | New style dimensions added via Config, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Personality/000-Overview.md | Style Profile is the fourth component of the Personality System |
| Personality/001-Identity-Profile.md | Style expresses Sou's identity in communication |
| Personality/003-Behavior-Patterns.md | Traits modulate style dimension values |
| Personality/005-Evolution.md | Style changes tracked through personality evolution |
| Brain/LLMOS/003-Prompt-Compiler.md | Style applied after content generation |
| Brain/Context/000-Overview.md | Context drives style adaptation |
| Bible/05-Platform/004-EVS.md | Events recorded throughout style lifecycle |
