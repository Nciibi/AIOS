# AIOS Bible â€” Brain
## 001 â€” Priority Scoring

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-001 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Priority Scoring computes a numerical salience score for every incoming signal, determining how relevant each signal is to Sou's current goals and context. The score drives every subsequent attention decision: which signals enter focus, which are snoozed, and which are dropped. Priority Scoring is the gate through which all signals must pass before Sou ever sees them.

Under ATT-003, every signal is evaluated before it can be dropped. Priority Scoring is that evaluation â€” no signal bypasses scoring.

## Data Model

### SalienceFactors

```typescript
SalienceFactors {
  goal_alignment: number         // 0.0â€“1.0 â€” relevance to active goal
  urgency: number                // 0.0â€“1.0 â€” time-sensitivity
  source_authority: number       // 0.0â€“1.0 â€” trust level of source
  novelty: number                // 0.0â€“1.0 â€” how different from recent signals
  user_proximity: number         // 0.0â€“1.0 â€” how directly related to user
}
```

### PriorityScore

```typescript
PriorityScore {
  signal_id: string
  factors: SalienceFactors
  raw_score: number              // 0.0â€“1.0 before normalization
  normalized_score: number       // 0.0â€“1.0 after normalization
  weights_used: WeightsConfig
  override_applied: boolean
  computed_at: timestamp
}
```

### WeightsConfig

```typescript
WeightsConfig {
  goal_alignment: number         // Default: 0.35
  urgency: number                // Default: 0.25
  source_authority: number       // Default: 0.15
  novelty: number                // Default: 0.10
  user_proximity: number         // Default: 0.15
  version: string                // Config version for traceability
}
```

### SalienceOverride

```typescript
SalienceOverride {
  source_pattern: string         // Glob or exact source name
  override_score: number         // 0.0â€“1.0, fixed score for this source
  reason: string
  expires_at?: timestamp
  created_by: string
}
```

## Core Concepts

### Weighted Linear Model

Salience is computed as a weighted sum of five factors:

```
salience = (w_ga * ga) + (w_ur * ur) + (w_sa * sa) + (w_no * no) + (w_up * up)

Where:
  w_ga = goal_alignment weight (default 0.35)
  w_ur = urgency weight        (default 0.25)
  w_sa = source_authority weight (default 0.15)
  w_no = novelty weight        (default 0.10)
  w_up = user_proximity weight (default 0.15)
```

The weighted model ensures that goal-aligned and urgent signals consistently score highest, while novelty alone is rarely enough to pull focus.

### Score Normalization

Raw scores are normalized to prevent any single factor from dominating:

| Method | When Applied | Behavior |
|--------|-------------|----------|
| Min-max scaling | Always | Normalize each factor to 0.0â€“1.0 range |
| Clamping | After computation | Clamp raw_score to [0.0, 1.0] |
| Histogram equalization | Optional (config) | Spread scores across full range |

Normalization ensures that a signal with moderately high values across all factors can outrank a signal that peaks in only one factor but is weak elsewhere.

### Dynamic Weight Adjustment

Weights are not static. The Priority Scorer adjusts weights based on context:

| Context | Adjustment | Rationale |
|---------|-----------|-----------|
| Sou is in Deep Work | goal_alignment weight +0.10, novelty weight -0.05 | Protect focus |
| Sou has been Idle > 30s | urgency weight +0.05 | Ready to respond |
| Recent interrupt storm | source_authority weight +0.10 | Trust trusted sources more |
| User is actively typing | user_proximity weight +0.10 | User input is more relevant |
| Mission-critical operation | goal_alignment weight +0.15, urgency weight +0.10 | Mission focus |

All dynamic adjustments preserve the invariant that weights always sum to 1.0.

### Per-Source Salience Overrides

Sou can manually override salience for specific sources:

```typescript
setOverride(source: "system_alerts", override_score: 0.8, reason: "Always want to see system alerts")
setOverride(source: "telemetry_*", override_score: 0.0, reason: "Ignore telemetry noise")
setOverride(source: "federation_message", override_score: null, reason: "Reset to default")
```

Overrides are checked before the weighted model. If an override matches, `override_applied = true` and the override score is used directly.

Override matching uses glob patterns: `*` matches any source, `source_*` matches any source starting with `source_`.

### Score Thresholds

The computed score maps to an attention action:

| Score Range | Action | Behavior |
|-------------|--------|----------|
| 0.80â€“1.00 | Focus | Immediately presented to Sou |
| 0.50â€“0.79 | Snooze | Added to Snooze Queue with `on_timeout` |
| 0.30â€“0.49 | Snooze | Added to Snooze Queue with `on_idle` |
| 0.00â€“0.29 | Drop | Signal dropped, source notified |

Thresholds are configurable per-session and can be dynamically adjusted when the attention budget is strained.

## Internal Interface

```typescript
interface PriorityScorer {
  score(
    signal: AttentionSignal,
    context: { focus_state: FocusState; active_goal?: string; recent_signals: string[] }
  ): Promise<PriorityScore>

  getSalience(signal_id: string): Promise<SalienceFactors | null>

  setOverride(
    source_pattern: string,
    override_score: number | null,
    reason: string
  ): Promise<SalienceOverride>

  removeOverride(source_pattern: string): Promise<void>
  getOverrides(): Promise<SalienceOverride[]>
  getFactors(signal_id: string): Promise<SalienceFactors | null>

  getWeights(): Promise<WeightsConfig>
  updateWeights(adjustments: Partial<WeightsConfig>): Promise<WeightsConfig>
  resetWeights(): Promise<WeightsConfig>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| ATT.ATTEvent |    signal_id, raw_score, normalized_score, factors | Signal scored by Priority Scorer |
| ATT.ATTEvent |    source_pattern, override_score, reason | Salience override created or updated |
| ATT.ATTEvent |    source_pattern, previous_score | Salience override deleted |
| ATT.ATTEvent |    source_pattern, expires_at | Override reached TTL, removed automatically |
| ATT.ATTEvent |    old_weights, new_weights, context_reason | Dynamic weight adjustment applied |
| ATT.ATTEvent |    previous_weights | Weights returned to defaults |
| ATT.ATTEvent |    signal_id, score, threshold, signal_type | Score crossed above focus threshold |
| ATT.ATTEvent |    signal_id, score, threshold, action | Score fell below threshold, signal snoozed/dropped |
| ATT.ATTEvent |    method, factor_before, factor_after | Factor normalization executed |
| ATT.ATTEvent |    adjustment_type, delta, rationale | Dynamic weight adjustment triggered |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-PRI-001 | Weights always sum to exactly 1.0 after any adjustment | Algorithmic â€” `normalizeWeights` called after every update |
| ATT-PRI-002 | Every signal is scored exactly once, before any attention decision | Architectural â€” `injectSignal` calls `score` first |
| ATT-PRI-003 | Per-source overrides take precedence over the weighted model | Algorithmic â€” override check precedes weight computation |
| ATT-PRI-004 | An override score of 0.0 does not drop the signal â€” it must still pass threshold evaluation | API-level â€” zero override means minimal salience, not signal deletion |
| ATT-PRI-005 | Normalized score never exceeds the [0.0, 1.0] range | Algorithmic â€” clamping enforced after every computation |
| ATT-PRI-006 | Dynamic weight adjustments are monotonic within a single scoring context | Algorithmic â€” weights are restored after context ends |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown factor name in weight config | `ATT_PRI_UNKNOWN_FACTOR` | Log warning; use default weight for that factor |
| Override pattern matches no source | `ATT_PRI_OVERRIDE_NO_MATCH` | Create override; log informational |
| Malformed factor values (NaN, Infinity) | `ATT_PRI_INVALID_FACTOR` | Clamp to 0.0; log error |
| Histogram normalization on empty signal pool | `ATT_PRI_EMPTY_POOL` | Skip equalization; use min-max only |
| Weight config version mismatch | `ATT_PRI_VERSION_MISMATCH` | Use latest config; log out-of-date version |
| Circular dependency in dynamic adjustment rules | `ATT_PRI_CIRCULAR_ADJUSTMENT` | Reject adjustment; log to Event Store |
| Override TTL in the past | `ATT_PRI_OVERRIDE_EXPIRED_IMMEDIATE` | Create with 0 TTL; log warning |


## Cross-Cutting Concerns

### Security

Attention System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Attention System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Attention System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Attention System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Priority Scoring does one thing: compute salience scores |
| R2 â€” Dependency Order | Depends on FocusState, Signal Registry; no upward deps |
| R3 â€” DRY | Factor definitions stored once in SalienceFactors schema |
| R4 â€” Builder Pattern | Score built from Factors â†’ Weighted Sum â†’ Normalization |
| R5 â€” Liskov Substitution | Any PriorityScorer implementation satisfies the interface |
| R6 â€” DI over Singletons | Weights config and normalization strategy injected |
| R9 â€” Deterministic | Same factors + weights produce identical scores |
| R10 â€” Simpler Over Complex | Uses weighted linear model, not neural network |
| R13 â€” Design for Failure | Invalid factors clamped, never crash |
| R14 â€” Paved Path | All signals routed through `score()` entry point |
| R15 â€” Open/Closed | New factors added via config, not core scoring logic |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Attention/000-Overview.md | Priority Scoring is the first stage of the Salience Scanner |
| Attention/002-Focus-Management.md | Focus state feeds context to dynamic weight adjustment |
| Attention/003-Interruption-Handling.md | Scores determine which signals become interrupts |
| Attention/004-Salience.md | Salience factors are computed by SalienceScorer |
| Attention/004-Salience.md | Scores below threshold route to Salience re-evaluation |
| Brain/Context/000-Overview.md | Context window provides goal and recent signal data |
| Brain/Personality/000-Overview.md | Personality profile influences base weights |

(End of file - total 327 lines)
