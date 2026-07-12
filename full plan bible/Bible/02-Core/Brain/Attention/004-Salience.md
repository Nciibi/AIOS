# AIOS Bible — Brain
## 004 — Salience

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible — Brain/Attention |
| Document ID | AIOS-BBL-002-ATT-004 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Salience determines how relevant any signal is to Sou at a given moment. It is the foundational evaluation that feeds Priority Scoring and all downstream attention decisions. The Salience Scorer evaluates every incoming signal against five factors — goal alignment, urgency, source authority, novelty, and user proximity — to produce a multidimensional assessment of why a signal matters, not just how much.

Under ATT-003, every signal must be evaluated before it can be dropped. Salience evaluation is that first pass: no signal reaches Sou without being scored.

## Data Model

### SalienceFactors

```typescript
SalienceFactors {
  goal_alignment: GoalAlignment
  urgency: UrgencyAssessment
  source_authority: SourceAuthority
  novelty: NoveltyScore
  user_proximity: UserProximity
}

GoalAlignment {
  score: number                    // 0.0–1.0
  matched_goal_id?: string
  matched_keywords: string[]
  alignment_confidence: number     // 0.0–1.0
  reasoning: string
}

UrgencyAssessment {
  score: number                    // 0.0–1.0
  time_sensitivity_ms: number      // How quickly action is needed
  deadline?: timestamp
  decay_rate: number               // How fast urgency increases
  reasoning: string
}

SourceAuthority {
  score: number                    // 0.0–1.0
  source_name: string
  trust_tier: "critical" | "high" | "standard" | "low" | "untrusted"
  past_reliability: number         // 0.0–1.0, based on historical accuracy
  reasoning: string
}

NoveltyScore {
  score: number                    // 0.0–1.0
  similarity_to_recent: number     // 0.0–1.0 (1.0 = identical)
  recent_signal_count: number
  unique_attributes: string[]
  first_seen: boolean
  reasoning: string
}

UserProximity {
  score: number                    // 0.0–1.0
  direct_user_input: boolean
  user_mentioned: boolean
  task_context_match: number       // 0.0–1.0
  reasoning: string
}
```

### SignalEvaluation

```typescript
SignalEvaluation {
  evaluation_id: string
  signal_id: string
  factors: SalienceFactors
  composite_score: number          // 0.0–1.0, passed to Priority Scorer
  evaluation_version: string
  computed_at: timestamp
  computation_time_ms: number
}
```

### SalienceThresholds

```typescript
SalienceThresholds {
  focus_threshold: number          // Default: 0.80
  snooze_threshold: number         // Default: 0.30
  immediate_drop_threshold: number // Default: 0.15
  deep_work_protection_boost: number  // Default: +0.10 to focus threshold
}
```

## Core Concepts

### Signal Evaluation Pipeline

Every signal passes through a five-stage evaluation pipeline:

`
Signal Received
      |
      v
+-----------------+
| 1. Goal         |-- Computes relevance to Sou's active goal
|    Alignment    |   Uses keyword matching and semantic similarity
+-----------------+
      |
      v
+-----------------+
| 2. Urgency      |-- Assesses time-sensitivity
|    Assessment   |   Checks deadlines, TTL, decay rate
+-----------------+
      |
      v
+-----------------+
| 3. Source       |-- Scores trust tier of signal origin
|    Authority    |   Checks past reliability, verified sources
+-----------------+
      |
      v
+-----------------+
| 4. Novelty      |-- Detects how different from recent signals
|    Detection    |   Computes similarity, flags duplicates
+-----------------+
      |
      v
+-----------------+
| 5. User         |-- Measures direct relationship to user
|    Proximity    |   Checks user input, mentions, task context
+-----------------+
      |
      v
   Composite Score (passed to Priority Scorer)
`

Each stage computes a 0.0–1.0 score. The pipeline is sequential: early stages (goal alignment, urgency) are computationally cheaper and can short-circuit if the signal is irrelevant (score < 0.10), avoiding expensive novelty and proximity computation.

### Goal Alignment Computation

Goal alignment measures how relevant a signal is to Sou's current active goal:

```typescript
computeGoalAlignment(
  signal: AttentionSignal,
  active_goal: { goal_id: string; description: string; keywords: string[] }
): GoalAlignment
```

Computation steps:
1. Extract keywords from signal content and metadata
2. Match against active goal keywords (exact match + semantic similarity)
3. Compute overlap ratio: matched_keywords / total_goal_keywords
4. Apply confidence based on match quality (exact > synonym > related)

| Match Type | Weight | Example |
|------------|--------|---------|
| Exact keyword match | 1.0 | Signal: "authentication" — Goal: "auth" |
| Synonym match | 0.7 | Signal: "login" — Goal: "authentication" |
| Contextual relatedness | 0.4 | Signal: "password" — Goal: "user management" |
| No match | 0.0 | Signal: "weather" — Goal: "implement auth" |

### Urgency Assessment

Urgency captures how time-sensitive a signal is:

`
urgency_score = clamp(1.0 - (time_remaining / max_relevance_time), 0.0, 1.0)

Where:
  time_remaining = deadline - now (if deadline exists)
  time_remaining = signal.ttl_ms (if no deadline)
  max_relevance_time = max(time_remaining, 60000ms)
`

| Condition | urgency_score | Reasoning |
|-----------|--------------|-----------|
| Security breach detected | 1.0 | Immediate action required |
| User waiting > 5s | 0.85 | User is expecting response |
| System error with retry | 0.60 | Needs attention but has fallback |
| Mission update, no deadline | 0.30 | Informational, no time pressure |
| Federation broadcast | 0.10 | Low urgency, can wait |

Urgency decays in reverse: if a signal is not processed, its urgency increases over time as deadlines approach.

### Source Authority Scoring

Source authority scores how much Sou should trust the signal's source:

| Trust Tier | Base Score | Sources | Adjustment |
|------------|-----------|---------|------------|
| critical | 1.0 | Security Council, User | Never decays |
| high | 0.85 | System Runtime, Mission OS | -0.05 per missed ack |
| standard | 0.60 | Memory OS, Tool Runner | -0.10 per missed ack |
| low | 0.30 | Federation unknown peers | -0.15 per missed ack |
| untrusted | 0.05 | External, unverified | Locked at 0.05 |

Past reliability tracks the source's historical accuracy. If a source has sent 100 signals and 95 were relevant, past_reliability = 0.95.

### Novelty Detection

Novelty detects how different a signal is from recent signals to prevent Sou from seeing duplicates or near-duplicates:

```typescript
detectNovelty(
  signal: AttentionSignal,
  recent_signals: AttentionSignal[],
  window_size: number  // Default: last 10 signals
): NoveltyScore
```

Detection algorithm:
1. For each recent signal, compute a similarity score (0.0–1.0)
2. Take the maximum similarity as similarity_to_recent
3. Compute novelty as: 1.0 - similarity_to_recent
4. Apply boost (+0.20) if irst_seen is true

| Similarity | Novelty | Action |
|------------|---------|--------|
| 0.0–0.20 | 0.80–1.00 | High novelty, full evaluation |
| 0.20–0.50 | 0.50–0.80 | Moderate novelty, proceed |
| 0.50–0.80 | 0.20–0.50 | Low novelty, consider dedup |
| 0.80–1.00 | 0.00–0.20 | Near-duplicate, flag or drop |

### User Proximity Scoring

User proximity measures how directly a signal relates to the user:

| Condition | Proximity | Reasoning |
|-----------|-----------|-----------|
| Direct user input | 1.0 | User is actively communicating |
| User mentioned by name | 0.80 | Signal references the user |
| Task context matches user preference | 0.60 | Related to user's stated preferences |
| System event affecting user | 0.40 | Indirect user impact |
| No user relationship | 0.00 | Irrelevant to user |

### Salience Thresholds Table

Thresholds determine the action taken based on composite score:

| Threshold Range | Action | Condition |
|----------------|--------|-----------|
| >= focus_threshold (0.80) | Focus | Presented to Sou immediately |
| >= snooze_threshold (0.30) but < focus_threshold | Snooze | Deferred with condition |
| >= immediate_drop_threshold (0.15) but < snooze_threshold | Low-priority snooze | Snooze on idle only |
| < immediate_drop_threshold (0.15) | Drop | Discarded, source notified |

During Deep Work, the focus threshold is increased by deep_work_protection_boost (0.80 -> 0.90), making it harder for non-critical signals to penetrate.

### Temporal Decay of Salience

Salience scores decay over time. A signal that was relevant 5 minutes ago may no longer be relevant:

| Factor | Decay Rate | Minimum | Behavior |
|--------|-----------|---------|----------|
| Goal alignment | 0.05 per minute | 0.0 | Decays as goals change |
| Urgency | Inverse (increases) | 0.0 | Urgency grows as deadline approaches, then drops to 0 after |
| Source authority | None | 0.05 | Permanent, never fully decays |
| Novelty | 0.10 per minute | 0.0 | Fast decay — old signals are not novel |
| User proximity | 0.05 per minute | 0.0 | Decays if user moves on |

Decay is applied:
- On every re-evaluation of a snoozed signal
- On every context window pull
- On explicit decaySalience(signal_id) call

After a signal's composite score drops below immediate_drop_threshold for two consecutive evaluations, it is automatically dropped.

## Internal Interface

```typescript
interface SalienceScorer {
  evaluate(
    signal: AttentionSignal,
    context: {
      active_goal?: ActiveGoal
      recent_signals: AttentionSignal[]
      user_context: { user_active: boolean; last_input?: timestamp }
    }
  ): Promise<SignalEvaluation>

  computeGoalAlignment(
    signal: AttentionSignal,
    active_goal: ActiveGoal
  ): Promise<GoalAlignment>

  assessUrgency(
    signal: AttentionSignal
  ): Promise<UrgencyAssessment>

  scoreSourceAuthority(
    source: string,
    trust_registry: TrustRegistry
  ): Promise<SourceAuthority>

  detectNovelty(
    signal: AttentionSignal,
    recent_signals: AttentionSignal[],
    window_size?: number
  ): Promise<NoveltyScore>

  computeUserProximity(
    signal: AttentionSignal,
    user_context: { user_active: boolean; last_input?: timestamp; mentioned_entities: string[] }
  ): Promise<UserProximity>

  getThresholds(): Promise<SalienceThresholds>
  setThresholds(thresholds: Partial<SalienceThresholds>): Promise<SalienceThresholds>

  decaySalience(
    signal_id: string,
    elapsed_ms: number
  ): Promise<SignalEvaluation | null>

  getEvaluationHistory(window_ms: number): Promise<SignalEvaluation[]>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| ATT.ATTEvent |      signal_id, source, type | Salience evaluation began for signal |
| ATT.ATTEvent |      evaluation_id, signal_id, composite_score, factors | Full evaluation finished |
| ATT.ATTEvent |      signal_id, matched_goal_id, score, confidence | Goal alignment factor computed |
| ATT.ATTEvent |      signal_id, score, time_sensitivity_ms, deadline | Urgency assessment completed |
| ATT.ATTEvent |      signal_id, source, trust_tier, score | Source authority scored |
| ATT.ATTEvent |      signal_id, score, similarity, first_seen | Novelty detection completed |
| ATT.ATTEvent |      signal_id, score, direct_input, mentioned | User proximity scored |
| ATT.ATTEvent |      signal_id, previous_score, new_score, elapsed_ms | Temporal decay applied |
| ATT.ATTEvent |      signal_id, composite_score, threshold, action | Signal crossed focus threshold |
| ATT.ATTEvent |      signal_id, composite_score, threshold, action | Signal fell below threshold |
| ATT.ATTEvent |      signal_id, stage, reason | Pipeline short-circuited at stage due to low score |
| ATT.ATTEvent |      signal_id, composite_score, consecutive_below_threshold | Signal dropped after decay below threshold |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| ATT-SAL-001 | Every signal is evaluated exactly once before any attention action | Architectural — injectSignal calls evaluate first |
| ATT-SAL-002 | Each factor score is independently computed and bounded [0.0, 1.0] | Algorithmic — clamping after each computation |
| ATT-SAL-003 | Goal alignment requires an active goal; if none, score defaults to 0.3 | Algorithmic — default applied when active_goal is null |
| ATT-SAL-004 | Temporal decay is monotonic (salience never increases organically) | Algorithmic — decay only reduces, urgency is the exception |
| ATT-SAL-005 | Urgency increases as deadline approaches, then drops to 0 after expiry | Algorithmic — computed as piecewise function |
| ATT-SAL-006 | Short-circuiting only skips novelity and proximity, never goal alignment or urgency | Algorithmic — pipeline order is fixed |
| ATT-SAL-007 | Salience thresholds are always ordered: drop < snooze < focus | Schema — validated on setThresholds |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Signal with no evaluable content | ATT_SAL_NO_CONTENT | Assign minimum factor scores (0.05); log warning |
| Active goal not found in goal registry | ATT_SAL_GOAL_NOT_FOUND | Default goal_alignment to 0.30; log warning |
| Source not found in trust registry | ATT_SAL_UNKNOWN_SOURCE | Default to "standard" tier; log informational |
| Novelty pool empty (first signal) | ATT_SAL_EMPTY_POOL | Set novelty to 1.0 (maximally novel); no warning |
| Evaluation exceeds max computation time | ATT_SAL_EVALUATION_TIMEOUT | Return best-effort scores from completed stages |
| Threshold config has invalid ordering | ATT_SAL_INVALID_THRESHOLDS | Reject config; use previous valid thresholds |
| Decay on non-existent evaluation | ATT_SAL_EVALUATION_NOT_FOUND | Return null; no error |
| Circular dependency in factor computation | ATT_SAL_CIRCULAR_EVALUATION | Break cycle; log critical error |


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
| R1 — Modulsingularity | Salience evaluates one thing: signal relevance |
| R2 — Dependency Order | Depends on Goal Registry, Trust Registry; no upward deps |
| R3 — DRY | Factor definitions stored once in SalienceFactors schema |
| R4 — Builder Pattern | Evaluation built from 5 sequential factor stages |
| R5 — Liskov Substitution | Any SalienceScorer implements the interface |
| R6 — DI over Singletons | Trust registry, goal registry, thresholds injected |
| R9 — Deterministic | Same signal + context = same evaluation |
| R10 — Simpler Over Complex | Uses linear factor model with clear heuristics |
| R13 — Design for Failure | Short-circuit on low scores saves compute |
| R14 — Paved Path | All signals flow through evaluate() entry point |
| R15 — Open/Closed | New factors added via config, not core pipeline |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Attention/000-Overview.md | Salience Scorer is the first component in the Attention System |
| Attention/001-Priority-Scoring.md | Composite score feeds directly into Priority Scoring weights |
| Attention/002-Focus-Management.md | Deep work state adjusts salience thresholds |
| Attention/003-Interruption-Handling.md | Urgency scores determine interrupt priority |
| Attention/001-Priority-Scoring.md | Scores below focus threshold route to Priority Scoring for re-evaluation |
| Brain/Context/000-Overview.md | Context provides active goal and user context |
| Brain/Personality/000-Overview.md | Personality traits influence factor weights |
| Bible/04-Execution/Security/ | Security sources have critical trust tier |
