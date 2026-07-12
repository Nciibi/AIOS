# AIOS Bible â€” Brain
## 005 â€” Decision Pipeline

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Decision |
| Document ID | AIOS-BBL-002-DEC-005 |
| Source Laws | Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Decision Pipeline orchestrates the end-to-end decision evaluation flow â€” from receiving a `DecisionRequest` to returning a `DecisionRecommendation`. It coordinates the Constraint Checker, Scoring Engine, and Trade-off Analyzer in the correct order, handles error recovery at each stage, and logs the final decision to the History Logger. The pipeline ensures that every evaluation is reproducible, traceable, and resilient to partial failure.

## Data Model

### PipelineStage

```typescript
enum PipelineStage {
  Validate         = 0,
  ConstraintCheck  = 1,
  Score            = 2,
  TradeoffAnalyze  = 3,
  Rank             = 4,
  Recommend        = 5,
  Log              = 6
}
```

### StageResult

```typescript
StageResult {
  stage: PipelineStage
  status: "pending" | "running" | "completed" | "skipped" | "failed"
  started_at?: timestamp
  completed_at?: timestamp
  duration_ms?: number
  output?: unknown                   // Stage-specific result data
  error?: StageError
}
```

### PipelineState

```typescript
PipelineState {
  pipeline_id: string
  request: DecisionRequest
  stages: Record<PipelineStage, StageResult>
  current_stage: PipelineStage
  surviving_options: DecisionOption[]   // Options still in consideration
  eliminated_options: EliminatedOption[]
  score_matrix: ScoreMatrix[]
  trade_offs: TradeOff[]
  ranked_options: RankedOption[]
  recommendation?: DecisionRecommendation
  started_at: timestamp
  last_activity: timestamp
  error?: PipelineError
  failed: boolean
  cancelled: boolean
}
```

### PipelineConfig

```typescript
PipelineConfig {
  timeout_per_stage: Record<PipelineStage, number>  // ms per stage
  parallel_execution: boolean                        // false = sequential only
  error_strategy: Record<PipelineStage, ErrorStrategy>
  total_timeout: number                              // ms, overall pipeline timeout
  max_retries: number                                // default retry count
  record_partial_results: boolean                    // emit partial results on failure
}
```

### ErrorStrategy

```typescript
type ErrorStrategy = "skip_stage" | "retry_once" | "retry_with_backoff" | "fail_pipeline"
```

### DecisionRequest (full from overview)

```typescript
DecisionRequest {
  request_id: string
  context: DecisionContext
  options: DecisionOption[]
  criteria: DecisionCriterion[]
  constraints: DecisionConstraint[]
}
```

### DecisionRecommendation (full from overview plus pipeline_metadata)

```typescript
DecisionRecommendation {
  request_id: string
  ranked_options: RankedOption[]
  trade_offs: TradeOff[]
  constraints_satisfied: boolean
  violated_constraints: ViolatedConstraint[]
  confidence: number
  explanation: string
  created_at: timestamp
  pipeline_metadata: {
    pipeline_id: string
    stages_completed: PipelineStage[]
    stages_skipped: PipelineStage[]
    stages_failed: PipelineStage[]
    total_duration_ms: number
    partial_result: boolean
  }
}
```

### PipelineReport

```typescript
PipelineReport {
  pipeline_id: string
  request_id: string
  state: "completed" | "partial" | "failed" | "cancelled"
  stages: StageReport[]
  total_duration_ms: number
  options_considered: number
  options_surviving: number
  options_eliminated: number
  final_recommendation?: DecisionRecommendation
  errors: PipelineError[]
}
```

## Pipeline Stages

The pipeline executes seven stages in strict sequential order:

### Stage 0 â€” Validate

Validates the incoming `DecisionRequest` structure before any processing begins.

```
Checklist:
  â˜ request_id is present and non-empty
  â˜ options is non-empty
  â˜ each option has option_id and label
  â˜ criteria is non-empty
  â˜ each criterion has criterion_id, name, weight, scoring_function
  â˜ sum of criteria weights â‰ˆ 1.0 (Â± 0.001 tolerance)
  â˜ constraints array present (may be empty)

On failure: Return DEC_INVALID_REQUEST error
```

### Stage 1 â€” Constraint Check

Runs all hard constraints against every option. Non-compliant options are eliminated.

```
For each option in options:
  For each constraint in constraints:
    If constraint.type == "hard":
      Evaluate constraint.expression against option.attributes
      If violated:
        Add option to eliminated_options with violated constraint
        Emit DEC.ConstraintViolated
        Remove option from surviving_options

Post-check:
  If surviving_options is empty:
    Emit DEC.AllOptionsEliminated
    Set state.error = DEC_ALL_ELIMINATED
    Pipeline enters partial completion path
```

### Stage 2 â€” Score

Computes the score matrix for all surviving options against all criteria.

```
For each option in surviving_options:
  Initialize score_row: { option_id, scores: {}, weighted_total: 0 }
  For each criterion in criteria:
    scoring_fn = resolveScoringFunction(criterion.scoring_function)
    raw_score = scoring_fn.score(
      option.attributes[criterion.name],
      criterion.preferences
    )
    score_row.scores[criterion.criterion_id] = raw_score
    score_row.weighted_total += raw_score * criterion.weight
  Append score_row to score_matrix

On scoring function resolution failure:
  Apply error_strategy for Score stage
  If skip_stage: omit criterion from scoring, continue
  If retry_once: retry failed criterion score
  If fail_pipeline: abort, return partial matrix
```

### Stage 3 â€” Trade-off Analyze

Identifies trade-offs between surviving options based on their score profiles.

```
For each pair (option_a, option_b) in surviving_options:
  Identify criteria where option_a scores high and option_b scores low (or vice versa)
  For each conflicting criterion pair (c_i, c_j):
    If delta(score_a_i - score_b_i) * delta(score_a_j - score_b_j) < 0:
      Trade-off detected between criteria c_i and c_j
      magnitude = abs(delta(score_a_i - score_b_i)) Ã— weight_i
                 + abs(delta(score_a_j - score_b_j)) Ã— weight_j
      Append TradeOff to trade_offs

Emit DEC.TradeOffIdentified for each discovered trade-off
```

### Stage 4 â€” Rank

Sorts surviving options by `weighted_total` descending and assigns ranks.

```
ranked = sort(score_matrix, by: weighted_total, order: desc)
For i, row in enumerate(ranked):
  row.rank = i + 1
  row.strength = classifyStrength(row.weighted_total)
  row.weakness = lowestScoreCriterion(row.scores)
```

### Stage 5 â€” Recommend

Packages the final recommendation with a human-readable explanation.

```
recommendation = {
  request_id: state.request.request_id
  ranked_options: ranked_options
  trade_offs: state.trade_offs
  constraints_satisfied: eliminated_options.length === 0
  violated_constraints: mapViolations(eliminated_options)
  confidence: computeConfidence(ranked_options, trade_offs)
  explanation: generateExplanation(
    ranked_options,
    trade_offs,
    eliminated_options,
    state.request.context
  )
  created_at: now()
  pipeline_metadata: buildPipelineMetadata(state)
}
```

### Stage 6 â€” Log

Records the complete evaluation in the History Logger.

```
record = {
  request_id: state.request.request_id
  session_id: state.request.context.session_id
  sou_identity: resolveSouIdentity()
  context_snapshot: state.request.context.context_window_snapshot
  options: state.request.options
  criteria: state.request.criteria
  recommendation: state.recommendation
  final_choice: null                   // Set later by recordFinalChoice()
  decision_latency_ms: total_duration
  created_at: now()
}

HistoryLogger.store(record)
Emit DEC.EvaluationCompleted
```

## Stage Coordination

### Execution Order

Stages execute strictly sequentially â€” each stage depends on the output of the previous stage:

```
Validate â†’ ConstraintCheck â†’ Score â†’ TradeoffAnalyze â†’ Rank â†’ Recommend â†’ Log
```

No stage begins until the previous stage reports `completed`. The pipeline maintains a running `PipelineState` that accumulates results across stages.

### Stage Timeout

Each stage has a configurable timeout specified in `PipelineConfig.timeout_per_stage`:

```
If stage.duration_ms > timeout_per_stage[stage]:
  Interrupt stage execution
  Apply error_strategy for that stage
```

### Context Passing

Each stage receives the full `PipelineState` and returns a partial update:

```typescript
type StageHandler = (state: PipelineState) => Partial<StageResult>
```

Stage outputs are merged into the shared state. The next stage sees all accumulated data.

### Parallel Execution Flag

If `PipelineConfig.parallel_execution` is set to `true`, stages that are independent of constraint results may be parallelized in future implementations. The default mode is sequential.

## Error Recovery

### Per-Stage Error Strategy

| Strategy | Behavior |
|----------|----------|
| `skip_stage` | Mark stage as skipped, continue pipeline with best-effort state |
| `retry_once` | Retry the stage one time; if second attempt fails, apply fallback |
| `retry_with_backoff` | Retry with exponential backoff (1s, 2s, 4s) up to `max_retries` |
| `fail_pipeline` | Abort pipeline immediately, return partial results if available |

### Partial Results Handling

When a stage fails but is configured to `skip_stage` or the pipeline has `record_partial_results` enabled:

- **Score stage partial failure**: If scoring fails for some options, continue with successfully scored options. Unscored options are marked with `score_status: "failed"` and placed at the bottom of the ranking.
- **Trade-off analysis partial failure**: If trade-off computation times out, return trade-offs identified so far with a `trade_offs_truncated` flag.
- **Log stage failure**: The recommendation is still returned to Sou, but a `DEC.LogFailed` warning is emitted.

### Pipeline Timeout

```
If (now() - state.started_at) > PipelineConfig.total_timeout:
  Halt current stage execution
  Build partial recommendation from available data
  Mark recommendation.pipeline_metadata.partial_result = true
  Emit DEC.PipelineTimedOut
  Return partial recommendation
```

### Error Chaining

Errors propagate through the pipeline state and are aggregated into the final `PipelineReport`:

```
Stage Error â†’ PipelineState.error â†’ PipelineReport.errors
```

## History Logger Integration

### Decision Record Creation

Every complete pipeline evaluation produces exactly one `DecisionRecord`:

```typescript
DecisionRecord {
  request_id: string
  session_id: string
  sou_identity: string
  context_snapshot: string
  options: DecisionOption[]
  criteria: DecisionCriterion[]
  recommendation: DecisionRecommendation
  final_choice: string | null
  decision_latency_ms: number
  created_at: timestamp
}
```

### Final Choice Recording

Sou's actual choice may differ from the top-ranked recommendation. The pipeline exposes `recordFinalChoice()` for Sou to record the decision:

```
recordFinalChoice(request_id: string, option_id: string):
  1. Lookup DecisionRecord by request_id
  2. Set record.final_choice = option_id
  3. Emit DEC.DecisionFinalized
  4. Return updated DecisionRecord
```

### History Querying

Decision history is queryable through the pipeline:

```typescript
getHistory(filters: {
  session_id?: string
  criterion_id?: string
  option_type?: string
  limit?: number
  offset?: number
}): DecisionRecord[]
```

- Filter by `session_id`: Returns all decisions from a session
- Filter by `criterion_id`: Returns decisions that used a specific criterion
- Filter by `option_type`: Returns decisions involving a specific type of option (based on option attributes)

## Pipeline Execution Flow

```
evaluateOptions(request: DecisionRequest) -> DecisionRecommendation:
  state = initPipeline(request)
  emit DEC.PipelineStarted

  for stage in [Validate, ConstraintCheck, Score, TradeoffAnalyze, Rank, Recommend, Log]:
    state.current_stage = stage
    emit DEC.StageStarted(stage)

    result = executeStage(stage, state)

    if result.status == "completed":
      mergeStageResult(state, result)
      emit DEC.StageCompleted(stage)

    else if result.status == "skipped":
      state.stages[stage].status = "skipped"
      emit DEC.StageSkipped(stage, result.error)

    else if result.status == "failed":
      errorStrategy = config.error_strategy[stage]

      if errorStrategy == "retry_once":
        result = retryStage(stage, state)
        if result.status == "failed":
          state.stages[stage].status = "failed"
          emit DEC.StageFailed(stage, result.error)
          if config.record_partial_results:
            handlePartialResult(state, stage)

      else if errorStrategy == "retry_with_backoff":
        for attempt in [1, 2, 4]:
          wait(attempt * 1000)
          result = retryStage(stage, state)
          if result.status == "completed":
            break
        if result.status == "failed":
          state.failed = true
          emit DEC.StageFailed(stage, result.error)
          break

      else if errorStrategy == "skip_stage":
        state.stages[stage].status = "skipped"
        emit DEC.StageSkipped(stage, result.error)

      else if errorStrategy == "fail_pipeline":
        state.failed = true
        emit DEC.StageFailed(stage, result.error)
        break

  if state.cancelled:
    emit DEC.PipelineCancelled
    return buildPartialRecommendation(state)

  if state.failed and not config.record_partial_results:
    emit DEC.PipelineFailed
    return null

  recommendation = buildRecommendation(state)
  if state.failed or timed_out:
    recommendation.pipeline_metadata.partial_result = true

  emit DEC.PipelineCompleted(stage)
  return recommendation
```

## Internal Interface

```typescript
interface DecisionPipeline {
  evaluateOptions(request: DecisionRequest): DecisionRecommendation

  executeStage(stage: PipelineStage, state: PipelineState): StageResult

  getPipelineState(pipeline_id: string): PipelineState | null

  cancelEvaluation(pipeline_id: string): void
  // Halts execution at the next safe checkpoint
  // Emits DEC.PipelineCancelled
  // Returns partial results

  getStageResult(pipeline_id: string, stage: PipelineStage): StageResult | null

  recordFinalChoice(request_id: string, option_id: string): DecisionRecord
  // Sou's actual choice â€” may differ from recommendation

  getHistory(filters: HistoryFilter): DecisionRecord[]
  // Query decision history by session_id, criterion_id, option_type

  getPipelineReport(pipeline_id: string): PipelineReport
  // Summary report of pipeline execution

  getDefaultConfig(): PipelineConfig
  // Returns default pipeline configuration
}
```

### Default Config

```typescript
PipelineConfig defaultConfig = {
  timeout_per_stage: {
    Validate: 500,
    ConstraintCheck: 2000,
    Score: 10000,
    TradeoffAnalyze: 10000,
    Rank: 1000,
    Recommend: 500,
    Log: 1000
  },
  parallel_execution: false,
  error_strategy: {
    Validate: "fail_pipeline",
    ConstraintCheck: "fail_pipeline",
    Score: "retry_once",
    TradeoffAnalyze: "skip_stage",
    Rank: "skip_stage",
    Recommend: "skip_stage",
    Log: "skip_stage"
  },
  total_timeout: 60000,
  max_retries: 3,
  record_partial_results: true
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| DEC.PipelineStarted |    pipeline_id, request_id, stage_count, started_at | Pipeline evaluation initiated |
| DEC.StageStarted |    pipeline_id, stage, started_at | Individual stage begins execution |
| DEC.StageCompleted |    pipeline_id, stage, duration_ms, result_summary | Stage finished successfully |
| DEC.StageSkipped |    pipeline_id, stage, error_code, reason | Stage skipped due to error strategy |
| DEC.StageFailed |    pipeline_id, stage, error_code, attempt | Stage failed after retries exhausted |
| DEC.StageRetrying |    pipeline_id, stage, attempt, backoff_ms | Stage is being retried |
| DEC.PipelineCompleted |    pipeline_id, request_id, total_duration_ms, partial | Full pipeline execution finished |
| DEC.PipelineFailed |    pipeline_id, request_id, failed_stage, error | Pipeline aborted due to unrecoverable error |
| DEC.PipelineCancelled |    pipeline_id, request_id, reason | Pipeline halted by cancelEvaluation |
| DEC.PipelineTimedOut |    pipeline_id, request_id, elapsed_ms, timeout_ms | Pipeline exceeded total_timeout |
| DEC.DecisionFinalized |    request_id, pipeline_id, final_choice, previous_top_rank | Sou recorded final choice |
| DEC.PartialResultEmitted |    pipeline_id, request_id, completed_stages, failed_stages | Partial results returned |
| DEC.StageTimeoutExceeded |    pipeline_id, stage, timeout_ms, actual_ms | Individual stage exceeded its timeout |
| DEC.AllOptionsEliminated |    pipeline_id, request_id, constraint_count | Hard constraints eliminated all options |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DEC-PL-001 | Stages execute strictly in order (0 â†’ 1 â†’ 2 â†’ 3 â†’ 4 â†’ 5 â†’ 6) | Algorithmic â€” no stage starts before previous completes |
| DEC-PL-002 | Every pipeline produces at most one DecisionRecord | Algorithmic â€” Log stage runs once per pipeline |
| DEC-PL-003 | Partial results are never returned with confidence > 0.5 | Algorithmic â€” partial results capped at 0.5 confidence |
| DEC-PL-004 | A cancelled pipeline always returns partial results | Algorithmic â€” cancelEvaluation builds partial recommendation |
| DEC-PL-005 | Pipeline timeout never destroys already-completed stage results | Architectural â€” completed stages preserved in state |
| DEC-PL-006 | `recordFinalChoice` only writes to existing DecisionRecords | Validation â€” request_id must reference a completed pipeline |
| DEC-PL-007 | Eliminated options are never scored or ranked | Algorithmic â€” ConstraintCheck runs before Score |
| DEC-PL-008 | The Validate stage always runs with `fail_pipeline` strategy | Config â€” overrides must not downgrade validation |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Empty options array | `DEC_PL_NO_OPTIONS` | Pipeline aborts in Validate stage; return error |
| Criteria weights sum outside 0.999â€“1.001 | `DEC_PL_INVALID_WEIGHTS` | Normalize weights and proceed with warning; emit DEC.PreferenceOverridden |
| Unknown scoring function in criterion | `DEC_PL_UNKNOWN_FUNCTION` | If Score stage strategy is skip_stage: omit criterion; if fail_pipeline: abort |
| All options eliminated by hard constraints | `DEC_PL_ALL_ELIMINATED` | Return empty recommendation with explanation; pipeline completes |
| Stage exceeds per-stage timeout | `DEC_PL_STAGE_TIMEOUT` | Apply per-stage error strategy; emit DEC.StageTimeoutExceeded |
| Pipeline exceeds total_timeout | `DEC_PL_PIPELINE_TIMEOUT` | Return partial recommendation capped at 0.5 confidence |
| Cancel called during stage execution | `DEC_PL_CANCELLED` | Halt at next safe checkpoint; return partial results |
| Log stage write failure | `DEC_PL_LOG_FAILED` | Return recommendation but emit warning; partial logging failure |
| Retry count exceeded for stage | `DEC_PL_RETRIES_EXHAUSTED` | Apply error_strategy fallback for the stage |
| Pipeline config has invalid error_strategy | `DEC_PL_INVALID_CONFIG` | Default to `fail_pipeline` for that stage |

## Usage Patterns

### Pattern 1: Standard Evaluation

```
1. Sou faces a choice (e.g., "which tool to use for code generation")
2. Sou builds DecisionRequest with 3 options and 5 criteria
3. Sou calls pipeline.evaluateOptions(request)
4. Pipeline runs Validate â†’ ConstraintCheck â†’ Score â†’ TradeoffAnalyze â†’ Rank â†’ Recommend â†’ Log
5. Sou receives DecisionRecommendation with ranked options and trade-offs
6. Sou reviews recommendation, makes final choice
7. Sou calls pipeline.recordFinalChoice(request_id, chosen_option_id)
8. DecisionRecord is stored with final_choice populated
```

### Pattern 2: Partial Failure Recovery

```
1. Sou submits request with 6 options and 8 criteria (including a custom scoring function)
2. Validate passes, ConstraintCheck eliminates 2 options
3. Score stage begins: 7 of 8 criteria score successfully
4. Custom scoring function for criterion "innovation_factor" fails to resolve
5. Error strategy for Score stage is "skip_stage": criterion is omitted
6. Pipeline continues with remaining criteria
7. Recommendation is generated with 4 surviving options scored on 7 criteria
8. recommendation.pipeline_metadata.stages_skipped includes Score (partial)
9. confidence is computed lower due to reduced criteria count
10. Sou is notified of the partial result and the omitted criterion
```

### Pattern 3: Cancellation During Long Evaluation

```
1. Sou submits request with 20 options and 10 criteria (large evaluation scope)
2. Pipeline passes Validate and ConstraintCheck (2 options eliminated)
3. Score stage begins processing 18 options against 10 criteria
4. After 45 seconds, Sou determines the choice is obvious
5. Sou calls pipeline.cancelEvaluation(pipeline_id)
6. Pipeline halts at next safe checkpoint (between option scores)
7. Partial recommendation built from completed scores (12 of 18 options scored)
8. Partial result returned with pipeline_metadata.partial_result = true
9. Unscored options are omitted from ranking
10. Sou uses partial recommendation to make the final decision
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
| R1 â€” Modulsingularity | Pipeline handles only orchestration; delegates to specialized engines |
| R2 â€” Dependency Order | Depends on Constraint Checker, Scorer, Trade-off Analyzer, History Logger |
| R3 â€” DRY | Stage handlers defined once in pipeline config |
| R4 â€” Builder Pattern | State built stage-by-stage, accumulated into final recommendation |
| R5 â€” Liskov Substitution | Any StageHandler implements the same signature |
| R6 â€” DI over Singletons | Config, error strategies, timeout values injected |
| R9 â€” Deterministic | Same input + same completion level produces same output |
| R10 â€” Simpler Over Complex | Sequential pipeline with clear stage boundaries |
| R13 â€” Design for Failure | Per-stage error strategies, partial results, graceful degradation |
| R14 â€” Paved Path | `evaluateOptions` is the single entry point for all evaluations |
| R15 â€” Open/Closed | New stages added by extending PipelineStage enum and providing handler |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Decision/000-Overview.md | Pipeline orchestrates the components defined in the overview |
| Decision/001-Scoring-Engine.md | Pipeline invokes Score stage via Scoring Engine |
| Decision/002-Trade-off-Analysis.md | Pipeline invokes Trade-off Analyze stage via Trade-off Analyzer |
| Decision/003-Constraints.md | Pipeline invokes Constraint Check stage via Constraint Checker |
| Decision/004-Criteria-Registry.md | Pipeline uses criteria from Registry for Log stage metadata |
| Brain/Context/000-Overview.md | Context snapshot captured in DecisionContext |
| Brain/Sou/000-Overview.md | Sou is the consumer of recommendations and calls recordFinalChoice |
| Bible/05-Platform/004-EVS.md | Events emitted throughout the pipeline lifecycle |

(End of file)
