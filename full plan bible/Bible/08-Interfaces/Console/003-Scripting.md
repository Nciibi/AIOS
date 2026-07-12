# AIOS Bible — Interfaces
## Console — 003: Scripting

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-GC-003 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Scripting engine enables automation of governance workflows through defined scripts. Scripts compose CLI commands into sequences with variable substitution, conditional execution, error handling, and scheduling. Every script execution produces step-level evidence, ensuring that automated governance actions are as traceable as manual ones.

## Architecture

```
script definition (YAML/JSON)
    │
    ▼
┌──────────────────┐
│  parse_script     │  validate syntax, resolve step references
└──────┬───────────┘
       ▼
┌──────────────────┐
│  resolve_variables│  substitute script variables and context values
└──────┬───────────┘
       ▼
┌──────────────────┐
│  execute_steps    │  run each step, evaluate conditions, handle errors
└──────┬───────────┘
       │
       ├──► step complete ──► record evidence ──► next step
       │
       ├──► condition met ──► branch to conditional path
       │
       └──► error ──► error handler ──► recover or abort
              │
              ▼
┌──────────────────┐
│  complete_script  │  finalize, record evidence, notify
└──────────────────┘
```

## Data Model (TypeScript)

```typescript
interface GovernanceScript {
  scriptId: string;
  name: string;
  description: string;
  version: string;
  steps: ScriptStep[];
  variables: ScriptVariable[];
  errorHandlers: ErrorHandler[];
  schedule?: ScriptSchedule;
  maxExecutionSeconds: number;
  evidenceRef: string;
}

interface ScriptStep {
  stepId: string;
  command: string;
  args: Record<string, string>;
  condition?: string;
  retryCount: number;
  timeoutSeconds: number;
  onSuccess?: string;
  onFailure?: string;
}

interface ScriptVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'secret';
  defaultValue?: unknown;
  required: boolean;
  description: string;
}

interface ConditionalBranch {
  expression: string;
  trueStep: string;
  falseStep?: string;
  description: string;
}

interface ErrorHandler {
  matchPattern: string;
  action: 'retry' | 'skip' | 'abort' | 'fallback';
  fallbackCommand?: string;
  maxRetries: number;
  description: string;
}

interface ScriptSchedule {
  cronExpression: string;
  timezone: string;
  enabled: boolean;
  maxConcurrentExecutions: number;
}

interface ScriptExecution {
  executionId: string;
  scriptId: string;
  startedAt: Timestamp;
  completedAt?: Timestamp;
  status: 'running' | 'completed' | 'failed' | 'aborted';
  stepResults: StepResult[];
  evidenceRef: string;
}

interface StepResult {
  stepId: string;
  command: string;
  status: 'success' | 'failed' | 'skipped' | 'retried';
  output: string;
  durationMs: number;
  evidenceRef: string;
}
```

## Core Concepts / Operations

### define_script

Accepts a script definition (YAML or JSON) and registers it in the script registry. Validates structure, resolves step references, and assigns a unique scriptId. Scripts are immutable after definition — changes require a new version.

### parse_script

Parses the script definition into the GovernanceScript structure. Validates syntax, checks variable references, ensures step dependencies are acyclic, and verifies error handler patterns. Returns the parsed script or detailed parse errors.

### execute_script

Runs the script steps sequentially, applying variable substitution at execution time. For each step: evaluates the condition (if any), executes the command via the CLI engine, checks result against error handlers, and records step-level evidence. Supports retry, skip, abort, and fallback actions.

### handle_error

Matches execution errors against registered ErrorHandler patterns. Applies the configured action: retry (up to maxRetries), skip (continue with next step), abort (terminate with failure), or fallback (execute alternate command). Every error action is recorded as evidence.

### schedule_script

Binds a script to a cron-based schedule. Enforces maxConcurrentExecutions to prevent overlapping runs. Each scheduled execution produces its own ScriptExecution record with independent evidence. Schedule changes are versioned.

## Internal Interfaces

```typescript
interface ScriptRegistry {
  register(script: GovernanceScript): void;
  get(scriptId: string): GovernanceScript | undefined;
  list(): GovernanceScript[];
  listScheduled(): GovernanceScript[];
}

interface ScriptParser {
  parse(source: string, format: 'yaml' | 'json'): ParseResult<GovernanceScript>;
  validateVariables(variables: ScriptVariable[], args: Record<string, unknown>): ValidationResult[];
}

interface ScriptExecutor {
  execute(script: GovernanceScript, variables: Record<string, unknown>, session: REPLSession): Promise<ScriptExecution>;
  executeStep(step: ScriptStep, context: EvalContext): Promise<StepResult>;
}

interface ErrorRouter {
  match(error: string, handlers: ErrorHandler[]): ErrorHandler | undefined;
  apply(handler: ErrorHandler, step: ScriptStep, context: EvalContext): Promise<StepResult>;
}

interface Scheduler {
  schedule(script: GovernanceScript, schedule: ScriptSchedule): Promise<void>;
  unschedule(scriptId: string): Promise<void>;
  getNextRun(scriptId: string): Timestamp | undefined;
}
```

## Events

| Event Type | Produced When | Fields |
|-------|--------|-------------|
| `GC.ScriptDefined` | scriptId, name, version | New script registered in the script registry |
| `GC.ScriptStarted` | scriptId, executionId, variableCount | Script execution initiated |
| `GC.ScriptStepCompleted` | scriptId, executionId, stepId, status, durationMs | Individual script step finished |
| `GC.ScriptStepRetried` | scriptId, executionId, stepId, attempt, error | Step retry triggered by error handler |
| `GC.ScriptFailed` | scriptId, executionId, stepId, error | Script execution terminated with failure |
| `GC.ScriptCompleted` | scriptId, executionId, stepCount, totalDuration | Script execution finished successfully |
| `GC.ScriptScheduled` | scriptId, cronExpression, nextRun | Script bound to a cron schedule |
| `GC.ScriptScheduleFired` | scriptId, executionId | Scheduled execution started |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| `GC_SCRIPT_SYNTAX_ERROR` | Script definition has invalid syntax or structure | Error | Report parse errors with line numbers |
| `GC_SCRIPT_VARIABLE_UNDEFINED` | Variable referenced in step but not provided or defaulted | Error | List required variables; abort execution |
| `GC_SCRIPT_STEP_TIMEOUT` | Individual step exceeds its timeoutSeconds | Warning | Apply error handler; retry or abort per handler config |
| `GC_SCRIPT_RECURSION_LIMIT` | Script calls itself or creates cycle exceeding max depth | Critical | Abort execution; log recursion chain |
| `GC_SCRIPT_DEPENDENCY_FAILURE` | Step depends on a previous step that failed without handler | Error | Abort with dependency chain in error message |
| `GC_SCRIPT_SCHEDULE_CONFLICT` | Scheduled execution overlaps with still-running instance | Warning | Skip this scheduled run; log conflict |
| `GC_SCRIPT_MAX_EXECUTION_EXCEEDED` | Total execution time exceeds maxExecutionSeconds | Critical | Abort all steps; record partial results as evidence |
| `GC_SCRIPT_STEP_EVIDENCE_FAILURE` | Step-level evidence recording fails | Critical | Abort script; underlying EVS may be degraded |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GC-003-01 | Every script execution produces step-level evidence records | Architectural — each step records to EVS before proceeding |
| GC-003-02 | Script execution is deterministic — same inputs produce same step sequence | Algorithmic — variable resolution is deterministic |
| GC-003-03 | Total execution time is bounded by maxExecutionSeconds | Algorithmic — executor enforces hard timeout |
| GC-003-04 | Scripts are immutable after definition — changes create new versions | Architectural — registry enforces append-only versioning |
| GC-003-05 | Scheduled scripts enforce maxConcurrentExecutions | Algorithmic — scheduler checks before firing |
| GC-003-06 | Step dependencies form a directed acyclic graph | Algorithmic — parser validates acyclic structure |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Scripting owns automation orchestration; CLI engine owns individual command execution |
| R2 — Dependency Order | Depends on CLI CommandRegistry, EVS, Scheduler; no circular deps |
| R3 — DRY | Steps reference CLI commands by name; script does not re-implement command logic |
| R4 — Builder Pattern | ScriptExecution built incrementally with each StepResult |
| R5 — Deterministic | Same script with same variables produces identical execution sequence |
| R6 — Single Source | Script definition is the single source of workflow specification |
| R9 — Deterministic | Replaying script execution from evidence produces identical step sequence |
| R10 — Simpler Over Complex | Default execution is linear; conditions and branching are opt-in |
| R13 — Design for Failure | Error handlers provide structured recovery paths for every failure mode |
| R14 — Paved Path | Standard scripts for override management, certification review, and audit export |
| R15 — Open/Closed | New error handler actions and step types register via extensions |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console overview — scripting automates governance workflows |
| Bible/08-Interfaces/Console/001-CLI-Commands.md | CLI commands define the atomic operations that scripts compose |
| Bible/08-Interfaces/Console/002-REPL.md | REPL can execute scripts interactively or inspect script state |
| Bible/08-Interfaces/Console/004-AutoComplete.md | Auto-complete assists script definition authoring |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard displays script execution status and schedules |
| Bible/08-Interfaces/UI/000-Overview.md | General human interface — console is governance-specific |
| Bible/01-Governance/000-Overview.md | Governance services that scripts automate |
| Bible/05-Platform/005-AUS.md | Audit System — script execution trails for audit |
| Bible/05-Platform/004-EVS.md | Evidence System — step-level evidence recording |
| Bible/06-Services/ACF/000-Overview.md | ACF transports all script command invocations |
