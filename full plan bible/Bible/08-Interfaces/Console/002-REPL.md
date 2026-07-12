# AIOS Bible — Interfaces
## Console — 002: REPL

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-GC-002 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The REPL (Read-Eval-Print-Loop) provides an interactive, stateful environment for governance operations. Unlike single-shot CLI commands, the REPL maintains context across evaluations: current session, selected constitution version, active filters, and command history. It supports multi-line input, history navigation, and auto-suggestions for an ergonomic governance workflow.

## Architecture

```
Human input
    │
    ▼
┌──────────────┐
│  read_input   │  capture input, handle multi-line, history recall
└──────┬───────┘
       ▼
┌──────────────┐
│  eval_command │  resolve against REPL context, dispatch execution
└──────┬───────┘
       ▼
┌──────────────┐
│  print_result │  format output for interactive display
└──────┬───────┘
       ▼
┌──────────────┐
│  update_context│  merge results into REPL session state
└──────┬───────┘
       │
       └──► loop back to read_input
```

## Data Model (TypeScript)

```typescript
interface REPLSession {
  sessionId: string;
  humanId: string;
  context: EvalContext;
  history: HistoryEntry[];
  suggestions: Suggestion[];
  startedAt: Timestamp;
  lastActivity: Timestamp;
  evidenceRef: string;
}

interface EvalContext {
  currentConstitutionVersion: string;
  activeFilters: AuditFilter;
  selectedOverrides: string[];
  lastResult: unknown;
  variables: Record<string, unknown>;
}

interface HistoryEntry {
  sequence: number;
  input: string;
  result: string;
  durationMs: number;
  timestamp: Timestamp;
  evidenceRef: string;
}

interface Suggestion {
  prefix: string;
  command: string;
  description: string;
  score: number;
}

interface PrintFormat {
  style: 'full' | 'compact' | 'minimal';
  colorEnabled: boolean;
  maxFieldWidth: number;
  truncationMarker: string;
}
```

## Core Concepts / Operations

### read_input

Captures human input from the terminal, handling multi-line input (continuation prompts), history recall (arrow keys), and inline editing. Supports backslash continuation for long commands. Returns a normalized input string.

### eval_command

Resolves the input against the REPL session's EvalContext. Supports context variables (`$var`), previous result references (`$_`, `$1`), and sub-expression evaluation. Dispatches to the CLI command engine for execution. Context is enriched with results after evaluation.

### print_result

Formats the evaluation result for interactive display. Supports full (verbose), compact (single-line), and minimal (status-only) styles. Applies color coding for success, warning, and error states. Truncates long fields with a configurable marker.

### suggest_commands

Generates auto-suggestions based on current input prefix and REPL context. Suggests commands, arguments, context variables, and previous history entries. Suggestions are scored by relevance and displayed in ranked order.

### navigate_history

Supports traversal of the REPL session's command history via arrow keys, search (Ctrl+R), and index reference. History is stored chronologically with timestamps and evidence references for audit.

## Internal Interfaces

```typescript
interface InputReader {
  read(prompt: string, multiLine: boolean): Promise<string>;
  enableHistory(history: HistoryEntry[]): void;
  setCompletion(suggestions: Suggestion[]): void;
}

interface EvalEngine {
  eval(input: string, context: EvalContext, session: REPLSession): Promise<EvalResult>;
  resolveVariable(name: string, context: EvalContext): unknown;
}

interface ResultPrinter {
  print(result: EvalResult, format: PrintFormat): string;
  formatError(err: EvalError): string;
}

interface SuggestionEngine {
  getSuggestions(prefix: string, context: EvalContext, history: HistoryEntry[]): Suggestion[];
  score(candidate: Suggestion, input: string): number;
}

interface HistoryNavigator {
  up(session: REPLSession): HistoryEntry | undefined;
  down(session: REPLSession): HistoryEntry | undefined;
  search(session: REPLSession, query: string): HistoryEntry[];
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `GC.REPLStarted` | sessionId, humanId, contextSnapshot | Interactive REPL session initialized |
| `GC.REPLCommandEvaluated` | sessionId, input, durationMs, success | Command evaluated against REPL context |
| `GC.REPLResultPrinted` | sessionId, style, outputSize | Evaluation result rendered to terminal |
| `GC.REPLContextUpdated` | sessionId, updatedKeys | EvalContext modified after evaluation |
| `GC.REPLSuggestionTriggered` | sessionId, prefix, suggestionCount | Auto-suggestions generated for input |
| `GC.REPLHistoryNavigated` | sessionId, direction, entrySequence | Human navigated command history |
| `GC.REPLSessionEnded` | sessionId, humanId, evalCount, duration | Interactive REPL session closed |
| `GC.REPLMultiLineStarted` | sessionId, lineCount | Multi-line input mode entered |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| `GC_REPL_EVAL_FAILURE` | Command evaluation throws unhandled exception | Error | Show error message; preserve context for retry |
| `GC_REPL_CONTEXT_CORRUPTION` | EvalContext contains invalid state | Critical | Reset context to defaults; log corruption details |
| `GC_REPL_INFINITE_LOOP` | Recursive eval exceeds maximum depth | Critical | Terminate evaluation; restore prior context |
| `GC_REPL_OUTPUT_TRUNCATED` | Result exceeds terminal buffer size | Warning | Show truncated result with continuation marker |
| `GC_REPL_HISTORY_OVERFLOW` | History exceeds configured maximum | Warning | Prune oldest entries; notify human |
| `GC_REPL_UNKNOWN_VARIABLE` | Context variable reference cannot be resolved | Error | List available variables; continue |
| `GC_REPL_SESSION_EXPIRED` | REPLSession idle timeout exceeded | Error | Save context snapshot; require re-authentication |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GC-002-01 | Every REPL evaluation produces an evidence record | Architectural — eval_command records to EVS before returning result |
| GC-002-02 | EvalContext is validated before every evaluation, never during | Algorithmic — context integrity check runs before eval |
| GC-002-03 | History entries are immutable after recording | Algorithmic — history is append-only within a session |
| GC-002-04 | REPL session state is preserved across context corruption via snapshot | Architectural — snapshots taken before each eval |
| GC-002-05 | Input is validated before dispatch to CLI engine | Algorithmic — read_input normalizes before eval_command |
| GC-002-06 | Multi-line input has a configurable maximum line count | Algorithmic — input reader enforces line limit |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | REPL owns interactive read-eval-print loop; CLI engine owns execution |
| R2 — Dependency Order | Depends on CLI CommandRegistry, EvalEngine, EVS; no circular deps |
| R3 — DRY | Command definitions sourced from CLI command registry; REPL does not duplicate |
| R4 — Builder Pattern | EvalResult built incrementally during evaluation |
| R5 — Deterministic | Same input with same context produces identical eval outcome |
| R6 — Single Source | EvalContext is the single source of session state |
| R9 — Deterministic | Replaying history with same context produces identical results |
| R10 — Simpler Over Complex | Default print style is compact; full and minimal are opt-in |
| R13 — Design for Failure | Context corruption triggers snapshot restore; eval failure preserves prior state |
| R14 — Paved Path | Standard workflow: type command, see result, navigate history |
| R15 — Open/Closed | New eval features register via EvalEngine extension without modifying REPL loop |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console overview — REPL is the interactive mode |
| Bible/08-Interfaces/Console/001-CLI-Commands.md | CLI commands provide the execution layer for REPL evaluations |
| Bible/08-Interfaces/Console/003-Scripting.md | Scripting engine can drive REPL sessions programmatically |
| Bible/08-Interfaces/Console/004-AutoComplete.md | Auto-complete powers REPL suggestion engine |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard surfaces context that REPL sessions consume |
| Bible/08-Interfaces/UI/000-Overview.md | General human interface — console is governance-specific |
| Bible/01-Governance/000-Overview.md | Governance services evaluated through REPL commands |
| Bible/05-Platform/005-AUS.md | Audit System — audit queries executed from REPL |
| Bible/05-Platform/004-EVS.md | Evidence System — every eval recorded as evidence |
| Bible/06-Services/ACF/000-Overview.md | ACF transports all REPL command invocations |
