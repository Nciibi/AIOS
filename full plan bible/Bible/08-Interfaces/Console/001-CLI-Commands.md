# AIOS Bible — Interfaces
## Console — 001: CLI Commands

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-GC-001 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The CLI command system provides a structured, scriptable interface for governance operations. It enforces consistent command parsing, argument validation, and output formatting so that every governance action performed through the console is valid, traceable, and replayable. The CLI bridges human intent to constitutional governance actions with deterministic behavior.

## Architecture

```
input string
    │
    ▼
┌──────────────┐
│  parse_command│  tokenize and identify command name
└──────┬───────┘
       ▼
┌──────────────┐
│ validate_args │  check required args, types, bounds
└──────┬───────┘
       ▼
┌──────────────┐
│ command route │  dispatch to registered handler
└──────┬───────┘
       ▼
┌──────────────┐
│   execute    │  run governance action, record evidence
└──────┬───────┘
       ▼
┌──────────────┐
│ format_output│  render structured result to terminal
└──────────────┘
```

## Data Model (TypeScript)

```typescript
interface CLICommand {
  commandId: string;
  name: string;
  description: string;
  args: ArgumentSpec[];
  handler: string;
  aliases: string[];
  minClearance: number;
}

interface ArgumentSpec {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'enum' | 'timestamp';
  required: boolean;
  default?: unknown;
  validValues?: string[];
  description: string;
}

interface OutputFormat {
  format: 'table' | 'json' | 'yaml' | 'plain';
  fields: string[];
  sortBy?: string;
  maxRows?: number;
}

interface CommandAlias {
  alias: string;
  targetCommand: string;
  expandedArgs: string[];
}

interface CommandSession {
  sessionId: string;
  humanId: string;
  commandHistory: CommandRecord[];
  startedAt: Timestamp;
  lastActivity: Timestamp;
  evidenceRef: string;
}

interface CommandRecord {
  timestamp: Timestamp;
  command: string;
  args: Record<string, unknown>;
  result: CommandResult;
  durationMs: number;
}

type CommandResult = {
  success: boolean;
  data?: unknown;
  error?: string;
  evidenceRef: string;
};
```

## Core Concepts / Operations

### parse_command

Accepts raw input string, tokenizes using shell-style quoting rules, identifies the command name from registered definitions, and maps aliases to canonical names. Returns a parsed command structure ready for validation.

### validate_args

For each ArgumentSpec in the matched command definition, checks presence (if required), type conformance, and value bounds. Rejects with specific error codes on failure. Returns the validated argument map.

### execute_command

Dispatches the validated command to its registered handler. The handler performs the governance action (RFC decision, override request, audit query, etc.), records evidence to EVS, and returns a CommandResult. Execution is bounded by a configurable timeout.

### format_output

Transforms the CommandResult into the requested output format: table, JSON, YAML, or plain text. Applies field selection, sorting, and row limits. Formats error results consistently.

### manage_history

Records every command execution into the CommandSession history. Supports retrieval of recent commands, search by substring, and replay of previous commands. History is bounded to a configurable maximum size.

## Internal Interfaces

```typescript
interface CommandRegistry {
  register(def: CLICommand): void;
  resolve(name: string): CLICommand | undefined;
  list(): CLICommand[];
}

interface ArgumentValidator {
  validate(spec: ArgumentSpec, value: unknown): ValidationResult;
  validateAll(specs: ArgumentSpec[], args: Record<string, unknown>): ValidationResult[];
}

interface CommandExecutor {
  execute(session: CommandSession, command: CLICommand, args: Record<string, unknown>): Promise<CommandResult>;
}

interface OutputFormatter {
  format(result: CommandResult, format: OutputFormat): string;
}

interface HistoryManager {
  record(session: CommandSession, record: CommandRecord): void;
  recent(session: CommandSession, count: number): CommandRecord[];
  search(session: CommandSession, query: string): CommandRecord[];
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `GC.CLICommandParsed` | sessionId, raw, commandName | Raw input parsed into command structure |
| `GC.CLIArgsValidated` | sessionId, commandName, args, valid | Argument validation completed |
| `GC.CLICommandExecuted` | sessionId, commandName, durationMs, success | Command dispatched and executed |
| `GC.CLIOutputFormatted` | sessionId, format, outputSize | Result formatted for display |
| `GC.CLISessionStarted` | sessionId, humanId | New CLI command session initialized |
| `GC.CLISessionEnded` | sessionId, humanId, commandCount | CLI session closed |
| `GC.CLIHistoryRetrieved` | sessionId, query, resultCount | History query executed |
| `GC.CLIAliasResolved` | sessionId, alias, targetCommand | Alias mapped to canonical command |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| `GC_CLI_UNKNOWN_COMMAND` | Command name does not match any registered definition | Error | List available commands via `help` |
| `GC_CLI_INVALID_ARGUMENT` | Argument fails type or bound validation | Error | Show usage for the command |
| `GC_CLI_EXECUTION_TIMEOUT` | Command handler exceeds configured timeout | Critical | Abort execution; return partial results if available |
| `GC_CLI_OUTPUT_FORMAT_ERROR` | Output formatter cannot render result | Warning | Fall back to plain text format |
| `GC_CLI_SESSION_EXPIRED` | CommandSession has exceeded idle timeout | Error | Require human re-authentication |
| `GC_CLI_HISTORY_OVERFLOW` | History exceeds configured maximum entries | Warning | Prune oldest entries; continue |
| `GC_CLI_REQUIRED_ARG_MISSING` | Required argument not provided | Error | List required arguments for command |
| `GC_CLI_CLEARANCE_DENIED` | Human lacks minimum clearance for command | Error | Log attempt; return permission denied |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GC-001-01 | Every CLI command execution produces an evidence record | Architectural — executor records to EVS before returning |
| GC-001-02 | Arguments are validated before execution, never during | Algorithmic — validate_args runs before execute_command |
| GC-001-03 | Command execution is idempotent — same input produces same evidence outcome | Algorithmic — command handlers are deterministic |
| GC-001-04 | CLI sessions expire after configurable idle timeout | Algorithmic — session manager enforces timeout |
| GC-001-05 | Alias resolution never creates cycles | Architectural — alias target must resolve to a registered command |
| GC-001-06 | History is bounded to a maximum configurable size | Algorithmic — oldest entries pruned on overflow |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | CLI owns parsing, validation, formatting; governance actions delegated to handlers |
| R2 — Dependency Order | Depends on CommandRegistry, ArgumentValidator, EVS; no circular deps |
| R3 — DRY | Argument specs defined once in CLICommand; reused by validation and help generation |
| R4 — Builder Pattern | CommandResult built incrementally during execution |
| R5 — Deterministic | Same input string always yields same parsed command and validation outcome |
| R6 — Single Source | Commands defined in registry; no scattered references |
| R9 — Deterministic | Replaying command history produces same evidence trail |
| R10 — Simpler Over Complex | Default output format is table; JSON and YAML are opt-in |
| R13 — Design for Failure | Session expiry traps preserve partial state; timeout aborts gracefully |
| R14 — Paved Path | Standard governance commands (override, rfc, certify) have first-class support |
| R15 — Open/Closed | New commands register via CommandRegistry without modifying the CLI engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console overview — CLI is the primary interaction mode |
| Bible/08-Interfaces/Console/002-REPL.md | REPL builds on CLI command definitions |
| Bible/08-Interfaces/Console/003-Scripting.md | Scripting engine executes sequences of CLI commands |
| Bible/08-Interfaces/Console/004-AutoComplete.md | Auto-complete uses command definitions and argument specs |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard surfaces governance alerts for CLI action |
| Bible/08-Interfaces/UI/000-Overview.md | General human interface — console is governance-specific |
| Bible/01-Governance/001-CLS.md | Constitutional Lifecycle Service — constitution versioning commands |
| Bible/01-Governance/003-CRP.md | Change Request Pipeline — RFC decision commands |
| Bible/05-Platform/005-AUS.md | Audit System — audit query commands |
| Bible/05-Platform/004-EVS.md | Evidence System — evidence recording for every command |
| Bible/06-Services/ACF/000-Overview.md | ACF transports all CLI command invocations |
