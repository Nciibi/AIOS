# AIOS Bible â€” Interfaces
## Console â€” 004: Auto-Complete

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-GC-004 |
| Source Laws | Law 1 â€” Law of Origin, Law 4 â€” Law of Evidence, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Auto-Complete engine accelerates governance console interaction by providing syntax-aware, context-sensitive suggestions as the human types. It reduces errors from incorrect command names, invalid arguments, and mistyped parameters. By integrating with the CLI command registry, REPL context, and help system, Auto-Complete ensures that humans can discover and use governance capabilities efficiently.

## Architecture

```
input prefix (partial input string)
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  context analysis â”‚  parse current state, position, partial tokens
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ candidate gen     â”‚  collect candidates from commands, args, values, history
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  scoring & rankingâ”‚  score by relevance, recency, frequency, match quality
â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  presentation     â”‚  display ranked suggestions with descriptions
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Data Model (TypeScript)

```typescript
interface CompletionCandidate {
  text: string;
  type: 'command' | 'argument' | 'value' | 'variable' | 'history' | 'help';
  description: string;
  source: string;
  score: number;
}

interface CompletionContext {
  input: string;
  cursorPosition: number;
  tokens: string[];
  currentTokenIndex: number;
  partialToken: string;
  precedingToken: string | undefined;
  session: REPLSession | undefined;
}

interface SuggestionScore {
  relevance: number;
  recency: number;
  frequency: number;
  fuzzyScore: number;
  total: number;
}

interface FuzzyMatchResult {
  text: string;
  score: number;
  matchedRanges: [number, number][];
}

interface HelpEntry {
  topic: string;
  summary: string;
  usage: string;
  examples: string[];
  relatedTopics: string[];
}
```

## Core Concepts / Operations

### get_candidates

Accepts the current CompletionContext and produces a list of CompletionCandidates. Collects candidates from the command registry (command names, argument names, accepted values), REPL session (context variables, history entries), and help system. Candidates include their source for traceability.

### score_suggestions

Assigns a SuggestionScore to each candidate based on: relevance (how well it matches the current token position), recency (how recently the candidate was used in this session), frequency (historical usage count), and fuzzy match quality. The total score determines ranking order.

### fuzzy_match

Performs fuzzy matching of the partial input against candidate texts. Returns match quality score and the character ranges where the input matches. Supports prefix matching, substring matching, and typo-tolerant matching using edit distance.

### show_help

Displays the HelpEntry for a selected candidate. Shows summary, usage syntax, examples, and related topics. Integrates with the command registry to display argument specs and default values. Help is context-sensitive â€” it shows the most relevant help based on current input.

### complete_parameter

Completes argument parameter values based on the ArgumentSpec's validValues enum, type constraints, and dynamic value providers. For enum types, suggests valid enum values. For entity references (agentId, rfcId), queries the governance services for active entities.

## Internal Interfaces

```typescript
interface CandidateProvider {
  getCandidates(context: CompletionContext): CompletionCandidate[];
  getCommands(prefix: string): CompletionCandidate[];
  getArguments(context: CompletionContext): CompletionCandidate[];
  getValues(context: CompletionContext): CompletionCandidate[];
}

interface ScoringEngine {
  score(candidate: CompletionCandidate, context: CompletionContext): SuggestionScore;
  rank(candidates: CompletionCandidate[], context: CompletionContext): CompletionCandidate[];
}

interface FuzzyMatcher {
  match(input: string, candidate: string): FuzzyMatchResult;
  matchAll(input: string, candidates: string[]): FuzzyMatchResult[];
}

interface HelpProvider {
  getHelp(topic: string): HelpEntry | undefined;
  getRelated(topic: string): HelpEntry[];
  search(query: string): HelpEntry[];
}

interface ParameterCompleter {
  completeValue(spec: ArgumentSpec, partial: string): CompletionCandidate[];
  completeEntity(type: string, partial: string): Promise<CompletionCandidate[]>;
}
```

## Events

| CON.EventType | Produced When | Fields |
|-------|--------|-------------|
| `GC.AutocompleteTriggered` | sessionId, inputLength, cursorPosition | Auto-completion activated by human input |
| `GC.CandidateGenerated` | sessionId, candidateCount, maxScore | Candidates generated from all providers |
| `GC.CandidateScored` | sessionId, candidateCount, topScore | Candidates scored and ranked |
| `GC.SuggestionAccepted` | sessionId, acceptedText, candidateType | Human selected a suggestion from the list |
| `GC.HelpDisplayed` | sessionId, topic, source | Help entry displayed for a command or topic |
| `GC.ParameterCompleted` | sessionId, paramName, valueSource | Parameter value completed from enum or dynamic source |
| `GC.FuzzyMatchPerformed` | sessionId, input, candidateCount, maxMatchScore | Fuzzy matching executed for partial input |
| `GC.CompletionContextResolved` | sessionId, tokenCount, position | CompletionContext built from current input state |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| `GC_AUTOCOMPLETE_CONTEXT_FAILURE` | CompletionContext cannot be resolved from input | Warning | Show default candidate set (command names only) |
| `GC_AUTOCOMPLETE_CANDIDATE_OVERFLOW` | Candidate count exceeds maximum display threshold | Warning | Return top N candidates by score; log count |
| `GC_AUTOCOMPLETE_FUZZY_TIMEOUT` | Fuzzy matching exceeds response time budget | Warning | Fall back to prefix-only matching for this invocation |
| `GC_AUTOCOMPLETE_HELP_UNAVAILABLE` | Help source for requested topic is not accessible | Warning | Show generic usage pattern; log missing source |
| `GC_AUTOCOMPLETE_UNABLE_TO_SUGGEST` | All candidate providers return empty results | Info | Show no suggestions indicator; continue |
| `GC_AUTOCOMPLETE_DYNAMIC_VALUE_FAILURE` | Dynamic value provider (entity query) fails | Warning | Omit dynamic values; show static enum values only |
| `GC_AUTOCOMPLETE_SCORING_ERROR` | Scoring engine encounters unexpected state | Warning | Apply default ranking (alphabetical) as fallback |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GC-004-01 | Suggestions are always context-aware â€” same prefix in different contexts may yield different candidates | Algorithmic â€” CompletionContext includes token position and session state |
| GC-004-02 | Candidate ordering is deterministic for the same input and context | Algorithmic â€” scoring uses consistent weight configuration |
| GC-004-03 | Auto-complete response time is bounded by a configurable budget | Algorithmic â€” fuzzy matching and dynamic queries have timeouts |
| GC-004-04 | Help entries are sourced from command definitions, never hardcoded | Architectural â€” HelpProvider reads from CommandRegistry |
| GC-004-05 | Fuzzy matching is typo-tolerant up to a configurable edit distance | Algorithmic â€” matcher enforces maximum edit distance |
| GC-004-06 | Candidate overflow is handled gracefully without crashing the UI | Architectural â€” overflow trigger returns capped set |


## Cross-Cutting Concerns

### Security

Console operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Console emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Console instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Console declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Auto-Complete owns suggestion generation only; command definitions owned by CLI registry |
| R2 â€” Dependency Order | Depends on CLI CommandRegistry, REPL session, EVS; no circular deps |
| R3 â€” DRY | Command names and argument specs sourced from CLICommand definitions; no duplication |
| R4 â€” Builder Pattern | CompletionContext built incrementally from input state |
| R5 â€” Deterministic | Same input and context always produce identical candidate ranking |
| R6 â€” Single Source | Command registry is the authoritative source for command metadata |
| R9 â€” Deterministic | Replaying autocomplete session with same input produces same suggestions |
| R10 â€” Simpler Over Complex | Default suggestion set is command names; context-aware and fuzzy are opt-in layers |
| R13 â€” Design for Failure | Dynamic value provider failure degrades gracefully to static values only |
| R14 â€” Paved Path | Standard completion flow: type prefix, see suggestions, accept with Tab |
| R15 â€” Open/Closed | New candidate providers register without modifying the auto-complete engine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Console/000-Overview.md | Governance Console overview â€” auto-complete enhances all console modes |
| Bible/08-Interfaces/Console/001-CLI-Commands.md | CLI commands provide the metadata for auto-complete suggestions |
| Bible/08-Interfaces/Console/002-REPL.md | REPL integration provides context and history for scoring |
| Bible/08-Interfaces/Console/003-Scripting.md | Scripting engine can use auto-complete during script authoring |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard surfaces commands that auto-complete indexes |
| Bible/08-Interfaces/UI/000-Overview.md | General human interface â€” console is governance-specific |
| Bible/01-Governance/000-Overview.md | Governance services provide dynamic entity values for parameter completion |
| Bible/05-Platform/005-AUS.md | Audit System â€” auto-complete assists audit query construction |
| Bible/06-Services/ACF/000-Overview.md | ACF transports auto-complete dynamic value queries |
