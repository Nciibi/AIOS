# AIOS Bible â€” Brain/LLMOS
## 010 â€” Guardrails

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-010 |
| Source Laws | Law 2 â€” Law of Non-Execution (safety), Law 8 â€” Law of Verification-First |
| Source Physics | Physics/008-Security.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 11 â€” Input Guardrail Check and 14 â€” Output Guardrail Check |

## Purpose

Guardrails enforce content policies on both input (prompts sent to AI models) and output (responses from AI models). Every prompt and every response is scanned against configured policy rules before proceeding. Guardrails run twice in the LLMOS pipeline: Stage 11 (input) before provider call, and Stage 14 (output) before response delivery.

## Architecture

```
Input (from Prompt Compiler)          Output (from Provider/Streaming Manager)
         â”‚                                      â”‚
         â–¼                                      â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  INPUT GUARDRAILâ”‚                  â”‚ OUTPUT GUARDRAILâ”‚
â”‚  Stage 11       â”‚                  â”‚ Stage 14        â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤                  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ Rule Engine     â”‚                  â”‚ Rule Engine      â”‚
â”‚ Policy Matcher  â”‚                  â”‚ Policy Matcher   â”‚
â”‚ Severity Eval   â”‚                  â”‚ Severity Eval    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚                                      â”‚
         â–¼                                      â–¼
   Blocked or Allowed                   Blocked or Allowed
         â”‚                                      â”‚
         â–¼                                      â–¼
   Pipeline fails (LLM-0401)           Response masked or replaced
   or continues                              or continues
```

## Rule Model

```typescript
interface GuardrailRule {
  rule_id: UUIDv7;
  name: string;
  description: string;
  category: GuardrailCategory;
  direction: "input" | "output" | "both";
  severity: "deny" | "mask" | "warn" | "audit";
  pattern: RulePattern;
  action: RuleAction;
  priority: u64;                    // Lower = evaluated first
  enabled: boolean;
  metadata: Map<string, string>;
}

type GuardrailCategory = 
  | "content_safety"       // Hate, violence, self-harm, sexual
  | "pii"                  // Personal identifiable information
  | "credentials"          // API keys, secrets, tokens
  | "jailbreak"            // Prompt injection, jailbreak attempts
  | "topical"              // Topic restrictions
  | "constitutional"       // AI constitutional bounds
  | "format"              // Response format compliance
  | "quality"             // Minimum quality standards
  | "custom";             // Entity-defined rules

type Severity = "deny" | "mask" | "warn" | "audit";

interface RulePattern {
  type: "regex" | "keyword" | "semantic" | "classifier" | "llm_judge";
  content: string;                  // Regex pattern, keyword list path, classifier model, LLM prompt
}

interface RuleAction {
  on_match: "block" | "replace" | "flag" | "log";
  replacement: string | null;       // For "replace" actions
  notify: boolean;                  // Send notification on match
  metadata: Map<string, string>;
}
```

## Severity Levels

| Severity | Input Behavior | Output Behavior |
|----------|---------------|-----------------|
| `deny` | Block prompt, fail with LLM-0401 | Block response, return error to caller |
| `mask` | Not applicable on input | Replace matching content with `[REDACTED]` |
| `warn` | Log warning, allow prompt | Log warning, allow delivery |
| `audit` | Log silently, allow | Log silently, allow |

## Built-in Rule Categories

### Content Safety

Evaluates against hate speech, violence, self-harm, and sexual content using a combination of:
- Keyword matching (deny list)
- Semantic classifier (ML model, ~100ms inference)
- Pattern matching for coded language

### PII Detection

Detects and masks (output) or blocks (input) personal information:
- Email addresses, phone numbers, SSN, credit card numbers
- IP addresses, physical addresses
- API keys and tokens (credential patterns)
- Custom PII patterns per entity

### Jailbreak Detection

Evaluates prompts for:
- Known prompt injection patterns
- Role-playing bypass attempts
- Delimiter manipulation
- Multi-language encoding evasion
- Token smuggling

Scored on a confidence scale; prompts above threshold are denied.

### Constitutional Bounds

Evaluates both input and output against configured constitutional principles:
- AI must not claim to be human
- AI must not provide harmful instructions
- AI must maintain safety boundaries
- Entity-specific constitutional rules

## Evaluation Pipeline

```typescript
async function evaluateGuardrails(
  content: string,
  direction: "input" | "output",
  context: GuardrailContext
): Promise<GuardrailResult>

interface GuardrailContext {
  request_id: UUIDv7;
  entity_id: UUIDv7;
  model_id: string;
  session_id: UUIDv7 | null;
  rules: GuardrailRule[];           // Pre-filtered rules for this entity
}

interface GuardrailResult {
  passed: boolean;
  blocked: boolean;
  matched_rules: MatchedRule[];
  masked_content: string | null;    // Only for output with mask actions
  evaluation_duration_us: u64;
}

interface MatchedRule {
  rule_id: UUIDv7;
  name: string;
  severity: Severity;
  action_taken: string;
  matched_content: string;          // Excerpt that matched (truncated to 200 chars)
  confidence: f64;                  // For classifier/LLM judge patterns
}
```

Evaluation is ordered by priority: rules with lower priority numbers are evaluated first. If a `deny`-severity rule matches, evaluation stops immediately and the request/response is blocked.

## Entity-Specific Rule Overrides

```typescript
interface EntityGuardrailConfig {
  entity_id: UUIDv7;
  enabled_categories: GuardrailCategory[];
  overrides: Array<{
    rule_id: UUIDv7;
    action: "disable" | "downgrade" | "upgrade";
    new_severity: Severity | null;
  }>;
  custom_rules: GuardrailRule[];     // Entity-defined rules
}
```

Entities can only downgrade their OWN rules (cannot weaken global rules). Custom rules must be approved through Security Council before activation.

## Rule Performance Requirements

| Pattern Type | Max Evaluation Time | Accuracy |
|-------------|-------------------|----------|
| regex | 10ms | Exact |
| keyword | 5ms | Exact |
| semantic | 100ms | >95% |
| classifier | 200ms | >90% |
| llm_judge | 1000ms | >97% |

If any rule exceeds its max evaluation time, it times out and falls to `audit` severity for that evaluation.

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-GRD-001 | Every pipeline execution evaluates guardrails twice: input (Stage 11) and output (Stage 14). | Architectural â€” dual-stage enforcement |
| LLM-GRD-002 | A `deny` match on input immediately fails the pipeline with LLM-0401. | Algorithmic â€” fail-fast on match |
| LLM-GRD-003 | A `deny` match on output blocks delivery and returns error to caller. | Algorithmic â€” output blocking |
| LLM-GRD-004 | Entity-specific rules never override global deny rules. | Governance â€” rule priority hierarchy |
| LLM-GRD-005 | All guardrail evaluations are logged regardless of match or pass. | Architectural â€” observability invariant |
| LLM-GRD-006 | Guardrail rules are immutable once deployed â€” changes require new rule version. | Governance â€” immutability policy |
| LLM-GRD-007 | Classifier-based rules are evaluated asynchronously to avoid blocking the pipeline. | Algorithmic â€” async evaluation |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.GuardrailChecked |   request_id, direction, rules_evaluated, passed, blocked, matched_rules, evaluation_duration_us | After guardrail evaluation (Stages 11 and 14) |


## Cross-Cutting Concerns

### Security

LLMOS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), LLMOS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), LLMOS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), LLMOS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Guardrails is the sole content policy enforcer |
| R2 â€” Dependency Order | Guardrails evaluates after Compiler, before Provider |
| R3 â€” DRY | Rule model centralized, not duplicated per direction |
| R4 â€” Builder Pattern | GuardrailRule built through configuration |
| R5 â€” Liskov Substitution | All rule categories handled uniformly |
| R6 â€” DI over Singletons | GuardrailEngine injected into pipeline |
| R9 â€” Deterministic | Same content gets same guardrail decision |
| R10 â€” Simpler Over Complex | Priority-ordered evaluation over complex ML pipeline |
| R13 â€” Design for Failure | Rule timeout falls to audit severity |
| R14 â€” Paved Path | Built-in rule categories cover standard policies |
| R15 â€” Open/Closed | New rule types added without pipeline changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/003-Prompt-Compiler.md | Input guardrails validate compiled prompt before provider call |
| LLMOS/008-Streaming-Manager.md | Output guardrails validate each chunk before delivery |
| Bible/04-Execution/Security/000-Overview.md | Security Council pipeline governs guardrail rule deployment |
| Physics/008-Security.md | Verification-first principle requires guardrail confirmation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Input blocked by guardrail | LLM-0401 | Return blocked with matched rule details |
| Output blocked by guardrail | LLM-0402 | Return blocked with matched rule details |
| Classifier model unavailable | â€” | Fall to audit severity for classifier rules |
| Rule timeout | â€” | Treat as audit; log timeout |
| Invalid custom rule | â€” | Skip rule; log for operator review |
