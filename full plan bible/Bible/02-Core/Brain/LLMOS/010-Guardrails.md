# AIOS Bible — Brain/LLMOS
## 010 — Guardrails

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-010 |
| Source Laws | Law 2 — Law of Non-Execution (safety), Law 8 — Law of Verification-First |
| Pipeline Stage | 11 — Input Guardrail Check and 14 — Output Guardrail Check |

## Purpose

Guardrails enforce content policies on both input (prompts sent to AI models) and output (responses from AI models). Every prompt and every response is scanned against configured policy rules before proceeding. Guardrails run twice in the LLMOS pipeline: Stage 11 (input) before provider call, and Stage 14 (output) before response delivery.

## Architecture

```
Input (from Prompt Compiler)          Output (from Provider/Streaming Manager)
         │                                      │
         ▼                                      ▼
┌─────────────────┐                  ┌─────────────────┐
│  INPUT GUARDRAIL│                  │ OUTPUT GUARDRAIL│
│  Stage 11       │                  │ Stage 14        │
├─────────────────┤                  ├─────────────────┤
│ Rule Engine     │                  │ Rule Engine      │
│ Policy Matcher  │                  │ Policy Matcher   │
│ Severity Eval   │                  │ Severity Eval    │
└─────────────────┘                  └─────────────────┘
         │                                      │
         ▼                                      ▼
   Blocked or Allowed                   Blocked or Allowed
         │                                      │
         ▼                                      ▼
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

- LLM-GRD-001: Every pipeline execution evaluates guardrails twice: input (Stage 11) and output (Stage 14).
- LLM-GRD-002: A `deny` match on input immediately fails the pipeline with LLM-0401.
- LLM-GRD-003: A `deny` match on output blocks delivery and returns error to caller.
- LLM-GRD-004: Entity-specific rules never override global deny rules.
- LLM-GRD-005: All guardrail evaluations are logged regardless of match or pass.
- LLM-GRD-006: Guardrail rules are immutable once deployed — changes require new rule version.
- LLM-GRD-007: Classifier-based rules are evaluated asynchronously to avoid blocking the pipeline.

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.GuardrailChecked` | request_id, direction, rules_evaluated, passed, blocked, matched_rules, evaluation_duration_us | After guardrail evaluation (Stages 11 and 14) |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/003-Prompt-Compiler.md | Input guardrails validate compiled prompt before provider call |
| LLMOS/008-Streaming-Manager.md | Output guardrails validate each chunk before delivery |
| Bible/04-Execution/Security/000-Overview.md | Security Council pipeline governs guardrail rule deployment |
| Physics/008-Verification.md | Verification-first principle requires guardrail confirmation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Input blocked by guardrail | LLM-0401 | Return blocked with matched rule details |
| Output blocked by guardrail | LLM-0402 | Return blocked with matched rule details |
| Classifier model unavailable | — | Fall to audit severity for classifier rules |
| Rule timeout | — | Treat as audit; log timeout |
| Invalid custom rule | — | Skip rule; log for operator review |
