# AIOS Bible â€” Brain/LLMOS
## 012 â€” Response Validator

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-012 |
| Source Laws | Law 8 â€” Law of Verification-First |
| Source Physics | Physics/008-Security.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 15 â€” Response Validation |

## Purpose

The Response Validator verifies that the AI model's output conforms to the expected format, schema, and quality requirements. It runs after output guardrails (Stage 14) and before cache storage (Stage 16). Responses that fail validation are rejected, triggering retry with corrected instructions or failing the pipeline with clear error details.

## Validation Types

| Type | Description | Failure Action |
|------|-------------|---------------|
| `schema` | Validate against JSON Schema | Reject, trigger retry with schema hint |
| `format` | Validate expected format (JSON, XML, markdown) | Reject, trigger retry with format instruction |
| `quality` | Validate minimum quality criteria | Reject, trigger retry with quality improvement hint |
| `consistency` | Validate internal consistency | Reject with detailed error report |
| `custom` | Entity-defined validation function | Per-function specification |

## Schema Validation

```typescript
interface SchemaValidation {
  type: "schema";
  schema: JSONSchema;                // Draft 2020-12 JSON Schema
  coerce: boolean;                   // Attempt type coercion (default: false)
  strict: boolean;                   // Reject additional properties (default: true)
}

function validateSchema(response: string, schema: SchemaValidation): ValidationResult {
  let parsed: any;
  try {
    parsed = JSON.parse(response);
  } catch {
    // Attempt to extract JSON from markdown code blocks
    parsed = extractJSON(response);
    if (!parsed) {
      return { valid: false, errors: [{ path: "$", message: "Response is not valid JSON", code: "PARSE_ERROR" }] };
    }
  }
  
  // Validate against schema
  return validateJSONSchema(parsed, schema.schema, { coerce: schema.coerce, strict: schema.strict });
}

function extractJSON(text: string): any | null {
  // Try ```json ... ```
  // Try ``` ... ```
  // Try raw JSON object
  // Return null if none match
}
```

## Format Validation

```typescript
interface FormatValidation {
  type: "format";
  expected_format: "json" | "xml" | "yaml" | "markdown" | "text";
  constraints: FormatConstraint[];
}

function validateFormat(response: string, format: FormatValidation): ValidationResult {
  switch (format.expected_format) {
    case "json": return validateJSONStructure(response);
    case "xml": return validateXMLStructure(response);
    case "yaml": return validateYAMLStructure(response);
    case "markdown": return validateMarkdownStructure(response);
    case "text": return { valid: true, errors: [] }; // Always valid
  }
}
```

## Quality Validation

```typescript
interface QualityValidation {
  type: "quality";
  min_length: u64;                   // Minimum character count
  max_length: u64;                   // Maximum character count
  required_sections: string[];       // Required content sections
  no_repetition: boolean;            // Reject repetitive content
  min_novelty: f64;                  // Minimum n-gram novelty (0.0-1.0)
}

function validateQuality(response: string, quality: QualityValidation): ValidationResult {
  const errors: ValidationError[] = [];
  
  if (response.length < quality.min_length) {
    errors.push({ path: "$", message: `Response too short: ${response.length} < ${quality.min_length}`, code: "TOO_SHORT" });
  }
  if (quality.max_length > 0 && response.length > quality.max_length) {
    errors.push({ path: "$", message: `Response too long: ${response.length} > ${quality.max_length}`, code: "TOO_LONG" });
  }
  if (quality.no_repetition) {
    // Check for repeated n-grams
    // If repetition detected: add error
  }
  
  return { valid: errors.length === 0, errors };
}
```

## Consistency Validation

```typescript
interface ConsistencyValidation {
  type: "consistency";
  checks: ConsistencyCheck[];
}

type ConsistencyCheck =
  | { type: "entity_references"; valid_entities: string[] }    // No hallucinated entity references
  | { type: "date_consistency"; }                               // No impossible dates
  | { type: "numerical_consistency"; constraints: NumericConstraint[] }
  | { type: "contradiction_check"; previous_responses: string[] }; // No contradiction with prior responses

function validateConsistency(response: string, consistency: ConsistencyValidation): ValidationResult {
  // Each check is domain-specific
  // Entity references: verify all entity references exist in valid_entities set
  // Date consistency: check for dates in the past/future within reason
  // Numerical consistency: check numerical statements against constraints
  // Contradiction: compare with previous responses for contradictions
}
```

## Retry on Validation Failure

When validation fails and retry is configured:

```typescript
interface ValidationRetryConfig {
  max_retries: u64;                  // Default: 1
  retry_strategy: ValidationRetryStrategy;
}

type ValidationRetryStrategy = 
  | { type: "add_instruction"; instruction: string }  // Append instruction to prompt
  | { type: "add_example"; example: string }            // Add example to prompt
  | { type: "increase_temperature"; delta: f64 }        // Increase temperature for diversity
  | { type: "change_model"; max_downgrade: QualityTier }; // Try different model
```

### Retry Flow

1. Validation fails â†’ produce `LLMOS.ResponseValidationFailed` Event
2. If `max_retries > 0` and retries not exhausted:
   a. Apply retry strategy (add instruction, example, or adjust temperature)
   b. Recompile prompt with the adjustment
   c. Re-run pipeline from Retry Engine (Stage 12) â€” skips Stages 0-11
3. If `max_retries` exhausted or retry not configured:
   a. Return validation error to caller with detailed error report
   b. Response is NOT cached (cache storage Stage 16 is skipped)

## Validation Result

```typescript
interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  retry_suggested: boolean;
  retry_strategy: ValidationRetryStrategy | null;
}

interface ValidationError {
  path: string;                      // JSON path to the error location
  message: string;                   // Human-readable error description
  code: string;                      // Machine-readable error code
  severity: "error" | "warning";
}

interface ValidationWarning {
  code: string;
  message: string;
}
```

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-VLD-001 | Every response with a defined schema is validated before delivery to caller. | Architectural â€” pre-delivery validation stage |
| LLM-VLD-002 | Responses that fail validation are never cached. | Architectural â€” cache bypass on failure |
| LLM-VLD-003 | Validation retries re-enter the pipeline at Stage 12, not Stage 0. | Architectural â€” retry re-entry point |
| LLM-VLD-004 | Schema validation is strict by default â€” additional properties cause failure. | Algorithmic â€” strict mode validation |
| LLM-VLD-005 | Quality validation requires minimum length > 0 to be enforced. | Algorithmic â€” minimum threshold check |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-009 | LLMOS is the ONLY path for AI inference inside the Brain. No direct provider calls. | Architectural - all inference requests route through LLMOS pipeline. Direct provider calls are blocked. |
## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| LLM.ResponseValidated |    request_id, validation_types, valid, errors, retry_count, retry_attempted | After validation (Stage 15) |
| LLM.ResponseValidationFailed |    request_id, validation_types, errors, retry_strategy, model_used | Validation failure |
| LLM.ResponseValidationRetry |    request_id, retry_number, strategy, adjusted_parameters | Before retry |


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
| R1 â€” Modulsingularity | Response Validator is the sole response quality gate |
| R2 â€” Dependency Order | Validator depends on Prompt Compiler schemas |
| R3 â€” DRY | Validation types defined once, not per provider |
| R4 â€” Builder Pattern | ValidationResult built through validation pipeline |
| R5 â€” Liskov Substitution | All responses validated uniformly |
| R6 â€” DI over Singletons | Validator injected into pipeline |
| R9 â€” Deterministic | Same response gets same validation result |
| R10 â€” Simpler Over Complex | JSON Schema validation over custom parsers |
| R13 â€” Design for Failure | Validation failure triggers retry |
| R14 â€” Paved Path | Standard validation types for all responses |
| R15 â€” Open/Closed | New validation types added without pipeline changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/003-Prompt-Compiler.md | Response schema is injected into prompt by Compiler |
| LLMOS/011-Cache.md | Only validated responses are written to cache |
| LLMOS/009-Retry-Engine.md | Validation retries re-enter at Retry Engine stage |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Output failed schema validation | LLM-0601 | Return validation error with details; retry if configured |
| Structured output parse failure | LLM-0602 | Return parse error; request retry with relaxed schema |
| All validation retries exhausted | â€” | Return final validation error with all failure details |
| Entity-defined validation crashes | â€” | Skip custom validation; log error |
