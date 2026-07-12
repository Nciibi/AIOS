# AIOS Bible â€” Brain
## 004 â€” Schema Validation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Tools |
| Document ID | AIOS-BBL-002-TOL-004 |
| Source Laws | Law 4 â€” Law of Evidence |
| Source Physics | Physics/004-Sessions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Schema Validation ensures that every tool invocation receives parameters matching its declared schema. It performs type checking, enum validation, range constraint enforcement, pattern matching, required field verification, and supports custom validators. The Schema Validator is the first stage of the invocation pipeline â€” no tool executes with invalid parameters.

Under Law 4 (Evidence), validation results serve as evidence that the invocation was correctly formed, enabling deterministic debugging and audit trails.

## Data Model

### ValidationRequest

```typescript
ValidationRequest {
  invocation_id: string
  tool_id: string
  parameters: Record<string, unknown>
  schema: ParameterSchema
  strict_mode: boolean          // If true, clamp/coerce is disallowed
  custom_validators?: string[]  // Names of additional validators to apply
}
```

### ValidationResult

```typescript
ValidationResult {
  invocation_id: string
  tool_id: string
  valid: boolean
  validated_parameters: Record<string, unknown>  // Possibly coerced/clamped
  errors: ValidationError[]
  warnings: ValidationWarning[]
  duration_ms: number
  validator_trace: string[]     // Which validators were applied
}
```

### ValidationError

```typescript
ValidationError {
  field: string
  code: ValidationErrorCode
  message: string
  expected: unknown
  received: unknown
  constraint?: string
}
```

### ValidationErrorCode

```typescript
ValidationErrorCode =
  | "REQUIRED_FIELD_MISSING"
  | "TYPE_MISMATCH"
  | "ENUM_VALUE_INVALID"
  | "RANGE_MIN_EXCEEDED"
  | "RANGE_MAX_EXCEEDED"
  | "PATTERN_MISMATCH"
  | "FORMAT_INVALID"
  | "CUSTOM_VALIDATION_FAILED"
  | "SCHEMA_MISMATCH"
```

### ValidationWarning

```typescript
ValidationWarning {
  field: string
  code: string
  message: string
  suggestion?: unknown          // Suggested corrected value
}
```

### ParameterSchema

```typescript
ParameterSchema {
  type: "object"
  properties: Record<string, ParameterProperty>
  required: string[]
  additional_properties: boolean  // Default false
}

ParameterProperty {
  type: "string" | "number" | "boolean" | "array" | "object"
  description: string
  enum?: string[]
  default?: unknown
  nullable?: boolean
  constraints?: {
    min?: number
    max?: number
    pattern?: string
    format?: "date" | "email" | "uri" | "uuid" | "ipv4" | "date-time"
    min_length?: number
    max_length?: number
    min_items?: number           // For arrays
    max_items?: number           // For arrays
  }
  items?: ParameterProperty     // For array types
  properties?: Record<string, ParameterProperty>  // For object types
}
```

## Core Concepts

### Validation Stages

```
Parameters Received
    â”‚
    â–¼
[1] Schema Structure Check â”€â”€â”€â”€ Schema itself is valid?
    â”‚
    â–¼
[2] Required Fields â”€â”€â”€â”€ All required fields present?
    â”‚
    â–¼
[3] Type Checking â”€â”€â”€â”€ Each field matches declared type?
    â”‚
    â–¼
[4] Enum Validation â”€â”€â”€â”€ Value in allowed set?
    â”‚
    â–¼
[5] Range Constraints â”€â”€â”€â”€ Within min/max bounds?
    â”‚
    â–¼
[6] Pattern Matching â”€â”€â”€â”€ String matches regex?
    â”‚
    â–¼
[7] Format Validation â”€â”€â”€â”€ UUID format, email, URI, etc.?
    â”‚
    â–¼
[8] Custom Validators â”€â”€â”€â”€ Registered custom validation rules?
    â”‚
    â–¼
ValidationResult
```

### Validation Behaviors

| Check | Strict Mode | Lenient Mode |
|-------|-------------|--------------|
| Required field missing | Error | Error |
| Type mismatch | Error | Error |
| Extra property not in schema | Error | Warning, strip property |
| Enum value not in list | Error | Error |
| Value below min | Error | Clamp to min, warning |
| Value above max | Error | Clamp to max, warning |
| Pattern mismatch | Error | Error |
| Format invalid | Error | Warning |
| Null on non-nullable field | Error | Error |
| Default available for missing field | Set default, no error | Set default, no error |

### Type Coercion Rules

When strict_mode is false, limited coercion is attempted:

| Declared Type | Received Type | Coercion Behavior |
|---------------|--------------|-------------------|
| string | number | Convert to string representation |
| number | string | Parse if valid numeric string; else error |
| boolean | string | Accept "true"/"false" as boolean; else error |
| number | boolean | Convert trueâ†’1, falseâ†’0 |
| array | single value | Wrap in array |

Coercion is never applied in strict mode.

### Custom Validators

Custom validators can be registered for tool-specific parameter logic:

```typescript
CustomValidator {
  name: string
  description: string
  validate: (
    parameters: Record<string, unknown>,
    schema: ParameterSchema
  ) => ValidationError[]
}
```

Examples:
- `file_path_exists` â€” Validates that a file path parameter refers to an existing file
- `valid_sql` â€” Validates that a query parameter contains valid SQL syntax
- `cross_field_consistency` â€” Ensures start_date < end_date

## Operations

### Validate

```typescript
validate(
  parameters: Record<string, unknown>,
  schema: ParameterSchema,
  options?: {
    invocation_id?: string
    tool_id?: string
    strict_mode?: boolean
    custom_validators?: string[]
  }
): ValidationResult
```

- Runs all validation stages in order
- Returns ValidationResult with valid flag and errors list
- In lenient mode, applies coercion and clamping where possible

### ValidateField

```typescript
validateField(
  value: unknown,
  property_schema: ParameterProperty,
  field_path: string
): ValidationError[]
```

- Validates single field against its property schema
- Returns array of errors for that field
- Used for incremental or targeted validation

### GetValidationErrors

```typescript
getValidationErrors(validation_result: ValidationResult): ValidationError[]
```

- Convenience method to extract errors from result
- Returns empty array if valid

### RegisterCustomValidator

```typescript
registerCustomValidator(validator: CustomValidator): void
```

- Registers a custom validator by name
- Validators can be referenced in ValidationRequest.custom_validators
- Emits TLS.CustomValidatorRegistered event

## Internal Interface

```typescript
interface SchemaValidator {
  validate(
    parameters: Record<string, unknown>,
    schema: ParameterSchema,
    options?: {
      invocation_id?: string
      tool_id?: string
      strict_mode?: boolean
      custom_validators?: string[]
    }
  ): ValidationResult

  validateField(
    value: unknown,
    property_schema: ParameterProperty,
    field_path: string
  ): ValidationError[]

  getValidationErrors(result: ValidationResult): ValidationError[]

  registerCustomValidator(validator: CustomValidator): void
  listCustomValidators(): CustomValidator[]
  removeCustomValidator(name: string): void
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| TOL.ValidationPassed |     invocation_id, tool_id, duration_ms | All validations passed |
| TOL.ValidationFailed |     invocation_id, tool_id, field, code, reason | Validation error detected |
| TOL.ValidationWarning |     invocation_id, tool_id, field, code, suggestion | Non-fatal validation warning |
| TOL.ValidationCoerced |     invocation_id, field, from_type, to_type, original_value | Value coerced to expected type |
| TOL.ValidationClamped |     invocation_id, field, constraint, original, clamped | Value clamped to range |
| TOL.ValidationDefaultApplied |     invocation_id, field, default_value | Default value used for missing field |
| TOL.CustomValidatorRegistered |     validator_name, description | New custom validator registered |
| TOL.CustomValidatorFailed |     validator_name, invocation_id, field, message | Custom validator returned error |
| TOL.SchemaValidationSkipped |     invocation_id, reason | Validation skipped (e.g., internal tool) |
| TOL.ValidationMetrics |     total_validations, pass_rate, avg_duration_ms | Aggregated validation metrics |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VAL-001 | Every tool invocation is validated before execution | Pipeline â€” Validation is invocation stage 1 |
| VAL-002 | Validation errors always include field path and expected/received values | Schema â€” ValidationError requires these fields |
| VAL-003 | Required fields without defaults must always be provided | Algorithmic â€” checked before any coercion |
| VAL-004 | Unknown properties are rejected in strict mode, warned in lenient | Schema â€” additional_properties defaults to false |
| VAL-005 | Custom validators cannot modify parameters (read-only) | API â€” validator signature returns errors only |
| VAL-006 | Validation is deterministic â€” same inputs always produce same result | Algorithmic â€” pure function |
| VAL-007 | Coercion never changes the semantic type of a value | Algorithmic â€” only format conversions allowed |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Required field missing | `REQUIRED_FIELD_MISSING` | Return error; list missing fields |
| Type mismatch | `TYPE_MISMATCH` | Return error; show expected and received types |
| Enum value not in allowed set | `ENUM_VALUE_INVALID` | Return error; show allowed values |
| Value below minimum | `RANGE_MIN_EXCEEDED` | Clamp to min (lenient) or error (strict) |
| Value above maximum | `RANGE_MAX_EXCEEDED` | Clamp to max (lenient) or error (strict) |
| Pattern does not match | `PATTERN_MISMATCH` | Return error; show expected pattern |
| Invalid format | `FORMAT_INVALID` | Return error (strict) or warning (lenient) |
| Custom validator not found | `CUSTOM_VALIDATOR_NOT_FOUND` | Skip custom validation; emit warning |
| Circular schema reference | `SCHEMA_CIRCULAR_REFERENCE` | Return error; max depth exceeded |


## Cross-Cutting Concerns

### Security

Tool System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Tool System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Tool System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Tool System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Schema Validator handles only parameter validation |
| R2 â€” Dependency Order | Depends on nothing beyond types; no upward deps |
| R3 â€” DRY | Validation rules defined in ParameterSchema, not in code |
| R4 â€” Builder Pattern | ValidationResult built by Stage Pipeline â†’ Error Collect |
| R5 â€” Liskov Substitution | Any SchemaValidator implements the interface |
| R6 â€” DI over Singletons | Validator stages and custom validators injected |
| R9 â€” Deterministic | Same parameters and schema produce same validation result |
| R10 â€” Simpler Over Complex | Clear sequential validation stages with typed errors |
| R13 â€” Design for Failure | Lenient mode ensures graceful handling of recoverable issues |
| R14 â€” Paved Path | All validation flows through validate() |
| R15 â€” Open/Closed | Custom validators add new rules without modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/Tools/000-Overview.md | Schema Validation is a core Tool System component |
| Brain/Tools/001-Registry.md | Parameter schemas are stored in Registry ToolDefinitions |
| Brain/Tools/003-Invocation.md | Validation runs as stage 1 of the invocation pipeline |
| Brain/Tools/005-Sandboxing.md | Validated parameters are passed to sandboxed execution |
| Bible/04-Execution/Runtime/001-SDK.md | Runtime SDK receives validated, typed parameters |
| Bible/05-Platform/004-EVS.md | Events emitted for every validation result |
