# AIOS Bible â€” Domains
## Coding â€” 002: Code Generation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-COD-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Code Generation is the core capability that produces source code across all supported programming languages. It transforms structured code plans from Sou into syntactically correct, stylistically consistent, and functionally complete source files. The generation pipeline manages prompt construction, context assembly, LLM invocation, output validation, and code formatting.

This component is the highest consumer of token budgets in the Coding domain. Every generation request is scoped by language profile, context window limits, and capability bounds from the Language Support Registry. The pipeline supports multiple generation modes: full file generation, targeted function generation, test generation, and docstring generation. Output is validated against language syntax rules before being returned to the caller.

## Architecture

```
CodePlan (from Sou)  â”€â”€â–¶  Prompt Constructor
                              â”‚
                              â–¼
                    Context Assembler  â—€â”€â”€ CodebaseIndex (Academy)
                              â”‚
                              â–¼
                    LLM Invocation  â”€â”€â–¶  GenerationTemplate
                              â”‚
                              â–¼
                    Output Validator  â—€â”€â”€ LanguageProfile (Registry)
                              â”‚
                              â–¼
                    Code Formatter  â”€â”€â–¶  Formatted Code Output
                              â”‚
                              â–¼
                    CodeGenResult (to Worker)
```

The pipeline processes one generation unit at a time. Context is assembled from the CodebaseIndex, relevant file fragments, and the structured plan step. The prompt is constructed using language-specific templates from the GenerationTemplate store. After LLM generation completes, the output is validated for syntax correctness and then formatted using the target language's formatter. The result is returned to the CodeWorker along with metadata about token consumption and confidence.

## Data Model

```typescript
interface CodeGenRequest {
  requestId: string
  workerId: string
  languageId: string
  generationType: GenerationType
  planStepId: string
  prompt: string
  context: ContextFragment[]
  templateId: string
  constraints: GenerationConstraints
  seed: number
  modelPreferences: ModelPreference[]
}

interface CodeGenResult {
  requestId: string
  code: string
  filePath: string
  languageId: string
  generationType: GenerationType
  validated: boolean
  formatted: boolean
  tokenUsage: TokenUsage
  confidence: number
  warnings: string[]
  lintErrors: LintError[]
  durationMs: number
}

interface GenerationTemplate {
  templateId: string
  languageId: string
  generationType: GenerationType
  templateBody: string
  variables: TemplateVariable[]
  expectedOutputFormat: string
  maxOutputTokens: number
  examples: TemplateExample[]
}

interface ContextFragment {
  fragmentId: string
  sourceFile: string
  content: string
  startLine: number
  endLine: number
  relevanceScore: number
  fragmentType: FragmentType
}

interface GenerationConstraints {
  maxTokens: number
  maxLines: number
  maxComplexity: number
  includeImports: boolean
  includeDocstrings: boolean
  enforceStyleGuide: boolean
  timeoutSeconds: number
}

interface TokenUsage {
  promptTokens: number
  completionTokens: number
  totalTokens: number
  estimatedCost: number
}

interface TemplateVariable {
  name: string
  type: string
  defaultValue: string
  required: boolean
  description: string
}

interface LintError {
  line: number
  column: number
  severity: string
  message: string
  ruleId: string
}

enum GenerationType {
  File = "file",
  Function = "function",
  Test = "test",
  Docstring = "docstring",
  Snippet = "snippet",
  Configuration = "configuration",
}

enum FragmentType {
  ImportBlock = "import",
  TypeDefinition = "type",
  FunctionSignature = "function_signature",
  ExistingImplementation = "implementation",
  TestCase = "test_case",
  DependencyGraph = "dependency_graph",
}
```

## Core Operations

| Operation | Precondition | Postcondition |
|-----------|-------------|---------------|
| generate_file | CodePlan step specifies file path and language | Complete file is generated, validated, and formatted |
| generate_function | Function signature and return type are specified | Function body is generated with type-safe implementation |
| generate_test | Target function or module is identified | Test suite covering specified cases is generated |
| generate_docstring | Function or module code exists | Docstring conforming to language conventions is prepended |
| generate_snippet | Specific code pattern is requested | Isolated code block matching pattern constraints is returned |
| regenerate | Prior generation failed validation | New generation with adjusted parameters is attempted |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| ICodeGenerator | Code Generation Pipeline | CodeWorker | ACF command |
| IPromptConstructor | Prompt Constructor | Code Generation Pipeline | Internal |
| IContextAssembler | Context Assembler | Code Generation Pipeline | Internal query |
| IOutputValidator | Output Validator | Code Generation Pipeline | Internal |
| ICodeFormatter | Code Formatter | Code Generation Pipeline | Internal |
| IGenerationTemplateStore | Template Store | Code Generation Pipeline | Internal query |

## Events

| COD.EventType |   Produced When | Fields |
|-----------|--------------|--------|
| COD.CodeGenStarted |   A generation request enters the pipeline | request_id, worker_id, language_id, generation_type, estimated_tokens |
| COD.CodeGenCompleted |   Generation produces output successfully | request_id, language_id, tokens_used, confidence, duration_ms |
| COD.CodeGenValidated |   Generated output passes syntax validation | request_id, lint_errors, validation_duration_ms |
| COD.CodeGenFailed |   Generation pipeline encounters an error | request_id, error_code, error_message, retry_count |
| COD.CodeGenRetried |   Generation is retried after failure | request_id, retry_attempt, adjusted_params |
| COD.CodeGenOverflow |   Context window limit is exceeded | request_id, context_size, max_size, overflow_strategy |
| COD.CodeGenFormatted |   Generated code is formatted | request_id, formatter_name, formatting_duration_ms |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| COD_GEN_001 | Context window exceeds model limit | Error | Split generation into multiple fragments; use overflow strategy |
| COD_GEN_002 | Generation timeout | Error | Retry with reduced max_tokens (up to 3 attempts); fall back to stub |
| COD_GEN_003 | Validation failure (syntax error) | Warning | Retry generation with error feedback in prompt (max 2 retries) |
| COD_GEN_004 | Template variable mismatch | Error | Log template error; fall back to generic generation template |
| COD_GEN_005 | Token budget exceeded for operation | Error | Emit budget exceeded event; pause until next budget cycle |
| COD_GEN_006 | Language not supported for generation | Error | Return unsupported language error with supported language list |
| COD_GEN_007 | Generated code exceeds length limit | Warning | Truncate with warning; request follow-up generation for remainder |
| COD_GEN_008 | Model preference unavailable | Warning | Fall back to default model; log preference mismatch |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| COD-GEN-I-001 | Same CodePlan step + context + seed produces identical output | Pipeline uses deterministic seed and temperature=0 for reproducible generation |
| COD-GEN-I-002 | All generated code passes language syntax validation | Pipeline blocks output that fails validation; retry loop enforces compliance |
| COD-GEN-I-003 | Generated code must not exceed context bounds of the target file | Pipeline enforces maxLines constraint from GenerationConstraints |
| COD-GEN-I-004 | Every generation produces an Event with token usage | Pipeline emits `Coding.CodeGenCompleted` or `Coding.CodeGenFailed` |
| COD-GEN-I-005 | Generation templates are immutable after registration | Template store enforces versioned immutable templates |
| COD-GEN-I-006 | Generated tests must be executable (syntax-valid) | Pipeline validates test output against language test framework syntax |


## Cross-Cutting Concerns

### Security

Coding operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Coding emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Coding instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Coding declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Code generation is a single pipeline with clear stage boundaries |
| R2 - Dependency Order | Pipeline depends on Language Registry for profiles; CodeWorker depends on pipeline |
| R3 - DRY | Generation templates capture reusable patterns; context deduplication before assembly |
| R4 - Builder Pattern | Pipeline uses builder stages: construct -> assemble -> invoke -> validate -> format |
| R5 - Liskov Substitution | All generation backends implement ICodeGenerator interface |
| R6 - DI over Singletons | Pipeline components are injected; no shared mutable state |
| R9 - Deterministic | Deterministic generation guaranteed with same inputs and seed value |
| R10 - Simpler Over Complex | Pipeline uses linear stages with no branching; overflow is a distinct path |
| R13 - Design for Failure | Validation failures trigger targeted retry with error feedback; timeout returns stub |
| R14 - Paved Path | Single paved path: request -> construct -> generate -> validate -> format -> return |
| R15 - Open/Closed | New generation types added via template registration without pipeline modification |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Coding/000-Overview.md | Coding domain overview â€” code generation is a core capability |
| Bible/07-Domains/Coding/001-Languages.md | Language Support Registry â€” provides language profiles and templates |
| Bible/07-Domains/Coding/003-Review.md | Code Review â€” generated code is reviewed by this component |
| Bible/07-Domains/Coding/004-Refactoring.md | Refactoring â€” refactoring engine consumes generated code patterns |
| Physics/005-Events.md | Evidence â€” all generation operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” generation token budgets bounded by capability profiles |
| Physics/010-Execution.md | Execution â€” generation is part of the execution pipeline |
| Bible/02-Core/Brain/LLMOS/004-Context-Builder.md | Context Builder â€” assembles LLM input context for generation |
| Bible/02-Core/Brain/LLMOS/003-Prompt-Compiler.md | Prompt Compiler â€” compiles structured prompts from templates |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” confidence scoring for generated code quality |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” token budget allocation for generation operations |
| Bible/02-Core/Sou/002-Planner.md | Planner â€” produces code plans that drive generation requests |
