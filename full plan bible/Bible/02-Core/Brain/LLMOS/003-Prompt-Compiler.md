# AIOS Bible — Brain/LLMOS
## 003 — Prompt Compiler

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/LLMOS |
| Document ID | AIOS-BBL-002-LLM-003 |
| Source Laws | Law 3 — Law of Communication |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |
| Pipeline Stage | 10 — Prompt Compilation |

## Purpose

The Prompt Compiler constructs the final prompt sent to the AI provider. It resolves prompt templates, interpolates variables, assembles conversation messages, and formats instructions. The Compiler works after Context Builder and Memory Injection have prepared the context window, so it has access to the complete context payload.

## Input

The Compiler receives a fully prepared PromptPayload from Stage 9 (Memory Injection):

```typescript
interface PromptPayload {
  request_id: UUIDv7;
  messages: CompiledMessage[];
  system_prompt: string;
  context_documents: ContextDocument[];
  injected_memories: MemoryBlock[];
  template_reference: string | null;
  template_variables: Map<string, any>;
  response_schema: Schema | null;
  model_info: ModelEntry;
  max_tokens: u64;
  temperature: f64;
  stop_sequences: string[];
  tools: ToolDefinition[];
  attachments: Attachment[];
}
```

## Compilation Pipeline

The Compiler executes in stages:

### Stage A: Template Resolution

If `template_reference` is provided, resolve it from the Template Registry:

```typescript
interface PromptTemplate {
  template_id: string;
  version: string;
  system_template: string;       // Jinja2/Handlebars-like template for system prompt
  message_templates: MessageTemplate[];
  metadata: TemplateMetadata;
  schema_path: string | null;    // Path to JSON schema for this template
}

interface MessageTemplate {
  role: "system" | "user" | "assistant" | "tool";
  content_template: string;
  condition: string | null;      // Optional condition string (evaluated at compile time)
}
```

Templates use `{{variable}}` syntax for interpolation. If no template is provided, the Compiler uses the raw `messages` array directly.

### Stage B: System Prompt Assembly

```typescript
function assembleSystemPrompt(payload: PromptPayload): string
```

1. If template exists: compile `system_template` with `template_variables`
2. If no template: use `payload.system_prompt` as-is
3. If both empty: use default system prompt from model config
4. Append model-specific formatting instructions (e.g., "You are Claude...")

### Stage C: Message Assembly

```typescript
function assembleMessages(payload: PromptPayload): FinalMessage[]
```

1. If template exists: compile each `message_template` in order, evaluating conditions
2. If no template: use `payload.messages` as-is, with variable substitution on text content
3. Insert system message as first message (if applicable for model format)
4. Append tool definitions as model-appropriate format
5. Inject context documents as structured content blocks
6. Inject memories as structured content blocks with metadata tags
7. Attach response schema as format instruction

### Stage D: Tool Formatting

Tools are formatted according to the target model's capabilities:

```typescript
function formatTools(payload: PromptPayload, model: ModelEntry): ToolBlock[]
```

- If model supports `tool_use`, tools are sent as native function declarations
- If model does not support `tool_use`, tools are inlined as XML instructions in the system prompt
- Each tool includes: name, description, input_schema (JSON Schema)

### Stage E: Response Schema Injection

If `response_schema` is provided:

```typescript
function injectResponseSchema(prompt: string, schema: Schema, model: ModelEntry): string
```

- If model supports `structured_output`, set response format at provider level
- If model does not, append: "Respond in valid JSON conforming to this schema:\n{schema}"
- Add fallback instruction: "Do not include markdown code fences or extra text"

### Stage F: Token Optimization

Apply token-saving optimizations:

- Remove duplicate whitespace (preserving markdown structure)
- Compress repeated system instructions into single instance
- Shorten variable names in tool definitions
- Remove optional sections below configured token threshold
- Flag oversize prompts for truncation (delegated to Context Builder feedback)

## Output

```typescript
interface CompiledPrompt {
  request_id: UUIDv7;
  provider_request: ProviderRequest;     // Final provider-specific request
  token_count: u64;                      // Estimated token count
  compile_duration_us: u64;              // Compilation duration
  template_used: string | null;          // Template ID if resolved
  optimization_applied: string[];        // List of optimizations applied
  sections: PromptSection[];            // Breakdown of prompt sections
}

interface ProviderRequest {
  model: string;
  system: string | null;
  messages: { role: string; content: any }[];
  max_tokens: u64;
  temperature: f64;
  top_p: f64;
  stop_sequences: string[];
  tools: ToolBlock[] | null;
  tool_choice: ToolChoice | null;
  response_format: ResponseFormat | null;
  stream: boolean;
  metadata: Map<string, string>;
}

interface PromptSection {
  name: string;     // "system", "messages", "tools", "context", "memory", "schema"
  token_count: u64;
  source: string;   // origin of this section
}
```

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| LLM-PCP-001 | Every compiled prompt has exactly one system section and at least one message. | Schema — compilation pipeline enforces structure |
| LLM-PCP-002 | The system prompt is never empty — if none provided, model default is used. | Algorithmic — fallback logic |
| LLM-PCP-003 | Token count is always estimated before sending to provider. | Algorithmic — pre-flight estimation |
| LLM-PCP-004 | Tool definitions match the target model's capabilities — no tool calling on models without tool support. | Algorithmic — capability-aware formatting |
| LLM-PCP-005 | Response schema injection respects the model's structured output capability. | Algorithmic — capability-gated schema injection |
| LLM-PCP-006 | Compiled prompt never exceeds the model's context window (enforced by Context Builder). | Architectural — upstream enforcement |

## Events

| Event | Fields | Trigger |
|-------|--------|---------|
| `LLMOS.PromptCompiled` | request_id, template_used, token_count, compile_duration_us, sections | After compilation (Stage 10) |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Compiler is the sole prompt construction authority |
| R2 — Dependency Order | Compiler depends on Context Builder and Memory Injection |
| R3 — DRY | Templates centralized in Template Registry |
| R4 — Builder Pattern | CompiledPrompt built through staged pipeline |
| R5 — Liskov Substitution | ProviderRequest is provider-agnostic |
| R6 — DI over Singletons | Compiler injected into pipeline stage |
| R9 — Deterministic | Same payload produces same compiled prompt |
| R10 — Simpler Over Complex | Template interpolation over complex DSL |
| R13 — Design for Failure | Fallback to raw messages when template not found |
| R14 — Paved Path | Default system prompt when none provided |
| R15 — Open/Closed | New models add formatting without compiler changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| LLMOS/004-Context-Builder.md | Provides the context payload that Compiler consumes |
| LLMOS/005-Memory-Injection.md | Provides memories for injection into prompt |
| LLMOS/012-Response-Validator.md | Defines schemas that Compiler injects |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Template not found | LLM-0301 | Fall back to raw messages; log warning |
| Template variable undefined | — | Insert empty string; log warning |
| Tool definition incompatible with model | — | Inline tools as XML; log model compatibility notice |
