# AIOS Bible â€” Brain
## 005 â€” Channel Adaptation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Conversation |
| Document ID | AIOS-BBL-002-CON-005 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Channel Adaptation (also Modality Adapter) handles the translation between Sou's internal text-based processing and the user's communication channel. It adapts input from various modalities (text, voice, API, multimodal) into a normalized text format for Sou, and adapts Sou's text responses into the appropriate output format for the user's channel.

Sou is modality-agnostic â€” it processes text internally. The Channel Adapter is the bridge that translates raw channel input into Sou-bound normalized text and Sou's text responses into channel-specific output. Each channel has its own codec, profile, and constraints.

## Data Model

### Channel

```typescript
Channel {
  channel_id: string                // "web_1", "slack_workspace", "cli_terminal"
  channel_type: "web" | "api" | "voice" | "mobile" | "cli" | "slack" | "custom"
  modality: "text" | "voice" | "api" | "multimodal"
  capabilities: ChannelCapability[]
  constraints: ChannelConstraints
  profiles: ChannelProfile[]
}

ChannelCapability =
  | "markdown_full"
  | "markdown_limited"
  | "code_blocks"
  | "syntax_highlighting"
  | "rich_media"
  | "emoji"
  | "streaming"
  | "attachments"
  | "structured_data"
  | "reactions"

ChannelConstraints {
  max_message_length: number        // characters per message
  max_attachment_size: number       // bytes
  rate_limit_mps: number            // messages per second
  supported_content_types: string[] // "text/plain", "text/markdown", "application/json"
  connection_reliable: boolean
  retry_policy: "none" | "exponential_backoff" | "fixed_interval"
}
```

### ChannelProfile

```typescript
ChannelProfile {
  profile_id: string
  channel_id: string
  session_id?: string               // null for defaults
  formality: number                 // 0.0 (casual) â€“ 1.0 (formal)
  verbosity: number                 // 0.0 (concise) â€“ 1.0 (verbose)
  emoji_allowed: boolean
  markdown_supported: boolean
  code_block_support: boolean
  max_attachment_size: number
  language: string
  accessibility: string[]           // "screen_reader", "high_contrast"
  response_pacing: "normal" | "fast" | "streamed"
}
```

### EncodedInput

```typescript
EncodedInput {
  raw: unknown                      // Original channel payload
  normalized_text: string           // Text after all normalization
  modality: string
  metadata: {
    device_info?: string
    client_version?: string
    channel_specific: Record<string, unknown>
    language?: string
    confidence?: number             // STT confidence, 0.0â€“1.0
    attachments?: AttachmentRef[]
    raw_length: number
  }
}

AttachmentRef {
  type: "image" | "audio" | "file" | "link"
  uri: string
  mime_type: string
  size_bytes?: number
}
```

### EncodedOutput

```typescript
EncodedOutput {
  content: string                   // Final formatted output
  format: "plain" | "markdown" | "json" | "ssml" | "html"
  modality: string
  metadata: {
    delivery_hints: {
      urgency: "low" | "normal" | "high"
      persist: boolean              // Store in conversation history
      ttl_ms?: number               // If ephemeral
    }
    channel_commands: Record<string, unknown>
    parts?: EncodedOutputPart[]     // For split/streamed responses
    original_text: string           // Before formatting
    token_count: number
    truncation_applied: boolean
  }
}

EncodedOutputPart {
  index: number
  content: string
  is_final: boolean
}
```

### AdaptationRule

```typescript
AdaptationRule {
  rule_id: string
  condition: AdaptationCondition
  transformation: InputNormalization | OutputFormatting
  priority: number                  // Lower = applied first
}

AdaptationCondition {
  channel_types?: string[]          // Apply only to these channels
  modalities?: string[]
  content_pattern?: RegExp          // Regex trigger
  length_threshold?: number         // Apply if content exceeds N chars
}

InputNormalization {
  type: "strip_markdown" | "normalize_whitespace" | "detect_language"
    | "expand_shortlinks" | "sanitize_html" | "extract_text_from_json"
  params?: Record<string, unknown>
}

OutputFormatting {
  type: "wrap_code_blocks" | "apply_markdown" | "convert_to_plain"
    | "add_ssml_annotations" | "truncate" | "split_long" | "strip_emoji"
  params?: Record<string, unknown>
}
```

### ModalityCodec

```typescript
interface ModalityCodec {
  modality: string
  encode(content: TurnContent): EncodedOutput
  decode(input: EncodedInput): TurnContent
  capabilities(): ChannelCapability[]
  latencyProfile(): {
    encode_ms: number
    decode_ms: number
    size_multiplier: number         // Output size / input size estimate
  }
}
```

## Channel Registry

The Channel Registry maintains all registered channels, their codecs, capabilities, and per-session profiles:

```
ChannelRegistry {
  channels: Map<string, Channel>
  codecs: Map<string, ModalityCodec>
  default_profiles: Map<string, ChannelProfile>
  session_profiles: Map<string, Map<string, ChannelProfile>>
}
```

### Available Channels and Codecs

| Channel Type | Default Codec | Modality | Capabilities |
|-------------|---------------|----------|--------------|
| web | TextCodec | text | markdown_full, code_blocks, syntax_highlighting, rich_media, emoji, streaming, attachments |
| api | JsonCodec | api | code_blocks, structured_data, streaming, attachments |
| voice | VoiceCodec | voice | streaming, attachments (audio only) |
| mobile | TextCodec (limited) | text | markdown_limited, code_blocks, emoji, streaming, attachments |
| cli | PlainTextCodec | text | code_blocks |
| slack | SlackCodec | text | markdown_limited, code_blocks, emoji, rich_media (links only), reactions, attachments |

### Channel Capability Discovery

```typescript
getChannelCapabilities(channel_id: string): ChannelCapability[]
hasCapability(channel_id: string, capability: ChannelCapability): boolean
```

Channels advertise capabilities on registration. Capability discovery is used by the Response Builder to select appropriate formatting rules. If a channel does not support a capability, the adapter strips or converts that feature.

### Channel-Specific Constraints

Each channel carries constraints that affect encoding decisions:

```
Channel Type   : web     api     voice   mobile  cli
max_msg_len    : 32000   64000   2000    16000   4000
max_attach_mb  : 25      50      10      20      0
rate_limit_mps : 10      100     5       10      30
reliable       : true    true    false    true    true
retry          : none    none    backoff none    none
```

### Channel Profile Per Session

Profiles are resolved by priority: session profile > default profile > channel defaults. Session profiles are established at session creation and may be updated by user preferences or channel metadata.

```typescript
resolveProfile(channel_id: string, session_id?: string): ChannelProfile
// Returns merged profile: merge(default, session_specific)
```

## Input Adaptation Pipeline

```
Raw Input
    â”‚
    â–¼
Channel Detection â”€â”€â”€ Identify channel_id from connection metadata
    â”‚
    â–¼
Modality Decode  â”€â”€â”€ codec.decode(input) â†’ TurnContent
    â”‚
    â–¼
Text Normalization â”€â”€ strip markdown, normalize whitespace,
    â”‚                   language detection, expand links
    â–¼
Intent Pre-classification â”€â”€ lightweight intent hint extraction
    â”‚
    â–¼
Sou-bound Output (normalized_text + metadata)
```

### Voice Input

```
Voice Audio â†’ Voice System STT â†’ Raw text (with confidence scores)
    â†’ Channel Adaptation: attach confidence, speaker diarization hints
    â†’ Normalization: remove filler words, repair punctuation
    â†’ Sou-bound: normalized_text + modality="voice" + confidence
```

### API Input

```
Structured JSON â†’ Parse fields â†’ Extract text payload
    â†’ Extract structured params (entities, filters, commands)
    â†’ Normalization: validate JSON, extract from known schemas
    â†’ Sou-bound: normalized_text + structured_data (passthrough)
```

### Multimodal Input

```
Image/Audio + Text â†’ Extract text component
    â†’ Extract media references â†’ attach as AttachmentRef[]
    â†’ Normalization: combine text + media descriptions
    â†’ Sou-bound: normalized_text + attachments metadata
```

### Text Normalization Steps

| Step | Operation | Example |
|------|-----------|---------|
| Strip HTML | Remove <tags>, decode entities | `&amp;` â†’ `&` |
| Normalize Unicode | NFC normalization | Composed characters |
| Normalize Whitespace | Collapse multiple spaces, trim | `"  hello   world "` â†’ `"hello world"` |
| Strip Control Chars | Remove non-printable chars | `\x00`â€“`\x1F` except `\n`, `\t` |
| Language Detection | Identify language for Sou | `"Bonjour"` â†’ `lang: "fr"` |
| Expand Shortlinks | Resolve t.co, bit.ly â†’ full URL | Only if enabled |
| Sanitize | Remove XSS, injection patterns | `<script>` stripped |

## Output Adaptation Pipeline

```
Sou Response (normalized text)
    â”‚
    â–¼
Style Application â”€â”€ Apply personality formality, verbosity
    â”‚
    â–¼
Formatting â”€â”€â”€â”€â”€â”€â”€â”€ Add markdown, code blocks, lists, links
    â”‚
    â–¼
Modality Encode â”€â”€â”€ codec.encode(turn_content) â†’ EncodedOutput
    â”‚
    â–¼
Channel-Specific Packaging â”€â”€ Apply channel constraints, truncation
    â”‚
    â–¼
Delivery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Emit EncodedOutput via channel transport
```

### Text Output (Web/Mobile)

```
Sou text â†’ Style Application â†’ Markdown rendering
    â†’ Code blocks with syntax highlighting (if supported)
    â†’ Link rendering as hyperlinks
    â†’ Emoji passthrough
    â†’ Length check â†’ truncate or split if exceeds max
    â†’ Delivery as text/markdown
```

### Voice Output

```
Sou text â†’ Style Application â†’ TTS preprocessing
    â†’ SSML annotation (pauses, emphasis, prosody)
    â†’ Speech pacing adjustments (slow for complex content)
    â†’ Code blocks â†’ paraphrase as "code block begins..."
    â†’ Emoji â†’ spoken description (":smile:" â†’ "smiling face")
    â†’ Length check â†’ split at sentence boundaries
    â†’ Delivery via Voice System TTS
```

### API Output

```
Sou text â†’ Style Application (minimal)
    â†’ Structure into JSON response fields
    â†’ Typed fields: text, structured_data, confidence
    â†’ Code blocks â†’ string fields with language tag
    â†’ No emoji, no markdown formatting
    â†’ Length check â†’ truncate field values
    â†’ Delivery as application/json
```

### CLI Output

```
Sou text â†’ Style Application (plain)
    â†’ Plain text, no markdown rendering
    â†’ Code blocks â†’ indented with line wrapping
    â†’ Links â†’ displayed as raw URLs
    â†’ Emoji â†’ stripped entirely
    â†’ Line-wrap at 80 characters
    â†’ Length check â†’ split at newline boundaries
    â†’ Delivery as text/plain
```

## Channel Capabilities

| Capability | Web | API | Voice | Mobile | CLI | Slack |
|------------|-----|-----|-------|--------|-----|-------|
| Markdown | Full | No | No | Limited | No | Limited |
| Code blocks | Yes | Yes | No | Yes | Yes | Yes |
| Syntax highlighting | Yes | No | No | No | No | Yes |
| Rich media | Yes | URLs | No | Yes | No | Links only |
| Emoji | Yes | No | No | Yes | No | Yes |
| Streaming | Yes | Yes | No | Yes | No | No |
| Attachments | Yes | Yes | No | Yes | No | Yes |
| Structured data | No | Yes | No | No | No | No |
| Reactions | No | No | No | No | No | Yes |

## Response Formatting Rules

### Length Adaptation

```typescript
formatResponse(text: string, channel_id: string, format_options?: {
  max_length?: number
  truncation_hint?: "end" | "middle" | "smart"
}): string

splitLongResponse(text: string, channel_id: string): string[]
```

- If `text.length <= max_message_length`: pass through
- If `text.length > max_message_length`:
  - Smart truncation: truncate at last sentence boundary within limit, append "..."
  - Middle truncation: keep first and last parts, remove middle
  - Split: divide at paragraph or sentence boundaries for multi-message delivery
- Voice: split at sentence boundaries for natural TTS breaks
- CLI: split at newline boundaries for terminal readability

### Format Conversion

| Source Format | Web | API | Voice | Mobile | CLI |
|---------------|-----|-----|-------|--------|-----|
| Markdown | Render HTML | Strip | Convert to SSML | Render limited | Strip |
| Code blocks | Highlighted | String field | Paraphrase | Highlighted | Indented |
| Bold/Italic | Rendered | Strip | Emphasize (SSML) | Rendered | Strip |
| Lists | Rendered | Array field | Natural phrasing | Rendered | Dashed |
| Headers | Rendered | Strip | Pause (SSML) | Rendered | Underline |

### Code Block Handling

| Channel | Behavior |
|---------|----------|
| Web | Render with syntax highlighting via highlight.js |
| API | Include as string field with `language` tag |
| Voice | Replace with "The following code: [language] block begins... [content]... block ends" |
| Mobile | Render with basic monospace formatting |
| CLI | Indent 4 spaces, wrap lines at terminal width |
| Slack | Use Slack mrkdwn code block formatting |

### Link Handling

| Channel | Behavior |
|---------|----------|
| Web | Render as `<a href="url">text</a>` |
| API | Include in structured `links[]` array |
| Voice | Read as "link: [text]" at end of sentence |
| Mobile | Render as tappable inline link |
| CLI | Display as `text [url]` |
| Slack | Use Slack link format `<url|text>` |

### Emoji Handling

| Channel | Behavior |
|---------|----------|
| Web | Render native emoji |
| API | Strip entirely |
| Voice | Convert to spoken form (`"ðŸŽ‰"` â†’ "party popper emoji") |
| Mobile | Render native emoji |
| CLI | Strip entirely |
| Slack | Render native emoji |

## Channel Constraints

### Rate Limiting

```typescript
interface RateLimiter {
  channel_id: string
  max_messages_per_second: number
  burst_size: number
  current_count: number
  window_start: timestamp
}

// Policy: sliding window
checkRateLimit(channel_id: string): boolean
// Returns false if rate limit exceeded; caller must queue or drop
```

| Channel Type | Rate Limit | Burst | Backpressure |
|-------------|-----------|-------|-------------|
| web | 10 msg/s | 20 | Queue excess |
| api | 100 msg/s | 200 | Return 429 |
| voice | 5 msg/s | 10 | Drop silent |
| mobile | 10 msg/s | 15 | Queue excess |
| cli | 30 msg/s | 50 | Drop excess |
| slack | 1 msg/s | 5 | Queue + 1s delay |

### Max Message Size

| Channel Type | Max Length | Truncation Strategy |
|-------------|-----------|---------------------|
| web | 32000 chars | Smart truncation at paragraph |
| api | 64000 chars | Field-level truncation |
| voice | 2000 chars | Split at sentence |
| mobile | 16000 chars | Smart truncation at paragraph |
| cli | 4000 chars | Split at newline |
| slack | 40000 chars | Split into blocks |

### Supported Content Types

| Channel Type | Input Types | Output Types |
|-------------|------------|-------------|
| web | text/plain, text/markdown | text/markdown, text/html |
| api | application/json | application/json |
| voice | audio/wav, audio/ogg | audio/mp3, audio/ogg |
| mobile | text/plain, image/jpeg, image/png | text/markdown, image/* |
| cli | text/plain | text/plain |
| slack | application/json (Slack API) | application/json (Slack blocks) |

### Connection Reliability

| Channel Type | Reliable | Retry Policy | Timeout |
|-------------|----------|-------------|---------|
| web | Yes | None | 30s |
| api | Yes | None | 60s |
| voice | No | Exponential backoff (3 retries) | 10s |
| mobile | Yes | None | 30s |
| cli | Yes | None | N/A |
| slack | No | Fixed interval (3 retries, 1s apart) | 5s |

## Internal Interfaces

```typescript
interface ChannelAdapter {
  // Registration
  registerChannel(channel_id: string, codec: ModalityCodec, profile: ChannelProfile): void
  unregisterChannel(channel_id: string): void
  getChannel(channel_id: string): Channel | null
  listChannels(): Channel[]

  // Adaptation
  adaptInput(channel_id: string, raw_input: unknown): EncodedInput
  adaptOutput(channel_id: string, sou_response: TurnContent): EncodedOutput

  // Capabilities
  getChannelCapabilities(channel_id: string): ChannelCapability[]
  hasCapability(channel_id: string, capability: ChannelCapability): boolean

  // Normalization
  normalizeText(raw: string, channel_id: string): string
  detectLanguage(text: string): string

  // Formatting
  formatResponse(text: string, channel_id: string, format_options?: {
    max_length?: number
    truncation_hint?: "end" | "middle" | "smart"
    style_profile?: string
  }): string

  splitLongResponse(text: string, channel_id: string): string[]

  // Profile management
  setSessionProfile(session_id: string, channel_id: string, profile: ChannelProfile): void
  getSessionProfile(session_id: string, channel_id: string): ChannelProfile
  resolveProfile(channel_id: string, session_id?: string): ChannelProfile

  // Constraint enforcement
  checkRateLimit(channel_id: string): boolean
  estimateTokenCount(text: string): number
}

interface ModalityCodec {
  modality: string
  encode(content: TurnContent): EncodedOutput
  decode(input: EncodedInput): TurnContent
  capabilities(): ChannelCapability[]
  estimatedLatency(input_size: number): number  // milliseconds
}

interface ChannelRegistry {
  channels: Map<string, Channel>
  codecs: Map<string, ModalityCodec>
  
  register(codec: ModalityCodec, channel: Channel): void
  unregister(channel_id: string): void
  getCodec(modality: string): ModalityCodec | null
  findChannelByType(channel_type: string): Channel[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| CONV.ChannelRegistered |   channel_id, channel_type, modality, capabilities_count | New channel registered with adapter |
| CONV.InputAdapted |   channel_id, turn_id, original_length, normalized_length, latency_ms | Raw input adapted to normalized text |
| CONV.OutputAdapted |   channel_id, turn_id, original_length, output_length, format, latency_ms | Sou response adapted to channel output |
| CONV.ModalityConverted |   channel_id, from_modality, to_modality, turn_id | Modality conversion performed (e.g., text â†’ SSML) |
| CONV.FormatApplied |   channel_id, turn_id, from_format, to_format, rules_applied | Response formatting transformation applied |
| CONV.LengthTruncated |   channel_id, turn_id, original_length, truncated_length, strategy | Response truncated due to length constraint |
| CONV.ChannelCapabilityUsed |   channel_id, capability, turn_id | Channel capability exercised during adaptation |
| CONV.ChannelError |   channel_id, error_code, turn_id, recoverable | Error during channel adaptation |
| CONV.ChannelRateLimited |   channel_id, backoff_ms, turn_id | Rate limit hit, backoff applied |
| CONV.ChannelProfileUpdated |   channel_id, session_id, profile_fields | Session profile changed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| CA-001 | Sou processes only normalized text regardless of input modality | Architectural â€” Input Adaptation Pipeline strips modality before reaching Sou |
| CA-002 | Every channel has exactly one active codec at a time | Algorithmic â€” `registerChannel` replaces previous codec for same channel_id |
| CA-003 | Output never exceeds channel max_message_length | Algorithmic â€” `formatResponse` enforces truncation or split |
| CA-004 | Channel capabilities are immutable for the duration of a session | Architectural â€” capabilities determined at registration |
| CA-005 | Rate limits are enforced per channel, never per session | Algorithmic â€” `RateLimiter` scoped to channel_id |
| CA-006 | Format conversion is idempotent for text-only channels | Algorithmic â€” applying format twice yields same result |
| CA-007 | Unknown capabilities are treated as unsupported (fail closed) | Architectural â€” `hasCapability` returns false for undefined capabilities |
| CA-008 | Channel profiles merge by specificity: session > channel > default | Algorithmic â€” `resolveProfile` applies override cascade |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown channel_id | `CONV_CHANNEL_NOT_FOUND` | Return error; cannot adapt without registered channel |
| Unsupported modality for channel | `CONV_MODALITY_UNSUPPORTED` | Return error; list supported modalities for channel |
| Codec decode failure | `CONV_CODEC_DECODE_FAILURE` | Return original raw input as text if possible; emit error |
| Codec encode failure | `CONV_CODEC_ENCODE_FAILURE` | Fall back to plain text encoding |
| Channel rate limit exceeded | `CONV_RATE_LIMITED` | Queue message or return 429; emit `CONV.ChannelRateLimited` |
| Message exceeds max length after truncation | `CONV_TRUNCATION_LIMIT` | Split into multiple messages; notify via metadata |
| Unsupported content type | `CONV_CONTENT_TYPE_UNSUPPORTED` | Return error; list accepted content types |
| Voice STT confidence below threshold | `CONV_LOW_STT_CONFIDENCE` | Flag input as low-confidence; Sou may ask for clarification |

## Usage Patterns

### Pattern 1: Voice Input Adaptation

```
1. User speaks: "What's the weather in London?"
2. Voice System captures audio, performs STT
3. Channel Adapter receives EncodedInput:
     { raw: audio_buffer, modality: "voice",
       metadata: { confidence: 0.92, language: "en" } }
4. Codec.decode(): extracts text "What's the weather in London?"
5. Normalization: lowercase, trim filler words â†’ "what is the weather in London"
6. Attach metadata: modality="voice", confidence=0.92
7. Deliver to Sou as TurnContent: { text: "what is the weather in London",
       structured_data: { modality: "voice", confidence: 0.92 } }
8. Sou processes and returns text response
9. Channel Adapter encodes for voice:
     - Convert markdown to SSML
     - Add prosody tags for emphasis
     - Split at sentence boundaries
10. Deliver to Voice System for TTS
```

### Pattern 2: API Structured Response

```
1. External service sends POST /api/chat with JSON body:
     { "message": "Create a task", "project_id": "42", "priority": "high" }
2. Channel Detection â†’ channel_id = "api_gateway_1", type = "api"
3. Codec.decode():
     - Extract "message" field â†’ text: "Create a task"
     - Extract "project_id", "priority" â†’ structured_data
4. Normalization: validate JSON structure, extract known fields
5. Deliver to Sou: TurnContent with text + structured_data
6. Sou processes, returns response with structured fields
7. Channel Adapter encodes for API:
     {
       content: "Task created successfully",
       format: "json",
       metadata: {
         structured_data: {
           task_id: "task-789",
           project_id: "42",
           priority: "high",
           status: "pending"
         }
       }
     }
8. Deliver as JSON HTTP response with typed fields
```

### Pattern 3: Mobile Truncation and Multi-Message Split

```
1. Sou produces long response (30,000 chars with code examples, tables, lists)
2. Channel Detection â†’ channel_id = "mobile_ios_1", type = "mobile"
3. Channel constraints: max_message_length = 16000, markdown_limited
4. Profile: emoji_allowed=true, code_block_support=true
5. Adaptation:
     a. Convert markdown to limited mobile format (no HTML tables)
     b. Apply emoji passthrough
     c. Code blocks â†’ mobile-friendly monospace rendering
     d. Length check: 30000 > 16000 â†’ split required
6. Split response:
     - Part 1: Introduction + first half (15800 chars) â†’ is_final: false
     - Part 2: Second half + code blocks + conclusion (14200 chars) â†’ is_final: true
7. Emit CONV.LengthTruncated with strategy: "split"
8. Deliver two EncodedOutputParts sequentially
9. Mobile client receives two messages with "continue" indicator
```


## Cross-Cutting Concerns

### Security

Conversation OS operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Conversation OS emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Conversation OS instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Conversation OS declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Channel Adaptation does one thing: translate between Sou's text and channel modalities |
| R2 â€” Dependency Order | Depends on Voice System, Conversation OS core; no upward deps |
| R3 â€” DRY | Channel profiles defined once per channel, merged per session |
| R4 â€” Builder Pattern | Output built by Style â†’ Format â†’ Encode â†’ Package pipeline |
| R5 â€” Liskov Substitution | Any ModalityCodec implements the encode/decode interface |
| R6 â€” DI over Singletons | Codecs and profiles injected per channel registration |
| R9 â€” Deterministic | Same input + same channel profile produces same output |
| R10 â€” Simpler Over Complex | Uses pipeline stages with clear separation of concerns |
| R13 â€” Design for Failure | Codec failures fall back to plain text; rate-limited messages queued |
| R14 â€” Paved Path | All channel I/O flows through adaptInput/adaptOutput |
| R15 â€” Open/Closed | New channels added via registerChannel, not by modifying pipeline |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Conversation/000-Overview.md | Channel Adaptation is a sub-component of Conversation OS |
| Conversation/004-Session-Management.md | Sessions hold per-channel profiles |
| Conversation/002-Multi-Turn.md | Turns carry modality metadata through the pipeline |
| Conversation/001-Dialogue-State.md | Modality influences dialogue state and intent routing |
| Conversation/000-Overview.md | Response Builder calls Channel Adapter for output formatting per overview |
| Brain/Voice/000-Overview.md | Voice System provides STT/TTS; Channel Adapter bridges to it |
| Brain/Personality/000-Overview.md | Style Application uses personality formality/verbosity settings |
| Bible/05-Platform/004-EVS.md | All adaptation events recorded through Event System |
