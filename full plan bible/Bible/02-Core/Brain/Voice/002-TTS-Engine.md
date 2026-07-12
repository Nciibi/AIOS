# AIOS Bible â€” Brain
## 002 â€” TTS Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-002 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The TTS Engine converts Sou's text responses into spoken audio for delivery to the user. It supports neural and concatenative synthesis across configurable quality levels, multiple voice profiles, and style controls (conversational, announcement, neutral). Audio output can be streamed in chunks for long-form responses, and each utterance supports per-word timing for synchronization with other modalities. Text normalization runs before synthesis to ensure numbers, dates, abbreviations, and special characters are spoken correctly.

Under VOI-004, the TTS Engine never modifies Sou's text content â€” the semantic meaning passes through verbatim.

## Data Model

### TTSRequest

```typescript
TTSRequest {
  request_id: string
  text: string
  voice: VoiceProfileRef
  config: TTSConfig
  session_id: string
}
```

### TTSResult

```typescript
TTSResult {
  request_id: string
  audio: AudioOutput
  format: "wav" | "mp3" | "ogg" | "pcm"
  duration_ms: number
  processing_time_ms: number
  word_timings?: WordTiming[]       // Only if requested
  text_normalized: string           // Text after normalization
  chunk_sequence?: number           // Streaming chunk index
  is_final: boolean                 // false for streaming chunks
}
```

### WordTiming

```typescript
WordTiming {
  word: string
  start_ms: number
  end_ms: number
}
```

### AudioOutput

```typescript
AudioOutput {
  data: bytes
  format: "wav" | "mp3" | "ogg" | "pcm"
  sample_rate: number
  channels: number
}
```

### TTSConfig

```typescript
TTSConfig {
  model: string                     // Provider-specific model ID
  quality: "high" | "standard" | "low"
  speed: number                     // 0.5â€“2.0 speech rate multiplier
  pitch: number                     // -0.5â€“0.5 semitone adjustment
  volume: number                    // 0.0â€“1.0
  style: "neutral" | "conversational" | "announcement"
  emphasis?: "strong" | "moderate" | "reduced"
  ssml?: boolean                    // Interpret text as SSML
  word_timings: boolean             // Include word-level timing in result
  streaming_chunk_size_ms: number   // Chunk duration for streaming output
}
```

### VoiceProfileRef

```typescript
VoiceProfileRef {
  profile_id: string
  provider: string
  voice_name: string
}
```

## Quality Levels

| Level | Engine | Prosody | Latency (first chunk) | Use Case |
|-------|--------|---------|----------------------|----------|
| High | Neural (full transformer) | Full intonation, emotion, pauses | < 1s | User-facing dialogue |
| Standard | Neural (reduced) | Moderate prosody, natural | < 500ms | Notifications, alerts, confirmations |
| Low | Concatenative (diphone) | Minimal prosody, robotic | < 200ms | System-internal, debugging, accessibility fallback |

Quality level is selected per-request via `config.quality`. If the selected provider does not support the requested level, the engine falls back to the nearest supported level and emits a warning event.

## Core Concepts

### Voice Selection

Voices are referenced via `VoiceProfileRef` which maps a profile to a provider-specific voice. The TTS Engine resolves the profile through `VoiceProfileManager`:

```typescript
VoiceSelection {
  profile: VoiceProfile
  provider_voice_id: string         // Resolved provider-specific voice name
  quality_supported: boolean
  style_supported: boolean
}
```

### Style Control

| Style | Characteristics | Use Case |
|-------|----------------|----------|
| neutral | Flat delivery, no emotional coloring | Default, system messages |
| conversational | Natural rhythm, contractions, varied pitch | Dialogue with user |
| announcement | Clear enunciation, slower pace, pauses | Briefings, summaries, list reading |

### Speed / Pitch / Volume Adjustment

| Parameter | Range | Step | Effect |
|-----------|-------|------|--------|
| speed | 0.5â€“2.0 | 0.1 | Speech rate multiplier (1.0 = normal) |
| pitch | -0.5â€“0.5 | 0.1 | Semitone adjustment from baseline |
| volume | 0.0â€“1.0 | 0.1 | Output gain, 1.0 = full volume |

Adjustments are applied at the provider level. Some providers may not support full ranges â€” `getCapabilities()` reports supported ranges per voice.

### SSML Support

When `config.ssml` is true, the text is interpreted as SSML (Speech Synthesis Markup Language). Supported SSML tags:

| Tag | Support | Notes |
|-----|---------|-------|
| `<speak>` | Required | Root element |
| `<voice>` | Full | Voice switch mid-synthesis |
| `<prosody>` | Full | Rate, pitch, volume overrides |
| `<break>` | Full | Pause with optional time attribute |
| `<emphasis>` | Full | Level attribute (strong/moderate/reduced) |
| `<say-as>` | Partial | Date, time, number, cardinal, ordinal |
| `<phoneme>` | Full | IPA or x-sampa pronunciation |
| `<paragraph>`<br>`<sentence>` | Full | Structural breaks |
| `<lang>` | Partial | Language switching (provider-dependent) |
| `<audio>` | Full | Embed audio clip inline |
| `<sub>` | Full | Substitution alias |

Malformed SSML returns `VOI_TTS_INVALID_SSML` â€” the engine does not attempt recovery.

### Word-Level Timing

When `config.word_timings` is true, each `TTSResult` includes an array of `WordTiming` objects mapping words to their start/end positions in milliseconds. Used by Conversation OS for:
- Speech-to-text alignment (lip-sync in avatar mode)
- Highlighting spoken words in UI
- Audio trimming by word boundaries

### Text Normalization

Before synthesis, the TTS Engine normalizes the input text. Normalization is deterministic and does not alter semantic content:

| Rule | Example | Output |
|------|---------|--------|
| Expand numbers | "123" | "one hundred twenty-three" |
| Expand dates | "2024-01-15" | "January fifteenth twenty twenty-four" |
| Expand time | "14:30" | "two thirty PM" |
| Expand abbreviations | "Dr. Smith" | "Doctor Smith" |
| Expand contractions | "don't" | "don't" (unchanged in conversational) |
| URL splitting | "example.com" | "example dot com" |
| Email splitting | "a@b.com" | "a at b dot com" |
| Symbol names | "#" | "hashtag" or "pound" |
| Currency | "$50" | "fifty dollars" |

Normalization output is saved in `TTSResult.text_normalized` for debugging.

## Operations

### Synthesize (Batch)

```typescript
synthesize(request: TTSRequest): Promise<TTSResult>
```

- Processes entire text input and returns full audio
- Text normalization runs before synthesis
- Returns `is_final: true` with complete audio

### Synthesize Stream

```typescript
synthesizeStream(request: TTSRequest): Promise<TTSStreamHandle>

TTSStreamHandle {
  read(): Promise<AudioOutput>       // Read next audio chunk
  cancel(): void
  on(event: "data", handler: (chunk: AudioOutput) => void): void
  on(event: "done", handler: () => void): void
  on(event: "error", handler: (error: Error) => void): void
  on(event: "word", handler: (timing: WordTiming) => void): void
}
```

- Emits audio chunks of `streaming_chunk_size_ms` duration
- Word-level timing events fire in real-time as each word is synthesized
- Stream is cancellable at any point via `cancel()`
- Final chunk has `is_final: true`

### List Voices

```typescript
listVoices(filter?: VoiceFilter): Promise<VoiceProfile[]>
```

Returns available voice profiles, optionally filtered by:

```typescript
VoiceFilter {
  provider?: string
  language?: string
  gender?: "male" | "female" | "neutral"
  quality?: "high" | "standard" | "low"
}
```

### Get Capabilities

```typescript
getCapabilities(profile_id?: string): Promise<TTSCapabilities>
```

Returns feature support for the selected voice or the engine:

```typescript
TTSCapabilities {
  max_text_length: number
  supported_formats: string[]
  supported_styles: string[]
  speed_range: { min: number, max: number, step: number }
  pitch_range: { min: number, max: number, step: number }
  volume_range: { min: number, max: number, step: number }
  supports_ssml: boolean
  supports_streaming: boolean
  supports_word_timings: boolean
  supports_emphasis: boolean
  supported_languages: string[]
}
```

## Internal Interface

```typescript
interface TTSEngine {
  // Batch synthesis
  synthesize(request: TTSRequest): Promise<TTSResult>

  // Streaming synthesis
  synthesizeStream(request: TTSRequest): TTSStreamHandle

  // List available voice profiles
  listVoices(filter?: VoiceFilter): Promise<VoiceProfile[]>

  // Get engine/voice capabilities
  getCapabilities(profile_id?: string): Promise<TTSCapabilities>

  // Available synthesis models
  getAvailableModels(): Promise<TTSModelInfo[]>

  // Provider health
  health(): ProviderHealth
}

interface TTSModelInfo {
  model_id: string
  quality: "high" | "standard" | "low"
  languages: string[]
  supports_ssml: boolean
  supports_streaming: boolean
  supports_word_timings: boolean
}

interface TTSStreamHandle {
  readonly stream_id: string
  readonly request: TTSRequest

  read(): Promise<AudioOutput | null>    // null when stream ends
  cancel(): void

  on(event: "data", handler: (chunk: AudioOutput) => void): void
  on(event: "done", handler: () => void): void
  on(event: "error", handler: (error: Error) => void): void
  on(event: "word", handler: (timing: WordTiming) => void): void
}

interface TTSNormalizer {
  normalize(text: string, style: string): NormalizedText
}

interface NormalizedText {
  original: string
  normalized: string
  transformations: NormalizationStep[]
}

interface NormalizationStep {
  original_segment: string
  normalized_segment: string
  rule: string
}

type TTSErrorCode =
  | "VOI_TTS_PROVIDER_ERROR"
  | "VOI_TTS_INVALID_SSML"
  | "VOI_TTS_TEXT_TOO_LONG"
  | "VOI_TTS_VOICE_NOT_FOUND"
  | "VOI_TTS_QUALITY_UNSUPPORTED"
  | "VOI_TTS_STREAM_CANCELLED"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VCE.TTSStarted |     request_id, session_id, text_length, voice, quality | TTS synthesis began |
| VCE.TTSCompleted |     request_id, session_id, format, duration_ms, word_count | Audio synthesis finished |
| VCE.TTSFailed |     request_id, session_id, error_code, reason | Synthesis failed |
| VCE.TTSStreamChunk |     request_id, session_id, chunk_sequence, duration_ms, is_final | Streaming audio chunk emitted |
| VCE.TTSWordSpoken |     request_id, word, start_ms, end_ms | Individual word timing generated |
| VCE.TTSQualityFallback |     request_id, requested_quality, actual_quality, provider | Quality level not available, fell back |
| VCE.TTSVoiceSwitch |     request_id, old_profile_id, new_profile_id | Voice changed mid-synthesis (SSML) |
| VCE.TTSStreamCancelled |     request_id, session_id, chunks_emitted | User cancelled mid-stream |
| VCE.TTSNormalizationApplied |     request_id, transformations_count | Text normalization completed |
| VCE.TTSStreamDone |     request_id, session_id, total_chunks, total_duration_ms | All stream chunks emitted |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| TTS-001 | TTS output never alters the semantic content of Sou's text | Architectural â€” text passes through verbatim; normalization only adjusts surface form |
| TTS-002 | Audio format is consistent across all chunks in a stream | Algorithmic â€” format locked on first chunk |
| TTS-003 | Word timings are monotonically increasing and non-overlapping | Algorithmic â€” each word.start_ms >= previous.end_ms |
| TTS-004 | Quality level fallback never downgrades more than one level | Algorithmic â€” highâ†’standardâ†’low; never skips |
| TTS-005 | SSML parsing fails closed â€” invalid SSML returns error, not raw text | Algorithmic â€” pre-validated before synthesis |
| TTS-006 | Streaming cancellation produces no further audio after cancel() returns | Algorithmic â€” cancel flushes buffer and terminates |
| TTS-007 | Speed, pitch, and volume are clamped to provider-supported ranges | Algorithmic â€” values capped at min/max before dispatch |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Text exceeds provider max length | `VOI_TEXT_TOO_LONG` | Return error; suggest streaming mode and report max length |
| Voice profile not found | `VOI_PROFILE_NOT_FOUND` | Return error; caller should fall back to default profile |
| Malformed SSML in input | `VOI_TTS_INVALID_SSML` | Return error; list invalid tag and line number |
| Provider does not support requested quality | `VOI_TTS_QUALITY_UNSUPPORTED` | Fall back to nearest quality; emit `TTSQualityFallback` event |
| Synthesize called with empty text | `VOI_TTS_EMPTY_TEXT` | Return error; minimum 1 character required |
| Stream cancelled mid-synthesis | `VOI_TTS_STREAM_CANCELLED` | Emit `TTSStreamCancelled`; no error, partial data discarded |
| Unknown provider in VoiceProfileRef | `VOI_PROVIDER_UNAVAILABLE` | Return error; list available providers |
| Speed/pitch/volume out of supported range | `VOI_TTS_PARAM_OUT_OF_RANGE` | Clamp to nearest valid value; emit warning |


## Cross-Cutting Concerns

### Security

Voice System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Voice System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Voice System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Voice System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | TTS Engine handles only text-to-speech synthesis |
| R2 â€” Dependency Order | Depends on Voice Profile Manager for voice resolution; no upward deps |
| R3 â€” DRY | Quality level behavior defined once in config schema |
| R4 â€” Builder Pattern | Streaming pipeline built by request â†’ normalize â†’ synthesize â†’ chunk |
| R5 â€” Liskov Substitution | Any provider adapter implements TTSProvider interface |
| R6 â€” DI over Singletons | Provider adapters, normalizer, and config injected |
| R9 â€” Deterministic | Same text + config produces same audio (provider-model-dependent) |
| R10 â€” Simpler Over Complex | Clear quality tier system with explicit fallback chain |
| R13 â€” Design for Failure | Quality fallback and stream cancellation always handled |
| R14 â€” Paved Path | All synthesis flows through `synthesize()` or `synthesizeStream()` |
| R15 â€” Open/Closed | New TTS providers added via adapter, not by modifying engine core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Voice/000-Overview.md | TTS Engine is a core Voice System component |
| Voice/003-Voice-Profiles.md | Voice profiles selected for TTS voice resolution |
| Voice/004-Streaming.md | Streaming architecture for chunked audio output |
| Brain/Conversation/000-Overview.md | Conversation OS delivers synthesized audio to user |
| Brain/Sou/000-Overview.md | Sou produces text input for TTS |
| Bible/04-Execution/Runtime/ | TTS providers registered as Execution Providers |
