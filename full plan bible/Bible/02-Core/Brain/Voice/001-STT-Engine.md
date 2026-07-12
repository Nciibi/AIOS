# AIOS Bible â€” Brain
## 001 â€” STT Engine

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-001 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The STT Engine converts audio input into text for Sou to process. It supports both real-time streaming transcription and batch processing of pre-recorded audio. The STT Engine abstracts provider-specific implementations behind a unified interface, enabling language detection, speaker diarization, custom vocabulary, punctuation restoration, and profanity filtering. All transcription includes confidence scoring and word-level timing for downstream use by Sou's context system.

Under BRAIN-007 and VOI-002, the STT Engine is stateless â€” audio is ephemeral unless explicitly stored to Memory OS.

## Data Model

### STTRequest

```typescript
STTRequest {
  request_id: string
  audio: AudioInput
  source_language?: string          // If omitted, language detection runs
  config: STTConfig
  session_id: string
}
```

### STTResult

```typescript
STTResult {
  request_id: string
  transcript: string
  confidence: number                // 0.0â€“1.0 overall confidence
  language: string
  language_confidence?: number      // 0.0â€“1.0, only if detection ran
  words: WordTiming[]
  speaker_labels?: SpeakerLabel[]   // Only if diarization enabled
  duration_ms: number
  processing_time_ms: number
  is_final: boolean                 // false for streaming chunks
  alternatives?: string[]           // max_alternatives > 1
}
```

### WordTiming

```typescript
WordTiming {
  word: string
  start_ms: number
  end_ms: number
  confidence: number                // 0.0â€“1.0 per-word confidence
  speaker_tag?: number              // Speaker label if diarization enabled
}
```

### SpeakerLabel

```typescript
SpeakerLabel {
  speaker_tag: number
  speaker_name?: string             // Resolved from known profiles
  start_ms: number
  end_ms: number
}
```

### STTConfig

```typescript
STTConfig {
  model: string                     // Provider-specific model ID
  language_hints?: string[]
  punctuation: boolean              // Restore punctuation
  diarization: boolean              // Enable speaker diarization
  max_alternatives: number          // Alternative transcriptions (0 = none)
  profanity_filter: boolean         // Mask profanity
  custom_vocabulary?: CustomVocabEntry[]
  timeout_ms: number                // Max time before streaming timeout
}
```

### CustomVocabEntry

```typescript
CustomVocabEntry {
  phrase: string
  boost: number                     // 1â€“20 recognition boost
  sounds_like?: string[]            // Phonetic hints
}
```

### AudioInput

```typescript
AudioInput {
  data: bytes
  format: "wav" | "mp3" | "ogg" | "webm" | "pcm"
  sample_rate: number
  channels: number
  duration_ms: number
}
```

## Core Concepts

### Real-Time vs Batch Transcription

| Mode | Latency | Use Case | Output |
|------|---------|----------|--------|
| Real-time (streaming) | < 300ms per chunk | Live conversation | `is_final: false` per chunk, `is_final: true` on end |
| Batch | Processing-time dependent | Pre-recorded uploads | Single `STTResult` with `is_final: true` |

### Language Detection

When `source_language` is omitted, the STT Engine auto-detects language from the first 5 seconds of audio:

```typescript
DetectedLanguage {
  language: string                  // BCP-47 tag
  confidence: number                // 0.0â€“1.0
  alternatives: { language: string, confidence: number }[]
}
```

Detection is re-evaluated on each streaming chunk if confidence is below 0.7.

### Speaker Diarization

When `config.diarization` is true, each word is assigned a `speaker_tag`. The speaker count is auto-detected (up to 10) or pre-configured via config. Speaker tags are stable across streaming chunks within a single session.

### Custom Vocabulary

Domain-specific terms are supplied via `custom_vocabulary` entries. Each entry has a `boost` value that increases recognition weight:

| Boost Range | Effect |
|-------------|--------|
| 1â€“5 | Mild preference |
| 6â€“10 | Strong preference â€” likely overrides acoustically similar terms |
| 11â€“20 | Explicit override â€” forces recognition (use with care) |

### Punctuation Restoration

When `config.punctuation` is true, the STT Engine adds `.`, `,`, `?`, `!`, `:`, `;` to the raw transcript. Punctuation is restored as a post-recognition step using a dedicated model, not inferred from audio pauses.

### Profanity Filtering

When `config.profanity_filter` is true, recognized profanity is replaced with `[redacted]`. Filtering runs after transcription and does not affect confidence scoring. Filtered words are counted and reported in metadata:

```typescript
ProfanityReport {
  total_masked: number
  masked_words: string[]             // Original words that were masked
}
```

## Accuracy Targets

| Condition | Target WER | Notes |
|-----------|-----------|-------|
| Clean audio, native language | < 5% | Ideal conditions, no background noise |
| Background noise, native | < 10% | Moderate background noise (e.g., office) |
| Accented speech | < 12% | Non-native accent, all noise conditions |
| Multiple speakers (diarization) | < 15% | Speaker identification error included |
| Streaming, real-time | < 10% | Incremental on partial utterances |
| Low bandwidth / compressed audio | < 15% | Audio < 16kHz sample rate |
| Punctuation restoration | > 95% F1 | Accuracy of inserted punctuation marks |

## Operations

### Transcribe (Batch)

```typescript
transcribe(request: STTRequest): Promise<STTResult>
```

- Accepts full AudioInput and processes entirely
- Returns single `STTResult` with `is_final: true`
- Language detection runs if `source_language` omitted
- Confidence is aggregate over all words

### Transcribe Stream

```typescript
transcribeStream(initialChunk: AudioInput): Promise<STTStreamHandle>

STTStreamHandle {
  push(chunk: AudioInput): Promise<void>
  onResult(callback: (result: STTResult) => void): void
  onError(callback: (error: STTError) => void): void
  close(): Promise<STTResult>       // Returns final result
  cancel(): void
}
```

- Accepts audio chunks as they arrive
- Emits partial `STTResult` with `is_final: false`
- Final `close()` returns complete transcript
- Each chunk must match format/sample_rate/channels of initial chunk

### Detect Language

```typescript
detectLanguage(audio: AudioInput): Promise<DetectedLanguage>
```

- Runs language detection on provided audio
- Uses first 5 seconds or full audio if shorter
- Returns confidence-sorted alternatives

### Get Word Timings

```typescript
getWordTimings(result_id: string): Promise<WordTiming[]>
```

- Retrieves word-level timing for a completed result
- Used by downstream for alignment with other modalities
- Results are ephemeral unless explicit storage requested

## Internal Interface

```typescript
interface STTEngine {
  // Batch transcription
  transcribe(request: STTRequest): Promise<STTResult>

  // Streaming transcription
  transcribeStream(request: STTRequest): STTStreamHandle

  // Language detection on audio sample
  detectLanguage(audio: AudioInput): Promise<DetectedLanguage>

  // Retrieve word-level timings for completed result
  getWordTimings(result_id: string): Promise<WordTiming[]>

  // List available models for the configured provider
  getAvailableModels(): Promise<STTModelInfo[]>

  // Provider health
  health(): ProviderHealth
}

interface STTModelInfo {
  model_id: string
  languages: string[]
  supports_streaming: boolean
  supports_diarization: boolean
  supports_custom_vocabulary: boolean
  latency_tier: "low" | "medium" | "high"
}

interface STTStreamHandle {
  readonly stream_id: string
  readonly request: STTRequest

  push(chunk: AudioInput): Promise<void>
  close(): Promise<STTResult>
  cancel(): void

  on(event: "result", handler: (result: STTResult) => void): void
  on(event: "error", handler: (error: Error) => void): void
  on(event: "close", handler: () => void): void
}

interface ProviderHealth {
  status: "healthy" | "degraded" | "unavailable"
  latency_ms: number
  last_check: timestamp
  error_rate: number               // 0.0â€“1.0 over last 100 requests
}

interface STTConfigDefaults {
  default_model: string
  default_timeout_ms: number
  max_alternatives_limit: number
  max_custom_vocab_entries: number
  supported_formats: string[]
}

type STTErrorCode =
  | "VOI_STT_PROVIDER_ERROR"
  | "VOI_STT_INVALID_AUDIO"
  | "VOI_STT_LOW_CONFIDENCE"
  | "VOI_STT_TIMEOUT"
  | "VOI_STT_LANGUAGE_UNSUPPORTED"
  | "VOI_STT_DIARIZATION_FAILED"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VCE.STTStarted |     request_id, session_id, format, duration_ms, model | STT processing began |
| VCE.STTCompleted |     request_id, session_id, transcript_length, confidence, language | Transcription finished |
| VCE.STTFailed |     request_id, session_id, error_code, reason | Transcription failed |
| VCE.STTStreamChunk |     request_id, session_id, partial_transcript, confidence, is_final | Streaming transcript chunk emitted |
| VCE.STTLanguageDetected |     request_id, session_id, language, confidence | Language auto-detected |
| VCE.STTSpeakerIdentified |     request_id, speaker_tag, duration_ms | New speaker detected in diarization |
| VCE.STTProfanityFiltered |     request_id, total_masked, original_words | Profanity was masked |
| VCE.STTCustomVocabApplied |     request_id, entries_matched, boosts_applied | Custom vocabulary influenced recognition |
| VCE.STTAlternativeGenerated |     request_id, alternative_count | Alternative transcriptions produced |
| VCE.STTStreamTimeout |     request_id, session_id, chunks_received, partial_transcript | Stream closed due to timeout |
| VCE.STTModelChanged |     model_id, request_id | Streaming model switched mid-stream |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| STT-001 | Every STT result includes a confidence score between 0.0 and 1.0 | Schema â€” required field |
| STT-002 | Audio input format must match the first chunk's format throughout a stream | Algorithmic â€” format validated on each push |
| STT-003 | Language detection is idempotent for identical audio | Model-dependent â€” same input returns same language |
| STT-004 | Profanity filtering never changes confidence scores | Algorithmic â€” filter runs post-recognition |
| STT-005 | Custom vocabulary entries are validated for boost range (1â€“20) | Schema â€” boost range enforced at config parse |
| STT-006 | Streaming results are monotonically additive â€” later chunks supersede earlier ones | Algorithmic â€” partial results aggregate forward |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Audio format not supported | `VOI_UNSUPPORTED_FORMAT` | Return error; list supported formats in error message |
| No provider supports requested language | `VOI_LANGUAGE_NOT_SUPPORTED` | Return error; suggest fallback language |
| Confidence below `STTConfig.min_confidence` threshold | `VOI_STT_LOW_CONFIDENCE` | Return transcript with `low_confidence` flag; caller decides |
| Audio shorter than 100ms | `VOI_AUDIO_TOO_SHORT` | Return error; minimum duration is 100ms |
| Stream chunk format mismatch | `VOI_STT_INVALID_AUDIO` | Close stream; emit error on handle |
| Streaming timeout reached | `VOI_STT_TIMEOUT` | Close stream; emit partial result with `is_final: true` |
| Diarization fails to separate speakers | `VOI_STT_DIARIZATION_FAILED` | Return transcript without speaker labels; emit warning event |
| Custom vocab exceeds max entries | `VOI_INVALID_CONFIG` | Truncate to max; emit warning |


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
| R1 â€” Modulsingularity | STT Engine handles only speech-to-text conversion |
| R2 â€” Dependency Order | Depends on Voice Router for provider selection; no upward deps |
| R3 â€” DRY | Audio format validation defined once in shared utilities |
| R4 â€” Builder Pattern | Streaming pipeline built by open â†’ push chunks â†’ close |
| R5 â€” Liskov Substitution | Any provider adapter implements STTProvider interface |
| R6 â€” DI over Singletons | Provider adapters and config injected |
| R9 â€” Deterministic | Same audio + config produces same transcript (provider-model-dependent) |
| R10 â€” Simpler Over Complex | Clear batch/streaming split with shared config model |
| R13 â€” Design for Failure | Stream timeout, low confidence, provider errors all handled gracefully |
| R14 â€” Paved Path | All transcription flows through `transcribe()` or `transcribeStream()` |
| R15 â€” Open/Closed | New STT providers added via adapter, not by modifying engine core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Voice/000-Overview.md | STT Engine is a core Voice System component |
| Voice/004-Streaming.md | Streaming architecture for STT chunked processing |
| Voice/005-Emotion-Detection.md | Emotion detection runs alongside STT transcription |
| Voice/003-Voice-Profiles.md | Voice profiles may influence STT language defaults |
| Brain/Conversation/000-Overview.md | Conversation OS routes audio to STT Engine |
| Brain/Sou/000-Overview.md | Sou consumes STTResult for understanding |
| Bible/04-Execution/Runtime/ | STT providers registered as Execution Providers |
