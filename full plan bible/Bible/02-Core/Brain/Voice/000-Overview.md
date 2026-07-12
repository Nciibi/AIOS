# AIOS Bible — Brain
## 000 — Voice System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-000 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Voice System provides speech input and output capabilities for the Brain. It converts spoken language into text for Sou to process (speech-to-text / STT) and converts Sou's text responses into spoken audio (text-to-speech / TTS). The Voice System is the auditory sensory and motor interface of the Brain.

Voice I/O is one modality managed by Conversation OS. When a user speaks, Conversation OS routes the audio to Voice System for transcription before the text reaches Sou. When Sou responds, Conversation OS requests Voice System to synthesize speech before delivering to the user.

## Architecture

```
Conversation OS (modality adapter)
    ▲                         │
    │                         ▼
    │              ┌──────────────────────┐
    │              │    Voice System       │
    │              │                      │
    │              │  ┌──────────┐        │
    │              │  │  STT      │        │
    │              │  │ Engine   │         │
    │              │  └────┬─────┘        │
    │              │       │              │
    │              │  ┌────▼─────┐        │
    ├──────────────┼──│  TTS      │        │
    │              │  │ Engine   │         │
    │              │  └──────────┘        │
    │              │                      │
    │              │  ┌──────────┐        │
    │              │  │  Voice    │        │
    │              │  │  Router   │        │
    │              │  └──────────┘        │
    │              │                      │
    │              │  ┌──────────┐        │
    │              │  │  Voice    │        │
    │              │  │  Profile  │        │
    │              │  └──────────┘        │
    └──────────────┴──────────────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │  Provider    │
                  │  SDK         │
                  └──────────────┘
```

Voice System is stateless per BRAIN-007. Audio files and processing history are persisted through Memory OS.

## Core Concepts

### Voice Model

```
STTRequest {
  request_id: string
  audio: AudioInput
  source_language?: string
  config: STTConfig
  session_id: string
}

STTResult {
  request_id: string
  transcript: string
  confidence: number           // 0.0–1.0
  language: string
  words: WordTiming[]
  duration_ms: number
  processing_time_ms: number
}

WordTiming {
  word: string
  start_ms: number
  end_ms: number
  confidence: number
}

TTSRequest {
  request_id: string
  text: string
  voice: VoiceProfileRef
  config: TTSConfig
  session_id: string
}

TTSResult {
  request_id: string
  audio: AudioOutput
  format: string               // "wav" | "mp3" | "ogg" | "pcm"
  duration_ms: number
  processing_time_ms: number
}

AudioInput {
  data: bytes
  format: string               // "wav" | "mp3" | "ogg" | "webm" | "pcm"
  sample_rate: number
  channels: number
  duration_ms: number
}

AudioOutput {
  data: bytes
  format: string
  sample_rate: number
  channels: number
}

STTConfig {
  model: string                // Which STT model to use
  language_hints?: string[]    // Expected languages for accuracy
  punctuation: boolean
  diarization: boolean         // Speaker diarization (multiple speakers)
  max_alternatives: number     // Max alternative transcriptions
  timeout_ms: number
}

TTSConfig {
  model: string                // Which TTS model to use
  speed: number                // 0.5–2.0 speech rate multiplier
  pitch: number                // -0.5–0.5 semitone adjustment
  volume: number               // 0.0–1.0
  emphasis?: string            // "strong" | "moderate" | "reduced"
  style?: string               // "neutral" | "conversational" | "announcement"
}

VoiceProfileRef {
  profile_id: string
  provider: string
  voice_name: string
}

VoiceProfile {
  profile_id: string
  name: string                 // User-facing name for this voice
  provider: string
  voice_name: string           // Provider-specific voice ID
  language: string
  gender?: "male" | "female" | "neutral"
  sample_url?: string          // URL to audio sample
  metadata: {
    created_at: timestamp
    updated_at: timestamp
    usage_count: number
    last_used: timestamp
  }
}
```

### 1. STT Engine — Speech-to-Text

Converts audio input into text. Supports multiple providers and languages:

| Capability | Description |
|------------|-------------|
| Real-time STT | Stream audio, receive incremental transcripts |
| Batch STT | Process pre-recorded audio files |
| Language detection | Auto-detect spoken language |
| Speaker diarization | Identify who spoke when (multi-speaker) |
| Custom vocabulary | Domain-specific terms for accuracy |
| Punctuation restoration | Automatic punctuation in output |
| Profanity filtering | Optional redaction of flagged words |

STT accuracy targets:

| Condition | Target WER | Notes |
|-----------|-----------|-------|
| Clean audio, native language | < 5% | Ideal conditions |
| Background noise, native | < 10% | Moderate noise |
| Accented speech | < 12% | Non-native accent |
| Multiple speakers | < 15% | Diarization ON |
| Streaming, real-time | < 10% | Incremental, partial utterances |

### 2. TTS Engine — Text-to-Speech

Converts text into spoken audio. Supports multiple voices and styles:

| Capability | Description |
|------------|-------------|
| Neural TTS | Deep learning-based natural speech |
| Voice selection | Multiple voices per provider |
| Style control | Conversational, announcement, neutral |
| Speed/pitch adjustment | Per-request modulation |
| SSML support | Speech Synthesis Markup Language |
| Word-level timing | Timestamps for each word |
| Streaming TTS | Chunked audio output for long text |

TTS quality levels:

| Level | Quality | Use Case | Latency |
|-------|---------|----------|---------|
| High | Neural, full prosody | User-facing dialogue | < 1s first chunk |
| Standard | Neural, reduced | Notifications, alerts | < 500ms |
| Low | Concatenative | System-internal, debugging | < 200ms |

### 3. Voice Router

Routes STT/TTS requests to the appropriate provider based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Language support | Required | Provider must support requested language |
| Quality tier | 0.35 | Match quality to use case |
| Latency requirement | 0.30 | Real-time vs batch |
| Cost | 0.20 | Per-character/per-second pricing |
| Availability | 0.15 | Provider health and capacity |

### 4. Voice Profile Manager

Manages voice profiles for users and contexts:

| Profile Type | Scope | Example |
|-------------|-------|---------|
| Default system voice | System-wide | "Sou's voice" |
| User preference | Per-user | User A prefers deep male voice |
| Context override | Per-session | Announcement mode for briefings |
| Custom voice | User-created | Cloned voice from samples |

User voice preferences are stored in Memory OS via Conversation OS UserPreferences.

## Interfaces

### Voice System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `stt(request)` | Sou, Conversation OS | Transcribe audio to text |
| `sttStream(initial_chunk)` | Sou, Conversation OS | Start streaming transcription |
| `tts(request)` | Sou, Conversation OS | Synthesize speech from text |
| `ttsStream(initial_chunk)` | Sou, Conversation OS | Start streaming synthesis |
| `listVoices(filter?)` | Sou only | List available voice profiles |
| `getVoice(profile_id)` | Sou only | Get voice profile details |
| `createVoice(profile)` | Sou only | Create a custom voice profile |
| `deleteVoice(profile_id)` | Sou only | Delete a voice profile |
| `getProviders()` | Sou only | List registered voice providers |

### Internal Interfaces

```
interface STTProvider {
  transcribe(audio: AudioInput, config: STTConfig): Promise<STTResult>
  transcribeStream(audio: AsyncIterable<AudioInput>): AsyncIterable<STTResult>
  health(): ProviderHealth
}

interface TTSProvider {
  synthesize(text: string, voice: VoiceProfileRef, config: TTSConfig): Promise<TTSResult>
  synthesizeStream(text: AsyncIterable<string>, voice: VoiceProfileRef, config: TTSConfig): AsyncIterable<AudioOutput>
  health(): ProviderHealth
}

interface VoiceRouterStrategy {
  selectSTTProvider(requirements: STTRequirements): STTProvider
  selectTTSProvider(requirements: TTSRequirements): TTSProvider
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `VOI.STTStarted` | request_id, audio_format, duration_ms | STT processing began |
| `VOI.STTCompleted` | request_id, transcript_length, confidence | Transcription finished |
| `VOI.STTFailed` | request_id, error_code, reason | Transcription failed |
| `VOI.STTStreamChunk` | request_id, partial_transcript, is_final | Streaming transcript chunk |
| `VOI.TTSStarted` | request_id, text_length, voice | TTS synthesis began |
| `VOI.TTSCompleted` | request_id, audio_format, duration_ms | Audio synthesis finished |
| `VOI.TTSFailed` | request_id, error_code, reason | Synthesis failed |
| `VOI.TTSStreamChunk` | request_id, chunk_sequence, is_final | Streaming audio chunk |
| `VOI.VoiceProfileCreated` | profile_id, provider, voice_name | New voice profile created |
| `VOI.VoiceProfileDeleted` | profile_id, provider | Voice profile removed |
| `VOI.ProviderHealthChanged` | provider, status | Voice provider health transitioned |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VOI-001 | Voice System never interprets meaning — it transcribes and synthesizes only | Architectural — no NLP in Voice System |
| VOI-002 | All audio data is ephemeral unless explicitly stored to Memory OS | Architectural — stateless per BRAIN-007 |
| VOI-003 | STT results always include a confidence score | Schema — required field on STTResult |
| VOI-004 | TTS never modifies Sou's text content | Architectural — text passes through verbatim |
| VOI-005 | Voice profiles are scoped to the user who created them | API-level — authorization enforced |
| VOI-006 | Streaming is always cancellable mid-stream | API-level — cancel signal on stream handle |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Voice System is a Brain Service |
| Brain/Conversation/000-Overview.md | Conversation OS routes audio to/from Voice System |
| Brain/Sou/000-Overview.md | Sou consumes STT output and produces TTS input |
| Brain/Memory/ | Voice profiles and audio history persisted here |
| Bible/04-Execution/Runtime/ | Voice providers are registered as Execution Providers |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unsupported audio format | `VOI_UNSUPPORTED_FORMAT` | Return error; list supported formats |
| No provider available for language | `VOI_LANGUAGE_NOT_SUPPORTED` | Return error; list supported languages |
| STT confidence below threshold | `VOI_LOW_CONFIDENCE` | Return transcript with low confidence flag |
| TTS text exceeds length limit | `VOI_TEXT_TOO_LONG` | Return error; suggest streaming |
| Voice profile not found | `VOI_PROFILE_NOT_FOUND` | Return error; fall back to default |
| Provider unavailable | `VOI_PROVIDER_UNAVAILABLE` | Queue request; fail after timeout |
| Audio too short for STT | `VOI_AUDIO_TOO_SHORT` | Return error; minimum duration requirement |
| Streaming timeout | `VOI_STREAM_TIMEOUT` | Close stream with partial results |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Voice System does one thing: speech I/O |
| R2 — Dependency Order | Depends on Memory OS, Conversation OS; no upward deps |
| R3 — DRY | Voice profiles defined once in Profile Manager |
| R4 — Builder Pattern | Audio pipeline built by Router → Provider → Stream |
| R5 — Liskov Substitution | Any STTProvider/TTSProvider implements the interface |
| R6 — DI over Singletons | Providers and routing strategies injected |
| R9 — Deterministic | Same audio+config produces same transcript (model-dependent) |
| R10 — Simpler Over Complex | Uses clear STT/TTS split with shared profile management |
| R13 — Design for Failure | Provider failover and streaming timeouts always handled |
| R14 — Paved Path | All voice I/O flows through `stt` and `tts` |
| R15 — Open/Closed | New providers added via Provider SDK, not by modifying core |
