# AIOS Bible â€” Brain
## 005 â€” Emotion Detection

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-005 |
| Source Laws | Law 3 â€” Law of Communication, Law 4 â€” Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Emotion Detection analyzes paralinguistic features of the user's voice (tone, pitch, pace, volume) to infer emotional state during STT processing. Detected emotions are passed as metadata alongside transcribed text, enabling Sou to adjust tone, empathy, or response strategy based on the user's emotional context. Emotion detection runs in real-time alongside streaming transcription and is purely ephemeral â€” emotion data is never persisted to Memory OS unless explicitly requested by Sou for diagnostics.

Under VOI-001, Emotion Detection infers emotional state from acoustic features, not from semantic content analysis.

## Data Model

### EmotionResult

```typescript
EmotionResult {
  request_id: string
  session_id: string
  primary_emotion: EmotionCategory
  primary_confidence: number          // 0.0â€“1.0 confidence in primary
  secondary_emotion?: EmotionCategory
  secondary_confidence?: number
  emotions: EmotionScores             // Scores for all categories
  timeline_segment?: EmotionTimelineSegment
  analysis: {
    features: AcousticFeatures
    duration_ms: number
    processing_time_ms: number
    model: string
  }
}
```

### EmotionCategory

```typescript
type EmotionCategory =
  | "happy"
  | "sad"
  | "angry"
  | "fearful"
  | "surprised"
  | "neutral"

// Emotion categories with dominant acoustic markers
EmotionAcousticProfile {
  happy:    { pitch: "high", pace: "fast", volume: "loud", tone: "bright" }
  sad:      { pitch: "low",  pace: "slow", volume: "quiet", tone: "dull" }
  angry:    { pitch: "loud", pace: "fast", volume: "loud", tone: "harsh" }
  fearful:  { pitch: "high", pace: "fast", volume: "variable", tone: "trembling" }
  surprised: { pitch: "high", pace: "pause-then-fast", volume: "loud", tone: "sharp" }
  neutral:  { pitch: "mid",  pace: "normal", volume: "moderate", tone: "even" }
}
```

### EmotionScores

```typescript
EmotionScores {
  happy: number                       // 0.0â€“1.0
  sad: number
  angry: number
  fearful: number
  surprised: number
  neutral: number                     // Always present, higher = less emotional
}
```

### AcousticFeatures

```typescript
AcousticFeatures {
  pitch_mean: number                  // Hz
  pitch_variance: number
  pitch_contour: "rising" | "falling" | "flat" | "variable"
  speaking_rate: number               // Words per minute
  volume_mean: number                 // RMS energy 0.0â€“1.0
  volume_variance: number
  voice_quality: "clear" | "breathy" | "creaky" | "strained"
  pauses: {
    count: number
    total_duration_ms: number
    avg_duration_ms: number
  }
}
```

### EmotionTimelineSegment

```typescript
EmotionTimelineSegment {
  start_ms: number
  end_ms: number
  primary_emotion: EmotionCategory
  primary_confidence: number
  acoustic_features: AcousticFeatures
}
```

## Core Concepts

### Emotion Categories

| Category | Description | Behavioral Signal for Sou |
|----------|-------------|--------------------------|
| happy | Positive affect, satisfaction, pleasure | Maintain tone, reinforce positive outcome |
| sad | Negative affect, disappointment, grief | Empathize, offer support, adjust pacing |
| angry | Frustration, annoyance, hostility | De-escalate, apologize if appropriate, stay calm |
| fearful | Anxiety, uncertainty, nervousness | Reassure, provide clarity, slow down |
| surprised | Startled, amazed, shocked | Acknowledge, explain if unexpected |
| neutral | Baseline, no strong emotional signal | Continue standard interaction |

### Acoustic Analysis

Emotion detection analyzes four primary acoustic dimensions:

| Dimension | Feature Extraction | Emotion Correlation |
|-----------|-------------------|---------------------|
| Pitch (F0) | Fundamental frequency mean, variance, contour | High pitch â†’ happy/surprised/fearful; Low pitch â†’ sad/neutral |
| Pace | Speaking rate in words per minute, pause patterns | Fast pace â†’ happy/angry/anxious; Slow pace â†’ sad/thoughtful |
| Volume | RMS energy, dynamic range | Loud â†’ angry/happy/surprised; Quiet â†’ sad/fearful |
| Tone | Spectral tilt, harmonics-to-noise ratio | Harsh â†’ angry; Breathy â†’ fearful/sad; Clear â†’ happy/neutral |

### Real-Time Detection During STT

Emotion detection runs in parallel with STT streaming:

```
STT Transcription Stream
    â”‚
    â”œâ”€â”€ Audio Chunk â†’ STT Engine â†’ Partial Transcript
    â”‚
    â””â”€â”€ Audio Chunk â†’ EmotionDetector â†’ EmotionResult
                                          â”‚
                                          â–¼
                              Context Metadata (ephemeral)
                                          â”‚
                                          â–¼
                                  Sou's Response Strategy
```

Emotion results are emitted at the same cadence as STT partial results. Each emotion result covers the audio segment since the last emission.

### Emotion Metadata Passing

Emotion results are attached as metadata to the STT result flowing into Sou:

```typescript
ContextEnrichedTranscript {
  transcript: string
  emotion?: EmotionResult
  confidence: number
  language: string
}
```

Sou reads `emotion` from context to adjust response tone. The emotion data is accessible in the context window but is not stored in Working Memory unless Sou explicitly pins it.

### Privacy Considerations

Emotion data is ephemeral by default under these rules:

| Rule | Enforcement |
|------|-------------|
| Emotion data is not persisted to Memory OS | Architectural â€” EmotionResult is never written to storage layer |
| Emotion data is not logged (except anonymous metrics) | Algorithmic â€” log filter strips emotion fields |
| Emotion data expires with the session context | Lifecycle â€” cleared when session ends |
| Emotion detection is opt-in per session | Config â€” `detect_emotion: boolean` on session init |
| Raw acoustic features are never stored | Architectural â€” only emotion category + confidence passed through |
| Users are informed that emotion detection is active | Policy â€” Conversation OS registers disclosure via privacy notice |

## Operations

### Detect Emotion

```typescript
detectEmotion(audio: AudioInput, request_id: string): Promise<EmotionResult>
```

- Processes full audio segment and returns single emotion result
- Used for batch detection (non-streaming)
- Returns confidence-sorted emotion scores

### Get Emotion Timeline

```typescript
getEmotionTimeline(session_id: string, request_id: string): Promise<EmotionTimelineSegment[]>
```

- Returns ordered segments of emotion state over the course of an utterance
- Each segment covers a time range with a dominant emotion
- Available only during the current session; cleared on session end

### Get Confidence

```typescript
getConfidence(emotion: EmotionCategory, result_id: string): Promise<number>
```

- Returns the confidence score for a specific emotion category in a given result
- Useful for Sou to threshold: "only act on anger if confidence > 0.8"

### Streaming Emotion Detection

```typescript
detectEmotionStream(session_id: string, initialChunk: AudioInput): Promise<EmotionStreamHandle>

EmotionStreamHandle {
  push(chunk: AudioInput): Promise<void>
  onEmotion(handler: (result: EmotionResult) => void): void
  close(): Promise<EmotionResult>     // Consolidated result for full utterance
  cancel(): void
}
```

- Works alongside `STTStreamHandle`
- Emits `EmotionResult` at the same cadence
- Final `close()` returns consolidated emotion for the entire utterance

## Internal Interface

```typescript
interface EmotionDetector {
  // Batch emotion detection
  detectEmotion(audio: AudioInput, request_id: string): Promise<EmotionResult>

  // Streaming emotion detection
  detectEmotionStream(session_id: string, initialChunk: AudioInput): EmotionStreamHandle

  // Timeline access (session-scoped)
  getEmotionTimeline(session_id: string, request_id: string): Promise<EmotionTimelineSegment[]>

  // Confidence query
  getConfidence(emotion: EmotionCategory, result_id: string): Promise<number>

  // Thresholds
  getConfidenceThreshold(): Promise<number>          // Min confidence to report emotion
  setConfidenceThreshold(threshold: number): Promise<void>

  // Available models
  getAvailableModels(): Promise<EmotionModelInfo[]>

  // Provider health
  health(): ProviderHealth
}

interface EmotionModelInfo {
  model_id: string
  categories: EmotionCategory[]          // Which emotions the model can detect
  supports_streaming: boolean
  latency_tier: "low" | "medium" | "high"
  languages: string[]                    // Language-specific models
}

interface EmotionStreamHandle {
  readonly stream_id: string
  readonly session_id: string

  push(chunk: AudioInput): Promise<void>
  close(): Promise<EmotionResult>
  cancel(): void

  on(event: "emotion", handler: (result: EmotionResult) => void): void
  on(event: "error", handler: (error: Error) => void): void
  on(event: "done", handler: () => void): void
}

interface EmotionDetectionConfig {
  enabled: boolean
  model: string
  confidence_threshold: number           // 0.0â€“1.0, default 0.6
  emit_interim_results: boolean          // Emit during streaming vs only on final
  include_acoustic_features: boolean     // Include raw acoustic data (privacy-sensitive)
  max_timeline_segments: number          // Max segments per utterance
}

type EmotionErrorCode =
  | "VOI_EMOTION_PROVIDER_ERROR"
  | "VOI_EMOTION_LOW_CONFIDENCE"
  | "VOI_EMOTION_INSUFFICIENT_AUDIO"
  | "VOI_EMOTION_MODEL_UNSUPPORTED"
  | "VOI_EMOTION_DISABLED"
  | "VOI_EMOTION_PREVIOUSLY_CANCELLED"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VCE.EmotionDetected |   request_id, session_id, primary_emotion, confidence | Emotion result produced |
| VCE.EmotionStreamChunk |   request_id, session_id, primary_emotion, confidence, is_final | Streaming emotion result |
| VCE.EmotionTimelineUpdated |   session_id, request_id, segments_count | Timeline segment added |
| VCE.EmotionLowConfidence |   request_id, top_emotion, confidence | No emotion above threshold |
| VCE.EmotionThresholdChanged |   old_threshold, new_threshold | Confidence threshold updated |
| VCE.EmotionFeatureExtracted |   request_id, pitch_mean, speaking_rate, volume_mean | Acoustic features computed |
| VCE.EmotionStreamStarted |   stream_id, session_id, model | Emotion detection stream began |
| VCE.EmotionStreamEnded |   stream_id, session_id, segments_count | Emotion detection stream ended |
| VCE.EmotionConfigurationChanged |   enabled, threshold, model | Emotion detection config updated |
| VCE.EmotionPrivacyFilterApplied |   request_id, fields_stripped | Acoustic features stripped per privacy config |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| EMD-001 | Emotion detection is based on acoustic features only, never on transcript content | Architectural â€” no NLP pipeline in EmotionDetector |
| EMD-002 | Emotion data is ephemeral and never persisted to Memory OS by default | Algorithmic â€” storage layer rejects emotion fields |
| EMD-003 | The sum of all emotion category scores always equals 1.0 | Algorithmic â€” scores are softmax-normalized |
| EMD-004 | Neutral is always reported; at least neutral has a non-zero score | Algorithmic â€” baseline neutral always included |
| EMD-005 | Emotion detection runs only when `detect_emotion: true` in session config | Config â€” entire pipeline skipped when disabled |
| EMD-006 | Emotion timeline segments are non-overlapping and cover the full utterance | Algorithmic â€” segments partition the timeline without gaps |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Audio too short for emotion analysis (< 500ms) | `VOI_EMOTION_INSUFFICIENT_AUDIO` | Return neutral with low confidence; log warning |
| All emotion scores below confidence threshold | `VOI_EMOTION_LOW_CONFIDENCE` | Return neutral with scores; flag `low_confidence` |
| Provider model does not support requested language | `VOI_EMOTION_MODEL_UNSUPPORTED` | Fall back to generic model; emit warning event |
| Emotion detection disabled in session config | `VOI_EMOTION_DISABLED` | Return null; no action taken |
| Stream cancelled during emotion processing | `VOI_EMOTION_PREVIOUSLY_CANCELLED` | Discard partial results; emit no final result |
| Provider unavailable | `VOI_EMOTION_PROVIDER_ERROR` | Emit error on stream; continue STT without emotion data |
| Privacy config strips acoustic features but model requires them | `VOI_EMOTION_INSUFFICIENT_AUDIO` | Use reduced feature set; emit `EmotionPrivacyFilterApplied` |


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
| R1 â€” Modulsingularity | Emotion Detection handles only paralinguistic emotion inference |
| R2 â€” Dependency Order | Depends on STT Engine for audio pipeline; no upward deps on Sou or Conversation OS |
| R3 â€” DRY | Emotion category definitions and acoustic profiles defined once |
| R4 â€” Builder Pattern | Emotion result built by AcousticAnalysis â†’ Classification â†’ Scoring |
| R5 â€” Liskov Substitution | Any EmotionDetector implementation produces EmotionResult-compatible output |
| R6 â€” DI over Singletons | Detection models and config injected |
| R9 â€” Deterministic | Same audio produces same emotion scores (model-dependent) |
| R10 â€” Simpler Over Complex | Six emotion categories with clear acoustic markers |
| R13 â€” Design for Failure | Low confidence and model fallback always return at least neutral |
| R14 â€” Paved Path | Detection flows through `detectEmotion()` or `detectEmotionStream()` |
| R15 â€” Open/Closed | New emotion categories added by extending type union and acoustic profiles |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Voice/000-Overview.md | Emotion Detection is an auxiliary Voice System component |
| Voice/001-STT-Engine.md | Emotion detection runs alongside STT on the same audio |
| Voice/004-Streaming.md | Emotion detection uses streaming infrastructure for real-time results |
| Brain/Sou/000-Overview.md | Sou reads emotion data from context to adjust response |
| Brain/Context/000-Overview.md | Emotion metadata is passed through the context window |
| Brain/Conversation/000-Overview.md | Conversation OS manages emotion privacy disclosure |
| Bible/05-Platform/005-AUS.md | Emotion timeline cleared on session end |
