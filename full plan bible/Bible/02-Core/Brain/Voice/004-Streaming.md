# AIOS Bible — Brain
## 004 — Streaming

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Voice |
| Document ID | AIOS-BBL-002-VCE-004 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence |
| Source Physics | Physics/009-Interaction.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Streaming system provides the architectural foundation for real-time, chunked audio processing in both STT and TTS pipelines. It manages stream lifecycle (open → data → close), handles backpressure between audio producers and consumers, supports mid-stream cancellation, enforces stream timeouts, and provides error recovery strategies during active streams. The Streaming system ensures that voice I/O is responsive, resource-efficient, and robust in the face of network interruptions or provider failures.

Under VOI-006, all streams are cancellable mid-stream. No stream holds resources indefinitely.

## Data Model

### StreamHandle

```typescript
StreamHandle {
  stream_id: string
  type: "stt" | "tts"
  session_id: string
  status: "open" | "active" | "closing" | "closed" | "cancelled" | "errored"
  config: StreamConfig
  created_at: timestamp
  last_activity: timestamp
  bytes_processed: number
  chunks_received: number
  chunks_emitted: number
  duration_ms: number
}
```

### StreamConfig

```typescript
StreamConfig {
  // Common
  timeout_ms: number                 // Max idle time between chunks (default: 30s)
  max_stream_duration_ms: number     // Max total stream lifetime (default: 300s)
  max_chunks: number                 // Max chunks before auto-close (default: 10000)
  buffer_size: number                // Internal buffer size in bytes
  backpressure_strategy: "drop" | "buffer" | "throttle" | "block"

  // STT-specific
  stt?: {
    partial_results_interval_ms: number   // Emit partial result every N ms
    finalize_on_timeout: boolean          // Auto-finalize when timeout hits
    max_alternative_chunks: number
  }

  // TTS-specific
  tts?: {
    chunk_size_ms: number             // Target duration per audio chunk
    prebuffer_chunks: number          // Chunks to buffer before first emit
    enable_word_events: boolean       // Emit word-level timing events
  }
}
```

### StreamChunk

```typescript
StreamChunk {
  stream_id: string
  sequence: number                    // Monotonically increasing
  data: bytes
  format: string                      // Audio format
  timestamp_ms: number                // Relative to stream start
  is_final: boolean                   // Last chunk in stream
  metadata?: {
    partial_transcript?: string       // STT: current accumulated transcript
    confidence?: number               // STT: current confidence
    word_timings?: WordTiming[]       // TTS: word boundaries in this chunk
    speaker_tag?: number              // STT: active speaker for this chunk
  }
}
```

## Core Concepts

### Stream Types

| Type | Direction | Data Flow | Consumer |
|------|-----------|-----------|----------|
| STT Stream | Audio → Text | Client pushes audio, STT emits text transcripts | Sou / Conversation OS |
| TTS Stream | Text → Audio | TTS emits audio chunks from text input | User / Audio output device |

### Stream Lifecycle

```
Open ──→ Active ──→ Closing ──→ Closed
  │                    │
  ├── Timeout          ├── Error ──→ Errored
  │                    │
  └── Cancel ──→ Cancelled
```

| State | Description | Allowed Actions |
|-------|-------------|-----------------|
| `open` | Stream initialized, no data yet | `push()`, `close()`, `cancel()` |
| `active` | Data flowing bidirectionally | `push()`, `read()`, `close()`, `cancel()` |
| `closing` | Close requested, flushing remaining data | `cancel()` only |
| `closed` | Stream completed normally | None |
| `cancelled` | Mid-stream cancellation | None |
| `errored` | Unrecoverable error occurred | `cancel()` for cleanup |

### Backpressure Handling

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| `drop` | Silently drop chunks when buffer full | Low-latency streaming where gaps are acceptable |
| `buffer` | Block producer until consumer reads | When data integrity matters |
| `throttle` | Slow producer to match consumer rate | Network-constrained environments |
| `block` | Backpressure propagates to caller | Real-time systems requiring every chunk |

The default strategy is `buffer` for STT and `throttle` for TTS.

### Chunked Audio Processing

Audio is processed in chunks of configurable size/number:

- **STT**: Audio chunks pushed by the client are buffered internally. The STT provider processes accumulated audio and emits partial transcripts at `partial_results_interval_ms` intervals. Final transcription is emitted when the client calls `close()` or the timeout fires.
- **TTS**: The full text is synthesized incrementally. Audio is emitted in chunks of `chunk_size_ms` duration. The TTS pre-buffers `prebuffer_chunks` before emitting the first chunk to ensure smooth playback.

### Incremental Transcription (STT)

Partial results are emitted with accumulating confidence:

```
Chunk 1: "I think"              conf: 0.65
Chunk 2: "I think the answer"   conf: 0.78
Chunk 3: "I think the answer is 42"  conf: 0.92
Close:   { ... full transcript }
```

Each partial result supersedes the previous. The final result is authoritative.

### Streaming Audio Output (TTS)

Audio chunks are emitted as they are synthesized. Word timing events fire in real-time:

```
Chunk 1 [0–500ms]:  "Hello there"   words: [hello(0–200), there(201–500)]
Chunk 2 [501–900ms]: "how are you"  words: [how(501–620), are(621–750), you(751–900)]
...
Done:   total_duration_ms: 3200
```

## Operations

### Open Stream

```typescript
openStream(request: StreamOpenRequest): Promise<StreamHandle>
```

```typescript
StreamOpenRequest {
  type: "stt" | "tts"
  session_id: string
  config?: Partial<StreamConfig>
  metadata?: Record<string, unknown>
}
```

- Validates stream type and session
- Returns `StreamHandle` with `status: "open"`
- Emits `VOI.StreamOpened`

### Write Chunk (STT)

```typescript
writeChunk(stream_id: string, chunk: BufferInput): Promise<void>
```

```typescript
BufferInput {
  data: bytes
  format: string
  timestamp_ms?: number
}
```

- Appends audio data to the STT stream buffer
- Validates format matches the initial chunk
- Emits `VOI.StreamChunkWritten`
- May trigger partial result emission if thresholds met

### Read Chunk (TTS)

```typescript
readChunk(stream_id: string): Promise<StreamChunk | null>
```

- Reads next available audio chunk from TTS stream
- Blocks if no chunk ready and stream still active (backpressure-strategy-dependent)
- Returns `null` when stream is done
- Emits `VOI.StreamChunkRead`

### Close Stream

```typescript
closeStream(stream_id: string): Promise<StreamResult>
```

```typescript
StreamResult {
  stream_id: string
  type: "stt" | "tts"
  total_chunks: number
  total_bytes: number
  duration_ms: number
  final_result?: STTResult | TTSResult
}
```

- Flushes remaining buffer data
- For STT: processes final buffered audio and emits final `STTResult`
- For TTS: emits remaining audio chunks, then done event
- Transitions stream to `closed`

### Cancel Stream

```typescript
cancelStream(stream_id: string): Promise<void>
```

- Immediately terminates stream processing
- Discards buffered data
- Transitions stream to `cancelled`
- Does not emit partial results after cancellation
- Emits `VOI.StreamCancelled`

## Internal Interface

```typescript
interface StreamManager {
  // Lifecycle
  openStream(request: StreamOpenRequest): Promise<StreamHandle>
  closeStream(stream_id: string): Promise<StreamResult>
  cancelStream(stream_id: string): Promise<void>

  // Data flow
  writeChunk(stream_id: string, chunk: BufferInput): Promise<void>
  readChunk(stream_id: string): Promise<StreamChunk | null>

  // Stream queries
  getStream(stream_id: string): Promise<StreamHandle | null>
  listActiveStreams(session_id?: string): Promise<StreamHandle[]>
  getStreamMetrics(stream_id: string): Promise<StreamMetrics>

  // Backpressure control
  setBackpressureStrategy(stream_id: string, strategy: BackpressureStrategy): Promise<void>
  getBackpressureState(stream_id: string): Promise<BackpressureState>

  // Timeout management
  setTimeout(stream_id: string, timeout_ms: number): Promise<void>
  extendTimeout(stream_id: string, additional_ms: number): Promise<void>

  // Cleanup
  cleanStaleStreams(): Promise<number>      // Called periodically
  cleanSessionStreams(session_id: string): Promise<number>  // On session end
}

interface StreamMetrics {
  stream_id: string
  chunks_in: number
  chunks_out: number
  bytes_in: number
  bytes_out: number
  avg_chunk_size_bytes: number
  avg_processing_time_ms: number
  total_idle_time_ms: number
  buffer_utilization: number        // 0.0–1.0
  backpressure_events: number
  timeouts_fired: number
}

interface BackpressureState {
  strategy: BackpressureStrategy
  buffer_bytes: number
  buffer_capacity_bytes: number
  producer_paused: boolean
  consumer_blocked: boolean
  dropped_chunks: number
}

// Internal stream driver interface for provider integration
interface StreamDriver {
  open(handle: StreamHandle): Promise<void>
  write(chunk: BufferInput): Promise<void>
  read(): Promise<StreamChunk | null>
  close(): Promise<StreamResult>
  cancel(): Promise<void>
}

type BackpressureStrategy = "drop" | "buffer" | "throttle" | "block"

type StreamErrorCode =
  | "VOI_STREAM_NOT_FOUND"
  | "VOI_STREAM_CLOSED"
  | "VOI_STREAM_CANCELLED"
  | "VOI_STREAM_TIMEOUT"
  | "VOI_STREAM_BUFFER_FULL"
  | "VOI_STREAM_FORMAT_MISMATCH"
  | "VOI_STREAM_MAX_DURATION_EXCEEDED"
  | "VOI_STREAM_MAX_CHUNKS_EXCEEDED"
  | "VOI_STREAM_PROVIDER_ERROR"
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `VOI.StreamOpened` | stream_id, type, session_id, config | Stream lifecycle started |
| `VOI.StreamClosed` | stream_id, type, total_chunks, duration_ms | Stream completed normally |
| `VOI.StreamCancelled` | stream_id, type, chunks_processed | Stream terminated mid-flight |
| `VOI.StreamErrored` | stream_id, type, error_code, reason | Unrecoverable stream error |
| `VOI.StreamChunkWritten` | stream_id, sequence, bytes | Audio chunk received (STT) |
| `VOI.StreamChunkRead` | stream_id, sequence, bytes, is_final | Audio chunk output (TTS) |
| `VOI.StreamTimeoutFired` | stream_id, idle_duration_ms | No activity within timeout window |
| `VOI.StreamBackpressureEngaged` | stream_id, strategy, buffer_utilization | Backpressure activated |
| `VOI.StreamBackpressureReleased` | stream_id, strategy | Backpressure deactivated |
| `VOI.StreamBufferDiscard` | stream_id, chunks_dropped, bytes_lost | Chunks dropped due to `drop` strategy |
| `VOI.StreamMaxDurationReached` | stream_id, duration_ms | Stream exceeded max lifetime |
| `VOI.StreamErrorRecovery` | stream_id, error_code, recovery_action | Error recovery initiated during stream |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| STM-001 | Every stream has exactly one lifecycle: open → active → (closed | cancelled | errored) | Algorithmic — state transitions enforced by FSM |
| STM-002 | Stream sequence numbers are monotonically increasing with no gaps | Algorithmic — sequence assigned on write/emit |
| STM-003 | Audio format is consistent across all chunks in a stream | Algorithmic — format validated on each writeChunk |
| STM-004 | A cancelled stream emits no further events after cancellation | Algorithmic — cancel flushes event queue |
| STM-005 | Streams are automatically cleaned up when their owning session ends | Lifecycle — `cleanSessionStreams` called by Session Manager |
| STM-006 | Backpressure never causes data corruption (only loss under `drop` strategy) | Architectural — buffer operations are atomic |
| STM-007 | Timeout timer resets on every successful writeChunk or readChunk call | Algorithmic — `last_activity` updated on each operation |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Stream ID not found | `VOI_STREAM_NOT_FOUND` | Return error; invalid stream ID |
| Write to closed/cancelled stream | `VOI_STREAM_CLOSED` | Return error; caller must open new stream |
| Read from closed/cancelled stream (no data left) | `VOI_STREAM_CLOSED` | Return `null`; no error |
| Stream chunk format does not match initial format | `VOI_STREAM_FORMAT_MISMATCH` | Reject chunk; emit error on stream |
| Stream idle timeout reached | `VOI_STREAM_TIMEOUT` | If `finalize_on_timeout`: finalize STT and close. Else: cancel stream |
| Stream exceeds `max_stream_duration_ms` | `VOI_STREAM_MAX_DURATION_EXCEEDED` | Force-close stream; return partial results |
| Stream exceeds `max_chunks` | `VOI_STREAM_MAX_CHUNKS_EXCEEDED` | Auto-close stream; emit final result |
| Buffer full under `block` strategy | `VOI_STREAM_BUFFER_FULL` | Producer blocks; no error, retry when buffer drains |
| Provider error during active stream | `VOI_STREAM_PROVIDER_ERROR` | Mark stream `errored`; emit error event; retry if recovery possible |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Streaming manages only stream lifecycle and data flow for voice |
| R2 — Dependency Order | Depends on STT Engine and TTS Engine for provider streams; no upward deps |
| R3 — DRY | Stream lifecycle FSM defined once in StreamManager core |
| R4 — Builder Pattern | Stream built by open → configure → data flow → close |
| R5 — Liskov Substitution | Any StreamDriver implementation works with StreamManager |
| R6 — DI over Singletons | Stream drivers, configs, and timeout strategies injected |
| R9 — Deterministic | Same inputs + same timing produce same stream behavior |
| R10 — Simpler Over Complex | Clear FSM with explicit state transitions and backpressure strategies |
| R13 — Design for Failure | Timeouts, cancellations, provider errors all handled without data corruption |
| R14 — Paved Path | All streaming flows through openStream → writeChunk/readChunk → closeStream |
| R15 — Open/Closed | New backpressure strategies added by extending strategy enum and driver |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Voice/000-Overview.md | Streaming is the data transport layer for Voice System |
| Voice/001-STT-Engine.md | STT streams use Streaming for chunked audio input |
| Voice/002-TTS-Engine.md | TTS streams use Streaming for chunked audio output |
| Voice/003-Voice-Profiles.md | Streaming config may reference profile defaults |
| Voice/005-Emotion-Detection.md | Emotion detection processes in parallel with STT stream |
| Brain/Conversation/000-Overview.md | Conversation OS manages stream session lifecycle |
| Bible/05-Platform/005-AUS.md | Session lifecycle events trigger stream cleanup |
