# AIOS Bible — Brain
## 004 — Video Processor

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Vision |
| Document ID | AIOS-BBL-002-VIS-004 |
| Source Laws | Law 4 — Law of Evidence, Law 3 — Law of Communication |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Video Processor analyzes video content by selecting representative frames, detecting key events, and producing summaries. It supports three analysis modes (summarize, detect, stream) and four frame selection strategies (uniform, scene-change, motion-based, custom). Video processing enables Sou to understand temporal visual content — meetings, surveillance footage, recordings, and live streams — without processing every frame.

Under VIS-007, video analysis always respects a configurable frame limit (`max_frames`) to prevent unbounded processing. Under VIS-003, video frames are ephemeral unless explicitly stored.

## Data Model

### VideoAnalysisRequest

```typescript
VideoAnalysisRequest {
  request_id: string
  video: VideoInput
  analysis_type: "summarize" | "detect" | "stream"
  config: VideoConfig
  session_id: string
  metadata?: {
    source: string                 // "upload" | "url" | "stream"
    title?: string
    tags: string[]
    priority: "low" | "normal" | "high"
  }
}
```

### VideoInput

```typescript
VideoInput {
  data: bytes                      // Raw video or reference to stream
  format: string                   // "mp4" | "webm" | "avi" | "mov" | "stream"
  duration_ms: number
  frame_rate: number
  source_url?: string
  stream_endpoint?: string         // For streaming analysis
}
```

### VideoAnalysisResult

```typescript
VideoAnalysisResult {
  request_id: string
  analysis_type: string
  frames_analyzed: number
  frames_total: number
  key_events: VideoEvent[]
  summary?: string
  frame_summaries?: FrameSummary[]
  duration_ms: number
  processing_time_ms: number
  metadata: {
    frame_selection_strategy: string
    frame_rate_sampled: number
    event_detection_enabled: boolean
    llmos_usage?: { tokens_consumed: number, model_used: string, calls_made: number }
  }
}
```

### VideoEvent

```typescript
VideoEvent {
  event_id: string
  timestamp_ms: number
  event_type: string               // e.g. "person_enters", "object_appears", "scene_change"
  description: string
  confidence: number               // 0.0–1.0
  frame: ImageInput                // Representative frame of the event
  duration_ms?: number             // How long the event lasted
  bounding_boxes?: BoundingBox[]   // Relevant objects in the event frame
  metadata?: Record<string, string>
}
```

### FrameSummary

```typescript
FrameSummary {
  frame_number: number
  timestamp_ms: number
  description: string
  key_objects: string[]
  text_detected?: string
  confidence: number
  event_detected: boolean
}
```

### FrameSelectionReport

```typescript
FrameSelectionReport {
  total_frames: number
  frames_selected: number
  strategy: FrameSelectionStrategy
  selection_ratio: number          // selected / total
  skipped_ranges: SkippedRange[]  // Long segments with no frames selected
}

SkippedRange {
  start_ms: number
  end_ms: number
  reason: "no_motion" | "static_scene" | "below_threshold"
}
```

### VideoConfig

```typescript
VideoConfig {
  max_frames: number               // Hard limit (VIS-007), default: 100
  analysis_type: "summarize" | "detect" | "stream"
  frame_selection: {
    strategy: "uniform" | "scene-change" | "motion-based" | "custom"
    interval_ms?: number           // For uniform sampling
    scene_change_threshold?: number // For scene-change detection (0.0–1.0)
    motion_threshold?: number      // For motion-based detection (0.0–1.0)
    custom_timestamps_ms?: number[] // For custom strategy
  }
  event_detection: {
    enabled: boolean
    event_types?: string[]         // Specific events to detect (all if empty)
    min_confidence: number         // Default: 0.5
  }
  summarization: {
    enabled: boolean
    max_summary_length: number     // Max tokens for summary
    include_frame_descriptions: boolean
  }
  frame_analysis: {
    analysis_type: "describe" | "detect" | "ocr" | "full"
    detail_level: "brief" | "normal"
    min_confidence: number
  }
  timeout_ms: number
}
```

## Core Concepts

### Analysis Modes

The Video Processor supports three analysis modes:

| Mode | Behavior | Frame Selection | Output | Use Case |
|------|----------|----------------|--------|----------|
| Summarize | Sample frames → describe key events | Automatic | Summary + key events + frame summaries | Meeting recording review |
| Detect | Monitor for specific events/objects | Event-driven | Key events with timestamps | Security camera monitoring |
| Stream | Real-time frame-by-frame analysis | Continuous | AsyncIterable of frame events | Live video processing |

```
Summarize:
  Video → [Frame Selector] → selected frames → [Scene Describer per frame]
       → [Event Detector] → key_events[] + summary

Detect:
  Video → [Frame Selector (event-driven)] → candidate frames
       → [Event Matcher] → matching key_events[]

Stream:
  Video stream → [Frame Selector (continuous)]
       → AsyncIterable → each frame analyzed in real-time
       → events emitted as they occur
```

### Frame Selection Strategies

The frame selection strategy determines which frames from the video are analyzed:

| Strategy | Algorithm | Best For | Caveats |
|----------|-----------|----------|---------|
| Uniform | Pick every Nth frame based on `interval_ms` | General summarization | Can miss brief events |
| Scene-change | Detect cuts/transitions → sample frames after each change | Lectures, presentations | May miss gradual changes |
| Motion-based | Analyze motion vectors → sample on significant motion | Surveillance footage | Higher computational cost |
| Custom | Use user-provided timestamp array | Specific frame timing | Requires prior knowledge |

```
Uniform (interval_ms=5000):
  Frame: 0s   5s   10s   15s   20s
         [X]  [X]  [X]   [X]   [X]

Scene-change:
  Frame: 0s   7s   7.5s  15s   15.2s
         [X]      [X]         [X]
         (scene A) (scene B)  (scene C)

Motion-based:
  Frame: 0s   3s   12s   18s
         [X]  [X]  [X]   [X]
         (still) (motion) (still) (motion)
```

### Key Event Detection

Key events are detected by analyzing frame descriptions for patterns:

```
Algorithm:
  1. Analyze each selected frame via Image Analysis
  2. Compare consecutive frame descriptions
  3. Detect significant changes:
     ┌────────────────────────────────┐
     │ New object/person appears      │ → "person_enters"
     │ Object/person disappears       │ → "person_exits"
     │ Scene context changes          │ → "scene_change"
     │ Action state changes           │ → "action_transition"
     │ Text on screen changes         │ → "text_change"
     │ User-defined pattern matched   │ → "custom_event"
     └────────────────────────────────┘
  4. Group related detections into events
  5. Filter by min_confidence
  6. Assign event_type from detected pattern
```

### Video Summarization

Summarization produces a condensed textual overview:

```
Raw frames → individual descriptions
     │
     ▼
Concatenate into transcript
     │
     ▼
LLMOS summarization call:
  "Summarize the following video frame descriptions into
   a coherent narrative of key moments..."
     │
     ▼
Summary output + key event timeline + frame summaries
```

### Frame Limit Enforcement (VIS-007)

The `max_frames` hard cap prevents unbounded processing:

```
Selection before enforcement:
  Strategy estimates N candidate frames

If N > max_frames:
  ┌─────────────────────────────────────┐
  │ Uniform:   Increase interval_ms      │
  │ Scene-change: Raise threshold        │
  │ Motion-based: Raise motion_threshold │
  │ Custom:    Take first max_frames     │
  └─────────────────────────────────────┘

  If strategy adjustment still exceeds max_frames:
    → Subsample uniformly to max_frames
    → Log frame_limit_reached warning

Result: frames_selected ≤ max_frames always
```

### Streaming Video Analysis

Streaming mode processes frames in real-time:

```
Stream Start
    │
    ▼
Establish connection to stream endpoint
    │
    ▼
Frame buffer (ring buffer, capacity = max_frames)
    │
    ▼
For each frame:
    ├── Apply frame selection strategy
    ├── Analyze frame (Image Analysis)
    ├── Detect events
    ├── Emit VIS.VideoFrameAnalyzed
    └── If event detected:
          └── Emit event via AsyncIterable
    │
    ▼
Stream End
    │
    └── Emit VIS.VideoProcessingCompleted
```

### Timestamp-Based Event Tracking

Every event is anchored to its video timestamp:

```
Event Timeline:
0:00 ────────────────────────────────────── duration_ms
      │     │              │         │
      ▼     ▼              ▼         ▼
     Person enters    Scene change   Person exits
     (0:03)           (1:15)        (2:30)

Query patterns:
  getEventsBetween(0:00, 1:00) → events in first minute
  getEventsByType("person_enters") → all entry events
  getEventsAfter(timestamp) → events after a point
```

## Internal Interface

```typescript
interface VideoProcessor {
  analyze(request: VideoAnalysisRequest): Promise<VideoAnalysisResult>

  selectFrames(
    video: VideoInput,
    strategy: FrameSelectionConfig
  ): AsyncIterable<SelectedFrame>

  detectEvents(
    frames: AsyncIterable<SelectedFrame>,
    config: EventDetectionConfig
  ): AsyncIterable<VideoEvent>

  getSummary(
    frames: AsyncIterable<FrameSummary>,
    config: SummarizationConfig
  ): Promise<string>

  analyzeStream(
    request: VideoAnalysisRequest
  ): AsyncIterable<StreamEvent>
}

interface FrameSelector {
  selectFrames(
    video: VideoInput,
    config: FrameSelectionConfig
  ): AsyncIterable<SelectedFrame>

  getSelectionReport(): FrameSelectionReport
}

interface SelectedFrame {
  frame_number: number
  timestamp_ms: number
  image: ImageInput
  metadata: {
    selection_reason: string
    motion_score?: number
    scene_change_score?: number
  }
}

interface EventDetector {
  detectEvents(
    frameStream: AsyncIterable<FrameSummary>,
    config: EventDetectionConfig
  ): AsyncIterable<VideoEvent>

  getSupportedEventTypes(): string[]
}

interface StreamHandler {
  connect(endpoint: string): AsyncIterable<ImageInput>
  disconnect(): void
  health(): StreamHealth
}

interface StreamHealth {
  connected: boolean
  frames_per_second: number
  buffer_utilization: number
  dropped_frames: number
}

type FrameSelectionStrategy =
  | "uniform" | "scene-change" | "motion-based" | "custom"

interface FrameSelectionConfig {
  strategy: FrameSelectionStrategy
  max_frames: number
  interval_ms?: number
  scene_change_threshold?: number
  motion_threshold?: number
  custom_timestamps_ms?: number[]
}

interface EventDetectionConfig {
  enabled: boolean
  event_types?: string[]
  min_confidence: number
  cooldown_ms: number             // Min time between same-type events
}

interface SummarizationConfig {
  enabled: boolean
  max_summary_length: number
  include_frame_descriptions: boolean
}

interface StreamEvent {
  type: "frame" | "event" | "status" | "error" | "end"
  timestamp_ms: number
  data: any
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `VIS.VideoProcessingStarted` | request_id, duration_ms, analysis_type, frames_planned | Video processing began |
| `VIS.VideoFrameSelected` | request_id, frame_number, timestamp_ms, strategy | Frame selected for analysis |
| `VIS.VideoFrameAnalyzed` | request_id, frame_number, timestamp, description | Individual frame analyzed |
| `VIS.VideoEventDetected` | request_id, event_id, event_type, timestamp, confidence | Key event detected in video |
| `VIS.VideoProcessingCompleted` | request_id, frames_analyzed, events_detected, processing_time | Video processing finished |
| `VIS.VideoProcessingFailed` | request_id, error_code, stage, reason | Video processing failed |
| `VIS.VideoFrameLimitReached` | request_id, max_frames, strategy_adjusted | Frame limit enforced (VIS-007) |
| `VIS.VideoSummaryGenerated` | request_id, summary_length, frame_summaries_count | Video summary created |
| `VIS.VideoStreamConnected` | request_id, endpoint, frame_rate | Stream connection established |
| `VIS.VideoStreamDisconnected` | request_id, reason, duration | Stream connection terminated |
| `VIS.VideoStreamFrameDropped` | request_id, frame_number, reason | Frame dropped from stream buffer |
| `VIS.VideoSceneChange` | request_id, timestamp_ms, confidence | Scene transition detected |
| `VIS.VideoMotionDetected` | request_id, timestamp_ms, motion_score, region | Significant motion detected |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VID-001 | Frames analyzed never exceeds max_frames | Algorithmic — VIS-007 hard cap enforced during selection |
| VID-002 | Every key event has a timestamp and representative frame | Schema — timestamp_ms and frame are required |
| VID-003 | Frame summaries are generated in chronological order | Algorithmic — frame pipeline preserves order |
| VID-004 | Event detection uses a cooldown period to prevent duplicate events | Algorithmic — cooldown_ms enforced between same-type events |
| VID-005 | Streaming analysis is always cancellable | Architectural — StreamHandler supports disconnect |
| VID-006 | Frame buffer is a ring buffer with bounded capacity | Algorithmic — buffer never exceeds max_frames |
| VID-007 | Summarization only runs on frames that were actually analyzed | Algorithmic — summarization input is frame analysis output |
| VID-008 | Video data is ephemeral unless explicitly stored to Memory OS | Architectural — stateless per VIS-003 |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unsupported video format | `VIS_VIDEO_UNSUPPORTED_FORMAT` | Return error; list supported formats |
| Video exceeds max duration | `VIS_VIDEO_TOO_LONG` | Return error; suggest sampling or trimming |
| Frame selection produced zero frames | `VIS_VIDEO_NO_FRAMES_SELECTED` | Return error; relax selection criteria |
| Event detection produced no events | `VIS_VIDEO_NO_EVENTS_DETECTED` | Return empty events array; not an error |
| Stream endpoint unreachable | `VIS_STREAM_UNREACHABLE` | Return error; retry with backoff |
| Stream disconnected mid-analysis | `VIS_STREAM_DISCONNECTED` | Return partial result with disconnected flag |
| Frame analysis timeout on individual frame | `VIS_FRAME_ANALYSIS_TIMEOUT` | Skip frame, continue processing, log warning |
| Motion detection failed | `VIS_MOTION_DETECTION_FAILED` | Fall back to uniform sampling |
| Summarization LLMOS call failed | `VIS_SUMMARIZATION_FAILED` | Return frame summaries without summary text |
| Frame buffer overflow in stream | `VIS_STREAM_BUFFER_OVERFLOW` | Drop oldest frame, log warning |
| Custom timestamps out of bounds | `VIS_CUSTOM_TIMESTAMPS_INVALID` | Clamp to video duration, log warning |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Video Processor handles only video content analysis |
| R2 — Dependency Order | Depends on Image Analysis, LLMOS; no upward deps |
| R3 — DRY | Frame models and config defined once in Vision Model |
| R4 — Builder Pattern | Analysis built by Frame Selector → Analyzer → Event Detector |
| R5 — Liskov Substitution | Any FrameSelector, EventDetector implements its interface |
| R6 — DI over Singletons | Frame selectors, event detectors, stream handlers injected |
| R9 — Deterministic | Same video + config produces same events (model-dependent) |
| R10 — Simpler Over Complex | Three modes; frame selection decoupled from analysis |
| R13 — Design for Failure | Frame skip on timeout; partial results; stream reconnect |
| R14 — Paved Path | All video analysis flows through `analyze()` |
| R15 — Open/Closed | New frame selection strategies added via FrameSelector |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Vision/000-Overview.md | Video Processor is a core sub-service of the Vision System |
| Vision/001-Image-Analysis.md | Each analyzed frame uses Image Analysis |
| Vision/003-Scene-Description.md | Frame descriptions use Scene Describer |
| Brain/LLMOS/000-Overview.md | LLMOS provides per-frame inference and summarization |
| Brain/Cognitive/000-Overview.md | Cognitive OS consumes video events and summaries |
| Brain/Sou/000-Overview.md | Sou requests video analysis for temporal understanding |
| Brain/Memory/000-Overview.md | Frame images optionally persisted via Memory OS |
| Bible/05-Platform/004-EVS.md | Events emitted throughout video processing lifecycle |
