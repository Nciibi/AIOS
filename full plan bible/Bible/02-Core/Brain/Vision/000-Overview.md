# AIOS Bible â€” Brain
## 000 â€” Vision System

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Vision |
| Document ID | AIOS-BBL-002-VIS-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 3 â€” Law of Communication |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Vision System provides visual input processing for the Brain. It extracts structured information from images, video frames, and visual documents â€” converting raw visual data into text and structured data that Sou can reason about. The Vision System is the visual sensory interface of the Brain.

Vision does not interpret context or make decisions about what it sees. It produces structured descriptions and extracted data that Sou consumes through Cognitive OS reasoning.

## Architecture

```
Sou (consumes vision output via Cognitive OS)
    â–²
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚              Vision System                   â”‚
â”‚                                              â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚  Image    â”‚  â”‚  OCR      â”‚  â”‚  Scene    â”‚  â”‚
â”‚  â”‚  Analysis â”‚â”€â–ºâ”‚  Engine   â”‚â”€â–ºâ”‚  Describerâ”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”˜  â”‚
â”‚                                      â”‚      â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”‚      â”‚
â”‚  â”‚  Video    â”‚  â”‚  Frame    â”‚         â”‚      â”‚
â”‚  â”‚  Processorâ”‚  â”‚  Selector â”‚         â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â”‚      â”‚
â”‚                                      â”‚      â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”‚      â”‚
â”‚  â”‚  Document â”‚  â”‚  Vision   â”‚         â”‚      â”‚
â”‚  â”‚  Parser   â”‚  â”‚  Router   â”‚         â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â”‚      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”˜
                                       â”‚
                                       â–¼
                                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                â”‚  LLMOS        â”‚
                                â”‚ (inference)   â”‚
                                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Vision System uses LLMOS for AI-powered vision inference (image description, object detection, document parsing). Traditional image processing (resize, format conversion, frame extraction) is handled internally.

## Core Concepts

### Vision Model

```
ImageInput {
  data: bytes
  format: string               // "png" | "jpg" | "webp" | "bmp" | "gif" | "tiff"
  width: number
  height: number
  source_url?: string
}

VideoInput {
  data: bytes                   // Raw video or reference to stream
  format: string               // "mp4" | "webm" | "avi" | "mov"
  duration_ms: number
  frame_rate: number
}

ImageAnalysisRequest {
  request_id: string
  image: ImageInput
  analysis_type: "describe" | "classify" | "detect" | "ocr" | "full"
  config: VisionConfig
  session_id: string
}

ImageAnalysisResult {
  request_id: string
  description?: string          // Natural language scene description
  labels?: Label[]              // Classification labels
  objects?: DetectedObject[]    // Detected objects with bounding boxes
  text?: ExtractedText[]        // OCR results
  faces?: Face[]                // Detected faces
  metadata: {
    width: number
    height: number
    format: string
    processing_time_ms: number
    llmos_usage?: { tokens_consumed: number, model_used: string }
  }
}

Label {
  name: string
  confidence: number
  category?: string
}

DetectedObject {
  name: string
  confidence: number
  bounding_box: BoundingBox
}

BoundingBox {
  x: number                     // Normalized 0.0â€“1.0
  y: number
  width: number
  height: number
}

ExtractedText {
  text: string
  confidence: number
  bounding_box?: BoundingBox
  language?: string
}

Face {
  bounding_box: BoundingBox
  confidence: number
  landmarks?: FaceLandmark[]
  attributes?: FaceAttributes
}

FaceLandmark {
  type: "eye_left" | "eye_right" | "nose" | "mouth_left" | "mouth_right"
  x: number
  y: number
}

FaceAttributes {
  age_estimate?: number
  emotion?: string
  glasses?: boolean
  blur?: number                 // 0.0â€“1.0
  exposure?: number             // 0.0â€“1.0
}

VideoAnalysisRequest {
  request_id: string
  video: VideoInput
  analysis_type: "summarize" | "detect" | "monitor"
  config: VideoConfig
  session_id: string
}

VideoAnalysisResult {
  request_id: string
  frames_analyzed: number
  key_events: VideoEvent[]
  summary?: string
  duration_ms: number
  processing_time_ms: number
}

VideoEvent {
  timestamp_ms: number
  event_type: string
  description: string
  confidence: number
  frame?: ImageInput
}

DocumentParseRequest {
  request_id: string
  image: ImageInput
  document_type: "invoice" | "receipt" | "form" | "identity" | "generic"
  config: VisionConfig
  session_id: string
}

DocumentParseResult {
  request_id: string
  fields: ParsedField[]
  raw_text: string
  confidence: number
  structure?: DocumentStructure
}

ParsedField {
  name: string
  value: string
  confidence: number
  bounding_box?: BoundingBox
}

VisionConfig {
  model?: string
  max_labels: number            // Max classification labels
  min_confidence: number        // Minimum confidence threshold
  language_hints?: string[]     // Expected text languages
  detail: "low" | "high"       // Analysis detail level
  timeout_ms: number
}

VideoConfig {
  max_frames: number            // Max frames to analyze
  interval_ms: number           // Frame sampling interval
  event_detection: boolean
  summarization: boolean
  min_event_confidence: number
}
```

### 1. Image Analysis

Processes static images to extract structured information:

| Mode | Output | Use Case |
|------|--------|----------|
| describe | Natural language description | General image understanding |
| classify | Labels with confidence scores | Categorize images |
| detect | Bounding boxes + object names | Object localization |
| ocr | Extracted text + positions | Document scanning |
| full | All of the above | Comprehensive analysis |

Image preprocessing before LLMOS inference:

| Step | Operation | Configurable |
|------|-----------|-------------|
| 1 | Format normalization | Yes â€” target format |
| 2 | Resize to model limits | Yes â€” max dimensions |
| 3 | Compression for latency | Yes â€” quality/performance trade-off |
| 4 | Enhancement | No â€” auto-applied for low quality |
| 5 | Face blurring (privacy) | Yes â€” PII protection |

### 2. OCR Engine

Extracts text from images with positional information:

| Capability | Description |
|------------|-------------|
| Printed text | High-accuracy printed text extraction |
| Handwriting | Moderate-accuracy handwriting recognition |
| Multi-language | Simultaneous multi-language support |
| Layout preservation | Table/cell structure recognition |
| Barcode/QR | Barcode and QR code detection |
| Document structure | Headings, paragraphs, list detection |

### 3. Scene Describer

Generates natural language descriptions of image content:

| Dimension | Detail | Example |
|-----------|--------|---------|
| Subject | Main objects/people | "A man in a blue suit" |
| Action | What is happening | "is giving a presentation" |
| Environment | Where it takes place | "in a modern conference room" |
| Attributes | Colors, sizes, positions | "with a large screen showing charts" |
| Text | Visible text content | "slide title: Q3 Results" |

### 4. Video Processor

Processes video content through frame analysis:

| Mode | Behavior | Use Case |
|------|----------|----------|
| Summarize | Sample frames â†’ describe key events | Meeting recording review |
| Detect | Monitor for specific events/objects | Security camera monitoring |
| Stream | Real-time frame-by-frame analysis | Live video processing |

Frame selection strategies:

| Strategy | Behavior | Best For |
|----------|----------|----------|
| Uniform | Fixed interval sampling | General summarization |
| Scene-change | Sample on scene transitions | Lecture/presentation video |
| Motion-based | Sample on significant motion | Surveillance footage |
| Custom | User-defined intervals | Specific frame timing |

### 5. Document Parser

Extracts structured data from document images:

| Document Type | Fields Extracted |
|---------------|------------------|
| Invoice | Invoice number, date, vendor, line items, totals, tax |
| Receipt | Merchant, date, items, total, payment method |
| Form | Form fields, checkboxes, signatures |
| Identity document | Name, ID number, date of birth, expiry |
| Generic | All detected text with layout structure |

### 6. Vision Router

Routes vision requests to the optimal provider/model:

| Factor | Weight | Description |
|--------|--------|-------------|
| Analysis type | Required | describe/classify/detect/ocr/full |
| Model capability | 0.40 | Model must support requested features |
| Latency requirement | 0.30 | Real-time vs batch |
| Cost | 0.20 | Per-image pricing |
| Quality | 0.10 | Accuracy benchmarks |

## Interfaces

### Vision System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `analyzeImage(request)` | Sou only | Analyze a single image |
| `analyzeImageBatch(requests)` | Sou only | Batch analyze multiple images |
| `analyzeVideo(request)` | Sou only | Process a video file |
| `parseDocument(request)` | Sou only | Extract structured data from document |
| `describeScene(image, config?)` | Sou only | Quick scene description shortcut |
| `extractText(image, config?)` | Sou only | Quick OCR shortcut |
| `getProviders()` | Sou only | List registered vision providers |
| `cancelAnalysis(request_id)` | Sou only | Cancel in-progress analysis |

### Internal Interfaces

```
interface VisionProvider {
  analyzeImage(image: ImageInput, config: VisionConfig): Promise<ImageAnalysisResult>
  analyzeVideo(video: VideoInput, config: VideoConfig): AsyncIterable<VideoEvent>
  health(): ProviderHealth
}

interface FrameSelector {
  selectFrames(video: VideoInput, config: VideoConfig): AsyncIterable<ImageInput>
}

interface ImagePreprocessor {
  normalize(image: ImageInput, config: VisionConfig): Promise<ImageInput>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VIS.ImageAnalysisStarted |  request_id, analysis_type, dimensions | Image analysis began |
| VIS.ImageAnalysisCompleted |  request_id, label_count, processing_time | Analysis finished |
| VIS.ImageAnalysisFailed |  request_id, error_code, reason | Analysis failed |
| VIS.OCRCompleted |  request_id, text_length, confidence | Text extraction finished |
| VIS.SceneDescribed |  request_id, description_length | Scene description generated |
| VIS.VideoProcessingStarted |  request_id, duration_ms, frames_planned | Video processing began |
| VIS.VideoFrameAnalyzed |  request_id, frame_number, timestamp | Individual frame processed |
| VIS.VideoProcessingCompleted |  request_id, frames_analyzed, events_detected | Video processing finished |
| VIS.DocumentParsed |  request_id, document_type, field_count | Document extraction completed |
| VIS.FaceDetected |  request_id, face_count | Faces found (count only, no identity) |
| VIS.PrivacyFilterApplied |  request_id, filter_type, regions | Privacy filter triggered |
| VIS.ProviderHealthChanged |  provider, status | Vision provider health transitioned |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| VIS-001 | Vision System extracts features; Sou interprets meaning | Architectural â€” no auto-decisions on vision output |
| VIS-002 | All vision processing routes through LLMOS for AI inference | Architectural â€” Vision System has no embedded vision models |
| VIS-003 | Image data is ephemeral unless explicitly stored to Memory OS | Architectural â€” stateless per BRAIN-007 |
| VIS-004 | Face detection produces bounding boxes only, never identity labels | Constitutional â€” privacy protection |
| VIS-005 | Privacy filters are applied before any image leaves the Vision System | Architectural â€” applied in ImagePreprocessor |
| VIS-006 | OCR confidence below threshold returns error, never hallucinated text | Schema â€” minimum confidence enforcement |
| VIS-007 | Video analysis always has a configurable frame limit | Schema â€” max_frames prevents unbounded processing |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Vision System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou consumes vision output for reasoning |
| Brain/Cognitive/000-Overview.md | Cognitive OS reasons about vision results |
| Brain/LLMOS/000-Overview.md | LLMOS provides the inference backend for vision |
| Brain/Memory/000-Overview.md | Vision analysis results persisted here |
| Bible/04-Execution/Runtime/ | Vision providers registered as Execution Providers |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unsupported image format | `VIS_UNSUPPORTED_FORMAT` | Return error; list supported formats |
| Image exceeds size limit | `VIS_IMAGE_TOO_LARGE` | Return error; suggest compression |
| No face detected (when required) | `VIS_NO_FACE_DETECTED` | Return empty result; not an error |
| OCR low confidence | `VIS_OCR_LOW_CONFIDENCE` | Return text with low confidence flag |
| Video too long | `VIS_VIDEO_TOO_LONG` | Return error; suggest sampling |
| Provider unavailable | `VIS_PROVIDER_UNAVAILABLE` | Fail over to next provider; log |
| Analysis timeout | `VIS_ANALYSIS_TIMEOUT` | Return partial results with error |
| Privacy filter blocked all content | `VIS_ALL_CONTENT_BLOCKED` | Return "content not available" |
| Document type not recognized | `VIS_DOCUMENT_TYPE_UNKNOWN` | Fall back to generic parsing |


## Cross-Cutting Concerns

### Security

Vision System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Vision System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Vision System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Vision System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Vision System does one thing: visual input processing |
| R2 â€” Dependency Order | Depends on LLMOS, Memory OS; no upward deps |
| R3 â€” DRY | Vision models defined once in Vision Model |
| R4 â€” Builder Pattern | Analysis built by Preprocessor â†’ Router â†’ Provider |
| R5 â€” Liskov Substitution | Any VisionProvider implements the interface |
| R6 â€” DI over Singletons | Providers and frame selectors injected |
| R9 â€” Deterministic | Same image+config produces same analysis (model-dependent) |
| R10 â€” Simpler Over Complex | Clear analysis modes (describe/classify/detect/ocr/full) |
| R13 â€” Design for Failure | Provider failover, timeouts, partial results always handled |
| R14 â€” Paved Path | All vision analysis flows through `analyzeImage` |
| R15 â€” Open/Closed | New analysis modes added via Provider SDK, not by modifying core |
