# AIOS Bible â€” Brain
## 001 â€” Image Analysis

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Vision |
| Document ID | AIOS-BBL-002-VIS-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 3 â€” Law of Communication |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Image Analysis processes static images to extract structured information. It is the primary entry point for visual input into the Brain â€” converting raw image bytes into labels, descriptions, objects, text, and face data that Sou can reason about. Image Analysis supports five distinct modes (describe, classify, detect, ocr, full) and applies a preprocessing pipeline (normalization, resize, compression, enhancement, privacy) before any LLMOS inference call.

Under VIS-003, image data is ephemeral unless explicitly persisted to Memory OS. Under VIS-004, face detection produces bounding boxes only â€” never identity labels. Under VIS-005, privacy filters are applied before any image leaves the Vision System.

## Data Model

### AnalysisMode

```typescript
AnalysisMode = "describe" | "classify" | "detect" | "ocr" | "full"
```

### ImageAnalysisRequest

```typescript
ImageAnalysisRequest {
  request_id: string
  image: ImageInput
  analysis_type: AnalysisMode
  config: VisionConfig
  session_id: string
  metadata?: {
    source: string               // "user_upload" | "url_fetch" | "video_frame" | "document"
    original_filename?: string
    priority: "low" | "normal" | "high"
    tags: string[]
  }
}
```

### ImageAnalysisResult

```typescript
ImageAnalysisResult {
  request_id: string
  analysis_type: AnalysisMode
  description?: string
  labels?: Label[]
  objects?: DetectedObject[]
  text?: ExtractedText[]
  faces?: Face[]
  preprocessing: {
    original_size: { width: number, height: number }
    processed_size: { width: number, height: number }
    format_converted: string
    compression_applied: boolean
    enhancement_applied: boolean
    privacy_filter_applied: boolean
    regions_redacted: number
  }
  metadata: {
    width: number
    height: number
    format: string
    processing_time_ms: number
    llmos_usage?: { tokens_consumed: number, model_used: string }
    mode_results: {
      describe_completed: boolean
      classify_completed: boolean
      detect_completed: boolean
      ocr_completed: boolean
    }
  }
}
```

### Label

```typescript
Label {
  name: string
  confidence: number              // 0.0â€“1.0
  category?: string
  taxonomy_id?: string            // Reference to classification taxonomy node
}
```

### DetectedObject

```typescript
DetectedObject {
  name: string
  confidence: number              // 0.0â€“1.0
  bounding_box: BoundingBox
  instance_id?: string            // For tracking objects across frames
  attributes?: Record<string, string>
}
```

### BoundingBox

```typescript
BoundingBox {
  x: number                       // Normalized 0.0â€“1.0
  y: number
  width: number
  height: number
}
```

### ExtractedText

```typescript
ExtractedText {
  text: string
  confidence: number              // 0.0â€“1.0
  bounding_box?: BoundingBox
  language?: string
  is_handwriting: boolean
}
```

### Face

```typescript
Face {
  bounding_box: BoundingBox
  confidence: number
  landmarks?: FaceLandmark[]
  attributes?: FaceAttributes
}
```

### FaceLandmark

```typescript
FaceLandmark {
  type: "eye_left" | "eye_right" | "nose" | "mouth_left" | "mouth_right"
  x: number
  y: number
}
```

### FaceAttributes

```typescript
FaceAttributes {
  age_estimate?: number
  emotion?: string
  glasses?: boolean
  blur?: number                   // 0.0â€“1.0
  exposure?: number               // 0.0â€“1.0
}
```

### PreprocessingConfig

```typescript
PreprocessingConfig {
  target_format: "png" | "jpg" | "webp"
  max_width: number               // Default: 2048
  max_height: number              // Default: 2048
  compression_quality: number     // 1â€“100, default: 85
  enhance_low_quality: boolean    // Default: true
  privacy_filter: {
    enabled: boolean
    filter_types: "face_blur" | "face_pixelate" | "region_redact"[]
    redact_regions?: BoundingBox[]
  }
}
```

### BatchAnalysisConfig

```typescript
BatchAnalysisConfig {
  requests: ImageAnalysisRequest[]
  concurrency: number             // Max parallel LLMOS calls
  fail_on_error: boolean          // Stop on first failure vs collect errors
  collect_partial: boolean        // Return partial results on failure
}
```

## Core Concepts

### Analysis Modes

Image Analysis supports five modes, each producing a distinct output type:

| Mode | Primary Output | LLMOS Model Type | Use Case |
|------|---------------|------------------|----------|
| describe | Natural language string | Vision-language model | General image understanding |
| classify | Label[] with confidence | Classification model | Categorize images |
| detect | DetectedObject[] with boxes | Object detection model | Object localization |
| ocr | ExtractedText[] with positions | OCR model | Document scanning |
| full | All of the above | Multi-modal model | Comprehensive analysis |

`full` mode executes all sub-modes in a single LLMOS call when the provider supports it, otherwise dispatches parallel sub-calls.

### Image Preprocessing Pipeline

All images pass through a deterministic preprocessing pipeline before LLMOS inference:

```
Raw Input
    â”‚
    â–¼
Step 1: Format Normalization
    â”‚   Convert to target format (default: png)
    â”‚   Unsupported formats â†’ VIS_UNSUPPORTED_FORMAT
    â”‚
    â–¼
Step 2: Resize
    â”‚   Scale to fit within max_width Ã— max_height
    â”‚   Maintains aspect ratio; pads if needed
    â”‚   Exceeds limit Ã— 2 â†’ VIS_IMAGE_TOO_LARGE
    â”‚
    â–¼
Step 3: Compression
    â”‚   Apply compression_quality setting
    â”‚   Trade-off: lower quality = faster inference
    â”‚
    â–¼
Step 4: Enhancement
    â”‚   Auto-applied for low-quality images
    â”‚   Adjusts brightness, contrast, sharpness
    â”‚   Skip if enhance_low_quality = false
    â”‚
    â–¼
Step 5: Privacy Filter
    â”‚   Face blurring/pixelation (configurable)
    â”‚   Region redaction (configurable)
    â”‚   Applied before any external output
    â”‚
    â–¼
Processed Image â†’ LLMOS Inference
```

### Face Detection

Face detection follows VIS-004 constraints:
- Always returns bounding boxes only
- Never extracts identity, facial recognition embeddings, or name labels
- Confidence threshold configurable via `min_confidence`
- Landmarks (eye, nose, mouth positions) returned only if attributes requested
- Emotion and age estimates are approximations, never stored as identity

### Privacy Filter Application (VIS-005)

Privacy filtration is mandatory and non-bypassable:
1. Face blurring applied at preprocessing stage
2. Region redaction removes user-specified bounding boxes
3. Filtered image is used for LLMOS inference â€” provider never sees raw faces
4. If all content is redacted, returns `VIS_ALL_CONTENT_BLOCKED`
5. Filter application is logged via `VIS.PrivacyFilterApplied` event

### Batch Image Analysis

Batch processing handles multiple images efficiently:

```
Batch Request
    â”‚
    â”œâ”€â”€ Validate all requests â†’ reject invalid upfront
    â”œâ”€â”€ Apply preprocessing per image (parallel)
    â”œâ”€â”€ Dispatch to LLMOS with concurrency limit
    â”‚
    â”œâ”€â”€ On individual failure:
    â”‚   fail_on_error=true  â†’ abort entire batch
    â”‚   fail_on_error=false â†’ collect partial results
    â”‚
    â””â”€â”€ Return BatchAnalysisResult
          â”œâ”€â”€ results: ImageAnalysisResult[]
          â”œâ”€â”€ errors: AnalysisError[]
          â””â”€â”€ summary: { total, succeeded, failed, total_time_ms }
```

## Internal Interface

```typescript
interface ImageAnalyzer {
  analyze(request: ImageAnalysisRequest): Promise<ImageAnalysisResult>
  analyzeBatch(requests: BatchAnalysisConfig): Promise<BatchAnalysisResult>

  preprocessImage(
    image: ImageInput,
    preprocessConfig: PreprocessingConfig
  ): Promise<PreprocessedImage>

  getLabels(
    image: ImageInput,
    config: VisionConfig
  ): Promise<Label[]>

  getObjects(
    image: ImageInput,
    config: VisionConfig
  ): Promise<DetectedObject[]>

  getFaces(
    image: ImageInput,
    config: VisionConfig
  ): Promise<Face[]>
}

interface ImagePreprocessor {
  normalize(
    image: ImageInput,
    targetFormat: string
  ): Promise<ImageInput>

  resize(
    image: ImageInput,
    maxWidth: number,
    maxHeight: number
  ): Promise<ImageInput>

  compress(
    image: ImageInput,
    quality: number
  ): Promise<ImageInput>

  enhance(
    image: ImageInput
  ): Promise<ImageInput>

  applyPrivacyFilter(
    image: ImageInput,
    filterConfig: PrivacyFilterConfig
  ): Promise<FilteredImage>
}

interface BatchAnalysisResult {
  request_id: string
  results: ImageAnalysisResult[]
  errors: AnalysisError[]
  summary: {
    total: number
    succeeded: number
    failed: number
    total_processing_time_ms: number
  }
}

interface PreprocessedImage {
  data: bytes
  format: string
  width: number
  height: number
  preprocessing_log: PreprocessingStep[]
}

interface PreprocessingStep {
  step: string
  applied: boolean
  details?: string
}

interface FilteredImage {
  data: bytes
  regions_redacted: number
  filter_types_applied: string[]
}

interface AnalysisError {
  request_id: string
  error_code: string
  message: string
  recoverable: boolean
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VIS.ImageAnalysisStarted |    request_id, analysis_type, dimensions, mode_count | Image analysis began |
| VIS.ImageAnalysisCompleted |    request_id, analysis_type, label_count, processing_time | Analysis finished successfully |
| VIS.ImageAnalysisFailed |    request_id, error_code, reason, stage | Analysis failed at a specific pipeline stage |
| VIS.PreprocessingStarted |    request_id, original_format, original_size | Preprocessing pipeline initiated |
| VIS.PreprocessingCompleted |    request_id, processed_format, processed_size, steps_applied | Preprocessing finished |
| VIS.FaceDetected |    request_id, face_count, max_confidence | Faces found in image (count only, no identity) |
| VIS.PrivacyFilterApplied |    request_id, filter_type, regions, total_redacted | Privacy filter triggered during preprocessing |
| VIS.BatchAnalysisStarted |    batch_id, request_count, concurrency | Batch analysis job began |
| VIS.BatchAnalysisProgress |    batch_id, completed, failed, total | Batch analysis progress update |
| VIS.BatchAnalysisCompleted |    batch_id, total, succeeded, failed, total_time_ms | Batch analysis finished |
| VIS.LabelExtracted |    request_id, label, confidence, category | Individual classification label produced |
| VIS.ObjectDetected |    request_id, object_name, confidence, box_area | Individual object detected with bounding box |
| VIS.AllContentBlocked |    request_id, filter_type, reason | Privacy filter redacted entire image |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IMA-001 | Every analysis request has exactly one analysis_type | Schema â€” analysis_type is required and validated |
| IMA-002 | Preprocessing always runs before LLMOS inference | Algorithmic â€” pipeline stages are sequential and mandatory |
| IMA-003 | Face detection never returns identity labels | Constitutional â€” VIS-004; bounding boxes only |
| IMA-004 | Privacy filter is always applied before image leaves Vision System | Algorithmic â€” filter runs in ImagePreprocessor, cannot be skipped |
| IMA-005 | Preprocessing output dimensions never exceed max_width Ã— max_height | Algorithmic â€” resize enforces hard limits |
| IMA-006 | Batch processing respects concurrency limit to prevent LLMOS overload | Algorithmic â€” semaphore-controlled dispatch |
| IMA-007 | Image data is ephemeral unless explicitly stored to Memory OS | Architectural â€” no automatic persistence |
| IMA-008 | All faces in an image are returned in a single result (no paging) | Schema â€” face array contains all detections |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unsupported image format | `VIS_UNSUPPORTED_FORMAT` | Return error; list supported formats in message |
| Image exceeds max dimensions Ã— 2 | `VIS_IMAGE_TOO_LARGE` | Return error; suggest compression before retry |
| Invalid analysis_type | `VIS_INVALID_ANALYSIS_TYPE` | Return error; list valid modes |
| Privacy filter blocked all content | `VIS_ALL_CONTENT_BLOCKED` | Return "content not available" with filter details |
| No objects detected (detect mode) | `VIS_NO_OBJECTS_DETECTED` | Return empty array; not an error |
| No text found (ocr mode) | `VIS_NO_TEXT_FOUND` | Return empty array; not an error |
| LLMOS inference timeout | `VIS_ANALYSIS_TIMEOUT` | Return partial results with timeout flag |
| Preprocessing enhancement failed | `VIS_ENHANCEMENT_FAILED` | Skip enhancement, continue pipeline, log warning |
| Batch: all requests failed | `VIS_BATCH_ALL_FAILED` | Return BatchAnalysisResult with empty results and all errors |
| Batch: concurrency limit exceeded | `VIS_BATCH_CONCURRENCY_EXCEEDED` | Cap to max concurrency, log warning, continue |
| Provider returned malformed response | `VIS_PROVIDER_MALFORMED_RESPONSE` | Retry once; on repeat failure, return error |


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
| R1 â€” Modulsingularity | Image Analysis handles only static image processing |
| R2 â€” Dependency Order | Depends on LLMOS for inference; no upward deps |
| R3 â€” DRY | All analysis modes share preprocessing pipeline |
| R4 â€” Builder Pattern | Analysis built by Preprocessor â†’ Provider â†’ Result Aggregator |
| R5 â€” Liskov Substitution | Any VisionProvider implements the interface |
| R6 â€” DI over Singletons | Providers and preprocessing config injected |
| R9 â€” Deterministic | Same image + config produces same analysis (model-dependent) |
| R10 â€” Simpler Over Complex | Five clear modes; full mode composes sub-modes |
| R13 â€” Design for Failure | Provider timeouts, partial results, batch error collection |
| R14 â€” Paved Path | `analyze()` is the single entry point for all modes |
| R15 â€” Open/Closed | New analysis modes added via provider, not by modifying ImageAnalyzer |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Vision/000-Overview.md | Image Analysis is the primary vision service |
| Vision/002-OCR.md | OCR mode delegates to OCREngine |
| Vision/003-Scene-Description.md | Describe mode delegates to SceneDescriber |
| Brain/LLMOS/000-Overview.md | LLMOS provides the inference backend |
| Brain/Cognitive/000-Overview.md | Cognitive OS consumes analysis results for reasoning |
| Brain/Sou/000-Overview.md | Sou initiates analysis requests |
| Brain/Memory/000-Overview.md | Results optionally persisted via Memory OS |
| Bible/05-Platform/004-EVS.md | Events emitted throughout lifecycle |
