# AIOS Bible â€” Brain
## 003 â€” Scene Describer

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Vision |
| Document ID | AIOS-BBL-002-VIS-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 3 â€” Law of Communication |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Scene Describer generates natural language descriptions of image content. It produces structured, multi-dimensional descriptions covering subjects, actions, environment, attributes, and visible text. Scene descriptions are the primary way Sou gains qualitative understanding of visual input â€” converting pixels into narrative context that can be reasoned about.

Under VIS-001, the Scene Describer extracts features only; Sou interprets meaning. Descriptions are factual observations, not interpretations, judgments, or decisions.

## Data Model

### SceneDescriptionRequest

```typescript
SceneDescriptionRequest {
  request_id: string
  image: ImageInput
  detail_level: "brief" | "normal" | "detailed"
  config: SceneDescriptionConfig
  session_id: string
}
```

### SceneDescriptionResult

```typescript
SceneDescriptionResult {
  request_id: string
  description: string              // Natural language description (detail-dependent)
  structured: StructuredDescription
  confidence: DescriptionConfidence
  metadata: {
    detail_level: string
    subject_count: number
    object_count: number
    text_mentions: number
    processing_time_ms: number
    llmos_usage?: { tokens_consumed: number, model_used: string }
  }
}
```

### StructuredDescription

```typescript
StructuredDescription {
  subjects: SceneSubject[]
  actions: SceneAction[]
  environment: SceneEnvironment
  attributes: SceneAttribute[]
  text_content: SceneText[]
}

SceneSubject {
  name: string
  classification: string          // e.g. "person", "animal", "object", "vehicle"
  attributes: string[]            // e.g. ["wearing blue suit", "standing"]
  position?: string               // e.g. "center", "left foreground", "background"
  relative_size: "dominant" | "large" | "medium" | "small"
  confidence: number              // 0.0â€“1.0
}

SceneAction {
  subject: string                 // References SceneSubject.name
  verb: string                    // e.g. "sitting", "walking", "holding"
  object?: string                 // e.g. "a laptop", "a coffee cup"
  confidence: number
}

SceneEnvironment {
  setting: string                 // e.g. "office", "outdoor park", "restaurant"
  lighting: "bright" | "dim" | "dark" | "mixed"
  time_of_day?: string            // e.g. "daytime", "night", "sunset"
  indoor: boolean
  confidence: number
}

SceneAttribute {
  attribute: string               // e.g. "colorful", "modern", "cluttered"
  subject_ref?: string            // Optional subject this attribute applies to
  confidence: number
}

SceneText {
  text: string
  context: string                 // e.g. "sign on wall", "book title", "slide heading"
  confidence: number
  bounding_box?: BoundingBox
}
```

### DescriptionConfidence

```typescript
DescriptionConfidence {
  overall: number                 // 0.0â€“1.0
  subject_confidence: number
  action_confidence: number
  environment_confidence: number
  attribute_confidence: number
  text_confidence: number
  uncertainty_reason?: string     // e.g. "blurry image", "occluded subjects"
}
```

### SceneDescriptionConfig

```typescript
SceneDescriptionConfig {
  detail_level: "brief" | "normal" | "detailed"
  max_subjects: number            // Max subjects to describe (default: 10)
  include_attributes: boolean     // Default: true
  include_text: boolean           // Default: true, include visible text
  include_environment: boolean    // Default: true
  min_confidence: number          // Minimum confidence to include dimension
  language: string                // Description language (default: "en")
  timeout_ms: number
}
```

## Core Concepts

### Scene Description Dimensions

The Scene Describer analyzes five dimensions of every image:

| Dimension | Description | Example Output |
|-----------|-------------|----------------|
| Subject | Main objects, people, animals | "a man in a blue suit", "a golden retriever" |
| Action | What is happening | "is giving a presentation", "is running through grass" |
| Environment | Where it takes place | "in a modern conference room", "in a sunny park" |
| Attributes | Colors, sizes, style, mood | "with a large screen", "dimly lit", "cluttered desk" |
| Text | Visible text content | "slide title: Q3 Results", "sign: Exit" |

### Description Detail Levels

The three detail levels control verbosity and depth:

```
brief:
  "A man presenting in a conference room with charts on screen."

normal:
  "A man in a blue suit is giving a presentation in a modern conference
   room. He is standing near a large screen showing Q3 revenue charts.
   The room has wooden tables and chairs. The screen text reads
   'Q3 Results 2024' and 'Revenue Growth: 15%'."

detailed:
  "A middle-aged man with short brown hair, wearing a navy blue suit
   with a light blue tie, is standing at the front of a modern conference
   room. He is gesturing toward a large wall-mounted display showing
   a bar chart labeled 'Q3 Results 2024'. The chart indicates revenue
   growth of 15% year-over-year. The room has floor-to-ceiling windows
   on the left side through which bright daylight enters. A glass table
   with six upholstered chairs occupies the center. On the table there
   are two coffee cups and a notepad. The atmosphere appears professional
   and focused."
```

| Level | Tokens (approx) | Use Case |
|-------|-----------------|----------|
| brief | 10â€“30 | Quick thumbnail understanding |
| normal | 50â€“150 | General image comprehension |
| detailed | 150â€“500 | Rich context for detailed reasoning |

### Natural Language Generation

Description generation follows a structured prompt pattern:

```
System: You are a scene describer. Describe what you see factually.
         Do not infer intent, emotion, or narrative beyond what is visible.
         Structure: subjects, actions, environment, attributes, visible text.

Image: [image input]

Detail Level: [brief/normal/detailed]

Output:
  For brief: 1â€“2 sentences covering the most salient elements.
  For normal: paragraph with subject, action, environment, key attributes.
  For detailed: structured breakdown of all visible elements.
```

### Structured Description Output

The structured description decomposes the natural language into queryable dimensions:

```
StructuredDescription {
  subjects: [
    { name: "man", classification: "person", attributes: ["blue suit", "standing"],
      position: "center", relative_size: "large", confidence: 0.95 },
    { name: "display screen", classification: "object", attributes: ["wall-mounted"],
      position: "background", relative_size: "large", confidence: 0.92 }
  ],
  actions: [
    { subject: "man", verb: "presenting", object: "to audience", confidence: 0.88 }
  ],
  environment: {
    setting: "conference room", lighting: "bright",
    time_of_day: "daytime", indoor: true, confidence: 0.94
  },
  attributes: [
    { attribute: "modern", subject_ref: "room", confidence: 0.85 },
    { attribute: "professional", confidence: 0.80 }
  ],
  text_content: [
    { text: "Q3 Results 2024", context: "chart title", confidence: 0.97 },
    { text: "Revenue Growth 15%", context: "chart label", confidence: 0.95 }
  ]
}
```

### Multi-Object Scene Handling

For scenes with multiple subjects, the Scene Describer applies:

| Strategy | Behavior |
|----------|----------|
| Prioritization | Most prominent subjects described first (by size/position) |
| Max limit | `max_subjects` cap prevents description overload |
| Positional ordering | Foreground â†’ background; center â†’ periphery |
| Grouping | Similar objects grouped (e.g., "a group of people" not 20 individuals) |

### Description Confidence

Confidence is computed per-dimension and aggregated to overall:

```
Factors affecting confidence:
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Image Quality                  â”‚ â† blur, noise, low resolution
  â”‚ Subject Occlusion              â”‚ â† partially hidden subjects
  â”‚ Lighting Conditions            â”‚ â† low light, backlight, shadows
  â”‚ Subject Familiarity            â”‚ â† common objects score higher
  â”‚ Ambiguity                      â”‚ â† unclear actions or environment
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Thresholding:
  If dimension.confidence < config.min_confidence:
    â†’ Exclude dimension from description
    â†’ Record reason in confidence.uncertainty_reason
  If overall.confidence < 0.3:
    â†’ Return low-confidence warning in result
```

## Internal Interface

```typescript
interface SceneDescriber {
  describe(request: SceneDescriptionRequest): Promise<SceneDescriptionResult>

  getDetailedDescription(
    image: ImageInput,
    config?: SceneDescriptionConfig
  ): Promise<StructuredDescription>

  getStructuredDescription(
    image: ImageInput,
    config?: SceneDescriptionConfig
  ): Promise<StructuredDescription>

  getDescriptionConfidence(
    image: ImageInput,
    config?: SceneDescriptionConfig
  ): Promise<DescriptionConfidence>

  getBrief(
    image: ImageInput,
    config?: SceneDescriptionConfig
  ): Promise<string>
}

interface DescriptionProvider {
  describe(image: ImageInput, config: SceneDescriptionConfig): Promise<SceneDescriptionResult>
  health(): ProviderHealth
}

interface StructuredDescriptionParser {
  parse(rawDescription: string): StructuredDescription
  extractConfidence(rawDescription: string): DescriptionConfidence
}

interface DimensionAnalyzer {
  analyzeSubjects(image: ImageInput): Promise<SceneSubject[]>
  analyzeAction(image: ImageInput): Promise<SceneAction[]>
  analyzeEnvironment(image: ImageInput): Promise<SceneEnvironment>
  analyzeAttributes(image: ImageInput): Promise<SceneAttribute[]>
  analyzeText(image: ImageInput): Promise<SceneText[]>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VIS.SceneDescriptionStarted |    request_id, detail_level, dimensions_requested | Scene description began |
| VIS.SceneDescriptionCompleted |    request_id, description_length, structured_fields | Description successfully generated |
| VIS.SceneDescriptionFailed |    request_id, error_code, reason | Description generation failed |
| VIS.SceneDimensionAnalyzed |    request_id, dimension, confidence | Individual dimension analyzed |
| VIS.SceneSubjectDetected |    request_id, subject_name, classification, confidence | Subject identified in scene |
| VIS.SceneEnvironmentClassified |    request_id, setting, indoor, lighting | Environment classification completed |
| VIS.SceneTextMentioned |    request_id, text_sample, context, confidence | Visible text included in description |
| VIS.SceneLowConfidence |    request_id, overall_confidence, uncertainty_reason | Description confidence below threshold |
| VIS.SceneDetailGenerated |    request_id, detail_level, token_count | Natural language description generated |
| VIS.SceneMultiSubject |    request_id, subject_count, group_count | Multiple subjects detected and handled |
| VIS.SceneOcclusionDetected |    request_id, subject, occlusion_estimate | Partial subject occlusion noted |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SCE-001 | Descriptions are factual observations, never interpretations or judgments | Constitutional â€” prompt-enforced; no inference of intent |
| SCE-002 | Every description has a detail level (brief/normal/detailed) | Schema â€” detail_level is required |
| SCE-003 | Dimensions below min_confidence are excluded from description | Algorithmic â€” threshold enforced before NLG |
| SCE-004 | Structured description always accompanies natural language output | Algorithmic â€” both generated from single LLMOS call |
| SCE-005 | Subject count never exceeds max_subjects | Algorithmic â€” truncation applied |
| SCE-006 | Text content in description references only visible text | Constitutional â€” no hallucinated text |
| SCE-007 | Multi-subject scenes describe subjects in prominence order | Algorithmic â€” sorting by size/position |
| SCE-008 | Description confidence is computed per-dimension and aggregated | Schema â€” per-dimension confidence in StructuredDescription |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Image too blurry for description | `VIS_SCENE_IMAGE_TOO_BLURRY` | Return low-confidence description with uncertainty note |
| No subjects detected | `VIS_SCENE_NO_SUBJECTS` | Return environment-only description |
| Environment classification failed | `VIS_SCENE_ENVIRONMENT_FAILED` | Exclude environment dimension, log warning |
| Description generation timeout | `VIS_SCENE_TIMEOUT` | Return partial description with timeout flag |
| LLMOS returned malformed description | `VIS_SCENE_MALFORMED_OUTPUT` | Retry once; on repeat failure, return error |
| Structured parsing failed | `VIS_SCENE_STRUCTURE_PARSE_FAILED` | Return description with natural language only |
| All dimensions below min_confidence | `VIS_SCENE_ALL_LOW_CONFIDENCE` | Return error; image may be unusable |
| Unsupported description language | `VIS_SCENE_LANGUAGE_UNSUPPORTED` | Fall back to English, log warning |
| Image exceeds max dimensions for provider | `VIS_SCENE_IMAGE_TOO_LARGE` | Return error; suggest resize |
| Text detection failed in image | `VIS_SCENE_TEXT_DETECTION_FAILED` | Skip text dimension, continue with others |


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
| R1 â€” Modulsingularity | Scene Describer handles only natural language description |
| R2 â€” Dependency Order | Depends on LLMOS; no upward deps |
| R3 â€” DRY | Description models and config defined once in Vision Model |
| R4 â€” Builder Pattern | Description built by Dimension Analysis â†’ NLG â†’ Structure Parser |
| R5 â€” Liskov Substitution | Any DescriptionProvider implements the interface |
| R6 â€” DI over Singletons | Providers, dimension analyzers, parsers injected |
| R9 â€” Deterministic | Same image + config produces same description (model-dependent) |
| R10 â€” Simpler Over Complex | Three detail levels; structured + natural language in one output |
| R13 â€” Design for Failure | Low confidence produces warning; timeout returns partial results |
| R14 â€” Paved Path | All descriptions flow through describe() |
| R15 â€” Open/Closed | New description dimensions added via provider SDK |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Vision/000-Overview.md | Scene Describer is a core sub-service of the Vision System |
| Vision/001-Image-Analysis.md | Describe mode delegates to SceneDescriber |
| Vision/002-OCR.md | Visible text in descriptions sourced from OCR |
| Brain/LLMOS/000-Overview.md | LLMOS provides vision-language models for description |
| Brain/Cognitive/000-Overview.md | Cognitive OS consumes scene descriptions for reasoning |
| Brain/Sou/000-Overview.md | Sou requests scene descriptions for qualitative understanding |
| Bible/05-Platform/004-EVS.md | Events emitted throughout description lifecycle |
