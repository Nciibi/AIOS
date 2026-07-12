# AIOS Bible â€” Brain
## 005 â€” Document Parser

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Vision |
| Document ID | AIOS-BBL-002-VIS-005 |
| Source Laws | Law 4 â€” Law of Evidence, Law 3 â€” Law of Communication |
| Source Physics | Physics/005-Events.md, Physics/009-Interaction.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Document Parser extracts structured data from document images â€” invoices, receipts, forms, identity documents, and generic documents. It combines OCR output with type-specific field extraction to produce structured, validated results with per-field confidence scores. When a document type is not recognized, it falls back to generic parsing (all detected text with layout).

The Document Parser is how Sou reads and extracts meaning from visual documents â€” converting scanned paper into structured data that can be stored, queried, and reasoned about.

## Data Model

### DocumentParseRequest

```typescript
DocumentParseRequest {
  request_id: string
  image: ImageInput
  document_type: "invoice" | "receipt" | "form" | "identity" | "generic" | "auto"
  config: DocumentParseConfig
  session_id: string
  metadata?: {
    source: string                 // "scan" | "photo" | "upload" | "fax"
    original_filename?: string
    expected_fields?: string[]     // For form validation
    tags: string[]
  }
}
```

### DocumentParseResult

```typescript
DocumentParseResult {
  request_id: string
  document_type: string           // Resolved type (or "generic")
  fields: ParsedField[]
  raw_text: string
  overall_confidence: number
  structure?: DocumentStructure
  detection: DocumentTypeDetection
  validation?: FieldValidationReport
  metadata: {
    page_count: number
    field_count: number
    required_fields_found: number
    required_fields_missing: number
    processing_time_ms: number
    llmos_usage?: { tokens_consumed: number, model_used: string }
  }
}
```

### ParsedField

```typescript
ParsedField {
  name: string                     // Field identifier, e.g. "invoice_number"
  value: string
  confidence: number               // 0.0â€“1.0
  bounding_box?: BoundingBox
  field_type: "text" | "number" | "date" | "currency" | "email" | "phone" | "checkbox" | "signature" | "barcode"
  is_required: boolean
  is_valid: boolean
  validation_errors?: string[]
  alternatives?: string[]          // Alternative extracted values
}
```

### DocumentStructure

```typescript
DocumentStructure {
  type: string                     // Detected document type
  regions: DocumentRegion[]
  tables?: ExtractedTable[]
  confidence: number
}

DocumentRegion {
  label: string                    // e.g. "header", "line_items", "totals", "footer"
  bounding_box: BoundingBox
  field_names: string[]            // Fields found in this region
  region_type: "header" | "body" | "table" | "totals" | "footer" | "signature"
}

ExtractedTable {
  label: string
  bounding_box: BoundingBox
  headers: string[]
  rows: TableRow[]
  confidence: number
}

TableRow {
  cells: TableCell[]
  row_number: number
}

TableCell {
  text: string
  confidence: number
  column_index: number
  bounding_box?: BoundingBox
}
```

### DocumentTypeDetection

```typescript
DocumentTypeDetection {
  detected_type: string
  confidence: number               // 0.0â€“1.0
  alternatives: DocumentTypeAlternative[]
  method: "layout" | "content" | "barcode" | "user_specified"
}

DocumentTypeAlternative {
  type: string
  confidence: number
}
```

### FieldValidationReport

```typescript
FieldValidationReport {
  valid: boolean
  field_results: FieldValidation[]
  required_fields_present: boolean
  missing_required_fields: string[]
}

FieldValidation {
  field_name: string
  is_valid: boolean
  errors: string[]
  warnings: string[]
  validated_against: string[]      // Validation rules applied
}
```

### DocumentParseConfig

```typescript
DocumentParseConfig {
  document_type?: "invoice" | "receipt" | "form" | "identity" | "generic" | "auto"
  auto_detect: boolean             // If type is "auto", attempt detection
  fields?: string[]                // Specific fields to extract (all if empty)
  min_field_confidence: number     // Default: 0.5
  validate_fields: boolean         // Default: true, apply type-specific validation
  extract_tables: boolean          // Default: true
  preserve_layout: boolean         // Default: true
  fallback_to_generic: boolean     // Default: true, fall back if type-specific fails
  language_hints?: string[]
  timeout_ms: number
}
```

## Core Concepts

### Document Type Detection

When `document_type` is `"auto"`, the Document Parser detects the type:

```
Algorithm:
  1. Run OCR to extract all text and layout
  2. Analyze layout features:
     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
     â”‚ Invoice:  header area, line items table,    â”‚
     â”‚           totals, invoice number pattern    â”‚
     â”‚ Receipt:  merchant name, items, total,      â”‚
     â”‚           date, payment method              â”‚
     â”‚ Form:     labeled fields, checkboxes,       â”‚
     â”‚           signature line                    â”‚
     â”‚ Identity: photo area, document number,      â”‚
     â”‚           name, date of birth, expiry       â”‚
     â”‚ Generic:  no clear type pattern             â”‚
     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
  3. Score each type based on layout + content
  4. Return highest-confidence match
  5. If no type exceeds threshold â†’ fall back to "generic"
```

### Document Types and Field Extraction

Each document type has a defined set of fields:

#### Invoice

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| invoice_number | text | Yes | Non-empty, alphanumeric |
| date | date | Yes | Valid date format |
| vendor_name | text | Yes | Non-empty |
| vendor_address | text | No | â€” |
| customer_name | text | Yes | Non-empty |
| line_items | table | Yes | At least one line item |
| subtotal | currency | Yes | Positive number |
| tax | currency | No | Positive number |
| total | currency | Yes | Matches subtotal + tax |
| due_date | date | No | Valid date, after invoice date |

#### Receipt

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| merchant_name | text | Yes | Non-empty |
| merchant_address | text | No | â€” |
| date | date | Yes | Valid date |
| items | table | Yes | At least one item |
| subtotal | currency | Yes | Positive number |
| tax | currency | No | Positive number |
| total | currency | Yes | Matches subtotal + tax |
| payment_method | text | No | e.g. "credit", "cash", "card" |
| tip | currency | No | â€” |

#### Form

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| form_title | text | No | â€” |
| fields[] | text | Varies | Per-field validation rules |
| checkboxes[] | checkbox | No | Boolean (checked/unchecked) |
| signature | signature | No | Must be non-empty if present |
| date_filled | date | No | Valid date |

#### Identity Document

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| full_name | text | Yes | Non-empty |
| document_number | text | Yes | Pattern-matched per country |
| date_of_birth | date | Yes | Valid date, not in future |
| date_of_expiry | date | Yes | Valid date |
| nationality | text | Yes | Valid country code |
| gender | text | No | â€” |
| address | text | Varies | â€” |
| photo_present | checkbox | No | Boolean from layout detection |

#### Generic

| Field | Type | Description |
|-------|------|-------------|
| All detected text | text | All text blocks with positions |
| Structure | layout | Regions, headings, paragraphs |

### Field Extraction Pipeline

Field extraction follows a multi-stage pipeline:

```
Document Image
    â”‚
    â–¼
Step 1: OCR
    â”‚   Extract all text with positions (OCR Engine)
    â”‚   Detect layout regions and tables
    â”‚
    â–¼
Step 2: Type Detection
    â”‚   Identify document type (or use user-specified)
    â”‚   If auto: score types â†’ pick best
    â”‚   If unknown: fall back to generic
    â”‚
    â–¼
Step 3: Field Extraction
    â”‚   Load type-specific field templates
    â”‚   Map text regions to field names
    â”‚   Extract values with confidence
    â”‚   Handle multi-value (line items, tables)
    â”‚
    â–¼
Step 4: Validation
    â”‚   Apply type-specific validation rules
    â”‚   Check required fields
    â”‚   Validate formats (date, currency, patterns)
    â”‚   Flag missing/invalid fields
    â”‚
    â–¼
Step 5: Assembly
    â”‚   Package into DocumentParseResult
    â”‚   Calculate overall_confidence
    â”‚   Emit VIS.DocumentParsed event
    â”‚
    â–¼
DocumentParseResult
```

### Layout Analysis

Layout analysis identifies structural regions in the document:

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  INVOICE                     â”‚  â† header region
â”‚  Invoice #: INV-2024-001     â”‚
â”‚  Date: 2024-03-15            â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Bill To:                    â”‚  â† body region (vendor info)
â”‚  Acme Corp                   â”‚
â”‚  123 Main St                 â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Item       Qty  Price  Totalâ”‚  â† table region
â”‚  Widget A    2   25.00  50.00â”‚
â”‚  Widget B    1   75.00  75.00â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Subtotal:         125.00    â”‚  â† totals region
â”‚  Tax (10%):         12.50    â”‚
â”‚  Total:            137.50    â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Payment Terms: Net 30       â”‚  â† footer region
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Table Extraction

Tables are extracted via layout analysis + cell boundary detection:

```
Detection:
  1. Identify grid lines or aligned text columns
  2. Detect header row (bold/different formatting)
  3. Map column positions to headers
  4. Extract each row's cell values
  5. Return ExtractedTable with headers + rows

Validation:
  - All rows have same column count as header
  - Numeric columns parse as numbers
  - Balance checks: sum of line items matches totals
```

### Field Validation

Each field type has specific validation rules:

| Field Type | Validation Rules |
|-----------|------------------|
| text | Non-empty, max length, regex pattern match |
| number | Parseable as number, within range |
| date | Valid date, not in future (for birth dates), format match |
| currency | Parseable as decimal, positive, two decimal places |
| email | Regex pattern, valid domain format |
| phone | Country-specific format, digit count |
| checkbox | Boolean (checked/unchecked) |
| signature | Non-empty pixel area, minimum stroke count |
| barcode | Valid decode, checksum verification |

### Fallback to Generic Parsing

When type-specific extraction fails, the Document Parser falls back:

```
Conditions for fallback:
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Type detection confidence < 0.5 â”‚
  â”‚ Required field extraction fails  â”‚
  â”‚ Validation produces > 50% errors â”‚
  â”‚ config.fallback_to_generic=true  â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Fallback behavior:
  1. Return all OCR text blocks as ParsedFields (name = block_type)
  2. Set overall_confidence to OCR overall confidence
  3. Mark document_type as "generic"
  4. Include structure layout if available
  5. Log fallback reason in metadata
```

## Internal Interface

```typescript
interface DocumentParser {
  parse(request: DocumentParseRequest): Promise<DocumentParseResult>

  detectType(
    image: ImageInput,
    config: DocumentParseConfig
  ): Promise<DocumentTypeDetection>

  extractFields(
    ocrResult: OCRResult,
    docType: string,
    config: DocumentParseConfig
  ): Promise<ParsedField[]>

  validateFields(
    fields: ParsedField[],
    docType: string
  ): Promise<FieldValidationReport>

  getStructure(
    image: ImageInput,
    config: DocumentParseConfig
  ): Promise<DocumentStructure>
}

interface DocumentTypeDetector {
  detect(image: ImageInput, ocrResult: OCRResult): Promise<DocumentTypeDetection>
}

interface FieldExtractor {
  extractFromInvoice(ocrResult: OCRResult, config: DocumentParseConfig): Promise<ParsedField[]>
  extractFromReceipt(ocrResult: OCRResult, config: DocumentParseConfig): Promise<ParsedField[]>
  extractFromForm(ocrResult: OCRResult, config: DocumentParseConfig): Promise<ParsedField[]>
  extractFromIdentity(ocrResult: OCRResult, config: DocumentParseConfig): Promise<ParsedField[]>
  extractGeneric(ocrResult: OCRResult, config: DocumentParseConfig): Promise<ParsedField[]>
}

interface FieldValidator {
  validateField(field: ParsedField, docType: string): FieldValidation
  validateAll(fields: ParsedField[], docType: string): FieldValidationReport
}

interface TableExtractor {
  extractTables(ocrResult: OCRResult): Promise<ExtractedTable[]>
  validateTable(table: ExtractedTable): TableValidation
}

interface LayoutAnalyzer {
  analyzeLayout(ocrResult: OCRResult): Promise<DocumentStructure>
  detectRegions(textBlocks: TextBlock[]): DocumentRegion[]
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| VIS.DocumentParsingStarted |  request_id, document_type, auto_detect | Document parsing began |
| VIS.DocumentTypeDetected |  request_id, detected_type, confidence, method | Document type identified |
| VIS.DocumentTypeUnknown |  request_id, fallback_to_generic, alternatives | Document type not recognized |
| VIS.DocumentFieldExtracted |  request_id, field_name, confidence, field_type | Individual field extracted |
| VIS.DocumentFieldValidated |  request_id, field_name, is_valid, errors | Field validation completed |
| VIS.DocumentParsed |  request_id, document_type, field_count, overall_confidence | Document parsing completed |
| VIS.DocumentParseFailed |  request_id, error_code, stage | Document parsing failed |
| VIS.DocumentValidationReport |  request_id, valid, missing_fields, error_count | Full validation report |
| VIS.DocumentTableExtracted |  request_id, table_label, rows, columns | Table detected and extracted |
| VIS.DocumentFallbackToGeneric |  request_id, reason, original_type | Falling back to generic parsing |
| VIS.DocumentSignatureDetected |  request_id, confidence, region | Signature field identified |
| VIS.DocumentCheckboxDetected |  request_id, field_name, checked | Checkbox field identified and read |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DOC-001 | Every parsed field has a name, value, and confidence score | Schema â€” required fields on ParsedField |
| DOC-002 | Document type detection always returns a result (never null) | Algorithmic â€” falls back to "generic" if no match |
| DOC-003 | Field validation runs after extraction, never before | Algorithmic â€” pipeline order enforced |
| DOC-004 | Required fields are validated; missing required fields are flagged | Algorithmic â€” validation report includes missing list |
| DOC-005 | Table extraction preserves row/column positional alignment | Algorithmic â€” cell grid validation |
| DOC-006 | Fallback to generic does not lose extracted data | Architectural â€” generic output contains all text blocks |
| DOC-007 | Auto-detection runs only when document_type is "auto" | Schema â€” explicit conditional |
| DOC-008 | Currency fields validate as positive decimal numbers | Algorithmic â€” type-specific validation rules |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Document type detection inconclusive | `VIS_DOCUMENT_TYPE_UNKNOWN` | Fall back to generic parsing |
| Required field extraction failed | `VIS_DOCUMENT_MISSING_REQUIRED_FIELD` | Include field with empty value, flag in validation |
| Table extraction failed | `VIS_DOCUMENT_TABLE_EXTRACTION_FAILED` | Return fields without table; log warning |
| Field validation produced > 50% errors | `VIS_DOCUMENT_VALIDATION_FAILED` | Return result with validation report; suggest fallback |
| OCR returned no text | `VIS_DOCUMENT_NO_TEXT` | Return error; document may be blank or unreadable |
| Unsupported document type specified | `VIS_DOCUMENT_UNSUPPORTED_TYPE` | Fall back to auto-detect; log warning |
| Identity document date of expiry is in the past | `VIS_DOCUMENT_EXPIRED` | Return result with expired flag; not a hard error |
| Invoice total does not match subtotal + tax | `VIS_DOCUMENT_TOTAL_MISMATCH` | Flag in validation report; return extracted values |
| Signature detection failed | `VIS_DOCUMENT_SIGNATURE_DETECTION_FAILED` | Skip signature field; continue extraction |
| Parse request timed out | `VIS_DOCUMENT_PARSE_TIMEOUT` | Return partial results with timeout flag |
| Line items table has inconsistent columns | `VIS_DOCUMENT_INCONSISTENT_COLUMNS` | Flag malformed rows; include valid rows |
| Form checkbox ambiguous | `VIS_DOCUMENT_CHECKBOX_AMBIGUOUS` | Return uncertain state; flag for manual review |


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
| R1 â€” Modulsingularity | Document Parser handles only document-structured visual input |
| R2 â€” Dependency Order | Depends on OCR Engine, LLMOS; no upward deps |
| R3 â€” DRY | Field templates defined once per document type |
| R4 â€” Builder Pattern | Parsing built by OCR â†’ Type Detection â†’ Field Extraction â†’ Validation |
| R5 â€” Liskov Substitution | Any FieldExtractor, FieldValidator implements its interface |
| R6 â€” DI over Singletons | Type detectors, field extractors, validators injected |
| R9 â€” Deterministic | Same document + config produces same fields (model-dependent) |
| R10 â€” Simpler Over Complex | Type-specific templates; fallback to generic |
| R13 â€” Design for Failure | Fallback to generic; validation errors non-fatal; partial results |
| R14 â€” Paved Path | All document parsing flows through `parse()` |
| R15 â€” Open/Closed | New document types added via FieldExtractor, not by modifying core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Vision/000-Overview.md | Document Parser is a core sub-service of the Vision System |
| Vision/002-OCR.md | Document Parser consumes OCR results for field extraction |
| Brain/LLMOS/000-Overview.md | LLMOS provides document type classification and field extraction |
| Brain/Cognitive/000-Overview.md | Cognitive OS consumes structured document data for reasoning |
| Brain/Sou/000-Overview.md | Sou requests document parsing for data extraction |
| Brain/Memory/000-Overview.md | Extracted fields optionally persisted via Memory OS |
| Bible/05-Platform/004-EVS.md | Events emitted throughout document parsing lifecycle |
