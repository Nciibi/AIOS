# AIOS Bible â€” Domains
## Research â€” 001: Literature Review

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-RES-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Literature Review engine enables AIOS to conduct systematic investigation of published research â€” searching academic databases, retrieving papers, extracting citations, comparing findings across sources, assessing quality, and identifying knowledge gaps. It ensures that AIOS builds on existing knowledge rather than duplicating effort or reaching uninformed conclusions.

## Architecture

```
search_papers â”€â”€> retrieve_papers â”€â”€> extract_citations â”€â”€> compare_findings â”€â”€> synthesize â”€â”€> identify_gaps
       â”‚               â”‚                   â”‚                      â”‚                  â”‚               â”‚
       v               v                   v                      v                  v               v
  QueryResult     PaperRecord        CitationList         ComparisonMatrix     SynthesisDoc     GapAnalysis
```

The pipeline is linear: each step depends on the previous. Partial results are propagated on failure with gaps noted.

## Data Model

```typescript
interface PaperRecord {
  paperId: string;
  title: string;
  authors: Author[];
  abstract: string;
  publicationDate: Date;
  source: AcademicDatabase;
  doi: string;
  url: string;
  isOpenAccess: boolean;
  citations: Citation[];
  keywords: string[];
  methodology: ResearchMethodology;
  qualityScore: number;
  retrievedAt: Date;
}

interface Author {
  name: string;
  orcid?: string;
  affiliation?: string;
}

interface Citation {
  citationId: string;
  citingPaperId: string;
  citedPaperId: string;
  context: string;
  location: number;
  isDirectClaim: boolean;
}

interface FindingExtract {
  findingId: string;
  paperId: string;
  claim: string;
  evidenceType: EvidenceType;
  confidenceInterval?: ConfidenceInterval;
  sampleSize?: number;
  statisticalSignificance?: number;
  extractedAt: Date;
}

interface ComparisonMatrix {
  comparisonId: string;
  topic: string;
  findings: FindingPosition[];
  agreementLevel: AgreementLevel;
  contradictions: Contradiction[];
  unresolvedDifferences: string[];
}

interface GapAnalysis {
  gapId: string;
  researchQuestion: string;
  coveredAspects: string[];
  uncoveredAspects: string[];
  partiallyCoveredAspects: string[];
  suggestedDirection: string;
  priority: number;
}

enum AcademicDatabase {
  ArXiv = "arxiv",
  PubMed = "pubmed",
  IEEE = "ieee",
  ACM = "acm",
  SemanticScholar = "semantic_scholar",
  Crossref = "crossref",
  OpenAlex = "openalex",
  Core = "core"
}

enum ResearchMethodology {
  SystematicReview = "systematic_review",
  MetaAnalysis = "meta_analysis",
  RandomizedTrial = "randomized_trial",
  ObservationalStudy = "observational_study",
  CaseStudy = "case_study",
  TheoreticalAnalysis = "theoretical_analysis",
  Simulation = "simulation",
  QualitativeStudy = "qualitative_study"
}

enum EvidenceType {
  EmpiricalQuantitative = "empirical_quantitative",
  EmpiricalQualitative = "empirical_qualitative",
  Theoretical = "theoretical",
  Computational = "computational",
  Anecdotal = "anecdotal"
}

enum AgreementLevel {
  Consistent = "consistent",
  MostlyConsistent = "mostly_consistent",
  Mixed = "mixed",
  MostlyContradictory = "mostly_contradictory",
  Contradictory = "contradictory"
}

interface FindingPosition {
  findingId: string;
  paperId: string;
  claim: string;
  supportsQuestion: boolean;
  confidence: number;
}

interface Contradiction {
  findingA: string;
  findingB: string;
  nature: string;
  resolution?: string;
}

interface ConfidenceInterval {
  lower: number;
  upper: number;
  level: number;
}
```

## Core Concepts / Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| search_papers | query, databases[], filters | QueryResult | Searches configured academic databases with deduplication |
| retrieve_paper | paperId | PaperRecord | Fetches full paper metadata and open-access content |
| extract_citations | paperId | Citation[] | Extracts all citations with context and relationship type |
| compare_findings | paperIds[], topic | ComparisonMatrix | Aligns findings across papers and identifies agreement |
| assess_quality | paperId | qualityScore | Evaluates methodology, sample size, statistical rigor |
| synthesize | comparisonId | SynthesisDoc | Produces consolidated summary of findings per topic |
| identify_gaps | researchQuestion, synthesis | GapAnalysis | Identifies covered, uncovered, and partially covered aspects |
| verify_finding | findingId, method | boolean | Re-checks a finding against source data or alternative analysis |

## Internal Interfaces

| Interface | Provider | Consumer | Method | Description |
|-----------|----------|----------|--------|-------------|
| ISearchProvider | AcademicDatabaseGateway | LiteratureReviewer | search(query, filters, limit) | Executes search against a configured database |
| IRetrievalProvider | ContentRetrievalService | LiteratureReviewer | retrieve(paperId) | Fetches paper metadata and full text |
| ICitationExtractor | CitationParser | LiteratureReviewer | extract(text) | Parses citation references from paper text |
| IQualityAssessor | MethodologyValidator | LiteratureReviewer | assess(paperRecord) | Scores paper methodology and reporting quality |
| IGapAnalyzer | GapDetectionEngine | LiteratureReviewer | analyze(synthesis, question) | Identifies knowledge gaps from synthesis |
| IComparisonEngine | FindingAligner | LiteratureReviewer | compare(findings) | Aligns and compares findings across papers |

## Events

| RES.EventType |     Produced When | Fields |
|-----------|--------------|--------|
| RES.LiteratureSearchRun |     Academic database search completes | search_id, query, databases_queried, result_count, duration_ms |
| RES.PaperRetrieved |     Full paper metadata is fetched | paper_id, source, retrieval_time, content_size, is_open_access |
| RES.CitationExtracted |     Citations are parsed from a paper | paper_id, citation_count, extraction_time, errors_count |
| RES.FindingCompared |     Two or more findings are compared | comparison_id, paper_count, agreement_level, contradictions_found |
| RES.QualityAssessed |     Paper quality scoring completes | paper_id, quality_score, methodology_score, sample_adequacy, rigor_score |
| RES.GapIdentified |     Gap analysis is produced | gap_id, uncovered_aspects_count, priority, research_question_id |
| RES.SynthesisGenerated |     Literature synthesis is created | synthesis_id, papers_covered, finding_count, word_count |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| LIT-ERR-001 | Academic database unreachable (timeout or DNS failure) | High | Retry with backoff (3 attempts). If still unreachable, skip database and log gap. Fail if all databases unreachable. |
| LIT-ERR-002 | Paper is behind paywall and no open-access version found | Medium | Log as paywalled. Search for preprint version. Include metadata-only result with paywall flag. |
| LIT-ERR-003 | Citation extraction produces malformed or unparseable references | Medium | Extract what is parseable. Log unparseable citations with line numbers. Flag for manual review. |
| LIT-ERR-004 | Contradictory findings detected across sources of equal quality | High | Document both findings with evidence quality scores. Flag contradiction. Do not suppress either finding. |
| LIT-ERR-005 | Search query returns zero results across all databases | Medium | Suggest broader query terms. Log empty result. Return empty set with query documentation. |
| LIT-ERR-006 | Paper metadata is incomplete (missing DOI, authors, or date) | Low | Proceed with available metadata. Flag incomplete fields. Use partial record. |
| LIT-ERR-007 | Rate limit exceeded on academic database API | High | Backoff and retry after rate-limit window. Queue remaining queries. If rate-limited repeatedly, reduce query rate. |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| LIT-I-001 | Every finding in a synthesis must be traceable to exactly one source paper | Synthesis generation validates traceability. Unattributed findings cause validation failure. |
| LIT-I-002 | Search methodology (query, databases, filters, date) must be recorded and reproducible | Search parameters are hashed and stored with results. Same inputs must reproduce same result set. |
| LIT-I-003 | Conflicting findings must be surfaced, not suppressed | Comparison engine must report all contradictions. Suppression is a constitutional violation. |
| LIT-I-004 | Quality scores must be computed using a documented, consistent rubric | Scoring methodology is immutable per rubric version. Rubric changes require RFC. |
| LIT-I-005 | Paywalled papers must still be cited in reference lists if their metadata is accessible | Reference list includes all retrieved papers regardless of access status. Paywalled marked accordingly. |


## Cross-Cutting Concerns

### Security

Research operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Research emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Research instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Research declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Each pipeline stage (search, retrieve, extract, compare, synthesize, gap) is a separate concern |
| R2 - Dependency Order | Literature Review depends on ACF for transport; depends on Academy for knowledge storage |
| R3 - DRY | Paper metadata stored once in Academy, referenced by all analyses and syntheses |
| R4 - Builder Pattern | ComparisonMatrix and GapAnalysis are built by dedicated builders from raw comparison data |
| R5 - Liskov Substitution | All ISearchProvider implementations (ArXiv, PubMed, IEEE) are interchangeable |
| R6 - DI over Singletons | Database gateways are injected into LiteratureReviewer, not accessed globally |
| R9 - Deterministic | Same search query on same data snapshot produces identical results |
| R10 - Simpler Over Complex | Pipeline is linear with no branching search exploration loops |
| R13 - Design for Failure | Unreachable databases produce partial results with gaps noted; pipeline does not halt |
| R14 - Paved Path | Single paved path: search -> retrieve -> extract -> compare -> synthesize -> gap |
| R15 - Open/Closed | New academic databases implement ISearchProvider without modifying existing gateways |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Research/000-Overview.md | Research domain overview â€” entities, capabilities, methodology |
| Physics/005-Events.md | Evidence â€” all literature review operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” search scope and rate limits |
| Physics/012-Experience.md | Experience â€” literature findings contribute to AIOS knowledge |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” paper metadata and findings stored as knowledge artifacts |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” quality scoring and confidence assessment methodology |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” token and compute budget for literature retrieval |
| Bible/06-Services/ACF/000-Overview.md | ACF â€” transport for academic database queries and responses |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding for evidence-based research |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles applied to literature review |
