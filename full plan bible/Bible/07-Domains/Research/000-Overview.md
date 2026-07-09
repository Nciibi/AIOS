# AIOS Bible — Domains
## Research — 000: Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-RES-000 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Research domain enables AIOS to conduct systematic investigation — gathering information, analyzing data, synthesizing findings, and producing evidence-backed conclusions. It provides the capability set for literature review, data analysis, experiment design, hypothesis testing, and knowledge synthesis across any subject domain.

Research is a meta-domain: it operates across all other domains by consuming their outputs and producing new knowledge. Unlike domains that produce executable artifacts (code, firmware, configurations), Research produces knowledge artifacts — reports, analyses, models, and recommendations that feed back into Sou's reasoning and the Academy's knowledge base.

## Domain Entities

The Research domain defines the following entity types:

| Entity | Description | Genome Source |
|--------|-------------|---------------|
| ResearchWorker | A Worker specialized for research and analysis | AGS: Research/ResearchWorker |
| DataAnalyst | A Worker specialized for data analysis and visualization | AGS: Research/DataAnalyst |
| LiteratureReviewer | A Worker specialized for systematic literature review | AGS: Research/LiteratureReviewer |
| ResearchReport | A knowledge artifact containing research findings | Academy: Knowledge |
| HypothesisRecord | A structured hypothesis with evidence chain | Academy: Knowledge |

## Capabilities

The Research domain provides the following capability groups:

| Capability Group | Capabilities | Resource Profile |
|-----------------|--------------|-----------------|
| Web Research | `search_web`, `fetch_page`, `extract_content`, `verify_source` | Low token, I/O bound |
| Literature Review | `search_papers`, `extract_citations`, `compare_findings`, `identify_gaps` | High token, medium compute |
| Data Analysis | `analyze_dataset`, `run_statistics`, `create_visualization`, `detect_patterns` | Low token, high compute |
| Synthesis | `write_report`, `generate_summary`, `create_brief`, `formulate_conclusion` | High token, low compute |
| Experiment Design | `design_experiment`, `identify_variables`, `calculate_sample_size`, `plan_analysis` | Medium token, low compute |
| Hypothesis Testing | `test_hypothesis`, `evaluate_evidence`, `compute_confidence`, `assess_replicability` | Low token, high compute |
| Fact-Checking | `verify_claim`, `cross_reference`, `assess_credibility`, `detect_bias` | Medium token, low compute |

## Research Methodology

Research in AIOS follows a structured methodology:

```
1. Question Formulation
   └─ Research question defined with scope, constraints, and success criteria
2. Literature Review
   └─ Existing knowledge retrieved from Academy + external sources
3. Hypothesis Generation
   └─ Falsifiable hypothesis produced from literature gap analysis
4. Data Collection
   └─ Evidence gathered (web search, dataset analysis, experiment, simulation)
5. Analysis
   └─ Statistical analysis, pattern detection, evidence weighting
6. Conclusion
   └─ Findings synthesized, confidence intervals reported, limitations documented
7. Knowledge Production
   └─ Research artifact submitted to Academy for validation and acceptance
8. Review
   └─ Academy Validator and Verifier process the artifact
9. Publication
   └─ Accepted knowledge published via Knowledge Distribution
```

## Evidence Quality Framework

Research Workers evaluate evidence quality on multiple dimensions:

| Dimension | Description | Scale |
|-----------|-------------|-------|
| Source Authority | Credibility and expertise of the source | 0.0–1.0 |
| Methodology Rigor | Strength of the research methodology used | 0.0–1.0 |
| Reproducibility | Whether findings have been independently reproduced | 0.0–1.0 |
| Recency | Age of the evidence (newer is higher quality) | 0.0–1.0 (decay over time) |
| Relevance | Directness of evidence to the research question | 0.0–1.0 |
| Consistency | Agreement with other evidence on the same topic | 0.0–1.0 |
| Independence | Whether the source has conflicts of interest | 0.0–1.0 |

Evidence with a composite quality score below 0.4 is flagged as low-confidence. Research conclusions must be accompanied by their evidence quality assessment.

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Research.QuestionFormulated` | Research question is defined | question_id, question_text, scope, constraints |
| `Research.SourceRetrieved` | External source is fetched | source_id, url, content_type, size_bytes, retrieval_time |
| `Research.AnalysisRun` | Data analysis completes | analysis_id, method, dataset_id, key_findings |
| `Research.HypothesisTested` | Hypothesis test is evaluated | hypothesis_id, result, confidence_interval, evidence_quality |
| `Research.ReportGenerated` | Research report is produced | report_id, title, findings_count, evidence_chain_hash |
| `Research.KnowledgeProposed` | Research artifact submitted to Academy | artifact_id, artifact_type, evidence_hashes |

## Cross-Cutting Concerns

### Security

Research Workers have controlled internet access for web search and source retrieval. Retrieved content is sanitized for malicious content before processing. Research artifacts are access-controlled per Organization policy. Data analysis runs in sandboxed environments — no network access during analysis. (Physics/008-Security.md)

### Evidence

Research is inherently evidence-driven. Every source, analysis step, and conclusion produces an Event. The complete evidence chain from question to conclusion is recorded and immutable. Research artifacts submitted to Academy include full provenance. (PHI-008)

### Lifecycle

Research Workers follow the canonical Worker lifecycle. Research projects follow a project lifecycle: Question → Review → Collect → Analyze → Conclude → Publish. Knowledge artifacts follow the Academy lifecycle: Proposed → Validated → Verified → Accepted → Published. (Physics/006-Lifecycles.md)

### Capability Bounds

Research capabilities are bounded by web access policies, token budgets for reading, and compute budgets for analysis. A ResearchWorker cannot access sources outside its Organization's authorized scope. Data analysis is bounded by dataset size and compute allocation. (Physics/007-Capabilities.md)

### Communication

All Research domain communication flows through ACF. Web search results and retrieved content arrive via ACF from internet-facing gateways. Research artifacts are submitted to Academy through ACF. Findings are distributed through ACF Knowledge Distribution channels. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each research capability (search, analyze, synthesize, fact-check) is a separate concern |
| R3 (DRY) | Research findings are stored once in Academy, referenced by all consumers |
| R7 (Testability) | Every research methodology step has a verifiable output |
| R9 (Deterministic) | Same source data and methodology produces identical analysis results |
| R10 (Simpler Over Complex) | Research methodology is linear — no unbounded exploration loops |
| R13 (Design for Failure) | Incomplete source retrieval produces partial results with gaps noted |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/0005-Domain-Architecture.md | Domain Architecture — Research domain structure |
| Physics/005-Events.md | Evidence — Research operations produce Events |
| Physics/007-Capabilities.md | Capabilities — Research capability bounds |
| Physics/012-Experience.md | Experience — Research findings contribute to AIOS experience model |
| Bible/02-Core/Sou/001-Reasoning.md | Reasoning — Sou consumes research findings for decision-making |
| Bible/02-Core/AGS/000-Overview.md | AGS — ResearchWorker and DataAnalyst Genome templates |
| Bible/02-Core/Academy/000-Overview.md | Academy — Research artifact knowledge lifecycle |
| Bible/02-Core/DTS/000-Overview.md | DTS — Evidence quality scoring for research confidence |
| Bible/02-Core/ROS/000-Overview.md | ROS — Token and compute budget for research operations |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
