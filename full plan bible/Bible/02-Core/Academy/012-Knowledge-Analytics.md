# AIOS Bible — Core
## Academy — 012: Knowledge Analytics

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-012 |
| Source Laws | Law 4 — Evidence |
| Source Physics | Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Knowledge Analytics measures, monitors, and analyses the Academy's knowledge ecosystem. It provides metrics on knowledge usage, quality, freshness, coverage, and gaps. Analytics enables the Security Council and Organization managers to make evidence-based decisions about knowledge strategy, resource allocation, and quality improvement.

Analytics is always aggregated. It never exposes individual entity evidence (CPR-010 — Evidence Privacy).

## Metrics

### Usage Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `query_frequency` | Number of search queries per time period | Search Events (010) |
| `top_knowledge_by_access` | Most frequently retrieved artifacts | Distribution Events (009) |
| `knowledge_by_type_distribution` | Query volume split by knowledge type | Search Events |
| `consumer_activity` | Active knowledge consumers per org per day | Distribution Events |
| `push_delivery_success_rate` | Percentage of push deliveries accepted | Distribution Events |
| `cache_hit_ratio` | How often cached knowledge is used vs. fresh pull | Distribution Events |

### Quality Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `confidence_distribution` | Spread of verification confidence scores across artifacts | Verifier Events (006) |
| `validation_pass_rate` | Percentage of proposed artifacts that pass validation | Validator Events (005) |
| `verification_pass_rate` | Percentage of validated artifacts that pass verification | Verifier Events |
| `review_approval_rate` | Percentage of reviewed artifacts that are approved | Review Events (007) |
| `average_review_time` | Mean time from Pending to decision in review | Review Events |
| `deprecation_rate` | Rate at which artifacts are deprecated over time | Versioning Events (008) |
| `artifact_freshness` | Age distribution of active artifacts | KMS Events (002) |

### Coverage Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `knowledge_coverage_by_domain` | Number of artifacts per domain/ concept | Knowledge Graph (003) |
| `concept_coverage` | Percentage of known concepts with at least one artifact | Knowledge Graph |
| `entity_coverage` | Percentage of entities that have produced knowledge | Registry Events (004) |
| `org_coverage` | Number of organizations contributing knowledge | Registry Events |
| `type_balance` | Distribution of artifacts across knowledge types | Registry Events |

## Gap Detection

Gap analysis identifies domains and areas with insufficient knowledge coverage:

### Gap Types

| Gap Type | Detection Method | Priority |
|----------|-----------------|----------|
| **Low coverage** | Concepts with < N artifacts (threshold: 3) | High |
| **Outdated knowledge** | Artifacts not updated in > M days (threshold: 90) | Medium |
| **Contradictory knowledge** | Artifacts with mutual `contradicts` edges (no resolution) | High |
| **Low confidence** | Artifacts with confidence < threshold (0.5) | Medium |
| **Unvalidated domain** | Complete domain with no accepted artifacts | Low |
| **Deprecated without replacement** | Deprecated artifacts not superseded by active ones | High |

### Gap Report Format

| Field | Description |
|-------|-------------|
| `gap_type` | Type of gap detected |
| `domain` | Affected domain or concept |
| `severity` | Critical, High, Medium, Low |
| `affected_artifacts` | List of relevant artifact IDs |
| `recommendation` | Suggested action to close the gap |
| `detected_at` | When the gap was first detected |
| `status` | Open, In-Progress, Resolved |

## Analytics Dashboard

The Analytics Dashboard is available to:

| Role | Access Level | Visible Metrics |
|------|-------------|-----------------|
| Security Council | Full | All metrics, all organizations |
| Organization manager | Organization-scoped | Metrics for their org only |
| Sou | Full | Strategic and coverage metrics |
| Individual entity | Self-scoped | Only knowledge they produced/consumed |

### Dashboard Sections

```
┌────────────────────────────────────────────────────────────┐
│  Knowledge Analytics Dashboard                                │
│  ┌──────────────────────┐  ┌──────────────────────────┐    │
│  │  Usage Overview       │  │  Quality Summary          │    │
│  │  Queries today: 1,234  │  │  Avg confidence: 0.82    │    │
│  │  Active consumers: 56  │  │  Validation pass: 87%    │    │
│  │  Top artifact: A-042   │  │  Review approval: 92%    │    │
│  └──────────────────────┘  └──────────────────────────┘    │
│  ┌──────────────────────┐  ┌──────────────────────────┐    │
│  │  Coverage Heatmap     │  │  Gap Alerts (3)          │    │
│  │  [Domain matrix]      │  │  • Org-X: low coverage  │    │
│  │                       │  │  • Concept-Y: outdated  │    │
│  │                       │  │  • A-030: contradicted  │    │
│  └──────────────────────┘  └──────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐      │
│  │  Trend: Confidence Over Time                       │      │
│  │  [Line chart: last 30 days]                        │      │
│  └──────────────────────────────────────────────────┘      │
└────────────────────────────────────────────────────────────┘
```

## Analytics Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Analytics.MetricComputed` | A metric is computed | metric_name, value, period, dimension |
| `Analytics.GapDetected` | A new knowledge gap is found | gap_type, domain, severity, affected_artifacts |
| `Analytics.GapResolved` | A previously detected gap is resolved | gap_id, resolution_type |
| `Analytics.ReportGenerated` | An analytics report is generated | report_type, period, org_id |
| `Analytics.DashboardViewed` | Dashboard is accessed | viewer_id, role, sections_viewed |

## Privacy Protections

Analytics operates under strict privacy constraints (CPR-010):

| Protection | Implementation |
|------------|----------------|
| **Aggregation only** | All metrics are aggregates (counts, averages, distributions). Never individual entity data. |
| **Minimum threshold** | Metrics are only reported if they represent ≥ 3 entities (prevents deanonymization) |
| **No event payload** | Analytics never includes raw Event payloads — only metadata (type, count, timestamp) |
| **No entity IDs** | Entity-level metrics are scoped to self-service only |
| **Retention** | Aggregated metrics retained for 365 days; raw analytics events retained for 90 days |
| **Access control** | Dashboard access is role-based and organization-scoped |

## Analytics Data Flow

```
Academy Events (005-011)
    │
    ▼
┌──────────────────────────────────────────────┐
│  Analytics Pipeline                            │
│                                                │
│  1. Consume Academy Events from ACF            │
│  2. Aggregate by metric type and dimension     │
│  3. Store in time-series database              │
│  4. Run gap detection algorithms               │
│  5. Update dashboard projections               │
│  6. Publish analytics events                   │
└──────────────────────────────────────────────┘
    │
    ├──▶ Time-Series Database (metrics)
    ├──▶ Gap Registry (open gaps)
    └──▶ Dashboard (real-time projections)
```

## Cross-Cutting Concerns

### Security

Analytics access is role-based and scoped. The Security Council sees all; Organization managers see their own; entities see only themselves. Raw Events are never exposed. Dashboard access is authenticated through ACF.

### Evidence

Every analytics computation produces an Event. All metrics are derived from Academy Events (005-011), which are themselves sourced from the Event Store. Analytics is evidence-based by construction.

### Lifecycle

Analytics runs continuously. Metric computation is triggered by Academy Events (real-time) and by scheduled batch jobs (daily for trend analysis). Gap detection runs daily.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| View dashboard | `analytics.dashboard.{scope}` |
| View gap reports | `analytics.gaps.{scope}` |
| View metrics | `analytics.metrics.{scope}` |
| Export report | `analytics.export` |

Scope is org-specific or global based on entity role.

### Communication

Analytics consumes all Academy Events from ACF topics. It publishes analytics events and gap alerts. Dashboard data is served through ACF request-response.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Analytics does measurement — does not intervene in knowledge operations |
| R2 | Analytics depends on Academy Events, not vice versa |
| R3 | Metrics are computed from Events (single source of truth) |
| R9 | Metrics are deterministic for the same time period |
| R10 | Analytics uses simple aggregations (count, avg, distribution) |
| R12 | Every analytics error has a unique code |
| R13 | Analytics fails closed on data source failure |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Analytics consumes Academy Events |
| Governance/006-AKM.md | AKM quality metrics measured by Analytics |
| Foundations/001-AIOS-Philosophy.md | PHI-008 — evidence over opinion (analytics is evidence-based) |
| Foundations/003-Core-Principles.md | CPR-010 — analytics respects privacy |
| Foundations/002-Design-DNA.md | R1, R2, R3, R9, R10, R12, R13 |
| 003-Knowledge-Graph.md | Coverage and gap analysis uses graph |
| 005-Knowledge-Validator.md | Validation pass rate metric |
| 006-Knowledge-Verifier.md | Confidence distribution metric |
| 007-Knowledge-Review.md | Review approval rate metric |
| 009-Knowledge-Distribution.md | Usage metrics from distribution |
| 010-Knowledge-Search.md | Query frequency metric |
