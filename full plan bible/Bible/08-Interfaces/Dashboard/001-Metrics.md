# AIOS Bible â€” Interfaces
## Dashboard â€” 001: Metrics

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-DB-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 8 â€” Law of Verification-First, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Metrics subsystem defines how dashboard values are defined, sourced, aggregated, and validated. Every number displayed on a dashboard traces through this pipeline: metric definition -> source query -> aggregation -> evidence binding -> display -> staleness check. Metrics are the atomic unit of all dashboard visualizations.

## Architecture

```
Metric Catalog (registered definitions)
       |
       v
Data Source Binding (AOP / EVS / AUS query config)
       |
       v
Query Execution -> DataAggregator.query(query)
       |
       v
Aggregation Pipeline (sum, avg, count, latest, distinct)
       |
       v
Evidence Binding (attach evidenceRef to MetricValue)
       |
       v
Display (widget consumes MetricValue)
       |
       v
Staleness Check (freshnessCheck on lastUpdated)
```

## Data Model

```typescript
interface MetricDefinition {
  metricId: string;
  name: string;
  description: string;
  unit: string;
  dataSource: DataSourceBinding;
  aggregation: AggregationPipeline;
  stalenessThresholdSeconds: number;
  tags: Record<string, string>;
}

interface MetricValue {
  metricId: string;
  value: number | string | boolean;
  evidenceRef: string;
  computedAt: Timestamp;
  sourceQuery: DataQuery;
  stale: boolean;
}

interface AggregationPipeline {
  steps: AggregationStep[];
  outputType: 'scalar' | 'series' | 'distribution';
}

interface AggregationStep {
  method: 'filter' | 'transform' | 'sum' | 'avg' | 'count' | 'latest' | 'distinct' | 'percentile';
  params: Record<string, unknown>;
}

interface DataSourceBinding {
  source: 'aop' | 'evs' | 'aus' | 'simulation';
  queryTemplate: DataQuery;
  retryPolicy: {
    maxRetries: number;
    backoffMs: number;
  };
}

interface StalenessCheck {
  metricId: string;
  lastUpdated: Timestamp;
  thresholdSeconds: number;
  stale: boolean;
  checkedAt: Timestamp;
}
```

## Core Concepts

### 1. Metric Definition

Metrics are defined in a catalog before use. Each definition specifies a data source, aggregation pipeline, staleness threshold, and metadata. Definitions are immutable once created; changes produce a new metric version.

### 2. Data Source Binding

Each metric binds to exactly one data source (AOP, EVS, AUS, or Simulation) via a DataQuery template. The template parameterizes filters, time windows, and aggregation method. Sources are resolved at query time.

### 3. Aggregation Pipeline

Values pass through a multi-step pipeline: filtering raw events, transforming fields, then aggregating via sum, avg, count, latest, distinct, or percentile. The pipeline is deterministic for identical inputs.

### 4. Evidence Binding

Every computed MetricValue carries an evidenceRef pointing to the source event or record that produced it. This satisfies Law 4 and enables drill-down tracing from any displayed number.

### 5. Staleness Detection

After freshnessCheck fails (current time - lastUpdated > threshold), the metric is marked stale. Stale metrics are never displayed as current â€” they show a warning state or are omitted until fresh data arrives.

## Operations

| Operation | Description |
|-----------|-------------|
| define_metric(def: MetricDefinition) | Register a new metric in the catalog |
| query_metric(metricId, context) | Execute source query and return raw results |
| aggregate_values(rawData, pipeline) | Run aggregation pipeline over raw results |
| bind_evidence(metricId, value, evidenceRef) | Attach evidence reference to computed value |
| check_staleness(metricId) | Evaluate freshness and mark stale if expired |
| get_metric_value(metricId) | Return current MetricValue with staleness status |

## Internal Interfaces

```typescript
interface MetricCatalog {
  register(def: MetricDefinition): Promise<void>;
  lookup(metricId: string): Promise<MetricDefinition>;
  list(tags?: Record<string, string>): Promise<MetricDefinition[]>;
}

interface MetricExecutor {
  execute(metricId: string, context?: Record<string, unknown>): Promise<MetricValue>;
  aggregate(steps: AggregationStep[], data: unknown[]): Promise<AggregatedValue>;
}

interface StalenessMonitor {
  check(metricId: string): Promise<StalenessCheck>;
  markStale(metricId: string): Promise<void>;
  refresh(metricId: string): Promise<void>;
}
```

## Events

| Event Type | Produced When | Fields |
|-------|--------|-------------|
| DB.MetricDefined | metricId, name, source | New metric registered in catalog |
| DB.MetricQueried | metricId, source, durationMs | Source query executed for metric |
| DB.MetricAggregated | metricId, stepCount, outputType | Aggregation pipeline completed |
| DB.ValueBound | metricId, evidenceRef, computedAt | Evidence reference attached to value |
| DB.MetricStale | metricId, lastUpdated, threshold | Metric marked stale due to freshness timeout |
| DB.MetricRefreshed | metricId, newValue | Stale metric received fresh data |
| DB.MetricError | metricId, errorCode | Metric computation failed |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| DB_METRIC_SOURCE_UNAVAILABLE | Data source unreachable for query | ERROR | Retry with backoff; mark stale after threshold |
| DB_METRIC_AGGREGATION_TIMEOUT | Aggregation pipeline exceeds time limit | ERROR | Return partial results; log timeout context |
| DB_METRIC_EVIDENCE_MISSING | EvidenceRef points to nonexistent record | WARNING | Surface value with degraded evidence status |
| DB_METRIC_STALE_THRESHOLD_EXCEEDED | StalenessCheck exceeds max threshold | ERROR | Clear displayed value; show "stale" placeholder |
| DB_METRIC_DEFINITION_INVALID | MetricDefinition missing required fields | FATAL | Reject registration; log validation failure |
| DB_METRIC_PIPELINE_FAILURE | AggregationStep encounters invalid data | ERROR | Skip step; return partial pipeline result |
| DB_METRIC_RETRY_EXHAUSTED | All retry attempts for source query failed | ERROR | Mark metric as unavailable; alert operators |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| DB-007 | Every MetricValue has a non-null evidenceRef | Architectural â€” bind_evidence required before display |
| DB-008 | Stale data is never displayed as current | Algorithmic â€” staleness check gates all widget rendering |
| DB-009 | Metric definitions are immutable after registration | Architectural â€” catalog enforces create-only |
| DB-010 | Aggregation pipeline is deterministic for identical inputs | Algorithmic â€” same steps + same data = same output |
| DB-011 | Each metric binds to exactly one data source | Architectural â€” DataSourceBinding is singular |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Metrics subsystem owns value computation; display is handled by Widgets |
| R2 â€” Dependency Order | Depends on AOP, EVS, AUS via DataSourceBinding; no circular deps |
| R3 â€” DRY | Metric catalog ensures single definition per metric; widgets reference by ID |
| R4 â€” Builder Pattern | AggregationPipeline uses builder for composing steps |
| R5 â€” Liskov Substitution | Compliant | Metric definitions are interchangeable through the MetricProvider interface |
| R6 â€” Immutability | MetricDefinition is immutable; versions track changes |
| R9 â€” Deterministic | Same DataQuery + same evidence = same MetricValue |
| R10 â€” Simpler Over Complex | Default metrics (count, avg, latest) cover 80% of use cases |
| R13 â€” Design for Failure | Source outage marks stale; stale threshold prevents silent data rot |
| R14 â€” Paved Path | Pre-defined health metrics are the default for all views |
| R15 â€” Open/Closed | New aggregation methods register via AggregationStep extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Dashboard/000-Overview.md | Base dashboard architecture and evidence invariants |
| Bible/05-Platform/Observability/000-AOP.md | AOP provides metric source data |
| Bible/05-Platform/004-EVS.md | EVS provides evidence-backed metric values |
| Bible/05-Platform/005-AUS.md | AUS provides audit metrics |
| Bible/06-Services/ACF/000-Overview.md | ACF transports metric queries |
| Bible/08-Interfaces/Dashboard/002-Widgets.md | Widgets consume MetricValue for display |
| Bible/08-Interfaces/UI/000-Overview.md | UI renders metric visualizations |
| Bible/08-Interfaces/Console/000-Overview.md | Alerts link to Console for metric review |
| Physics/005-Events.md | Evidence invariants â€” metric values are evidence-derived |
| Physics/011-Design-DNA.md | Design DNA rules govern metric construction |
