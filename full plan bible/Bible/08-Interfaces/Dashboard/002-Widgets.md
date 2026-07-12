# AIOS Bible â€” Interfaces
## Dashboard â€” 002: Widgets

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-DB-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 8 â€” Law of Verification-First, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Widget system defines how individual visual components are created, configured, bound to data, laid out, and wired for drill-down. Widgets are the visual atoms of the Dashboard â€” each widget renders one aspect of system state by consuming a MetricValue and presenting it as a metric card, chart, table, alert list, or heatmap.

## Architecture

```
Widget Definition (config, type, layout)
       |
       v
Type Resolution (metric | chart | table | alert-list | heatmap)
       |
       v
Data Binding (attach MetricValue via query)
       |
       v
Layout Assignment (position, size, order within view)
       |
       v
Drill-Down Wiring (link points to DrillDown.trace)
       |
       v
Rendering (UI consumes WidgetConfig + data)
```

## Data Model

```typescript
interface WidgetConfig {
  widgetId: string;
  type: WidgetType;
  title: string;
  metricId?: string;
  query: DataQuery;
  layout: WidgetLayout;
  drillDown?: DrillDownLink;
  settings: Record<string, unknown>;
}

type WidgetType = 'metric' | 'chart' | 'table' | 'alert-list' | 'heatmap';

interface WidgetLayout {
  viewId: string;
  row: number;
  column: number;
  width: number;
  height: number;
  zIndex: number;
}

interface ChartSpec {
  type: 'line' | 'bar' | 'pie' | 'area' | 'scatter';
  xAxis: string;
  yAxis: string;
  series: ChartSeries[];
  options: Record<string, unknown>;
}

interface ChartSeries {
  name: string;
  metricId: string;
  color?: string;
}

interface DrillDownLink {
  targetType: 'evs' | 'aus' | 'aop' | 'console' | 'ui';
  targetId: string;
  params: Record<string, string>;
  label: string;
}

interface WidgetRenderer {
  widgetId: string;
  type: WidgetType;
  data: MetricValue | MetricValue[];
  config: WidgetConfig;
  renderedAt: Timestamp;
}
```

## Core Concepts

### 1. Widget Types

Five widget types serve all dashboard use cases: metric (single number), chart (time series or distribution), table (structured rows), alert-list (active alerts), heatmap (density visualization). Each type has a dedicated renderer and data binding pattern.

### 2. Data Binding

Widgets bind to data via a metricId reference or an inline DataQuery. The Data Aggregator resolves the binding and returns a MetricValue. Widgets display the value alongside its evidenceRef for drill-down.

### 3. Layout Management

Widgets are positioned on a grid defined per view. Layout specifies row, column, width, height, and z-index. The layout manager enforces grid boundaries and resolves overlaps by adjusting z-order.

### 4. Drill-Down Wiring

Every widget can define a DrillDownLink that specifies target system (EVS, AUS, AOP, Console, UI), target ID, and parameters. Clicking a widget element navigates the human to the linked evidence or action surface.

### 5. Configuration

WidgetConfig stores type-specific settings: chart axis configuration, table column definitions, alert-list severity filters, heatmap threshold colors. Settings are validated against the widget type schema.

## Operations

| Operation | Description |
|-----------|-------------|
| create_widget(config: WidgetConfig) | Register a new widget in a view |
| configure_widget(widgetId, settings) | Update widget type-specific settings |
| bind_data(widgetId, metricId) | Attach a metric definition as data source |
| render_widget(widgetId) | Execute rendering pipeline for widget |
| drill_down(widgetId, point) | Navigate to linked evidence via DrillDownLink |
| remove_widget(widgetId) | Unregister widget from its view |

## Internal Interfaces

```typescript
interface WidgetRegistry {
  register(config: WidgetConfig): Promise<void>;
  lookup(widgetId: string): Promise<WidgetConfig>;
  listByView(viewId: string): Promise<WidgetConfig[]>;
  remove(widgetId: string): Promise<void>;
}

interface WidgetRenderer {
  render(config: WidgetConfig, data: MetricValue | MetricValue[]): Promise<WidgetRenderer>;
  supportedTypes(): WidgetType[];
}

interface LayoutManager {
  assign(config: WidgetConfig): Promise<WidgetLayout>;
  resolveConflicts(viewId: string): Promise<WidgetLayout[]>;
  validate(layout: WidgetLayout): boolean;
}
```

## Events

| DASH.EventType |      Produced When | Fields |
|-------|--------|-------------|
| DASH.WidgetCreated |      widgetId, type, viewId | New widget registered in a view |
| DASH.WidgetConfigured |      widgetId, settings | Widget settings updated |
| DASH.WidgetBound |      widgetId, metricId, query | Data source attached to widget |
| DASH.WidgetRendered |      widgetId, type, durationMs | Widget rendering completed |
| DASH.DrillDownExecuted |      widgetId, targetType, targetId | Human drilled down from widget |
| DASH.WidgetRemoved |      widgetId, viewId | Widget unregistered from view |
| DASH.LayoutConflict |      viewId, widgetIds | Layout overlap detected and resolved |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| DB_WIDGET_TYPE_UNSUPPORTED | Widget type not in supported renderers | FATAL | Reject widget creation; list supported types |
| DB_WIDGET_DATA_BIND_FAILED | MetricId or DataQuery cannot be resolved | ERROR | Show widget in error state with retry button |
| DB_WIDGET_LAYOUT_OVERFLOW | Widget layout exceeds view grid boundaries | WARNING | Clamp to grid; notify layout manager |
| DB_WIDGET_DRILL_TARGET_MISSING | DrillDownLink target ID does not exist | WARNING | Remove drill-down link; show widget without navigation |
| DB_WIDGET_CONFIG_INVALID | WidgetConfig fails type-specific schema validation | ERROR | Reject configuration; return validation errors |
| DB_WIDGET_RENDER_TIMEOUT | Rendering exceeds time limit | ERROR | Show loading placeholder; log timeout |
| DB_WIDGET_SETTINGS_CONFLICT | Widget settings conflict with parent view settings | WARNING | Apply widget settings with override flag |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| DB-012 | Every widget has exactly one data binding | Architectural â€” WidgetConfig requires metricId or inline query |
| DB-013 | Widget type must be in supported renderer list | Algorithmic â€” WidgetRegistry validates type on registration |
| DB-014 | Drill-down always reaches a verifiable evidence record | Algorithmic â€” DrillDownLink validated against target registry |
| DB-015 | Widget layout never exceeds parent view boundaries | Algorithmic â€” LayoutManager.validate enforces grid constraints |
| DB-016 | Widgets are composable within views; no circular nesting | Architectural â€” widget containment is flat per view |
| DB-017 | Widget settings are type-safe per WidgetType schema | Algorithmic â€” configure_widget validates against type schema |


## Cross-Cutting Concerns

### Security

Dashboard operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Dashboard emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Dashboard instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Dashboard declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Widget system owns visualization; metrics own computation |
| R2 - Dependency Order | Depends on Metrics subsystem and DrillDown Engine; no circular deps |
| R3 - DRY | Widget configs reference metric IDs; metric definitions are not duplicated |
| R4 - Builder Pattern | WidgetConfig uses builder for layout and drill-down composition |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Same WidgetConfig + same MetricValue = same rendered output |
| R10 - Simpler Over Complex | Metric and alert-list widgets cover most use cases; chart is opt-in |
| R13 - Design for Failure | Data bind failure shows error state with retry, not blank |
| R14 - Paved Path | Metric-card widgets are the default for all dashboard views |
| R15 - Open/Closed | New widget types register via WidgetRenderer extension point |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Dashboard/000-Overview.md | Base dashboard architecture and widget composition |
| Bible/08-Interfaces/Dashboard/001-Metrics.md | Widgets consume MetricValue from Metrics subsystem |
| Bible/08-Interfaces/Dashboard/003-RealTime.md | Widgets receive live updates via Real-Time system |
| Bible/08-Interfaces/Dashboard/005-Alerts.md | Alert-list widgets surface active alerts |
| Bible/08-Interfaces/UI/000-Overview.md | UI rendering channel produces final widget visuals |
| Bible/08-Interfaces/Console/000-Overview.md | Drill-down links route to Console for governance actions |
| Bible/05-Platform/Observability/000-AOP.md | AOP provides chart source data |
| Bible/06-Services/ACF/000-Overview.md | ACF transports widget data queries |
| Physics/005-Events.md | Evidence invariants â€” widget values are evidence-derived |
| Physics/011-Design-DNA.md | Design DNA rules govern widget construction |
