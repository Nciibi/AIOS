# AIOS Bible â€” Interfaces
## Dashboard â€” 000: Observability Dashboard

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-DB-000 |
| Source Laws | Law 4 â€” Law of Evidence, Law 8 â€” Law of Verification-First, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Dashboard is the observability surface of AIOS â€” a read-only, evidence-based view of system state for humans and automated monitors. It aggregates data from the Observability Platform (AOP), Evidence System (EVS), Audit System (AUS), and Simulation System into coherent views: system health, agent performance, mission progress, resource consumption, security posture, and economic status.

The Dashboard never acts â€” it observes. All data shown is derived from evidence (Law 4) and reflects verified state (Law 8). A dashboard showing "green" means the underlying evidence confirms health; a dashboard showing "red" means the evidence indicates a problem. The Dashboard is the transparency layer that makes AIOS accountable to humans.

## Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                    Dashboard                            â”‚
â”‚                                                         â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚  Health   â”‚  â”‚  Agent    â”‚  â”‚  Mission  â”‚  â”‚ Resourceâ”‚ â”‚
â”‚  â”‚  View     â”‚  â”‚  View     â”‚  â”‚  View     â”‚  â”‚  View   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜ â”‚
â”‚        â”‚              â”‚              â”‚              â”‚     â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â–¼â”€â”€â”€â”€â” â”‚
â”‚  â”‚  Security  â”‚  â”‚  Economic  â”‚  â”‚  Audit    â”‚  â”‚  Sim    â”‚ â”‚
â”‚  â”‚  View      â”‚  â”‚  View      â”‚  â”‚  View     â”‚  â”‚  View   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜ â”‚
â”‚        â”‚              â”‚              â”‚              â”‚     â”‚
â”‚        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â”‚                       â”‚              â”‚                    â”‚
â”‚              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”          â”‚
â”‚              â”‚   Dashboard Data Aggregator     â”‚          â”‚
â”‚              â”‚   (queries AOP, EVS, AUS)       â”‚          â”‚
â”‚              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜          â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                              â”‚
                              â–¼
        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
        â”‚ AOP, EVS, AUS, Simulation, ROS, Security â”‚
        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Core Concepts

### 1. View Model

A Dashboard View is a coherent panel of related metrics: Health, Agents, Missions, Resources, Security, Economic, Audit, Simulation. Each view subscribes to relevant data sources and renders current state. Views are composable â€” a single "Operations" dashboard can embed Health + Mission + Resource views.

### 2. Evidence-Backed Rendering

Every number on a dashboard traces to evidence. A metric like "Agent error rate: 2%" is computed from EVS event records, not from a cached guess. Dashboards re-query their sources on a refresh interval (configurable per view) to stay current. Stale data is flagged as "stale" rather than shown as current.

### 3. Health Scoring

The Health View aggregates subsystem status into a composite health score: green (all checks pass), yellow (degraded but functional), red (failure detected). Health scoring uses AOP alerts and AUS audit findings as inputs. The score is derived, never asserted â€” it reflects actual evidence.

### 4. Drill-Down

Every dashboard element is drill-downable: click "Agent X error rate 2%" â†’ see the specific error events in EVS â†’ click an event â†’ see the full evidence trail. Drill-down preserves the evidence chain, so a human can always trace a displayed number back to its source.

### 5. Alert Surface

The Dashboard surfaces alerts from AOP and AUS: threshold breaches, anomalies, audit findings. Alerts are actionable â€” clicking an alert may link to the Governance Console for override or the Human Interface for approval. Alerts never auto-resolve sensitive actions; they inform.

### 6. Simulation Overlay

The Simulation View shows active and historical simulations: what scenarios were run, their outcomes, and confidence. This lets humans compare "what we simulated" against "what actually happened" â€” closing the loop between prediction and reality.

## Data Model

```typescript
interface DashboardView {
  viewId: string;
  name: string;
  category: 'health' | 'agents' | 'missions' | 'resources' | 'security' | 'economic' | 'audit' | 'simulation';
  refreshIntervalSeconds: number;
  widgets: Widget[];
  dataSourceRefs: string[];  // AOP/EVS/AUS query refs
}

interface Widget {
  widgetId: string;
  type: 'metric' | 'chart' | 'table' | 'alert-list' | 'heatmap';
  title: string;
  query: DataQuery;
  evidenceRef?: string;  // source evidence for current value
  lastUpdated: Timestamp;
  stale: boolean;
}

interface HealthScore {
  score: 'green' | 'yellow' | 'red';
  components: ComponentHealth[];
  computedAt: Timestamp;
  evidenceRef: string;
}

interface ComponentHealth {
  componentId: string;
  status: 'green' | 'yellow' | 'red';
  reason: string;
  lastChecked: Timestamp;
}

interface DataQuery {
  source: 'aop' | 'evs' | 'aus' | 'simulation';
  filter: Record<string, unknown>;
  aggregation: 'sum' | 'avg' | 'count' | 'latest' | 'distinct';
  windowSeconds: number;
}
```

## Interfaces

### Dashboard API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `getView(viewId)` | Any authenticated | Retrieve a dashboard view and its widgets |
| `listViews(category?)` | Any authenticated | List available views, optionally by category |
| `refreshView(viewId)` | Any authenticated | Force re-query of view data sources |
| `drillDown(widgetId, point)` | Any authenticated | Trace a displayed value to its evidence |
| `subscribeAlerts(filter)` | Verified Human | Subscribe to dashboard alerts |
| `getHealthScore()` | Any authenticated | Get composite system health score |
| `getSimulationOverlay()` | Any authenticated | Get active/historical simulation summary |

### Internal Interfaces

```typescript
interface DataAggregator {
  query(query: DataQuery): Promise<QueryResult>;
  aggregate(results: QueryResult[], method: string): Promise<AggregatedValue>;
  freshnessCheck(lastUpdated: Timestamp): boolean;
}

interface HealthCalculator {
  compute(components: ComponentHealth[]): HealthScore;
  decompose(score: HealthScore): ComponentHealth[];
}

interface AlertSurface {
  surface(alerts: Alert[]): Promise<void>;
  linkToConsole(alertId: string): ConsoleLink;
  linkToUI(alertId: string): UILink;
}

interface DrillDown {
  trace(widgetId: string, point: DataPoint): Promise<EvidenceTrace>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| View Manager | Registers and serves dashboard views |
| Data Aggregator | Queries AOP/EVS/AUS; computes widget values |
| Health Calculator | Computes composite health score from components |
| Alert Surface | Surfaces AOP/AUS alerts to dashboard |
| Drill-Down Engine | Traces displayed values to evidence |
| Simulation Overlay | Shows simulation results alongside live state |

## Data Flow

```
Dashboard loads views for human/monitor
        â”‚
        â–¼
Data Aggregator queries sources (AOP, EVS, AUS)
        â”‚
        â–¼
Widgets computed from evidence
        â”‚
        â–¼
Health Calculator aggregates component status
        â”‚
        â–¼
Dashboard renders; Alert Surface shows alerts
        â”‚
        â–¼
Human drills down â”€â”€â–º Drill-Down Engine â”€â”€â–º Evidence trace
        â”‚
        â–¼
All displayed data is evidence-backed (Law 4)
```

## Events

| DASH.EventType |      Produced When | Fields |
|-------|--------|-------------|
| DASH.ViewLoaded |      viewId, category, viewerId | Dashboard view rendered |
| DASH.WidgetUpdated |      widgetId, value, evidenceRef | Widget value refreshed from source |
| DASH.DataStale |      widgetId, lastUpdated | Data source unreachable; marked stale |
| DASH.HealthComputed |      score, componentCount | Composite health score recalculated |
| DASH.AlertSurfaced |      alertId, severity, source | Alert shown on dashboard |
| DASH.AlertActioned |      alertId, action, target | Human acted on alert (console/UI link) |
| DASH.DrillDown |      widgetId, point, evidenceRef | Human traced value to evidence |
| DASH.SimulationShown |      simulationId, outcome | Simulation result displayed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Data source unavailable | `DB_SOURCE_UNAVAILABLE` | Mark widgets stale; show last known value with warning |
| Query timeout | `DB_QUERY_TIMEOUT` | Return partial results; flag incomplete |
| Invalid view ID | `DB_VIEW_NOT_FOUND` | Return error; no rendering |
| Drill-down evidence missing | `DB_DRILL_NO_EVIDENCE` | Show "source unavailable"; cannot trace |
| Health score uncomputable | `DB_HEALTH_UNCOMPUTABLE` | Show "unknown" status; alert operators |
| Refresh rate too high | `DB_REFRESH_THROTTLED` | Apply rate limit; notify requester |
| Unauthorized view access | `DB_VIEW_DENIED` | Reject; view requires permission |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| DB-001 | Every displayed value traces to evidence (Law 4) | Architectural â€” widgets require evidenceRef or mark stale |
| DB-002 | Stale data is never shown as current | Algorithmic â€” freshnessCheck flags stale widgets |
| DB-003 | Dashboard is read-only â€” no state changes via dashboard | Architectural â€” dashboard has no write path to subsystems |
| DB-004 | Health score is derived from evidence, never asserted | Algorithmic â€” Health Calculator requires component evidence |
| DB-005 | Alerts inform only â€” never auto-resolve sensitive actions | Constitutional â€” alert actions route to Console/UI for human |
| DB-006 | Drill-down always reaches a verifiable evidence record | Algorithmic â€” Drill-Down Engine rejects untraceable points |


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
| R1 - Modulsingularity | Dashboard owns visualization exclusively; AOP/EVS/AUS own data collection |
| R2 - Dependency Order | Depends on AOP, EVS, AUS, Simulation; no circular deps |
| R3 - DRY | Metrics computed once in aggregator; views reference, not duplicate |
| R4 - Builder Pattern | Dashboard views use builder for widget composition |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Same query + same evidence = same displayed value |
| R10 - Simpler Over Complex | Default Health + Mission views cover most needs; advanced views opt-in |
| R13 - Design for Failure | Source outage marks stale, not blank; health unknown is explicit |
| R14 - Paved Path | Health dashboard is the default landing view |
| R15 - Open/Closed | New view categories register via View Manager extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/05-Platform/Observability/000-AOP.md | AOP is the primary dashboard data source |
| Bible/05-Platform/004-EVS.md | EVS provides evidence-backed metric values |
| Bible/05-Platform/005-AUS.md | AUS provides audit findings shown on dashboard |
| Bible/04-Execution/Simulation/000-Overview.md | Simulation results shown in Simulation overlay |
| Bible/02-Core/ROS/000-Overview.md | Resource view sources from ROS allocation state |
| Bible/07-Domains/Economic/000-Overview.md | Economic view sources from Economic System |
| Bible/08-Interfaces/UI/000-Overview.md | UI visualization channel renders dashboard views |
| Bible/08-Interfaces/Console/000-Overview.md | Alerts link to Console for governance actions |
| Bible/06-Services/ACF/000-Overview.md | ACF transports dashboard queries |
| Physics/005-Events.md | Evidence invariants â€” dashboard values are evidence-derived |
| Physics/011-Design-DNA.md | Design DNA rules govern dashboard construction |
