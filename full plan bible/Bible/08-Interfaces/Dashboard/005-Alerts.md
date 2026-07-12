# AIOS Bible — Interfaces
## Dashboard — 005: Alerts

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-DB-005 |
| Source Laws | Law 4 — Law of Evidence, Law 8 — Law of Verification-First, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/005-Events.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Alert subsystem surfaces actionable notifications from AOP, AUS, and the Simulation system onto the Dashboard. Alerts are classified by severity, linked to supporting evidence, routed to the appropriate human interface (Console for governance, UI for awareness), and tracked through their lifecycle. Alerts inform — they never auto-resolve sensitive actions.

## Architecture

```
Alert Ingestion (from AOP, AUS, Simulation)
       |
       v
Classification (severity: critical, warning, info)
       |
       v
Surfacing (display on alert-list widgets)
       |
       v
Drill-Down Linkage (link to evidence in EVS / AUS)
       |
       v
Notification Routing (Console / UI / external)
       |
       v
Action Linking (alert -> governance action or UI view)
       |
       v
Archive / History (persist for audit)
```

## Data Model

```typescript
interface DashboardAlert {
  alertId: string;
  title: string;
  message: string;
  severity: AlertSeverity;
  source: AlertSource;
  sourceAlertId: string;
  surfacedAt: Timestamp;
  evidenceRef: string;
  actions: AlertAction[];
  state: 'active' | 'acknowledged' | 'resolved' | 'archived';
  resolvedAt?: Timestamp;
}

type AlertSeverity = 'critical' | 'warning' | 'info';

interface AlertSource {
  system: 'aop' | 'aus' | 'simulation';
  componentId: string;
  ruleId?: string;
}

interface AlertAction {
  actionId: string;
  label: string;
  targetType: 'console' | 'ui' | 'external';
  targetUrl: string;
  params: Record<string, string>;
}

interface AlertHistory {
  historyId: string;
  alertId: string;
  event: 'surfaced' | 'acknowledged' | 'actioned' | 'resolved' | 'archived';
  timestamp: Timestamp;
  userId?: string;
  details: Record<string, unknown>;
}

interface AlertFilter {
  severities?: AlertSeverity[];
  sources?: string[];
  states?: string[];
  since?: Timestamp;
  limit?: number;
}
```

## Core Concepts

### 1. Alert Ingestion

Alerts originate from AOP (threshold breaches, anomalies), AUS (audit findings, policy violations), and Simulation (scenario outcomes). The Alert subsystem ingests these into the Dashboard's unified alert surface via the AlertSurface interface.

### 2. Severity Classification

Each alert is classified as critical, warning, or info. Classification is derived from the source system's own severity assessment, enriched by AUS audit context. Classification follows evidence — severity is never manually asserted.

### 3. Surfacing

Classified alerts appear on alert-list widgets throughout the Dashboard. Active alerts are displayed prominently; acknowledged alerts are visually muted. Alerts remain visible until archived or resolved.

### 4. Drill-Down Linkage

Every alert carries an evidenceRef linking to the EVS event or AUS finding that triggered it. Clicking an alert navigates to the evidence trail, preserving the chain from notification to root cause.

### 5. Action Routing

Alerts define AlertAction entries that link to the Governance Console (for overrides, approvals) or the Human Interface (for awareness views). Actions never execute directly on the Dashboard — they route to the appropriate system for human decision.

## Operations

| Operation | Description |
|-----------|-------------|
| surface_alert(alert: DashboardAlert) | Ingest and display a new alert on dashboard |
| classify_severity(alertId, severity) | Assign or update severity classification |
| link_to_evidence(alertId, evidenceRef) | Attach evidence reference to alert |
| route_action(alertId, actionId) | Navigate human to action target (Console/UI) |
| acknowledge_alert(alertId, userId) | Mark alert as acknowledged by human |
| archive_alert(alertId) | Move alert to archive; remove from active view |
| list_alerts(filter: AlertFilter) | Query active and historical alerts |

## Internal Interfaces

```typescript
interface AlertIngestor {
  ingest(alert: DashboardAlert): Promise<void>;
  acknowledge(alertId: string, userId: string): Promise<void>;
  resolve(alertId: string): Promise<void>;
}

interface AlertClassifier {
  classify(alert: DashboardAlert): Promise<AlertSeverity>;
  reclassify(alertId: string, severity: AlertSeverity): Promise<void>;
}

interface AlertHistoryStore {
  record(event: AlertHistory): Promise<void>;
  query(alertId: string): Promise<AlertHistory[]>;
  list(filter: AlertFilter): Promise<DashboardAlert[]>;
}

interface ActionRouter {
  resolve(action: AlertAction): Promise<string>;
  execute(actionId: string, context?: Record<string, unknown>): Promise<void>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| DB.AlertSurfaced | alertId, severity, source | Alert displayed on dashboard alert-list |
| DB.AlertClassified | alertId, severity, classifier | Severity assigned or updated |
| DB.AlertAcknowledged | alertId, userId | Human acknowledged alert |
| DB.AlertActioned | alertId, actionId, targetType | Human navigated to action target |
| DB.AlertResolved | alertId, source | Source system reported resolution |
| DB.AlertArchived | alertId, userId | Alert moved to archive |
| DB.AlertHistoryExported | count, since | Alert history exported for audit |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| DB_ALERT_SOURCE_UNAVAILABLE | Alert source system unreachable | ERROR | Retry ingestion; queue alerts for later surfacing |
| DB_ALERT_CLASSIFICATION_FAILED | Severity classification algorithm fails | WARNING | Default to 'info'; log classification failure |
| DB_ALERT_ACTION_LINK_BROKEN | AlertAction target URL or ID is invalid | WARNING | Remove broken action; log for operator review |
| DB_ALERT_ARCHIVE_CONFLICT | Alert already archived or does not exist | WARNING | Return current state; no-op on archive |
| DB_ALERT_EVIDENCE_MISSING | EvidenceRef points to deleted or expired record | WARNING | Surface alert with "evidence unavailable" marker |
| DB_ALERT_DUPLICATE_SUPPRESSED | Same source alert ingested multiple times | INFO | Suppress duplicate; log suppression event |
| DB_ALERT_HISTORY_OVERFLOW | Alert history store exceeds retention limit | ERROR | Prune oldest records; notify administrator |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| DB-030 | Alerts inform only — never auto-resolve sensitive actions | Constitutional — action routing always requires human navigation |
| DB-031 | Every alert links to verifiable evidence | Algorithmic — link_to_evidence validates evidenceRef existence |
| DB-032 | Severity is derived from evidence, never manually asserted | Algorithmic — AlertClassifier requires source context |
| DB-033 | Archived alerts are immutable; no edits after archive | Architectural — archive transitions state to read-only |
| DB-034 | Action links target Console or UI, never direct execution | Architectural — ActionRouter resolves to view URLs only |
| DB-035 | Duplicate alerts from same source are suppressed | Algorithmic — AlertIngestor deduplicates by sourceAlertId |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Alert subsystem owns surfacing; AOP/AUS own detection |
| R2 — Dependency Order | Depends on AOP, AUS, EVS, Simulation; no circular deps |
| R3 — DRY | Alerts ingested once; surfaced on all relevant alert-list widgets |
| R4 — Builder Pattern | AlertAction uses builder for target URL construction |
| R5 — Law of Demeter | Alert subsystem communicates with sources via AlertSurface interface only |
| R9 — Deterministic | Same source alert + same classification = same surfaced presentation |
| R10 — Simpler Over Complex | Active alert list is default; history and analytics are opt-in |
| R13 — Design for Failure | Source unavailable queues alerts; evidence missing marks degraded |
| R14 — Paved Path | Critical alerts appear on Health view by default |
| R15 — Open/Closed | New alert sources register via AlertIngestor extension |
| R16 — Evidence Traceability | All alerts carry evidenceRef to source event |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/08-Interfaces/Dashboard/000-Overview.md | Base dashboard architecture and AlertSurface interface |
| Bible/08-Interfaces/Dashboard/001-Metrics.md | Alert thresholds defined in metric definitions |
| Bible/08-Interfaces/Dashboard/002-Widgets.md | Alert-list widgets render surfaced alerts |
| Bible/08-Interfaces/Dashboard/003-RealTime.md | Real-time streams deliver alert updates |
| Bible/08-Interfaces/Dashboard/004-User-Management.md | Alert visibility gated by user permissions |
| Bible/08-Interfaces/Console/000-Overview.md | Alerts link to Console for governance actions |
| Bible/08-Interfaces/UI/000-Overview.md | Alerts link to UI for awareness views |
| Bible/05-Platform/Observability/000-AOP.md | AOP provides threshold breach alerts |
| Bible/05-Platform/005-AUS.md | AUS provides audit finding alerts |
| Bible/04-Execution/Simulation/000-Overview.md | Simulation provides scenario outcome alerts |
| Bible/01-Governance/001-CLS.md | Constitutional limits on auto-resolution govern alert actions |
| Physics/005-Events.md | Evidence invariants — alert values are evidence-derived |
| Physics/011-Design-DNA.md | Design DNA rules govern alert construction |
