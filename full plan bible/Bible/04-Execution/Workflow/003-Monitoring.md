# AIOS Bible — Execution
## 003 — Monitoring & Observability

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Workflow |
| Document ID | AIOS-BBL-004-WFE-003 |
| Source Laws | Law 8 — Law of Verification-First, Law 6 — Law of Lifecycle Compliance, Law 4 — Law of Evidence |
| Source Physics | Physics/010-Execution.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Monitor workflow execution health, performance, and compliance — metrics, alerts, dashboards, and audit trails.

## Architecture

Monitoring is integrated into the WFE pipeline as a cross-cutting concern. Every pipeline stage and state transition emits observability data that feeds into metrics collection, alert evaluation, dashboard updates, and audit trail recording. The monitoring subsystem interfaces with AOP (Observability Platform) for storage, visualization, and alert routing.

```
            ┌─────────────────────────────────────────────────────┐
            │              Monitoring Subsystem                    │
            │                                                      │
            │  ┌──────────────┐  ┌─────────────┐  ┌────────────┐ │
            │  │   Metrics    │  │    Alert    │  │ Dashboard  │ │
            │  │   Collector  │  │   Evaluator │  │   Manager  │ │
            │  └──────┬───────┘  └──────┬──────┘  └─────┬──────┘ │
            │         │                 │                │        │
            │  ┌──────▼─────────────────▼────────────────▼──────┐ │
            │  │              Audit Recorder                      │ │
            │  └──────────────────────┬──────────────────────────┘ │
            │                         │                            │
            └─────────────────────────┼────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
              ┌──────────┐     ┌──────────┐     ┌──────────────┐
              │   AOP    │     │   EVS    │     │  Dashboard   │
              │ Metrics  │     │ Evidence │     │  Store       │
              └──────────┘     └──────────┘     └──────────────┘
```

Metrics are collected at two granularities: workflow-level (end-to-end) and step-level (individual execution). Alert rules are evaluated against these metrics on a configurable cadence. Dashboards are updated in near real-time. Audit records are immutable and written to EVS.

## Data Model

```typescript
interface WorkflowMetrics {
  workflowId: string;
  status: WorkflowState;
  duration: Duration;                    // wall-clock time from first step to terminal state
  totalSteps: number;
  completedSteps: number;
  failedSteps: number;
  retriedSteps: number;
  approvalGates: number;
  approvalGatesResolved: number;
  approvalGatesTimedOut: number;
  pauseCount: number;
  totalPauseDuration: Duration;
  checkpointCount: number;
  lastCheckpointTimestamp: Timestamp;
  evidenceRef: string;
  collectedAt: Timestamp;
}

interface StepMetrics {
  workflowId: string;
  stepId: string;
  stepType: WorkflowStep['type'];
  executionCount: number;                // includes retries
  retryCount: number;
  lastExecutionDuration: Duration;
  totalExecutionDuration: Duration;
  avgExecutionDuration: Duration;
  maxExecutionDuration: Duration;
  status: 'pending' | 'running' | 'completed' | 'failed';
  approvalWaitDuration?: Duration;       // for approval-type steps
  evidenceRef: string;
  collectedAt: Timestamp;
}

interface AlertRule {
  alertRuleId: string;
  name: string;
  description: string;
  metric: string;                        // metric path, e.g. "step.duration.max"
  condition: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'ne';
  threshold: number;
  duration: Duration;                    // how long condition must hold before alert fires
  severity: 'info' | 'warning' | 'critical';
  cooldown: Duration;                    // minimum time between alert firings
  enabled: boolean;
  notifyChannels: string[];              // ACF notification channel IDs
}

interface DashboardDefinition {
  dashboardId: string;
  name: string;
  description: string;
  panels: DashboardPanel[];
  refreshInterval: Duration;
  defaultTimeRange: Duration;
}

interface DashboardPanel {
  panelId: string;
  title: string;
  metric: string;
  chartType: 'line' | 'bar' | 'gauge' | 'table' | 'heatmap';
  filters: Record<string, string>;       // e.g. { workflowId: "abc", stepType: "atomic" }
  groupBy: string[];                     // e.g. ["status", "stepType"]
  aggregation: 'avg' | 'sum' | 'max' | 'min' | 'count' | 'p95' | 'p99';
}

interface AuditRecord {
  auditId: string;
  workflowId: string;
  entityType: 'workflow' | 'step' | 'pipeline' | 'gate' | 'checkpoint';
  entityId: string;
  action: string;
  actor: string;
  fromState?: WorkflowState;
  toState?: WorkflowState;
  details: Record<string, unknown>;
  timestamp: Timestamp;
  evidenceRef: string;
  immutable: true;                       // audit records are never mutated
}

interface WorkflowHealth {
  workflowId: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheckTimestamp: Timestamp;
  metrics: WorkflowMetrics;
  alertCount: number;
  activeAlerts: string[];                // alertRuleIds currently firing
  recentErrors: { code: string; message: string; timestamp: Timestamp }[];
  recoveryAction: string | null;         // suggested recovery action, if any
}
```

## Core Concepts / Operations

### Metrics Collection

Metrics are collected at two levels:

**Workflow-level metrics** — captured on state transitions and at regular intervals during execution:

| Metric | Source | Collection Point |
|--------|--------|-----------------|
| Workflow duration | Wall-clock timer | Started on Running entry, stopped on terminal state |
| Step completion rate | Count of completed steps / total steps | On every StepCompleted event |
| Retry rate | Retried steps / total steps executed | On every StepRetrying event |
| Failure rate | Failed steps / total steps executed | On every StepFailed event (retries exhausted) |
| Approval gate wait time | Timer per approval gate | Started on GateAwaitingApproval, stopped on GateApproved or GateTimedOut |
| Pause duration | Per-pause timer | Started on Pause, stopped on Resume |
| Checkpoint frequency | Count over time | On every CheckpointCreated event |

**Step-level metrics** — captured per step execution:

| Metric | Source | Collection Point |
|--------|--------|-----------------|
| Execution duration | Per-execution timer | Started on StepStarted, stopped on StepCompleted/StepFailed |
| Retry count | Counter incremented per retry | On every StepRetrying event |
| Approval wait | Per-gate timer | Started on GateAwaitingApproval, stopped on GateApproved |
| Dispatch latency | Time from step readiness to Worker dispatch | Measured in StepExecutor |

Metrics are aggregated into time-series buckets (default 60-second windows) and pushed to AOP.

### Step-Level Instrumentation

Every step execution is instrumented with:

1. A timer measuring wall-clock execution duration
2. A counter tracking execution attempts (first attempt + retries)
3. A gauge tracking the current retry backoff value
4. A histogram of execution durations for p95/p99 latency analysis
5. Labels: `workflowId`, `stepId`, `stepType`, `status`, `retryCount`

Instrumentation is injected by the StepExecutor before dispatching to the Worker and is non-blocking — a failed instrumentation write does not affect step execution.

### Alert Rules

| Rule Name | Metric | Condition | Threshold | Duration | Severity | Description |
|-----------|--------|-----------|-----------|----------|----------|-------------|
| StepTimeout | `step.duration.max` | gt | step timeout config | 0s (instant) | critical | A step exceeded its configured timeout |
| RetryExhaustion | `step.retryCount` | gte | step max retries | 0s (instant) | critical | All retry attempts for a step exhausted |
| ApprovalGateExpiry | `approvalGate.waitDuration` | gt | gate timeout config | 0s (instant) | warning | An approval gate is approaching or has exceeded its timeout |
| PipelineFailure | `workflow.status` | eq | failed | 0s (instant) | critical | A workflow transitioned to Failed state |
| HighRetryRate | `workflow.retryRate` | gt | 0.5 (50%) | 5m | warning | More than half of steps are being retried |
| StateStall | `workflow.stateDuration` | gt | workflow max state duration | 0s (instant) | warning | Workflow has been in a non-terminal state too long |
| CheckpointLag | `checkpoint.age` | gt | 2× checkpoint interval | 0s (instant) | warning | No checkpoint created within expected interval |
| AnomalousLatency | `step.duration.p95` | gt | 2× baseline avg | 10m | info | Step latency significantly above historical baseline |

Alert firing emits `WFE.Mon.AlertTriggered`. When the condition clears, `WFE.Mon.AlertResolved` is emitted. Alerts are routed through ACF notification channels.

### Integration with AOP (Observability Platform)

Monitoring integrates with AOP at three integration points:

1. **Metrics sink** — all workflow and step metrics are pushed to AOP's metrics API as structured time-series data
2. **Alert routing** — alert rules are registered in AOP's alert manager; AOP handles deduplication, escalation, and notification dispatch
3. **Dashboard hosting** — dashboard definitions are synced to AOP's dashboard service; panels are rendered from AOP metrics queries

The integration contract is defined in `Bible/05-Platform/Observability/000-AOP.md`.

### Dashboard Definitions

Three default dashboards are defined:

| Dashboard | Purpose | Key Panels |
|-----------|---------|------------|
| Workflow Overview | High-level health of all workflows | Active workflows by state, completion rate, failure rate, avg duration by workflow type |
| Step Performance | Deep-dive into step execution | p50/p95/p99 duration by step type, retry rate by step type, timeout count by workflow |
| Alert History | Alert timeline and resolution | Active alerts, alert firing frequency, mean-time-to-resolve, alert by severity |

Each panel is filterable by workflow ID, step type, time range, and status.

### Audit Trail

Every state transition produces an immutable audit record with:

- Actor identity (system or human)
- Previous and next state
- Trigger event
- Timestamp (monotonic, sourced from system clock)
- Evidence reference linking to EVS

Audit records are written to EVS and are queryable by workflow ID, time range, and action type. The audit trail supports compliance verification (Law 4) and post-mortem analysis.

### Health Check Protocol

The health check runs on a configurable interval (default 30s) for each active workflow:

1. Load current workflow state from State Store
2. Verify the state is consistent with the last known checkpoint
3. Compare current timestamp against last state transition timestamp
4. If the workflow has been in a non-terminal state beyond the configured maximum duration → degraded
5. If the workflow has active critical alerts → unhealthy
6. If the last checkpoint age exceeds 2× the checkpoint interval → degraded
7. If all checks pass → healthy

Health check results are published as `WFE.Mon.HealthCheckPassed` or `WFE.Mon.HealthCheckFailed` events.

## Internal Interfaces

```typescript
interface MetricsCollector {
  recordWorkflowMetric(metrics: WorkflowMetrics): Promise<void>;
  recordStepMetric(metrics: StepMetrics): Promise<void>;
  flush(): Promise<void>;                // push buffered metrics to AOP
}

interface AlertEvaluator {
  evaluate(metrics: WorkflowMetrics | StepMetrics): Promise<AlertResult[]>;
  getAlertRules(context?: { severity?: string; enabled?: boolean }): AlertRule[];
  createAlertRule(rule: AlertRule): Promise<void>;
  updateAlertRule(ruleId: string, rule: Partial<AlertRule>): Promise<void>;
  deleteAlertRule(ruleId: string): Promise<void>;
}

interface DashboardManager {
  syncDefinitions(): Promise<void>;      // sync all dashboard defs to AOP
  getDashboard(dashboardId: string): DashboardDefinition;
  updatePanel(dashboardId: string, panel: DashboardPanel): Promise<void>;
}

interface AuditRecorder {
  record(audit: AuditRecord): Promise<void>;
  query(filters: AuditQuery): Promise<AuditRecord[]>;
}

interface HealthChecker {
  check(workflowId: string): Promise<WorkflowHealth>;
  runAll(): Promise<WorkflowHealth[]>;   // run health check on all active workflows
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `WFE.Mon.MetricsCollected` | workflowId, metricCount, timeBucket | Metrics snapshot collected and pushed to AOP |
| `WFE.Mon.AlertTriggered` | workflowId, alertRuleId, severity, metric, value, threshold | Alert rule condition met |
| `WFE.Mon.AlertResolved` | workflowId, alertRuleId, severity, duration | Alert condition cleared |
| `WFE.Mon.HealthCheckPassed` | workflowId, state, duration | Health check passed for workflow |
| `WFE.Mon.HealthCheckFailed` | workflowId, state, reason, failingChecks | Health check failed with reasons |
| `WFE.Mon.AnomalyDetected` | workflowId, metric, baseline, current, deviation | Anomalous metric value detected |
| `WFE.Mon.DashboardUpdated` | dashboardId, panelCount, refreshedAt | Dashboard refreshed with latest metrics |
| `WFE.Mon.AuditRecordCreated` | auditId, workflowId, action, actor | Immutable audit record persisted |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Metrics collection buffer overflow | `WFE_MON_001` | Drop oldest metrics bucket; emit warning; increase buffer if persistent |
| Alert evaluator rule evaluation error | `WFE_MON_002` | Skip rule evaluation for current cycle; log error; continue with remaining rules |
| Dashboard sync to AOP fails | `WFE_MON_003` | Retry sync; if exhausted, log critical and continue with cached dashboard defs |
| Audit record write to EVS fails | `WFE_MON_004` | Retry write; if exhausted, buffer audit record to local store for later sync |
| Health check timed out | `WFE_MON_005` | Mark health as degraded for that workflow; continue checking other workflows |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| WFE-MON-001 | Every state transition produces an audit record (Law 4) | Architectural — AuditRecorder invoked on every approved state transition |
| WFE-MON-002 | Metrics collection is non-blocking and does not affect workflow execution | Algorithmic — Metrics recorded asynchronously; failures are logged but never propagated |
| WFE-MON-003 | Alert rules are evaluated on every metrics collection cycle | Architectural — AlertEvaluator called after every MetricsCollected event |
| WFE-MON-004 | Audit records are immutable once written | Architectural — EVS enforces append-only semantics for audit records |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Monitoring owns all observability concerns; no other component produces metrics or alerts |
| R2 — Dependency Order | Monitoring depends on AOP (storage), EVS (evidence), ACF (notifications); no cycles |
| R3 — DRY | Metric definitions and alert rules are defined once; reused across all dashboards |
| R9 — Deterministic | Same metrics input produces same alert evaluation outcome |
| R10 — Simpler Over Complex | Default dashboards and alert rules cover 90% of observability needs; custom rules are additive |
| R13 — Design for Failure | Health checks detect degradation; alerts notify operators before failures escalate |
| R14 — Paved Path | Default three dashboards cover common monitoring patterns; teams extend as needed |
| R15 — Open/Closed | New metrics, alert rules, and dashboard panels can be added via RFC without modifying core monitoring |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-Overview.md | Parent document — WFE architecture and component map |
| 001-Pipeline-Architecture.md | Pipeline Monitor stage collects metrics and evaluates health |
| 002-State-Machine.md | State machine transitions are audited and monitored |
| Bible/05-Platform/Observability/000-AOP.md | AOP hosts metrics storage, alert routing, and dashboards |
| Bible/05-Platform/004-EVS.md | EVS stores audit records and evidence |
| Bible/05-Platform/005-AUS.md | AUS audits monitoring subsystem compliance |
| Bible/06-Services/ACF/000-Overview.md | ACF routes alert notifications to channels |
