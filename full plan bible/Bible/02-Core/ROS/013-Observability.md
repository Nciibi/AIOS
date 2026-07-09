# AIOS Bible — Core
## 013 — ROS Observability

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-013 |
| Source Laws | Law 4 — Law of Evidence |
| Source Physics | Physics/005-Events.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

ROS Observability provides metrics, monitoring, and alerting for all resource management operations. All metrics are derived from Events per the Observability via Events pattern (Foundations/005-Architectural-Patterns.md). Observability serves the Security Council (system health), Organization managers (resource utilization), and entity supervisors (entity resource behavior).

## Event-Derived Metrics

Every metric is computed from Events in the Event Store. No separate metric collection pipeline exists.

```
Event Store ──→ Event Stream ──→ Metric Aggregator ──→ Dashboards & Alerts
     ▲                                                        │
     │                                                        ▼
     └───────────────── (all data derived from Events) ───────┘
```

## Metrics

### Resource Utilization

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_resource_total` | Gauge | resource_type, provider_id | Total capacity reported by providers |
| `ros_resource_available` | Gauge | resource_type, provider_id | Currently available capacity |
| `ros_resource_allocated` | Gauge | resource_type, provider_id | Currently allocated capacity |
| `ros_resource_utilization_pct` | Gauge | resource_type, provider_id | (allocated / total) × 100 |
| `ros_resource_utilization_by_org` | Gauge | resource_type, org_id | Per-organization utilization |
| `ros_resource_utilization_by_type` | Gauge | resource_type | System-wide utilization per type |

### Allocation Performance

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_allocation_requests_total` | Counter | resource_type, strategy | Total allocation requests |
| `ros_allocation_success_total` | Counter | resource_type, strategy | Successful allocations |
| `ros_allocation_denied_total` | Counter | resource_type, reason | Denied allocations (budget, quota, capacity) |
| `ros_allocation_latency_ms` | Histogram | resource_type, strategy | Allocation latency distribution |
| `ros_allocation_duration_seconds` | Histogram | resource_type | Allocation duration distribution |
| `ros_allocation_size` | Histogram | resource_type | Allocation size distribution |

### Budget Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_budget_total` | Gauge | entity_id, resource_type | Total budget per entity |
| `ros_budget_used` | Gauge | entity_id, resource_type | Used budget per entity |
| `ros_budget_utilization_pct` | Gauge | entity_id, resource_type | (used / total) × 100 |
| `ros_budget_exhausted_total` | Counter | entity_id, resource_type | Budget exhaustion count |
| `ros_budget_warnings_total` | Counter | entity_id, resource_type | Budget warning count |

### Quota Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_quota_violations_total` | Counter | scope_type, resource_type | Quota violation count |
| `ros_quota_warnings_total` | Counter | scope_type, resource_type | Soft quota warning count |
| `ros_quota_utilization_pct` | Gauge | scope_type, scope_id, resource_type | Quota utilization percentage |

### Provider Health

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_provider_health` | Gauge | provider_id | 1=healthy, 0=degraded, -1=unhealthy |
| `ros_provider_heartbeat_latency_ms` | Histogram | provider_id | Heartbeat round-trip latency |
| `ros_provider_missed_heartbeats_total` | Counter | provider_id | Missed heartbeat count |
| `ros_provider_allocation_latency_ms` | Histogram | provider_id | Provider allocation latency |

### Energy Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_energy_consumption_watts` | Gauge | provider_id | Current power draw |
| `ros_energy_consumption_wh_total` | Counter | provider_id, entity_id | Cumulative energy consumed |
| `ros_energy_cap_utilization_pct` | Gauge | entity_id, org_id | Energy cap usage percentage |

### Recovery Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ros_recovery_triggered_total` | Counter | trigger_type | Recovery trigger count |
| `ros_recovery_completed_total` | Counter | trigger_type | Completed recovery count |
| `ros_recovery_failed_total` | Counter | trigger_type | Failed recovery count |
| `ros_recovery_duration_seconds` | Histogram | trigger_type | Recovery duration |
| `ros_resources_recovered_total` | Counter | resource_type | Total resources recovered |

## Monitoring Dashboards

### Security Council Dashboard

System-wide resource health overview:

| Panel | Metric | Refresh |
|-------|--------|---------|
| System resource utilization | ros_resource_utilization_by_type | 30s |
| Provider health status | ros_provider_health | 30s |
| Active quota violations | ros_quota_violations_total (last 1h) | 60s |
| Budget exhaustion alerts | ros_budget_exhausted_total (last 24h) | 60s |
| Allocation success rate | ros_allocation_success_total / ros_allocation_requests_total | 60s |
| Recovery activity | ros_recovery_triggered_total (last 24h) | 60s |

### Organization Manager Dashboard

Per-organization resource overview:

| Panel | Metric | Refresh |
|-------|--------|---------|
| Organization utilization | ros_resource_utilization_by_org{org_id} | 30s |
| Budget utilization by entity | ros_budget_utilization_pct{org_id} | 60s |
| Quota status | ros_quota_utilization_pct{org_id} | 60s |
| Top consumers by cost | Derived from ros_allocation_size and cost rate | 60s |

### Entity Supervisor Dashboard

Per-entity resource view:

| Panel | Metric | Refresh |
|-------|--------|---------|
| Entity budget usage | ros_budget_used{entity_id} | 30s |
| Entity allocation count | ros_allocation_requests_total{entity_id} | 60s |
| Entity energy consumption | ros_energy_consumption_watts{entity_id} | 30s |

## Alerting

### Alert Thresholds

| Alert Name | Condition | Severity | Escalation |
|------------|-----------|----------|------------|
| HighUtilization | ros_resource_utilization_pct > 0.85 for 5 min | warning | Notify org admin |
| CriticalUtilization | ros_resource_utilization_pct > 0.95 for 2 min | critical | Notify Security Council |
| AllocationFailureRate | allocation_denied / allocation_total > 0.1 for 5 min | warning | Notify org admin |
| ProviderDown | ros_provider_health < 1 for 30s | critical | Notify ROS admin |
| BudgetExhausted | ros_budget_exhausted_total increased | warning | Notify entity supervisor |
| QuotaViolationSpike | ros_quota_violations_total > 10 in 5 min | critical | Notify Security Council |
| RecoveryFailure | ros_recovery_failed_total increased | critical | Notify ROS admin |
| HeartbeatMissed | ros_provider_missed_heartbeats_total > 3 | warning | Notify provider owner |

### Alert Channels

| Severity | Channel | Response Time |
|----------|---------|---------------|
| critical | Security Council ACF channel | < 1 minute |
| warning | Organization admin ACF channel | < 5 minutes |
| info | Dashboard notification | < 15 minutes |

## Privacy

Per CPR-010 (Evidence Privacy):

| Data Type | Visibility |
|-----------|------------|
| Aggregated resource utilization | All dashboards (no entity-level detail) |
| Per-entity usage | Entity supervisor, entity's organization |
| Per-organization usage | Organization admin, Security Council |
| System-wide metrics | Security Council |
| Individual allocation details | Entity owner only |

Metrics dashboards display aggregated data only. Per-entity usage details are never exposed outside the entity's organization. Anonymised aggregate data may be used for system-wide planning.

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| MetricUpdated | Metric aggregation period elapsed | metric_name, value, labels, timestamp |
| AlertTriggered | Alert threshold crossed | alert_name, severity, current_value, threshold, timestamp |
| AlertResolved | Alert condition cleared | alert_name, severity, timestamp |
| DashboardAccessed | Dashboard viewed | user_id, dashboard_name, timestamp |

## Cross-Cutting Concerns

### Security

Dashboard access requires authorization. Security Council dashboards are accessible only to Security Council members. Organization dashboards are accessible to Organization admins and members.

### Evidence

All metrics are derived from Events. No separate data collection creates untracked data. Alert history is retained for audit.

### Lifecycle

Metrics retention follows Event Store retention policies. Entity metrics are retained for 90 days after entity termination for audit purposes.

### Capability Bounds

Observability does not enforce capability bounds. It reports utilization but does not intervene in allocation decisions.

### Communication

Observability reads from the Event Store via the read-replica pattern. Alerts are sent via ACF to the appropriate channels.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Observability handles only metrics, monitoring, and alerting. Separate from resource management. |
| R3 — DRY | All metrics are derived from Events. No duplicate metric data store. |
| R7 — Tests Exist | Every metric has corresponding tests verifying correct derivation from Events. |
| R9 — Deterministic | Metric computation is deterministic — same Events always produce same metric values. |
| R10 — Simpler Over Complex | Simple aggregation over Event streams. No complex analytics pipelines. |
| R13 — Design for Failure | Observability is non-blocking. If the Event Store is unavailable, dashboards show stale data but do not crash. |
| R14 — Paved Path | The paved path is: Event → Event Store → Metric Aggregation → Dashboard + Alert. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/002-Registry.md | Provider health metrics source |
| ROS/003-Allocator.md | Allocation performance metrics source |
| ROS/005-Budget.md | Budget metrics source |
| ROS/006-Quota.md | Quota metrics source |
| ROS/010-Cost.md | Cost metrics source |
| ROS/011-Energy.md | Energy metrics source |
| ROS/012-Recovery.md | Recovery metrics source |
| Foundations/005-Architectural-Patterns.md | Observability via Events pattern |
| Physics/005-Events.md | Event sourcing for all metrics |
| Bible/03-Institutions/Security-Council | Alert escalation target |
