# AIOS Bible — Interfaces
## SDK — 001: Audit SDK

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Interfaces |
| Document ID | AIOS-BBL-008-SDK-001 |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 9 — Law of Design DNA |
| Source Physics | Physics/005-Events.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Audit SDK provides the standard interface for audit and evidence tools to integrate with AIOS. It defines how external and internal audit systems query, verify, and analyze the Event Store — the immutable record of all AIOS operations. The Audit SDK enables compliance monitoring, forensic investigation, real-time alerting, and regulatory reporting.

Audit is a constitutional requirement in AIOS. Law 4 (Evidence) mandates that every operation produces an Event. The Audit SDK provides the tooling to consume, validate, and act on those Events. Every audit tool, whether built by the AIOS core team, an Organization, or a third party, must implement the interfaces defined herein.

## Audit Provider Interface

Every audit tool must implement the `AuditProvider` interface:

```
interface AuditProvider {
  // Query
  queryEvents(filter: EventFilter): EventIterator
  getEventById(eventId: EventID): Event
  streamEvents(filter: EventFilter): EventStream

  // Verification
  verifyChain(eventId: EventID): ChainVerificationResult
  verifyIntegrity(eventRange: EventRange): IntegrityReport
  computeHash(eventId: EventID): HashDigest

  // Analysis
  analyzePattern(filter: EventFilter, pattern: AnalysisPattern): AnalysisResult
  computeAggregation(filter: EventFilter, metric: AggregationMetric): AggregationResult
  detectAnomaly(filter: EventFilter, baseline: BaselineModel): AnomalyReport

  // Compliance
  checkCompliance(filter: EventFilter, standard: ComplianceStandard): ComplianceReport
  generateEvidencePackage(caseId: CaseID, filter: EventFilter): EvidencePackage
  produceReport(template: ReportTemplate, filter: EventFilter): AuditReport

  // Lifecycle
  registerAsObserver(): ObserverRegistration
  setRetentionPolicy(policy: RetentionPolicy): void
  getRetentionPolicy(): RetentionPolicy
}
```

| Method | Description | Use Case |
|--------|-------------|----------|
| `queryEvents` | Query Events by filter criteria | General audit queries |
| `getEventById` | Retrieve a single Event by ID | Evidence lookup |
| `streamEvents` | Subscribe to real-time Event stream | Live monitoring |
| `verifyChain` | Verify Event chain integrity (hash links) | Forensic investigation |
| `verifyIntegrity` | Verify integrity of an Event range | Compliance evidence |
| `computeHash` | Compute cryptographic hash of an Event | Evidence sealing |
| `analyzePattern` | Detect patterns across Events | Threat hunting |
| `computeAggregation` | Aggregate metrics from Event stream | Dashboard metrics |
| `detectAnomaly` | Detect anomalous patterns | Security monitoring |
| `checkCompliance` | Check compliance against a standard | Regulatory audit |
| `generateEvidencePackage` | Package Events as evidence for a case | Legal/regulatory |
| `produceReport` | Generate formatted audit report | Compliance reporting |
| `registerAsObserver` | Register to receive Event notifications | Real-time monitoring |

## Event Filter Specification

Event queries use a standardized filter:

```
{
  "time_range": { "start": "ISO8601", "end": "ISO8601" },
  "event_types": ["string"],
  "source_entities": ["entity_id"],
  "correlation_id": "uuid",
  "severity_range": { "min": 0.0, "max": 1.0 },
  "full_text_search": "string",
  "limit": 1000,
  "offset": 0,
  "order_by": "timestamp_desc"
}
```

| Filter Field | Description | Required |
|-------------|-------------|----------|
| `time_range` | Inclusive time window for Events | Yes |
| `event_types` | Filter by event type (e.g., `ROS.ResourceAllocated`) | No |
| `source_entities` | Filter by source entity identity | No |
| `correlation_id` | Filter by correlation ID (trace a flow) | No |
| `severity_range` | Filter by severity score | No |
| `full_text_search` | Full-text search across Event payloads | No |
| `limit` | Maximum Events to return (default 1000, max 10000) | No |
| `offset` | Pagination offset | No |
| `order_by` | Sort order (timestamp_desc or timestamp_asc) | No |

## Audit Provider Registration

Audit tools register with the Event Store through a structured registration:

```
{
  "provider_id": "uuid-v7",
  "provider_name": "string",
  "version": "1.0.0",
  "capabilities": ["query", "verify", "analyze", "compliance", "stream"],
  "scopes": ["organization_id", "global"],
  "retention_supported": {
    "min_days": 30,
    "max_days": 3650
  },
  "compliance_standards": ["SOC2", "ISO27001", "PCI-DSS", "GDPR"]
}
```

Registration is validated by the Audit Service. Providers with unsupported scopes or invalid compliance standards are rejected.

## Query Performance

The Audit SDK must meet these query performance targets:

| Query Type | Target Latency | Max Results |
|------------|---------------|-------------|
| Single Event by ID | < 50ms | 1 |
| Time-range query (1 hour) | < 200ms | 10,000 |
| Time-range query (1 day) | < 1 second | 100,000 |
| Full-text search (indexed) | < 500ms | 1,000 |
| Full-text search (unindexed) | < 5 seconds | 100 |
| Aggregation query | < 2 seconds | N/A |
| Stream subscription | < 100ms to first event | Unlimited |

## Evidence Chain Verification

The Audit SDK supports cryptographic verification of Event chains:

```
Event Chain Structure:

Event[N] ──hash──▶ Event[N+1] ──hash──▶ Event[N+2]

Each Event includes:
  - previous_event_hash: hash of Event[N-1]
  - event_payload_hash: hash of the event data
  - signature: provider-signed hash chain entry
```

| Verification Level | Check | Purpose |
|--------------------|-------|---------|
| L1 — Single Event | Hash matches payload | Data integrity |
| L2 — Chain Link | Event[N] references Event[N-1] hash | Chain continuity |
| L3 — Full Chain | All links from start to end verify | Complete chain integrity |
| L4 — Signature | Provider signature on chain checkpoints | Non-repudiation |

## Retention Policies

Audit providers must support configurable retention policies:

| Policy | Description | Default |
|--------|-------------|---------|
| Time-based | Events retained for N days | 365 days |
| Size-based | Events retained up to N GB | 100 GB per Organization |
| Tiered | Hot (30 days, fast access) → Warm (1 year, standard) → Cold (archive, slow) | Configured |
| Compliance-based | Minimum retention per compliance standard | Varies (e.g., PCI-DSS: 365 days) |
| Legal hold | Events preserved regardless of other policies | On-demand |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Audit.EvidenceQueried` | Audit query is executed | query_id, filter_hash, result_count, duration_ms, query_type |
| `Audit.ChainVerified` | Event chain verification completes | chain_id, start_event, end_event, is_valid, broken_links, verification_level |
| `Audit.AnomalyDetected` | Anomaly detection triggers | anomaly_id, pattern, severity, affected_events_count, confidence |
| `Audit.ComplianceReportGenerated` | Compliance report is produced | report_id, standard, scope, passed_checks, failed_checks, score_pct |
| `Audit.EvidencePackageSealed` | Evidence package is created and sealed | package_id, case_id, event_count, seal_hash, retention_days |
| `Audit.EvidencePackageAccessed` | Sealed evidence package is accessed | package_id, accessed_by, access_reason, timestamp |
| `Audit.RetentionPolicyChanged` | Retention policy is modified | policy_id, previous_policy, new_policy, changed_by, reason |

## Cross-Cutting Concerns

### Security

Audit tools access Event data based on the requesting entity's authorization scope. An Organization's audit tools may only access Events within that Organization's scope. The Security Council has unrestricted audit access. Evidence packages are cryptographically sealed to prevent tampering. (Physics/008-Security.md)

### Evidence

The Audit SDK is meta-evidential — it consumes Events to produce audit evidence. Every audit operation (query, verify, analyze, report) produces its own Event. Evidence packages include provenance chains, verification results, and seal hashes. (PHI-008)

### Lifecycle

Audit tools follow the canonical SDK lifecycle: Registered → Active → Deprecated → Retired. Evidence packages follow their own lifecycle: Created → Sealed → Retained → Expired/Archived. Retention policies define how long Events and evidence packages are preserved. (Physics/006-Lifecycles.md)

### Capability Bounds

Audit SDK capabilities are bounded by the requesting entity's data access scope. A ComplianceWorker may only audit Events within its Organization. Event queries are bounded by time range and result limits. Evidence package size is bounded by storage allocation. (Physics/007-Capabilities.md)

### Communication

All Audit SDK communication flows through ACF. Event queries are RPC-style requests. Real-time event monitoring uses ACF subscriptions. Evidence package distribution uses ACF with guaranteed delivery. Compliance reports are published to restricted ACF topics. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Audit SDK covers only audit and evidence — no execution or knowledge concerns |
| R3 (DRY) | Events are stored once in the Event Store — audit queries reference the canonical source |
| R5 (Liskov) | All audit tools implement the same AuditProvider interface |
| R7 (Testability) | Event chains are automatically verifiable — integrity is always checkable |
| R9 (Deterministic) | Same Event filter always returns same result set (for same time range) |
| R13 (Design for Failure) | Event Store unavailability returns partial results with cut-off timestamp |
| R14 (Paved Path) | Paved path: query → verify → analyze → report → seal |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 