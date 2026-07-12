# AIOS Bible — Institutions
## 004 — Mission Failure & Recovery

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-MSN-004 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Handle Mission failures gracefully — detection, classification, escalation paths, and recovery strategies while maintaining evidence integrity.

## Architecture

Failure recovery follows a detect-classify-escalate-recover pipeline. Detection produces a raw FailureRecord which is classified into a category. Based on category and severity, an escalation path is chosen, and a recovery strategy is proposed and executed.

```
Failure Event
    │
    ▼
Detection (timeout / error / heartbeat / evidence / contract)
    │
    ▼
Classification (transient / systemic / constitutional / cascading)
    │
    ▼
Escalation Decision
    ├── Auto-Retry ──► Success → Resume
    │                  └── Exhausted → Escalate
    ├── Supervisor ──► Recovery Strategy Proposed
    ├── Security Council
    └── Console
           │
           ▼
    Recovery Execution (retry / rollback / failover / degrade / abort)
           │
           ├── Success → Resume Mission
           └── Failure → Escalate to Next Level
```

Every step produces evidence for audit and maintains the evidence chain integrity invariant.

## Data Model

```typescript
interface FailureRecord {
  failure_id: UUID;
  mission_id: UUID;
  detection_method: DetectionMethod;
  classification: FailureClassification;
  timestamp: Timestamp;
  evidence: EvidenceRef[];
  context: FailureContext;
}

interface FailureClassification {
  category: FailureCategory;
  severity: Severity;
  scope: FailureScope;
  is_cascading: boolean;
  root_cause: string;
}

interface EscalationPath {
  escalation_id: UUID;
  failure_id: UUID;
  current_level: EscalationLevel;
  history: EscalationStep[];
  deadline: Timestamp;
  status: EscalationStatus;
}

interface RecoveryStrategy {
  strategy_id: UUID;
  failure_id: UUID;
  type: RecoveryType;
  parameters: Map<string, any>;
  risk_assessment: number;
  approved_by?: UUID;
}

interface RecoveryExecution {
  execution_id: UUID;
  strategy_id: UUID;
  status: RecoveryExecutionStatus;
  checkpoint_id?: UUID;
  started_at: Timestamp;
  completed_at?: Timestamp;
  result: RecoveryResult;
}
```

## Core Concepts / Operations

### Failure Detection Methods
| Method | Description | Latency |
|--------|-------------|---------|
| Timeout | Milestone or worker exceeds maximum duration | Configurable SLA |
| Error Return | Worker or subsystem returns error code | Immediate |
| Heartbeat Loss | No heartbeat received within interval | Configurable interval |
| Evidence Inconsistency | Evidence hash chain mismatch or integrity failure | On check-in |
| Contract Violation | Delegation contract terms breached | On verification |

### Failure Classification
| Category | Description | Recovery Approach |
|----------|-------------|-------------------|
| Transient | Temporary issue (network blip, resource contention) | Auto-retry |
| Systemic | Infrastructure or systemic failure (service down, quota exhausted) | Failover or degrade |
| Constitutional | Violation of Laws, rules, or authorization boundaries | Escalate to Security Council |
| Cascading | Failure propagates from sub-Mission or dependency | Isolate and contain |

### Escalation Paths
```
Auto-Retry → Supervisor → Security Council → Console
```

1. **Auto-Retry**: Automatic retry with backoff (transient failures only). Configurable max attempts.
2. **Supervisor**: Escalate to owning Organization supervisor for human judgment (systemic or persistent).
3. **Security Council**: Escalate for constitutional review (constitutional violations, cascading failures).
4. **Console**: Final escalation to human operator console (unrecoverable, requires external intervention).

### Recovery Strategies
| Strategy | Description | Applicable To |
|----------|-------------|---------------|
| Retry | Re-execute the failed action with same parameters | Transient |
| Rollback | Revert to last checkpoint and re-execute from there | Transient, Systemic |
| Failover | Route to alternative Worker or resource pool | Systemic |
| Degrade | Continue with reduced capabilities, skip non-critical milestones | Systemic, Constitutional |
| Abort | Terminate Mission execution, record failure evidence | Constitutional, Cascading |

### Recovery Execution State Machine
```
Pending → Approved → Running → [Completed | Failed]
                      ↓
                  Rejected (by approver)
```
- **Pending**: Strategy proposed, awaiting approval.
- **Approved**: Strategy approved by authorized entity.
- **Running**: Recovery actions being executed.
- **Completed**: Recovery successful, Mission may resume or transition.
- **Failed**: Recovery unsuccessful, escalate to next level.
- **Rejected**: Strategy rejected by approver, alternative required.

### Partial Failure Handling
When only a subset of milestones fail:
- Isolate failed milestones (mark as Blocked)
- Continue executing non-failed milestones
- Attempt recovery on failed milestones in parallel
- If recovery succeeds, re-integrate milestones
- If partial failure is unrecoverable, evaluate overall Mission impact

## Lifecycle

Failure handling intersects the Mission lifecycle at Running, Waiting, Paused, and Blocked states. Detection transitions the Mission to Blocked. Recovery may return the Mission to Running or trigger escalation to Review for human assessment.

## Internal Interfaces

| Method | Input | Output | Consumed By |
|--------|-------|--------|-------------|
| detectFailure(mission, detection) | UUID, DetectionSignal | FailureRecord | Monitor |
| classifyFailure(failure) | FailureRecord | FailureClassification | Classifier |
| escalate(failure, level) | FailureRecord, EscalationLevel | EscalationPath | Security Council |
| proposeRecovery(failure, strategy) | FailureRecord, RecoveryStrategy | StrategyID | Sou |
| approveRecovery(strategy_id, approver) | UUID, Approver | ApprovalRecord | Supervisor |
| executeRecovery(strategy) | RecoveryStrategy | RecoveryExecution | LMS |
| rollbackToCheckpoint(checkpoint_id) | UUID | RecoveryExecution | LMS |

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.Fail.FailureDetected | failure_id, mission_id, method, details | Failure detected |
| MSN.Fail.FailureClassified | failure_id, category, severity, root_cause | Failure classified |
| MSN.Fail.AutoRetryScheduled | failure_id, attempt_number, backoff_ms | Auto-retry scheduled |
| MSN.Fail.AutoRetryCompleted | failure_id, attempt_number, success | Auto-retry succeeds |
| MSN.Fail.AutoRetryExhausted | failure_id, attempts_made, last_error | All retries exhausted |
| MSN.Fail.Escalated | failure_id, level, escalated_to | Escalation triggered |
| MSN.Fail.RecoveryStarted | failure_id, strategy_type, checkpoint_ref | Recovery begins |
| MSN.Fail.RecoveryCompleted | failure_id, strategy_type, outcome | Recovery succeeds |
| MSN.Fail.RecoveryFailed | failure_id, strategy_type, error | Recovery fails |
| MSN.Fail.PartialFailure | failure_id, failed_count, total_count, isolated_milestones | Partial failure |
| MSN.Fail.CascadingFailure | failure_id, source_mission, affected_missions | Cascading failure |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_FAIL_001 | Unknown failure type — cannot classify |
| MSN_FAIL_002 | Retry limit exceeded — all auto-retry attempts exhausted |
| MSN_FAIL_003 | Escalation timeout — no response at current level |
| MSN_FAIL_004 | Recovery strategy not approved — cannot execute |
| MSN_FAIL_005 | Rollback checkpoint not found — state unrecoverable |
| MSN_FAIL_006 | Cascading failure containment failed — propagation not stopped |
| MSN_FAIL_007 | Recovery execution failed — strategy unsuccessful |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MSN-FAIL-001 | Every failure must be classified before recovery can begin | Algorithmic — Recovery rejected without classification |
| MSN-FAIL-002 | Auto-retry is only permitted for transient failures | Architectural — RetryHandler checks classification category |
| MSN-FAIL-003 | Recovery approval must come from level above current escalation | Algorithmic — Approval authorization check |
| MSN-FAIL-004 | Evidence integrity must be preserved through all recovery actions | Architectural — Evidence chain is append-only during recovery |
| MSN-FAIL-005 | Cascading failure must isolate affected Missions before propagation | Algorithmic — Containment check before recovery execution |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Failure and recovery is a single focused concern |
| R3 — DRY | Recovery state machine follows same pattern as Mission lifecycle |
| R9 — Deterministic | Same failure with same strategy produces same recovery outcome |
| R10 — Simpler Over Complex | Clear escalation ladder with defined gates |
| R12 — Embrace Errors | All recovery errors have unique codes (MSN_FAIL_001–007) |
| R13 — Design for Failure | Every failure mode has a defined detection and recovery path |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/001-Planning.md | Sibling — risk assessment informs recovery |
| Missions/002-Execution.md | Sibling — failures originate during execution |
| Missions/003-Delegation.md | Sibling — delegation failures trigger recovery |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — failure containment |
| Bible/04-Execution/Security/001-Security-Council.md | Security Council escalation |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
