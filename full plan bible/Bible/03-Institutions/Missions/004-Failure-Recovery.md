# AIOS Bible â€” Institutions
## 004 â€” Mission Failure & Recovery

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Institutions |
| Document ID | AIOS-BBL-003-MSN-004 |
| Source Laws | Law 1 â€” Law of Origin, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Handle Mission failures gracefully â€” detection, classification, escalation paths, and recovery strategies while maintaining evidence integrity.

## Architecture

Failure recovery follows a detect-classify-escalate-recover pipeline. Detection produces a raw FailureRecord which is classified into a category. Based on category and severity, an escalation path is chosen, and a recovery strategy is proposed and executed.

```
Failure Event
    â”‚
    â–¼
Detection (timeout / error / heartbeat / evidence / contract)
    â”‚
    â–¼
Classification (transient / systemic / constitutional / cascading)
    â”‚
    â–¼
Escalation Decision
    â”œâ”€â”€ Auto-Retry â”€â”€â–º Success â†’ Resume
    â”‚                  â””â”€â”€ Exhausted â†’ Escalate
    â”œâ”€â”€ Supervisor â”€â”€â–º Recovery Strategy Proposed
    â”œâ”€â”€ Security Council
    â””â”€â”€ Console
           â”‚
           â–¼
    Recovery Execution (retry / rollback / failover / degrade / abort)
           â”‚
           â”œâ”€â”€ Success â†’ Resume Mission
           â””â”€â”€ Failure â†’ Escalate to Next Level
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
Auto-Retry â†’ Supervisor â†’ Security Council â†’ Console
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
Pending â†’ Approved â†’ Running â†’ [Completed | Failed]
                      â†“
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

```typescript
interface FailureManager {
  detectFailure(missionId: UUID, signal: DetectionSignal): Promise<FailureRecord>;
  classifyFailure(record: FailureRecord): Promise<FailureClassification>;
  escalate(record: FailureRecord, level: EscalationLevel): Promise<EscalationPath>;
  proposeRecovery(record: FailureRecord, strategy: RecoveryStrategy): Promise<StrategyID>;
  approveRecovery(strategyId: UUID, approver: Approver): Promise<ApprovalRecord>;
  executeRecovery(strategy: RecoveryStrategy): Promise<RecoveryExecution>;
  rollbackToCheckpoint(checkpointId: UUID): Promise<RecoveryExecution>;
}
```

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.MSNEvent |      failure_id, mission_id, method, details | Failure detected |
| MSN.MSNEvent |      failure_id, category, severity, root_cause | Failure classified |
| MSN.MSNEvent |      failure_id, attempt_number, backoff_ms | Auto-retry scheduled |
| MSN.MSNEvent |      failure_id, attempt_number, success | Auto-retry succeeds |
| MSN.MSNEvent |      failure_id, attempts_made, last_error | All retries exhausted |
| MSN.MSNEvent |      failure_id, level, escalated_to | Escalation triggered |
| MSN.MSNEvent |      failure_id, strategy_type, checkpoint_ref | Recovery begins |
| MSN.MSNEvent |      failure_id, strategy_type, outcome | Recovery succeeds |
| MSN.MSNEvent |      failure_id, strategy_type, error | Recovery fails |
| MSN.MSNEvent |      failure_id, failed_count, total_count, isolated_milestones | Partial failure |
| MSN.MSNEvent |      failure_id, source_mission, affected_missions | Cascading failure |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_FAIL_001 | Unknown failure type â€” cannot classify |
| MSN_FAIL_002 | Retry limit exceeded â€” all auto-retry attempts exhausted |
| MSN_FAIL_003 | Escalation timeout â€” no response at current level |
| MSN_FAIL_004 | Recovery strategy not approved â€” cannot execute |
| MSN_FAIL_005 | Rollback checkpoint not found â€” state unrecoverable |
| MSN_FAIL_006 | Cascading failure containment failed â€” propagation not stopped |
| MSN_FAIL_007 | Recovery execution failed â€” strategy unsuccessful |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MSN-FAIL-001 | Every failure must be classified before recovery can begin | Algorithmic â€” Recovery rejected without classification |
| MSN-FAIL-002 | Auto-retry is only permitted for transient failures | Architectural â€” RetryHandler checks classification category |
| MSN-FAIL-003 | Recovery approval must come from level above current escalation | Algorithmic â€” Approval authorization check |
| MSN-FAIL-004 | Evidence integrity must be preserved through all recovery actions | Architectural â€” Evidence chain is append-only during recovery |
| MSN-FAIL-005 | Cascading failure must isolate affected Missions before propagation | Algorithmic â€” Containment check before recovery execution |


## Cross-Cutting Concerns

### Security

Missions operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Missions emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Missions instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Missions declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Failure and recovery is a single focused concern |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Recovery state machine follows same pattern as Mission lifecycle |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Same failure with same strategy produces same recovery outcome |
| R10 - Simpler Over Complex | Clear escalation ladder with defined gates |
| R13 - Design for Failure | Every failure mode has a defined detection and recovery path |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/001-Planning.md | Sibling â€” risk assessment informs recovery |
| Missions/002-Execution.md | Sibling â€” failures originate during execution |
| Missions/003-Delegation.md | Sibling â€” delegation failures trigger recovery |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle â€” failure containment |
| Bible/04-Execution/Security/000-Overview.md | Security Council escalation |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
