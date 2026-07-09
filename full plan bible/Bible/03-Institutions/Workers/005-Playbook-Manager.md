# AIOS Bible — Institutions
## Workers 005 — Playbook Manager

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-WKR-005 |
| Source Laws | Law 2 — Law of Non-Execution, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Playbook Manager handles the creation, validation, publication, execution, and lifecycle management of Playbooks (runbooks). A Playbook is a sequence of automated actions that can be executed by a Worker or KEE (Core/Academy/013-KEE.md). Playbooks enable automated operations — incident response, deployment, backup, recovery, and routine maintenance — with defined steps, timeouts, rollback plans, and risk tiering.

## Playbook Structure

```
Playbook {
    playbook_id: UUID                    // Unique identifier
    name: String                         // Human-readable name
    version: String                      // SemVer version
    description: String                  // Purpose and scope
    trigger: Trigger                     // event | schedule | manual
    steps: Step[]                        // Ordered sequence of actions
    timeout: Duration                    // Maximum execution time for entire playbook
    rollback: RollbackStep[]             // Rollback plan (reverse steps)
    approval_required: bool              // Requires approval before execution?
    risk_tier: RiskTier                  // low | medium | high | critical
    owner_org: UUID                      // Organization that owns this playbook
    created_at: Timestamp
    updated_at: Timestamp
}
```

### Step Structure

```
Step {
    step_id: UUID                        // Unique step identifier
    name: String                         // Step name
    action: ActionRef                    // Reference to executable action
    parameters: Map<String, Value>       // Action parameters
    timeout: Duration                    // Max duration for this step
    retry_policy: RetryPolicy            // retry_count, backoff, retry_condition
    on_failure: FailureAction            // stop | skip | rollback | continue
    depends_on: UUID[]                   // Step dependencies (for parallel execution)
    evidence_requirements: EvidenceSpec  // What evidence this step must produce
}
```

### Rollback Plan

```
RollbackStep {
    step_id: UUID                        // References the original step
    rollback_action: ActionRef           // Action to reverse the step
    parameters: Map<String, Value>       // Rollback parameters
    timeout: Duration                    // Max duration for rollback
    critical: bool                       // If true, rollback MUST succeed
}
```

## Trigger Types

| Trigger | Description | Example |
|---------|-------------|---------|
| **Event** | Playbook executes automatically when a specific Event occurs | Security incident detected → incident response playbook |
| **Schedule** | Playbook executes on a cron schedule | Daily backup at 02:00 |
| **Manual** | Playbook is executed by an authorized entity (Org Admin, Security Council) | On-demand infrastructure refresh |

## Playbook Lifecycle

```
Draft → Validated → Published → Deprecated → Archived
```

| State | Description | Can Execute? | Modifiable? |
|-------|-------------|-------------|-------------|
| **Draft** | Playbook is being authored. Not yet ready for use. | No | Yes |
| **Validated** | Playbook has passed validation (syntax, safety, rollback coverage). | No | Yes (limited) |
| **Published** | Playbook is available for execution. | Yes | No (immutable) |
| **Deprecated** | Playbook is no longer recommended for new executions. Existing executions may complete. | No (new) / Yes (in-flight) | No |
| **Archived** | Playbook record is preserved for audit. Not executable. | No | No |

### Transitions

| Transition | Authorized By | Requires Evidence? | Notes |
|-----------|--------------|-------------------|-------|
| Draft → Validated | Playbook Validator (automated) | Yes (validation report) | All validation gates must pass |
| Validated → Published | Org Admin or Security Council | Yes (approval) | For high risk: Security Council required |
| Published → Deprecated | Org Admin | Yes (deprecation rationale) | Existing executions allowed to finish |
| Deprecated → Archived | Automatic (after retention) | Yes (retention compliance) | No further execution |

## Execution Lifecycle

```
Pending → Approved → Running → Step[N] → Step[N+1] → ... → Completed
                 → Rejected        → Failed → Rollback
```

| State | Description |
|-------|-------------|
| **Pending** | Execution requested. Awaiting approval (if required) or slot availability. |
| **Approved** | Execution authorized to begin (if approval_required). |
| **Rejected** | Execution request denied by authorizing entity. |
| **Running** | Playbook steps are being executed. |
| **Step[N]** | Individual step N is executing. |
| **Step[N] Failed** | Step N encountered an error — on_failure action triggered. |
| **Rollback** | Rollback plan is being executed. |
| **Completed** | All steps completed successfully (or within acceptable partial completion). |
| **Failed** | Execution failed — rollback may have failed or was not available. |

## Risk Tiers

| Tier | Description | Examples | Approval Required? | Rollback Required? |
|------|-------------|----------|-------------------|-------------------|
| **Low** | No production impact. Read-only operations. | Log inspection, metric query | No | No |
| **Medium** | Potential minor impact. Limited write operations. | Configuration update with rollback | Org Admin | Yes |
| **High** | Significant production impact. System modification. | Deployment, database migration | Security Council | Yes (tested) |
| **Critical** | System-wide impact. Emergency operations. | Emergency shutdown, failover | Security Council + Sou | Yes (mandatory) |

## Playbook Operations

### createPlaybook

```
Input:  name, steps[], trigger, timeout, rollback?, approval_required?, risk_tier
Process: validate structure → store as Draft → return
Output: Playbook { playbook_id, status: Draft }
Authorization: Org Admin or Manager
Event: PLAYBOOK.Created
```

### validatePlaybook

```
Input:  playbook_id
Process: validate syntax → validate action references → validate rollback coverage → validate risk tier → security scan
Output: ValidationReport { passed, issues[] }
Authorization: Playbook Validator (automated)
Event: PLAYBOOK.Validated
```

### publishPlaybook

```
Input:  playbook_id, approval_evidence (if required)
Process: verify validation passed → verify approvals (if required) → set status to Published
Output: Playbook (status: Published)
Authorization: Org Admin (low/medium), Security Council (high/critical)
Event: PLAYBOOK.Published
```

### executePlaybook

```
Input:  playbook_id, parameters?, triggered_by
Process: authorize execution → create execution record → dispatch steps → monitor → handle failures → complete
Output: ExecutionResult { execution_id, status, step_results[] }
Authorization: Per risk tier (none/Low, Org Admin/Medium, Security Council/High, Council+Sou/Critical)
Event: PLAYBOOK.ExecutionStarted
```

### cancelExecution

```
Input:  execution_id, reason
Process: stop current step → initiate rollback (if applicable) → seal evidence
Output: CancellationRecord
Authorization: Same as execute authorization
Event: PLAYBOOK.ExecutionCancelled
```

### getExecutionStatus

```
Input:  execution_id
Process: query execution record → return
Output: ExecutionStatus { execution_id, state, current_step, progress, started_at, estimated_completion }
Authorization: Member of owning Org
```

## Execution Flow

```
1. Trigger fires (event/schedule/manual)
2. Authorization check based on risk_tier
3. If approval_required → request approval (Org Admin or Security Council)
4. Create execution record (Pending state)
5. When approved → transition to Running
6. Execute steps in order:
   a. Resolve step dependencies
   b. Dispatch action to Worker or KEE
   c. Monitor step execution
   d. Collect evidence from step
   e. If step succeeds → advance to next step
   f. If step fails:
      - on_failure = stop → halt execution
      - on_failure = skip → continue to next step
      - on_failure = rollback → initiate rollback plan
      - on_failure = continue → proceed despite failure (with warning)
   g. Check overall timeout → if exceeded → initiate rollback
7. All steps complete → transition to Completed
8. Notify stakeholders of completion
```

## Playbook Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `PLAYBOOK.Created` | New playbook is created | playbook_id, name, risk_tier, owner_org |
| `PLAYBOOK.Validated` | Playbook passes validation | playbook_id, validation_report, issues_found |
| `PLAYBOOK.Published` | Playbook is published | playbook_id, published_by, effective_date |
| `PLAYBOOK.Deprecated` | Playbook is deprecated | playbook_id, deprecation_reason |
| `PLAYBOOK.Archived` | Playbook is archived | playbook_id, retention_period |
| `PLAYBOOK.ExecutionStarted` | Playbook execution begins | execution_id, playbook_id, triggered_by, parameters |
| `PLAYBOOK.ExecutionApproved` | Execution request is approved | execution_id, approved_by, approval_evidence |
| `PLAYBOOK.ExecutionRejected` | Execution request is denied | execution_id, rejected_by, reason |
| `PLAYBOOK.StepCompleted` | Individual step finishes | execution_id, step_id, result, evidence_hash |
| `PLAYBOOK.StepFailed` | Step encounters error | execution_id, step_id, error, on_failure_action |
| `PLAYBOOK.RollbackInitiated` | Rollback plan begins execution | execution_id, rollback_step_id, reason |
| `PLAYBOOK.RollbackCompleted` | Rollback finishes | execution_id, rollback_result, final_state |
| `PLAYBOOK.ExecutionCompleted` | Playbook execution finishes successfully | execution_id, step_results[], duration, summary |
| `PLAYBOOK.ExecutionFailed` | Execution fails (unrecoverable) | execution_id, failed_step, rollback_status |
| `PLAYBOOK.ExecutionCancelled` | Execution is cancelled mid-run | execution_id, cancelled_by, reason, rollback_status |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| PLAY_001 | Playbook validation failed — syntax error |
| PLAY_002 | Playbook validation failed — missing rollback for high risk tier |
| PLAY_003 | Playbook validation failed — action reference not found |
| PLAY_004 | Execution authorization denied — insufficient authority |
| PLAY_005 | Execution timeout exceeded — playbook took longer than configured timeout |
| PLAY_006 | Step timeout exceeded — individual step took longer than step timeout |
| PLAY_007 | Rollback failed — critical rollback step did not complete |
| PLAY_008 | Playbook not in Published state — cannot execute |
| PLAY_009 | Execution cancelled — manual intervention by authorized entity |

## Cross-Cutting Concerns

### Security

Playbook execution authorization is risk-tier-dependent. High and Critical playbooks require Security Council authorization. Rollback plans are mandatory for Medium+ risk tiers. All executions produce Events for Security Council audit. (Physics/008-Security.md)

### Evidence

Every playbook operation — creation, validation, publication, execution, step completion, rollback — produces an Event. Complete execution histories are recorded in the Event Store for audit and post-mortem analysis. (PHI-008)

### Lifecycle

Playbooks follow their own lifecycle (Draft → Validated → Published → Deprecated → Archived). Execution follows a separate lifecycle (Pending → Approved/Running → Completed/Failed). Both are instances of the canonical lifecycle model. (PHI-006)

### Capability Bounds

Playbook execution is bounded by the executing Worker's or KEE's capabilities. A playbook cannot execute actions that the Worker does not have capability for. Risk tier limits what actions a playbook can contain (e.g., Critical playbooks require rollback plans). (Physics/007-Capabilities.md)

### Communication

Playbook triggers (events), execution commands, step dispatching, and completion notifications all flow through ACF. The Playbook Manager communicates with Workers and KEEs through ACF for step execution. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Playbook Manager focuses solely on playbook lifecycle and execution |
| R9 (Deterministic) | Same playbook with same parameters always executes same steps in same order |
| R10 (Simpler Over Complex) | Linear step execution with clear failure handling — no branching complexity |
| R12 (Embrace Errors) | All errors have unique codes (PLAY_001–009) |
| R13 (Design for Failure) | Rollback plans ensure system returns to safe state on failure |
| R14 (Paved Path) | Paved path: Create → Validate → Publish → Execute → Monitor → Complete |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/005-Events.md | Evidence — every playbook operation produces Events |
| Physics/006-Lifecycles.md | Lifecycles — playbook and execution lifecycles |
| Physics/007-Capabilities.md | Capabilities — playbook actions bounded by Worker capabilities |
| Physics/010-Execution.md | Execution — playbook steps are executed actions |
| Bible/02-Core/Academy/013-KEE.md | KEE — Knowledge Execution Engine, alternative executor for playbooks |
| Bible/02-Core/Academy/000-Overview.md | Academy — playbook evidence feeds learning |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — playbook ownership |
| Bible/03-Institutions/Workers/000-Overview.md | Workers overview — Workers execute playbook steps |
| Bible/03-Institutions/Workers/001-WOM.md | WOM — Worker capability set bounds playbook actions |
| Bible/03-Institutions/Workers/002-WHS.md | WHS — health monitoring during execution |
| Bible/03-Institutions/Workers/003-WSS.md | WSS — security isolation during automated execution
