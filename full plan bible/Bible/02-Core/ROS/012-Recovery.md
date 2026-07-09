# AIOS Bible — Core
## 012 — Resource Recovery

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-012 |
| Source Laws | Law 12 — Law of Bounded Capability |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Resource Recovery ensures that when an entity terminates — whether gracefully or catastrophically — all of its resources are promptly returned to the available pool. Recovery is the safety net that prevents resource leaks and guarantees liveness per ROS-005. It integrates with LMS (Physics/006-Lifecycles) for lifecycle-driven cleanup.

## Recovery Triggers

| Trigger | Source | Description |
|---------|--------|-------------|
| Entity termination | LMS | Normal entity lifecycle completion |
| Entity crash | LMS / Health Monitor | Entity process terminated unexpectedly |
| Mission completion | Sou / OSYS | Mission ended, all participant resources released |
| Organization dissolution | OSYS | Organization dissolved, all member resources released |
| Entity autonomy revocation | Security Council | Entity autonomy revoked, resources seized |
| Manual recovery | Administrator | Operator-initiated cleanup |
| Scheduled maintenance | ROS | Planned resource pool draining |

## Recovery Process

### Graceful Recovery

Allows in-flight operations to complete before deallocating resources.

```
1. Recovery triggered
2. Identify all resources allocated to the scope
3. Send grace period notification to affected entities (if applicable)
4. Wait for grace period (configurable, default: 30 seconds)
5. For each allocation:
   a. Check if operation completed
   b. If complete: mark as complete, release resources
   c. If in-flight: allow completion up to grace period
6. After grace period:
   a. Force-release any remaining allocations
7. Update budget: subtract released resources from used
8. Notify affected providers
9. Produce RecoveryCompleted Event
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `grace_period` | Duration | 30 seconds | Time allowed for in-flight operations to complete |
| `force` | Boolean | false | If true, skip grace period and force-release immediately |

### Force Recovery

Immediate deallocation without waiting for in-flight operations. Used for failed entities, security violations, and autonomous revocation.

```
1. Recovery triggered (force=true)
2. Identify all resources allocated to the scope
3. For each allocation:
   a. Issue immediate termination to entity
   b. Force-release resources on provider
   c. Mark allocation as force-released
4. Update budget: subtract released resources from used
5. Notify affected providers
6. Produce ForceRecoveryCompleted Event
```

## Recovery Operations

### triggerRecovery

Triggers resource recovery for a scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, mission, organization |
| `scope_id` | UUID | Scope to recover |
| `trigger_type` | Enum | termination, crash, completion, dissolution, revocation, manual |
| `force` | Boolean | Force recovery (skip grace period) |

**Event produced**: `RecoveryStarted { recovery_id, scope_type, scope_id, trigger_type, force, timestamp }`

### getRecoveryStatus

Returns the status of an active or completed recovery.

| Parameter | Type | Description |
|-----------|------|-------------|
| `recovery_id` | UUID | Recovery operation identifier |

**Returns**: Recovery status with list of allocations processed, pending, and failed.

### listPendingRecoveries

Lists all scopes with pending resource recovery (resources not yet released after termination).

**Returns**: List of scopes with unreleased resources, grouped by trigger type.

## Recovery Data Structures

```
RecoveryRecord {
    recovery_id: UUID
    scope_type: Enum
    scope_id: UUID
    trigger_type: Enum
    force: Boolean
    started_at: Timestamp
    completed_at: Timestamp (optional)
    status: Enum (in_progress, completed, failed)
    allocations_recovered: Int
    allocations_failed: Int
    resources_recovered: Map<ResourceType, Quantity>
}

AllocationRecoveryRecord {
    allocation_id: UUID
    entity_id: UUID
    provider_id: UUID
    resources: Map<ResourceType, Quantity>
    recovery_type: Enum (graceful, force)
    status: Enum (pending, releasing, released, failed)
    released_at: Timestamp (optional)
    error: String (optional)
}
```

## Provider Notification

When resources are recovered, affected providers are notified:

| Notification | Timing | Content |
|-------------|--------|---------|
| Graceful recovery notice | At start of grace period | `{ allocation_id, grace_period_end }` |
| Force recovery notice | Immediate | `{ allocation_id, reason: "force_recovery" }` |
| Recovery complete | After all allocations released | `{ recovery_id, released_count, failed_count }` |

If provider notification fails, the Recovery component retries up to 3 times with exponential backoff. After 3 failures, the allocation is marked as released in ROS and the provider is flagged for manual reconciliation.

## Integration with LMS

Recovery is triggered by LMS lifecycle transitions:

| LMS Event | Recovery Action |
|-----------|----------------|
| EntityTerminating | Trigger graceful recovery for entity |
| EntityCrashed | Trigger force recovery for entity |
| EntityPurged | Trigger force recovery (with cleanup verification) |
| MissionCompleting | Trigger graceful recovery for all mission entities |
| OrganizationDissolving | Trigger graceful recovery for all org entities |

## Recovery Guarantees

| Guarantee | Description |
|-----------|-------------|
| Completeness | Every allocation belonging to the recovered scope is released |
| Idempotency | Running recovery twice on the same scope is safe — already-released allocations are skipped |
| Non-blocking | Recovery runs asynchronously; it does not block other ROS operations |
| Auditability | Every recovered allocation produces a deallocation Event |

## Recovery Scenarios

### Entity Crash Recovery

When LMS detects an entity crash:
1. LMS sends `EntityCrashed` Event to Recovery
2. Recovery immediately triggers force recovery for the entity
3. All active allocations are force-released on their providers
4. All active reservations are expired
5. Budget is adjusted: used -= recovered amount
6. `RecoveryCompleted` Event produced
7. Entities depending on the crashed entity's resources (e.g., through ACF calls) receive notifications

| Step | Action | Time Budget |
|------|--------|-------------|
| 1 | LMS notification received | < 1 second |
| 2 | Allocations identified | < 2 seconds |
| 3 | Force release initiated | < 5 seconds |
| 4 | Provider confirmations | < 10 seconds |
| 5 | Budget adjusted | < 1 second |
| 6 | Completion Event produced | < 1 second |

### Mission Completion Recovery

When a Mission completes:
1. Sou sends `MissionCompleted` Event to Recovery
2. Recovery triggers graceful recovery for all mission entities
3. Each entity receives a grace period notification (30 seconds)
4. Entities may complete in-flight operations
5. After grace period, any remaining allocations are force-released
6. Mission budget is finalized and archived
7. `RecoveryCompleted` Event produced with mission summary

### Organization Dissolution Recovery

When an Organization dissolves:
1. OSYS sends `OrganizationDissolving` Event to Recovery
2. Recovery triggers graceful recovery for all member entities
3. Organization-level budget and quota are deactivated
4. Entity budgets are adjusted to remove organization-level allocations
5. Member entities may continue as independent entities or be assigned to a new organization
6. Organization resource records are archived

### Scheduled Maintenance Recovery

When maintenance is planned:
1. Administrator triggers recovery with `maintenance` reason
2. Recovery initiates graceful recovery for targeted providers
3. Entities on affected providers receive extended grace period (configurable, default 5 minutes)
4. Allocator redirects new allocations to alternative providers
5. After grace period, remaining allocations on target providers are force-released
6. Providers are drained and maintenance proceeds
7. After maintenance, providers re-register and capacities are restored

## Recovery Guarantees and Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Recovery triggered for already-terminated entity | Idempotent — no-op, already-released allocations are skipped |
| Provider unreachable during recovery | Retry 3 times with exponential backoff; mark allocation as released in ROS; flag for manual reconciliation |
| Recovery during active allocation | Grace period allows completion; force recovery aborts immediately |
| Recovery race condition (two triggers simultaneously) | First trigger acquires lock; second trigger returns already-in-progress |
| Budget inconsistency after recovery | Budget is adjusted to reflect actual released amount; discrepancy logged for audit |
| Partial recovery (some allocations fail to release) | Failed allocations are flagged for manual intervention; recovery is marked as partial |

## Recovery Audit Trail

Every recovery produces an immutable audit record:

```
RecoveryAuditRecord {
    recovery_id: UUID
    scope_type: Enum
    scope_id: UUID
    trigger_type: Enum
    force: Boolean
    started_at: Timestamp
    completed_at: Timestamp
    duration_ms: Int
    total_allocations: Int
    graceful_releases: Int
    force_releases: Int
    failed_releases: Int
    resources_recovered: Map<ResourceType, Quantity>
    providers_notified: List<UUID>
    errors: List<RecoveryError>
}
```

Audit records are retained for the lifetime of the AIOS instance and are accessible only to the Security Council.

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| RecoveryStarted | triggerRecovery | recovery_id, scope_type, scope_id, trigger_type, force, timestamp |
| RecoveryCompleted | All resource released | recovery_id, allocations_recovered, allocations_failed, resources_recovered, timestamp |
| RecoveryFailed | Recovery could not complete | recovery_id, error, failed_allocations, timestamp |
| AllocationForceReleased | Force recovery of single allocation | allocation_id, entity_id, provider_id, timestamp |
| ProviderNotified | Provider notified of recovery | provider_id, allocation_id, notification_type, timestamp |

## Cross-Cutting Concerns

### Security

Recovery may be triggered only by authorized entities: LMS for lifecycle events, Security Council for autonomy revocation, administrators for manual recovery.

### Evidence

Every recovery action produces Events. Full recovery history is auditable.

### Lifecycle

Recovery is the final stage of the resource lifecycle. It ensures resources do not outlive their owning entities.

### Capability Bounds

Recovery respects capability bounds by releasing only what was allocated. It never releases more than the original allocation.

### Communication

Recovery communicates with providers via ACF. Provider notification retries with exponential backoff.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Recovery handles only resource cleanup on termination. Separate from allocation and budgeting. |
| R9 — Deterministic | Recovery is deterministic — same allocations always produce the same release sequence. |
| R10 — Simpler Over Complex | Two recovery modes (graceful/force) cover all cases. No complex recovery coordination. |
| R13 — Design for Failure | Recovery is the safety net for R13. Entities may crash; recovery ensures resources are not leaked. Recovery itself retries on failure. |
| R14 — Paved Path | The paved path is: Entity Terminates → Recovery Triggered → Grace Period → Resources Released → Providers Notified. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Recovery deallocates resources allocated by the Allocator |
| ROS/002-Registry.md | Recovery notifies providers of resource release |
| ROS/009-Reservation.md | Recovery releases active reservations |
| Physics/006-Lifecycles.md | LMS triggers recovery on lifecycle transitions |
| Physics/005-Events.md | Event sourcing for recovery operations |
| Foundations/002-Design-DNA.md | R13 — Design for Failure — recovery is the failure safety net |
