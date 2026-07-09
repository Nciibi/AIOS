# AIOS Bible — Foundations
## 008 — Object Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-008 |
| Source Laws | Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Every constitutional entity in AIOS has a lifecycle governed by the Lifecycle Management Service (LMS). Lifecycles define entity states, authorised transitions, and transition authors. This document provides the canonical lifecycle model shared by all entity types.

## Canonical Lifecycle

```
Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived
```

| State | Description | Can Act? | Modifiable? | Terminal? |
|-------|-------------|----------|-------------|-----------|
| **Created** | Entity record exists, identity assigned | No | Limited (metadata only) | No |
| **Planned** | Purpose, scope, and resources are defined | No | Yes (plan details) | No |
| **Assigned** | Resources and capabilities are allocated | No | Yes (assignments) | No |
| **Running** | Entity is actively performing its function | Yes | Yes (runtime config) | No |
| **Waiting** | Entity is waiting for external input or dependency | No | No | No |
| **Paused** | Entity execution is suspended. Resumable | No | No | No |
| **Blocked** | Entity cannot proceed due to an unresolved issue | No | No | No |
| **Review** | Entity requires review before completion | Yes (limited) | No | No |
| **Completed** | Entity has finished its function successfully | No | No | No |
| **Archived** | Entity record is preserved for audit. Not operational | No | No | Yes |

## Authorised Transitions

```
Created → Planned
Planned → Assigned
Assigned → Running
Running → Waiting (when external dependency is required)
Running → Paused (explicit pause by supervisor)
Running → Blocked (failure or exception)
Running → Review (when check-in is required)
Waiting → Running (dependency resolved)
Paused → Running (supervisor resumes)
Blocked → Running (blocker resolved)
Blocked → Review (requires human assessment)
Review → Running (approved to continue by reviewer)
Review → Completed (approved as finished by reviewer)
Completed → Archived (automatic after retention period)
```

### Transition Authorization Matrix

| Transition | Authorized By | Requires Evidence? |
|-----------|--------------|-------------------|
| Created → Planned | Creator entity (Sou, OSYS, etc.) | No |
| Planned → Assigned | Resource orchestrator (ROS) | Yes (resource availability) |
| Assigned → Running | LMS (automatic when ready) | No |
| Running → Waiting | Entity itself | Yes (dependency identified) |
| Running → Paused | Supervisor or Security Council | Yes (pause reason) |
| Running → Blocked | Entity itself (failure) | Yes (error details) |
| Running → Review | Entity itself or policy trigger | Yes (check-in reason) |
| Waiting → Running | LMS (automatic on dependency resolution) | Yes (dependency completion) |
| Paused → Running | Supervisor | No |
| Blocked → Running | Resolution by entity/supervisor | Yes (resolution evidence) |
| Blocked → Review | Entity or supervisor | Yes (block details) |
| Review → Running | Reviewer | Yes (review decision) |
| Review → Completed | Reviewer | Yes (approval) |
| Completed → Archived | LMS (automatic, timer-based) | Yes (retention policy) |

## Lifecycle Events

Every transition produces an Event:

| Event Type | Fields | Consumed By |
|-----------|-------|-------------|
| `Lifecycle.StateChanged` | entity_id, from_state, to_state, authorized_by, timestamp | Audit, Security Council, parent entity |
| `Lifecycle.TransitionDenied` | entity_id, from_state, attempted_to, reason, authorized_by | Security Council, parent entity |
| `Lifecycle.EntityCreated` | entity_id, entity_type, created_by | LMS, IDS, Audit |
| `Lifecycle.EntityCompleted` | entity_id, completed_by, completion_evidence | Audit, parent entity |
| `Lifecycle.EntityArchived` | entity_id, retention_period, archived_at | Audit, Event Store |

## Resource Bounds and Lifecycle

Entity capabilities are lifecycle-state-dependent:

| State | Capability Access | Resource Budget |
|-------|------------------|----------------|
| Created | None | None |
| Planned | Read-only metadata | None |
| Assigned | Read-only, resource discovery | Budget allocated but not drawable |
| Running | Full capability scope | Budget active and drawable |
| Waiting | Read-only, status queries | Budget frozen |
| Paused | Read-only, status queries | Budget frozen |
| Blocked | Read-only, error reporting | Budget frozen |
| Review | Read-only, review actions | Budget active (limited) |
| Completed | Read-only (evidence access) | Budget returned to pool |
| Archived | None | Evidenced budget recorded |

## Cross-Cutting Concerns

### Identity

Lifecycle is parallel to identity lifecycle. An entity has both:
- **Identity lifecycle** (Created → Verified → Active → Suspended → Restored → Retired → Archived) — see IDS/003-Lifecycle.md
- **Operational lifecycle** (Created → Planned → Assigned → Running → ... → Archived) — this document

Identity lifecycle is managed by IDS. Operational lifecycle is managed by LMS. The two converge at identity verification (entity must have Active status in IDS before entering Running state in LMS).

### Evidence

Every lifecycle transition produces an Event. The Event Store preserves the complete lifecycle history for every entity. Lifecycle events are included in the entity's evidence chain.

### Capabilities

Capabilities are bound by lifecycle state. An entity in Running state has access to its full capability scope. An entity in Paused state has no access to capabilities (all tokens are revoked until Running resumes).

### Security

Lifecycle transitions that affect operational state (Running → Paused, Running → Blocked) require Security Council authorisation or notification. Unauthorized transitions are constitutional violations and trigger S2 escalation.