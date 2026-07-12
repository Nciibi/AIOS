# AIOS Bible â€” Institutions
## Missions 000 â€” Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Institutions |
| Document ID | AIOS-BBL-003-MSN-000 |
| Source Laws | Law 1 â€” Law of Origin, Law 4 â€” Law of Evidence, Law 6 â€” Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Mission Lifecycle defines the constitutional state machine governing every Mission in AIOS based on the canonical 10-state model from Physics/006-Lifecycles.md. A Mission exists in exactly one state at all times. State transitions require authorization, produce Events, and affect the Mission's capabilities, resource access, and operational status.

This document extends Physics/002-Missions.md (Mission Invariants) and Foundations/008-Object-Lifecycle.md (Canonical Lifecycle). Missions are the constitutional container for purposeful work â€” they transform Human Intent into coordinated, observable, verifiable execution.

## Mission Lifecycle States

```
Created â†’ Planned â†’ Assigned â†’ Running â†’ Waiting â†’ Paused â†’ Blocked â†’ Review â†’ Completed â†’ Archived
```

| State | Description | Can Act? | Modifiable? | Terminal? |
|-------|-------------|----------|-------------|-----------|
| **Created** | Mission record exists, identity assigned by IDS. No planning has occurred. | No | Limited (metadata only) | No |
| **Planned** | Sou has decomposed Intent into objectives, milestones, resource requirements, and success criteria. | No | Yes (plan details, milestones) | No |
| **Assigned** | Mission is assigned to an owning Organization. Resources are allocated. Workers may be prepared. | No | Yes (assignments, resource budget) | No |
| **Running** | Workers are actively executing Mission tasks. Evidence is being produced. | Yes | Yes (runtime configuration) | No |
| **Waiting** | Mission is waiting for an external dependency or sub-Mission completion. | No | No | No |
| **Paused** | Mission execution is temporarily suspended. Context is preserved. Resumable. | No | No | No |
| **Blocked** | Mission cannot proceed due to an unresolvable constraint or failure. | No | No | No |
| **Review** | Mission execution is complete. Results are being verified against success criteria. | Yes (limited â€” review actions only) | No | No |
| **Completed** | Mission objectives have been met. Final evidence is sealed. Workers are terminated. | No | No | No |
| **Archived** | Mission record is preserved for audit. Not operational. | No | No | Yes |

## Mission Structure

| Field | Type | Description |
|-------|------|-------------|
| mission_id | UUID | Globally unique, immutable identity assigned by IRS |
| goals | Goal[] | Constitutional objectives derived from Human Intent |
| milestones | Milestone[] | Ordered milestones with acceptance criteria |
| resource_requirements | ResourceMap | Budget of compute, tokens, storage, network |
| dependencies | Dependency[] | Prerequisite Missions or external conditions |
| owner_org | UUID | The Organization constitutionally responsible for this Mission |
| parent_mission | UUID (optional) | Parent Mission if this is a sub-Mission |
| success_criteria | Criterion[] | Measurable conditions for completion |
| evidence_chain | EvidenceRef[] | Immutable record of all actions and Events |

## Transition Authorization Matrix

| Transition | Authorized By | Requires Evidence? | Notes |
|-----------|--------------|-------------------|-------|
| Created â†’ Planned | Sou | Yes (Intent evidence, goal specification) | Sou decomposes Intent into plan |
| Planned â†’ Assigned | DGP + Security Council | Yes (approved plan, resource availability) | Council verifies plan compliance |
| Assigned â†’ Running | LMS (automatic when ready) | Yes (assignment confirmation) | Resources must be allocated |
| Running â†’ Waiting | Entity itself (Mission coordinator) | Yes (dependency identified) | External dependency required |
| Running â†’ Paused | Supervisor (Organization) or Security Council | Yes (pause reason) | Temporary suspension |
| Running â†’ Blocked | Entity itself (failure detection) | Yes (error details, failure evidence) | Unresolvable constraint |
| Running â†’ Review | Entity itself or policy trigger | Yes (check-in reason, completion claim) | Mandatory before Completed |
| Waiting â†’ Running | LMS (automatic on dependency resolution) | Yes (dependency completion evidence) | Dependency resolved |
| Paused â†’ Running | Supervisor (Organization) | Yes (resume decision) | Supervisor authorizes continuation |
| Blocked â†’ Running | Resolution by entity/supervisor | Yes (resolution evidence) | Blocker resolved |
| Blocked â†’ Review | Entity or supervisor | Yes (block details, escalation) | Requires human assessment |
| Review â†’ Running | Reviewer | Yes (review decision â€” rework required) | Approved to continue with changes |
| Review â†’ Completed | Reviewer (human operator or policy-defined) | Yes (approval, success verification) | All success criteria met |
| Completed â†’ Archived | LMS (automatic, timer-based) | Yes (retention policy compliance) | Automatic after retention period |

## State Authorization Detail

### Created
- **Description**: Mission identity is assigned by IDS. Record exists in Mission Registry. No planning has occurred.
- **Who authorizes creation**: Sou (via Planner â†’ DGP) or an authorized entity with mission.create capability
- **Evidence required**: Human Intent provenance chain (Law 1 compliance)
- **Capability access**: None
- **Resource budget**: None allocated

### Planned
- **Description**: Sou has decomposed the Intent into a structured plan with goals, milestones, resources, dependencies, timeline, and risk assessment.
- **Who authorizes transition**: Sou (planner)
- **Evidence required**: Goal specification, constitutional compliance check, resource feasibility
- **Capability access**: Read-only metadata
- **Resource budget**: None

### Assigned
- **Description**: Mission is assigned to an owning Organization. ROS allocates resources. Workers may be prepared.
- **Who authorizes transition**: DGP + Security Council (after plan approval)
- **Evidence required**: Approved plan, Organization assignment, resource allocation confirmation
- **Capability access**: Read-only, resource discovery
- **Resource budget**: Allocated but not drawable

### Running
- **Description**: Workers are actively executing tasks. Evidence is being produced. Mission coordinator monitors progress.
- **Who authorizes transition**: LMS (automatic when all preconditions met)
- **Evidence required**: Resource activation, Worker readiness confirmation
- **Capability access**: Full capability scope per Mission plan
- **Resource budget**: Active and drawable

### Waiting
- **Description**: Mission is paused awaiting external dependency resolution (human input, sub-Mission completion, external service).
- **Who authorizes transition**: Mission coordinator (entity self) when dependency identified
- **Evidence required**: Dependency identified and documented
- **Capability access**: Read-only, status queries
- **Resource budget**: Frozen

### Paused
- **Description**: Mission execution is temporarily suspended by supervisor. Context preserved.
- **Who authorizes transition**: Supervisor Organization or Security Council
- **Evidence required**: Pause reason, supervisor authorization
- **Capability access**: Read-only, status queries
- **Resource budget**: Frozen

### Blocked
- **Description**: Mission cannot proceed due to unresolvable constraint or failure. Escalation required.
- **Who authorizes transition**: Entity itself (on failure detection)
- **Evidence required**: Error details, failure evidence, attempted resolutions
- **Capability access**: Read-only, error reporting
- **Resource budget**: Frozen

### Review
- **Description**: Execution is complete. Results verified against success criteria. Reviewer evaluates outcome.
- **Who authorizes transition**: Mission coordinator or policy trigger (automatic on completion claim)
- **Evidence required**: Completion claim, evidence package
- **Capability access**: Read-only, review actions
- **Resource budget**: Active (limited â€” review operations only)

### Completed
- **Description**: All success criteria met. Final evidence sealed. Workers terminated or returned to pool.
- **Who authorizes transition**: Reviewer (human or automated)
- **Evidence required**: Approval decision, success verification, evidence completeness check
- **Capability access**: Read-only (evidence access)
- **Resource budget**: Returned to Organization pool

### Archived
- **Description**: Mission record preserved for constitutional audit. No further operations possible.
- **Who authorizes transition**: LMS (automatic, timer-based)
- **Evidence required**: Retention period compliance, audit readiness
- **Capability access**: None
- **Resource budget**: Evidenced budget recorded

## Lifecycle Events

Every transition produces an Event:

| Event Type | Fields | Consumed By |
|-----------|-------|-------------|
| `Mission.StateChanged` | mission_id, from_state, to_state, authorized_by, timestamp, evidence_ref | Audit, Security Council, Sou, parent Organization |
| `Mission.Created` | mission_id, source_intent, created_by, parent_mission | LMS, IDS, Audit |
| `Mission.Planned` | mission_id, plan_hash, milestone_count, resource_budget | Sou, DGP, Security Council |
| `Mission.Assigned` | mission_id, org_id, worker_count, budget_id | OSYS, ROS, LMS |
| `Mission.Activated` | mission_id, activated_at, runtime_config | LMS, Workers, Sou |
| `Mission.DependencyResolved` | mission_id, dependency_id, resolution_evidence | LMS |
| `Mission.Paused` | mission_id, reason, paused_by, expected_duration | Sou, Security Council |
| `Mission.Blocked` | mission_id, blocker_type, error_code, attempted_resolutions | Sou, Security Council |
| `Mission.ReviewInitiated` | mission_id, reviewer_id, sla_deadline | Reviewer, Security Council |
| `Mission.Completed` | mission_id, goal_achievement_score, evidence_hash | Sou, Academy, OSYS |
| `Mission.Archived` | mission_id, retention_period, archived_at | Audit, Event Store |
| `Mission.TransitionDenied` | mission_id, from_state, attempted_to, reason, denied_by | Security Council, parent Organization |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| MSN_LIF_001 | Transition not allowed â€” invalid from/to state combination |
| MSN_LIF_002 | Transition authorization denied by Security Council |
| MSN_LIF_003 | Cannot assign Mission â€” no Organization available |
| MSN_LIF_004 | Cannot complete Mission â€” success criteria not met |
| MSN_LIF_005 | Cannot archive Mission â€” retention period not satisfied |
| MSN_LIF_006 | Mission not found â€” cannot transition |
| MSN_LIF_007 | Mission stuck in Blocked state â€” escalation timeout exceeded |
| MSN_LIF_008 | Evidence package incomplete â€” cannot transition to Review |

## Cross-Cutting Concerns

### Security

Every lifecycle transition requires authorization from the designated authority. Transitions without authorization are constitutional violations and trigger S2 escalation. The Security Council monitors all state transitions. Council oversight is required for transitions from Running to Paused/Blocked and from Blocked to Review. (Physics/008-Security.md)

### Evidence

Every lifecycle transition produces an Event. The complete Mission lifecycle â€” from Created through Archived â€” is an immutable chain in the Event Store. Evidence chains trace from Human Intent through every state transition. (PHI-008, CPR-004)

### Lifecycle

This document defines the Mission lifecycle as an instance of the canonical 10-state model (Physics/006-Lifecycles.md, Foundations/008-Object-Lifecycle.md). All lifecycle invariants apply: ordered states, authorized transitions, state-dependent capabilities, hierarchical constraint by Organization lifecycle. (PHI-006)

### Capability Bounds

Mission capabilities are lifecycle-state-dependent. A Mission in Running state has full capability scope. A Mission in Paused or Blocked state has no execution capabilities. Completion requires passing through Review state â€” capabilities in Review are limited to review actions. (Physics/007-Capabilities.md)

### Communication

All transition notifications are broadcast via ACF. Affected entities (owning Organization, Workers, Sou, Security Council) are notified of each state change. Inter-Mission dependency resolution is communicated through ACF. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Mission lifecycle is focused solely on Mission state machine |
| R3 (DRY) | Lifecycle model is a single instance of canonical 10-state model |
| R9 (Deterministic) | Same transition request with same authorization always produces same result |
| R10 (Simpler Over Complex) | Linear lifecycle with clearly defined transitions â€” no branching complexity |
| R12 (Embrace Errors) | All errors have unique codes (MSN_LIF_001â€“008) |
| R13 (Design for Failure) | Failed transition leaves Mission in current state â€” no partial transitions |
| R14 (Paved Path) | Single paved path: Created â†’ Planned â†’ Assigned â†’ Running â†’ Review â†’ Completed â†’ Archived |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/002-Missions.md | Mission Physics â€” canonical Mission definitions and invariants |
| Physics/005-Events.md | Evidence â€” every transition produces an Event |
| Physics/006-Lifecycles.md | Lifecycles â€” canonical 10-state lifecycle model |
| Physics/007-Capabilities.md | Capabilities â€” state-dependent Mission capabilities |
| Physics/008-Security.md | Security â€” transition authorization and Council oversight |
| Bible/00-Foundations/008-Object-Lifecycle.md | Object Lifecycle â€” canonical state model with Reviewer role |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
| Bible/01-Governance/000-Overview.md | GOV-001â€“005 â€” governance identifiers |
| Bible/02-Core/Sou/003-Missions.md | Sou's Missions component â€” Sou's view of Mission lifecycle |
| Bible/02-Core/Sou/002-Planner.md | Planner â€” Sou produces Mission plans |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle â€” hierarchical constraint on Missions |
| Bible/02-Core/ROS/005-Budget.md | Budget â€” Mission resource budgets |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations â€” Organizations own and execute Missions |
| Bible/03-Institutions/Workers/000-Overview.md | Workers â€” Workers execute Mission tasks |
| Bible/04-Execution/Security/IDS | IDS â€” Mission identity creation
