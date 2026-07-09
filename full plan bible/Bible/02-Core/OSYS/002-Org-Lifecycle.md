# AIOS Bible — Core
## OSYS 002 — Organization Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-OSYS-002 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 8 — Law of Verification-First |
| Source Physics | Physics/003-Organizations.md, Physics/005-Events.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Organization Lifecycle defines the constitutional state machine governing every Organization in AIOS. An Organization exists in exactly one state at all times. State transitions require authorization, produce Events, and affect the Organization's capabilities, resource access, and constitutional status.

## Lifecycle States

```
Created → Verified → Active → Suspended → Restored → Dissolved → Archived
                ↘                           ↗
           (automatic if verification    (Security Council
            fails → back to Draft)        authorization)
```

## State Definitions

### Created

| Property | Value |
|----------|-------|
| Description | Organization record exists in Registry. Identity assigned by IDS. Not yet operational. |
| Can Act? | No |
| Can Be Modified? | Limited (metadata only) |
| Terminal? | No |
| Resource Budget | None allocated |
| Capability Access | None |

### Verified

| Property | Value |
|----------|-------|
| Description | Organization structure, governance, and constitutional compliance have been verified. Ready for activation. |
| Can Act? | No |
| Can Be Modified? | Yes (structure, policies, membership) |
| Terminal? | No |
| Resource Budget | Allocated but not drawable |
| Capability Access | Read-only (self-structure query) |

### Active

| Property | Value |
|----------|-------|
| Description | Organization is fully operational. May own missions, employ Workers, manage resources, and communicate with other Organizations. |
| Can Act? | Yes |
| Can Be Modified? | Yes (within constitutional bounds) |
| Terminal? | No |
| Resource Budget | Fully drawable |
| Capability Access | Full capability scope per Genome |

### Suspended

| Property | Value |
|----------|-------|
| Description | Organization operations are suspended due to constitutional violation or Security Council order. |
| Can Act? | No |
| Can Be Modified? | No |
| Terminal? | No |
| Resource Budget | Frozen |
| Capability Access | None (except read-only compliance reporting) |

### Restored

| Property | Value |
|----------|-------|
| Description | Organization is restored from Suspended state. Returns to Active after verification. |
| Can Act? | No (until transition to Active) |
| Can Be Modified? | Yes (remediation actions) |
| Terminal? | No |
| Resource Budget | Frozen (until Active) |
| Capability Access | Read-only |

### Dissolved

| Property | Value |
|----------|-------|
| Description | Organization is permanently dissolved. All missions are terminated or transferred. All resources are returned to ROS. All Workers are reassigned or released. |
| Can Act? | No |
| Can Be Modified? | No |
| Terminal? | No (retained for audit) |
| Resource Budget | Returned to pool |
| Capability Access | None |

### Archived

| Property | Value |
|----------|-------|
| Description | Organization record is preserved for constitutional audit. Not operational. |
| Can Act? | No |
| Can Be Modified? | No |
| Terminal? | Yes |
| Resource Budget | Evidenced budget recorded |
| Capability Access | None |

## Transition Authorization

| Transition | Authorized By | Requires Evidence? | Notes |
|-----------|--------------|-------------------|-------|
| Created → Verified | Security Council | Yes (verification report) | |
| Verified → Active | Automatic | No | Automatic after verification |
| Active → Suspended | Security Council | Yes (violation evidence) | Organization may appeal |
| Suspended → Restored | Security Council | Yes (remediation evidence) | Must resolve violation cause |
| Active → Dissolved | Security Council + Sou Approval | Yes (dissolution rationale) | Sou must confirm strategic impact |
| Suspended → Dissolved | Security Council + Sou Approval | Yes (dissolution rationale) | Direct from Suspended if irresolvable |
| Dissolved → Archived | Automatic | Yes (retention period) | Automatic after retention period |

## Transition Authorization Matrix

```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   From \ To     │    Verified      │     Active      │    Suspended    │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│    Created      │ Security Council │       —         │       —         │
│    Verified     │       —         │ Automatic       │       —         │
│     Active      │       —         │       —         │ Security Council│
│    Suspended    │       —         │ Security Council│       —         │
│     (Restored)  │                 │                 │                 │
│     Active      │       —         │       —         │       —         │
│     → Dissolved │                 │                 │                 │
│                 │   → Dissolved   │   → Archived    │                 │
│                 │ Sec Council+SOU │ Automatic       │                 │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

## Resource and Budget Effects

Each transition affects the Organization's resource budget:

| Transition | Budget Effect | ROS Integration |
|-----------|---------------|-----------------|
| Created → Verified | Budget allocated but frozen | ROS allocates budget line |
| Verified → Active | Budget unfrozen, drawable | ROS activates budget |
| Active → Suspended | Budget frozen | ROS freezes draw |
| Suspended → Restored | Budget unfrozen | ROS reactivates budget |
| Active → Dissolved | Budget returned to pool | ROS reclaims all resources |
| Suspended → Dissolved | Budget returned to pool | ROS reclaims all resources |
| Dissolved → Archived | Final budget recorded | ROS archives budget record |

## Lifecycle Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `OSYS.OrgCreated` | Organization is created | org_id, name, type, parent_id, creator |
| `OSYS.OrgVerified` | Organization passes verification | org_id, verified_by, verification_hash |
| `OSYS.OrgActivated` | Organization becomes Active | org_id, activated_at, budget_id |
| `OSYS.OrgSuspended` | Organization is suspended | org_id, reason, suspended_by, evidence_ref |
| `OSYS.OrgRestored` | Organization is restored | org_id, restored_by, remediation_evidence |
| `OSYS.OrgDissolved` | Organization is dissolved | org_id, dissolution_reason, approved_by |
| `OSYS.OrgArchived` | Organization is archived | org_id, archived_at, retention_period |
| `OSYS.TransitionDenied` | A transition is denied | org_id, from_state, target_state, reason, denied_by |
| `OSYS.OrgSuspensionWarning` | Organization receives suspension warning | org_id, warning_type, compliance_deadline |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| OSYS_LIF_001 | Transition not allowed — invalid from → to state |
| OSYS_LIF_002 | Transition authorization denied by Security Council |
| OSYS_LIF_003 | Cannot dissolve Organization with active missions |
| OSYS_LIF_004 | Cannot archive Organization before retention period expires |
| OSYS_LIF_005 | Organization not found — cannot transition |
| OSYS_LIF_006 | Sou approval required for dissolution — not provided |
| OSYS_LIF_007 | Resource budget reclamation failed during dissolution |

## Cross-Cutting Concerns

### Security

All lifecycle transitions are authorized by the Security Council. Transitions without authorization are constitutionally invalid and produce security Events. (Physics/008-Security.md)

### Evidence

Every transition produces an Event. The complete lifecycle of every Organization is an immutable chain in the Event Store. Lifecycle audits are supported by full Event history. (PHI-008)

### Lifecycle

This document defines the Organization lifecycle — an instance of the canonical lifecycle model (Physics/006-Lifecycles.md). All lifecycle invariants from Physics apply. (PHI-006)

### Capability Bounds

An Organization's capabilities are lifecycle-state-dependent. An Organization in Suspended state has no capabilities. An Organization in Active state has full capabilities per its Genome. (Physics/007-Capabilities.md)

### Communication

Lifecycle transition notifications are broadcast via ACF. Affected entities (sub-Organizations, Workers, mission owners) are notified of transitions that affect them. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Lifecycle is focused solely on Organization state machine |
| R9 (Deterministic) | Same transition request with same authorization always produces same result |
| R10 (Simpler Over Complex) | Linear lifecycle with clearly defined transitions — no branching complexity |
| R12 (Embrace Errors) | All errors have unique codes (OSYS_LIF_001–007) |
| R13 (Design for Failure) | Failed transition leaves Organization in current state — no partial transitions |
| R14 (Paved Path) | Single paved path: Created → Verified → Active → (Suspended ↔ Restored) → Dissolved → Archived |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/003-Organizations.md | Organizations Physics — canonical Organization lifecycle |
| Physics/005-Events.md | Evidence — every transition produces an Event |
| Physics/006-Lifecycles.md | Lifecycles — canonical lifecycle model |
| Bible/02-Core/OSYS/000-Overview.md | OSYS overview — lifecycle context |
| Bible/02-Core/OSYS/001-Architecture.md | OSYS architecture — Lifecycle Manager component |
| Bible/04-Execution/Security/IDS/003-Lifecycle.md | Identity lifecycle — parallel to Organization lifecycle |
| Bible/02-Core/ROS | ROS — resource budget lifecycle tied to Organization state |
| Bible/03-Institutions/Organizations/000-Overview.md | Organization types — lifecycle variations per type |
| Bible/01-Governance/002-DGP.md | DGP — dissolution requires Sou approval through DGP |
| Bible/00-Foundations/008-Object-Lifecycle.md | Object Lifecycle — canonical state model |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
