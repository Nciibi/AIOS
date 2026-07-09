# AIOS Bible — Core
## OSYS 000 — Overview (Organization System)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-OSYS-000 |
| Source Laws | Law 1 — Law of Origin, Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/003-Organizations.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Organization System (OSYS) manages Organization entities — their creation, lifecycle, structure, and dissolution. An Organization is the constitutional unit of collective action in AIOS. Organizations own missions, employ engines, manage resources, and govern their members.

OSYS is the administrative backbone of AIOS. Every Worker, every Mission, and every resource belongs to an Organization. Without OSYS, there is no structure — only disconnected entities.

## What Is an Organization?

An Organization is a constitutional entity that:
- Owns and manages Missions (work units)
- Employs Workers (executing entities)
- Manages resource budgets (via ROS)
- Governs member entities through policies and oversight
- Has a defined lifecycle (OSYS/002-Org-Lifecycle.md)
- Has a unique identity (assigned by IDS)
- Has a Genome that defines its capabilities (via AGS)

Organizations form a hierarchy — each Organization (except root) has a parent Organization. Sub-Organizations (departments) inherit the parent's constitutional authority but may have independent policies.

## What OSYS Does

| Function | Description | Document |
|----------|-------------|----------|
| Create Organizations | Validate requests, assign identities, register | OSYS/001-Architecture.md |
| Manage Lifecycle | Transition Organizations through constitutional states | OSYS/002-Org-Lifecycle.md |
| Manage Departments | Create, restructure, and dissolve sub-Organizations | OSYS/001-Architecture.md |
| Enforce Governance | Audit compliance, report violations | OSYS/001-Architecture.md |
| Maintain Registry | Store and query Organization records | OSYS/001-Architecture.md |

## What OSYS Does Not Do

OSYS does NOT:
- Run missions (Workers execute missions under Organization ownership)
- Allocate resources (ROS manages resource allocation)
- Make strategic decisions (Sou proposes strategy)
- Authenticate entities (ATS handles authentication)
- Learn from outcomes (Sou Learning and Academy learn)

## Organization Types

| Type | Description | Genome Source |
|------|-------------|---------------|
| ORG | Root Organization | AGS: Organization/ORG |
| ODS | Department/Squad | AGS: Organization/ODS |
| OHS | Hub/Shared Service | AGS: Organization/OHS |
| OOM | Operational Oversight | AGS: Organization/OOM |
| OPE | Project/Program Entity | AGS: Organization/OPE |
| EEE | Engine Execution Environment | AGS: Organization/EEE |
| OIS | Isolation/Sandbox | AGS: Organization/OIS |
| DOM | Domain Organization | AGS: Organization/DOM |

## Organization Hierarchy Rules

| Rule | Description |
|------|-------------|
| Single Parent | Every Organization has exactly one parent (except root) |
| Tree Structure | Organization hierarchy is a tree — no cycles |
| Depth Limit | Maximum 7 levels from root to deepest leaf |
| Parent Scope | Parent defines policy bounds for children |
| Resource Flow | Resources flow from parent to child |

## OSYS Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Organization System                       │
│                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────┐ │
│  │  Organization  │  │   Lifecycle    │  │  Department │ │
│  │   Factory      │  │   Manager      │  │  Manager   │ │
│  │                │  │                │  │            │ │
│  └───────┬────────┘  └───────┬────────┘  └─────┬──────┘ │
│          │                   │                  │        │
│          ▼                   ▼                  ▼        │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │    Registry    │  │  Governance    │                 │
│  │                │  │  Enforcer      │                 │
│  └───────┬────────┘  └───────┬────────┘                 │
│          │                   │                           │
└──────────┼───────────────────┼───────────────────────────┘
           │                   │
           ▼                   ▼
  ┌────────────────┐  ┌────────────────┐
  │   IDS (ID)    │  │ ROS (resources)│
  │   LMS (life)  │  │ ACF (comm)     │
  │   Security    │  │                │
  │   Council     │  │                │
  └────────────────┘  └────────────────┘
```

## OSYS Components

| Component | Document | Function |
|-----------|----------|----------|
| Organization Factory | OSYS/001-Architecture.md | Creates Organizations from approved requests |
| Registry | OSYS/001-Architecture.md | Stores and queries Organization records |
| Lifecycle Manager | OSYS/002-Org-Lifecycle.md | Manages Organization state transitions |
| Department Manager | OSYS/001-Architecture.md | Manages sub-Organization structure |
| Governance Enforcer | OSYS/001-Architecture.md | Ensures Organizations comply with constitutional rules |

## OSYS Data Flow

```
Organization Request (from Sou, Security Council, or Administrator)
    │
    ▼
┌─────────────────────────────────────────┐
│  OSYS Organization Factory               │
│  ├── validate(request)                    │
│  ├── request_identity(IDS)               │
│  ├── request_budget(ROS)                 │
│  └── create_org_record()                 │
│         │                                │
│         ▼                                │
│  Created Organization (Registry)         │
│         │                                │
│         └──► OSYS Lifecycle Manager      │
└─────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  OSYS Lifecycle Manager (002)            │
│  ├── Created → Verified (Security Cncl)  │
│  ├── Verified → Active (Automatic)       │
│  ├── Active → Suspended (Security Cncl)  │
│  ├── Suspended → Restored (Sec Cncl)    │
│  ├── Active → Dissolved (Sec Cncl + Sou)│
│  └── Dissolved → Archived (Automatic)   │
│         │                                │
│         ▼                                │
│  Lifecycle Event → Event Store           │
└─────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  OSYS Governance Enforcer                │
│  ├── checkCompliance(org_id)             │
│  ├── enforcePolicy(policy)              │
│  └── reportViolation(violation)         │
│         │                                │
│         ▼                                │
│  Compliance Report / Violation Event     │
│         │                                │
│         └──► Security Council            │
└─────────────────────────────────────────┘
```

## OSYS Invariants

1. **Organization Is the Unit of Action**: Every mission, every Worker, every resource belongs to exactly one Organization. No orphan entities. (CPR-001)

2. **Hierarchy Without Bypass**: Sub-organizations communicate through their parent Organization. No direct communication between child Organizations without parent mediation. (Law 3 — Communication)

3. **Lifecycle Compliance**: Every Organization follows the canonical lifecycle: Created → Verified → Active → Suspended → Restored → Dissolved → Archived. (PHI-006, CPR-006)

4. **Resource Accountability**: Organizations manage resources through ROS. Resource allocations are tracked per Organization. No resource is unowned. (Law 7 — Capability Bounds)

5. **Constitutional Governance**: Every Organization operates within constitutional bounds. Governance Enforcer ensures compliance. Organizations that violate the Constitution are suspended or dissolved. (CPR-009)

## OSYS Integrations

| System | Integration | Purpose |
|--------|-------------|---------|
| IDS (Identity) | Creates Organization identities at creation | Every Organization has a constitutional identity |
| ROS (Resources) | Manages Organization resource budgets | Resource allocation per Organization |
| LMS (Lifecycle) | Manages Organization state transitions | Lifecycle compliance |
| ACF (Communication) | All Organization communication | Inter-Organization messaging |
| Security Council | Authorizes lifecycle transitions | Security verification |
| Sou (Strategic) | Receives strategic direction | Sou proposes, OSYS implements |

## OSYS Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `OSYS.OrgCreated` | Organization is created | org_id, name, org_type, parent_id, creator |
| `OSYS.OrgVerified` | Organization passes verification | org_id, verified_by |
| `OSYS.OrgActivated` | Organization becomes Active | org_id, activated_at |
| `OSYS.OrgSuspended` | Organization is suspended | org_id, reason, suspended_by |
| `OSYS.OrgRestored` | Organization is restored | org_id, restored_by |
| `OSYS.OrgDissolved` | Organization is dissolved | org_id, reason, dissolved_by |
| `OSYS.OrgArchived` | Organization is archived | org_id, retention_period |
| `OSYS.DepartmentCreated` | Sub-organization is created | org_id, department_id, department_type |

## Cross-Cutting Concerns

### Security

Organization creation requires Security Council authorization. Lifecycle transitions require authorization. Organization records are access-controlled. (Physics/008-Security.md)

### Evidence

Every Organization operation produces an Event. The complete lifecycle of every Organization is recorded in the Event Store. Organization audits are supported by immutable Events. (PHI-008)

### Lifecycle

Organizations follow the defined lifecycle (OSYS/002-Org-Lifecycle.md). Lifecycle management is OSYS's primary function. (Physics/006-Lifecycles.md)

### Capability Bounds

Organizations have defined capability scopes. An Organization may not exceed its constitutional bounds. Capabilities are tied to the Organization, not to individual members. (Physics/007-Capabilities.md)

### Communication

All Organization communication flows through ACF. Inter-Organization communication requires parent Organization routing. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | OSYS focused solely on Organization management |
| R4 (Builder) | Organization Factory is separate from lifecycle management |
| R5 (Liskov) | All Organization types implement the Organization interface |
| R10 (Simpler Over Complex) | Organization hierarchy is a tree — no complex graph structures |
| R12 (Embrace Errors) | All errors have unique codes |
| R13 (Design for Failure) | Organization Registry is read-replicated — queries available during partial failure |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/003-Organizations.md | Organizations Physics — canonical Organization definitions |
| Physics/005-Events.md | Evidence — OSYS produces Events |
| Physics/006-Lifecycles.md | Lifecycle — Organizations have defined lifecycles |
| Physics/007-Capabilities.md | Capabilities — Organizations have capability bounds |
| Bible/02-Core/OSYS/001-Architecture.md | OSYS architecture — component details |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — state definitions and transitions |
| Bible/04-Execution/Security/IDS | IDS — Organization identity management |
| Bible/02-Core/ROS | ROS — Organization resource management |
| Bible/03-Institutions/Organizations | Organization types — detailed Organization specifications |
| Bible/02-Core/Sou | Sou — Organization strategic direction |
| Bible/01-Governance/002-DGP.md | DGP — Organization-related decisions |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
