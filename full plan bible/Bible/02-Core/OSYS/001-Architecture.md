# AIOS Bible — Core
## OSYS 001 — Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-OSYS-001 |
| Source Laws | Law 5 — Law of Capability Bounds, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/003-Organizations.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This document describes the internal architecture of the Organization System, including component details, data flow, clustering topology, and system integrations. OSYS is the administrative backbone of AIOS — its architecture emphasizes availability for organization queries and consistency for lifecycle transitions.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     OSYS Application Layer                     │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │ Organization Factory│    │  Lifecycle Manager  │            │
│  │                    │    │                     │            │
│  │  - create()        │    │  - transition()     │            │
│  │  - validate()      │    │  - authorize()      │            │
│  │  - initialize()    │    │  - notify()         │            │
│  └────────┬───────────┘    └────────┬────────────┘            │
│           │                        │                          │
│           ▼                        ▼                          │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │      Registry      │    │ Department Manager  │            │
│  │                    │    │                     │            │
│  │  - register()      │    │  - createDept()     │            │
│  │  - query()         │    │  - assignToDept()   │            │
│  │  - search()        │    │  - restructure()    │            │
│  └────────┬───────────┘    └────────┬────────────┘            │
│           │                        │                          │
│           ▼                        ▼                          │
│  ┌──────────────────────────────────────────────┐            │
│  │           Governance Enforcer                  │            │
│  │                                                │            │
│  │  - checkCompliance()                           │            │
│  │  - enforcePolicy()                             │            │
│  │  - reportViolation()                           │            │
│  └──────────────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                     OSYS Data Layer                            │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │  Organization Store│    │ Department Store    │            │
│  │  (primary +       │    │  (primary +        │            │
│  │   read replicas)  │    │   read replicas)   │            │
│  └────────────────────┘    └────────────────────┘            │
│                                                               │
│  ┌────────────────────┐    ┌────────────────────┐            │
│  │  Membership Store  │    │  Event Writer      │            │
│  │  (per-Organization)│    │  (to Event Store)  │            │
│  └────────────────────┘    └────────────────────┘            │
└──────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Organization Factory

| Function | Description |
|----------|-------------|
| create(request) | Validates creation request, coordinates with IDS for identity, registers new Organization |
| validate(request) | Validates request against constitutional requirements (type, parent, resources) |
| initialize(org) | Sets up initial state, resource budget, department structure, and policies |

The Factory is invoked when an Organization creation request is approved by the Security Council. It orchestrates the multi-step creation process across IDS, ROS, LMS, and ACF.

### Registry

| Function | Description |
|----------|-------------|
| register(org) | Stores the Organization record in the Organization Store |
| query(org_id) | Returns Organization record by ID |
| search(criteria) | Searches Organizations by name, type, parent, status |
| getHierarchy(org_id) | Returns the Organization tree (parent + children) |

### Lifecycle Manager

See OSYS/002-Org-Lifecycle.md for full details. Summary:

| Function | Description |
|----------|-------------|
| transition(org_id, target_state) | Validates and executes lifecycle transition |
| authorize(org_id, transition) | Requests Security Council authorization |
| notify(org_id, transition) | Notifies affected entities of state change |

### Department Manager

| Function | Description |
|----------|-------------|
| createDept(org_id, dept_spec) | Creates a sub-Organization within an Organization |
| assignToDept(entity_id, dept_id) | Assigns an entity to a department |
| restructure(org_id, new_structure) | Reorganizes department hierarchy |

Departments are lightweight sub-Organizations. They share the parent Organization's identity and resource budget but have their own capability assignments and membership.

### Governance Enforcer

| Function | Description |
|----------|-------------|
| checkCompliance(org_id) | Verifies Organization complies with constitutional and policy requirements |
| enforcePolicy(org_id, policy) | Applies a governance policy to the Organization |
| reportViolation(org_id, violation) | Records a compliance violation, triggers Security Council notification |

The Governance Enforcer runs continuously. It audits Organization operations against constitutional requirements and reports violations.

## Data Flow

```
1. Sou or authorized entity submits Organization creation request (via ACF)
2. OSYS Factory validates the request against constitutional constraints
3. OSYS Factory requests identity from IDS
4. OSYS Factory requests initial resource budget from ROS
5. OSYS Factory registers the Organization in the Registry
6. Lifecycle Manager transitions Organization to Verified state
7. Security Council authorizes Active state
8. Lifecycle Manager transitions to Active
9. Organization is operational — can own missions, employ Workers, manage resources
```

## OSYS Clustering

OSYS uses an active-passive topology (identical to DTS):

| Role | Description | Reads | Writes |
|------|-------------|-------|--------|
| Primary (active) | Handles all lifecycle transitions and writes | Yes | Yes |
| Replica 1 | Read-only Organization queries | Yes | No |
| Replica 2 | Read-only Organization queries | Yes | No |

### Failover

If the primary fails, a replica is promoted. During failover, Organization queries are served from remaining replicas. Lifecycle transitions are queued until primary is restored or failover completes.

## OSYS Integrations

| System | Integration | Protocol |
|--------|-------------|----------|
| IDS | Organization identity creation and management | ACF command/response |
| ROS | Resource budget allocation and tracking | ACF command/response |
| LMS | Lifecycle state management | ACF command/response |
| ACF | Inter-Organization communication routing | ACF message routing |
| Security Council | Lifecycle transition authorization | ACF event stream |
| Sou | Strategic direction and Organization proposals | ACF event stream |

## OSYS Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `OSYS.OrgCreated` | Organization Factory creates an Organization | org_id, name, type, parent_id |
| `OSYS.OrgValidated` | Creation request passes validation | request_id, validation_result |
| `OSYS.OrgRegistered` | Organization is registered in Registry | org_id, registry_entry |
| `OSYS.DepartmentRestructured` | Department hierarchy is reorganized | org_id, old_structure, new_structure |
| `OSYS.ComplianceViolationReported` | Governance Enforcer detects violation | org_id, violation_type, details |
| `OSYS.ClusterRoleChanged` | OSYS cluster undergoes failover | node_id, old_role, new_role |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| OSYS_ARC_001 | Organization creation request missing required fields |
| OSYS_ARC_002 | Organization type not recognized |
| OSYS_ARC_003 | Parent Organization not found or not Active |
| OSYS_ARC_004 | Resource budget request denied by ROS |
| OSYS_ARC_005 | Identity creation failed at IDS |
| OSYS_ARC_006 | Governance Enforcer reports pre-existing compliance issue |

## Cross-Cutting Concerns

### Security

Organization creation is a constitutional event. All lifecycle transitions require Security Council authorization. Organization records are protected from unauthorized access. (Physics/008-Security.md)

### Evidence

Every OSYS operation produces an Event. The complete history of every Organization — from creation to dissolution — is recorded in the Event Store. (PHI-008)

### Lifecycle

The Lifecycle Manager is the central component of OSYS. Every Organization lifecycle transition is authorized, validated, and recorded. (Physics/006-Lifecycles.md)

### Capability Bounds

Organizations are bounded by their Genome (AGS). An Organization may not exceed its constitutional capability scope. The Governance Enforcer audits capability use. (Physics/007-Capabilities.md)

### Communication

All OSYS components communicate via ACF. Inter-Organization messages are routed through ACF with parent Organization visibility. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each OSYS component has a single responsibility |
| R4 (Builder) | Factory separates construction from lifecycle management |
| R5 (Liskov) | All Organization types implement the Organization interface |
| R10 (Simpler Over Complex) | Tree hierarchy — no complex Organization graphs |
| R12 (Embrace Errors) | All errors have unique codes (OSYS_ARC_001–006) |
| R13 (Design for Failure) | Read replicas serve queries during primary failover |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/003-Organizations.md | Organizations Physics — canonical Organization definitions |
| Physics/006-Lifecycles.md | Lifecycles — Organizations follow canonical lifecycle |
| Physics/007-Capabilities.md | Capabilities — Organizations are capability containers |
| Bible/02-Core/OSYS/000-Overview.md | OSYS overview — architecture context |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — state machine |
| Bible/04-Execution/Security/IDS | IDS — Organization identity |
| Bible/02-Core/ROS | ROS — Organization resource budgets |
| Bible/03-Institutions/Organizations | Organization types — specifications |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
