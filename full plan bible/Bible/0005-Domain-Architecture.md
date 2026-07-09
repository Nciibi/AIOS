# AIOS Bible
## 0005 — Domain Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Root |
| Document ID | AIOS-BBL-0005 |
| Source Laws | All Laws — Domain architecture implements all constitutional requirements |
| Source Physics | Physics/000-Laws.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Domain Architecture defines the domain model of AIOS — the entity hierarchy, the relationships between entities, the capability matrix that maps capabilities to entity types, and the entity lifecycle framework. This document provides the conceptual foundation for all entity-related specifications in the Bible.

## Entity Hierarchy

### Entity Types

AIOS defines the following constitutional entity types, organized by hierarchy level:

```
Level 0 — Constitutional Institutions
├── Sou                       — Strategic authority
├── Security Council           — Judicial/verification authority
├── Academy                   — Learning/knowledge authority

Level 1 — Organizational Entities
├── Organization              — Persistent operational unit
│   ├── Department            — Sub-unit within an Organization
│   └── Team                  — Operational unit within a Department

Level 2 — Execution Entities
├── Worker                    — Temporary execution agent
├── Mission                   — Unit of work
├── Runtime                   — Execution environment

Level 3 — Infrastructure Entities
├── Provider                  — External resource provider
├── Plugin                    — Extension module
├── Session                   — Communication channel
├── Resource                  — Computational resource (compute, storage, network)

Level 4 — Governance Entities
├── RFC                       — Change request
├── ADG                       — Architectural decision
├── Law                       — Constitutional law
├── Policy                    — Security/operational policy
```

### Entity Identity Structure

Every entity has a structured identity:

```
EntityIdentity {
    entity_id: UUID          // Globally unique, immutable
    entity_type: String      // Type enum (Sou, Worker, Organization, etc.)
    display_name: String     // Human-readable name
    parent_id: Option<UUID> // Parent entity (e.g., Organization for Workers)
    instance_id: UUID       // Home AIOS instance
    created_at: Timestamp   // Creation time
    public_key: PublicKey   // Identity public key
}
```

### Entity Relations

```
Sou
├── proposes Missions
├── directs Organizations
└── consults Academy

Security Council
├── verifies all actions
├── approves RFCs
├── certifies capabilities
└── adjudicates disputes

Academy
├── learns from Events
├── manages Knowledge Graph
├── validates knowledge
└── provides insights to Sou

Organization
├── contains Departments
├── manages Workers
├── executes Missions
└── consumes resources

Department
├── contains Teams
├── scopes Workers
└── manages domain capabilities

Worker
├── executes actions
├── consumes resources
├── produces evidence
└── operates within bounds

Mission
├── defines objectives
├── allocates resources
├── assigns Workers
└── produces outcomes

Runtime
├── hosts Workers
├── enforces sandbox
├── provides SDK
└── reports health
```

## Capability Matrix

The capability matrix defines which capabilities each entity type has at each autonomy level.

### Governance Capabilities

| Capability | Sou | SecCouncil | Academy | Org | Worker | Runtime |
|-----------|-----|------------|---------|-----|--------|---------|
| Propose Mission | L0+ | — | — | — | — | — |
| Approve RFC | — | L0+ | — | — | — | — |
| Create Policy | — | L0+ | — | — | — | — |
| Amend Constitution | L0+ | — | — | — | — | — |
| Adjudicate Dispute | — | L0+ | — | — | — | — |
| Certify Capability | — | L0+ | — | — | — | — |
| Manage Knowledge | — | — | L0+ | — | — | — |
| Validate Knowledge | — | — | L0+ | — | — | — |

### Operational Capabilities

| Capability | Organization | Worker | Runtime | Provider | Plugin |
|-----------|-------------|--------|---------|----------|--------|
| Create Worker | L0+ | — | — | — | — |
| Execute Action | — | L0+ | — | — | L0+ |
| Allocate Resource | L0+ | — | — | L0+ | — |
| Assign Mission | L0+ | — | — | — | — |
| Manage Session | — | — | L0+ | — | — |
| Communicate via ACF | L0+ | L0+ | L0+ | L0+ | L0+ |
| Produce Evidence | L0+ | L0+ | L0+ | L0+ | L0+ |

### Infrastructure Capabilities

| Capability | Provider | Plugin | Resource |
|-----------|----------|--------|----------|
| Register Capability | L0+ | L0+ | — |
| Declare Capacity | L0+ | L0+ | — |
| Report Health | L0+ | L0+ | L0+ |
| Scale Resources | L0+ | — | L0+ |
| Manage Lifecycle | L0+ | L0+ | L0+ |

## Entity Lifecycle Framework

### Core Lifecycle State Machine

All entities share a common core lifecycle, extended by entity-specific states:

```
                    ┌─────────────┐
                    │   Created   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
              ┌────►│   Active    │◄────┐
              │     └──────┬──────┘     │
              │            │            │
              │            ▼            │
              │     ┌─────────────┐     │
              │     │  Suspended  │─────┘
              │     └──────┬──────┘
              │            │
              │            ▼
              │     ┌─────────────┐
              └─────│   Retired   │
                    └─────────────┘
```

### Entity-Specific Lifecycle Extensions

**Worker Lifecycle**:
```
Created → Initialized → Running → Completed → Destroyed
                              │
                              ▼
                          Suspended → Resumed → Running
```

**Mission Lifecycle**:
```
Created → Planned → Assigned → Running → Completed → Archived
                                      │
                                      ▼
                                  Failed → Reviewed → Archived
```

**Organization Lifecycle**:
```
Proposed → Ratified → Active → Restructuring → Active
                              │
                              ▼
                          Dissolved → Archived
```

**Session Lifecycle**:
```
Created → Handshaking → Active → Terminated
                              │
                              ▼
                          Suspended → Resumed → Active
```

## Domain Boundaries

### Domain Definition

A domain is a functional area within AIOS. Each domain has:
- A defined scope and responsibility
- One or more entity types that operate within the domain
- Specific capabilities, skills, and knowledge
- Domain-specific policies and governance

### Current Domains

| Domain | Scope | Primary Entities |
|--------|-------|------------------|
| Governance | Constitutional processes | Sou, Security Council, CLS, DGP, CRP |
| Identity | Entity identity and registration | IRS |
| Security | Verification, enforcement, audit | Security Council, Security Kernel |
| Knowledge | Learning, knowledge management | Academy, KMS, KCE, KEE |
| Execution | Action execution, resource consumption | Workers, Runtimes |
| Communication | Inter-entity messaging | ACF |
| Organization | Organizational structure | Organizations, Departments |
| Mission | Work definition and tracking | Missions |
| Resource | Resource allocation and accounting | ROS, Providers |
| Federation | Cross-instance operations | IXP, CXP |

### Domain Ownership

Every entity operates within one or more domains. Domain ownership defines:
- Which policies apply to the entity
- Which capabilities the entity may acquire
- Which knowledge domains the entity may access
- Which governance processes the entity participates in

```
Entity ────belongs to──► Domain ────has──► Policies
  │                                             │
  │                                             ▼
  └───acquires──► Capabilities ◄───governs── Domain Governance
```

## Domain Interaction Model

Domains interact through well-defined interfaces:

```
Domain A                    Domain B
┌──────────┐               ┌──────────┐
│  Entity  │──ACF Message──►  Entity  │
│  Type X  │◄──ACF Message──│  Type Y  │
└──────────┘               └──────────┘
```

### Cross-Domain Interactions

| Source Domain | Target Domain | Interaction Type | Example |
|--------------|---------------|-----------------|---------|
| Governance | Security | Request-Response | Security Council requests identity verification |
| Identity | Security | Request-Response | Security Kernel requests identity validation |
| Security | Execution | Pipeline | Security Kernel issues execution authorization |
| Execution | Knowledge | Event-Driven | Worker execution Events flow to Academy |
| Knowledge | Governance | Event-Driven | Academy knowledge informs Sou strategy |
| Organization | Resource | Request-Response | Organization requests resource allocation |
| Mission | Organization | Event-Driven | Mission progress updates to parent Organization |
| Federation | Communication | Protocol | IXP messages flow through ACF |

## Capability Inheritance

Entities inherit capabilities from their parent entity, with scope restrictions:

```
Organization (capabilities: A, B, C)
    └── Department (capabilities: A, B) — inherits A, B from parent; C not delegated
        └── Team (capabilities: A) — inherits A from parent; B not delegated
            └── Worker (capabilities: A) — inherits A from parent; additional skills declared
```

### Inheritance Rules
1. An entity can only inherit capabilities that its parent possesses
2. The parent may restrict which capabilities are inherited
3. An entity may declare additional capabilities through CCA certification
4. Inherited capabilities cannot exceed the parent's capability scope
5. Capability revocation at parent level cascades to children

## Capability Verification Model

Every action is verified against the actor's capabilities:

```
Action Request ──► Identify Actor ──► Lookup Capabilities ──► Verify Action
                                                                    │
                                                            ┌───────┴───────┐
                                                            ▼               ▼
                                                        Approved         Denied
```

### Capability Verification Stages
1. **Identity Resolution**: Who is the actor? (IRS lookup)
2. **Capability Lookup**: What capabilities does the actor have? (Capability Registry)
3. **Action Verification**: Does the action fall within declared capabilities?
4. **Resource Verification**: Does the actor have sufficient resources?
5. **Policy Verification**: Does the action comply with domain policies?
6. **Authorization**: Grant or deny with evidence.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 0003-Platform-Architecture.md | Platform architecture — platform infrastructure supports domain operations |
| 0004-Service-Architecture.md | Service architecture — services implement domain capabilities |
| 0006-Reference-Architecture.md | Reference architecture — patterns for domain modeling |
| 00-Foundations/001-AIOS-Philosophy.md | Philosophy — PHI-003 (Entity Autonomy), PHI-004 (Identity Precedes Action) |
| 00-Foundations/002-Design-DNA.md | Design DNA — R1 (Modulsingularity) applies to domain boundaries |
| 02-Core (all documents) | Core engines — Sou, Academy, OSYS, ROS implement domain entities |
| 03-Institutions (all documents) | Institutions — Organizations, Workers, Missions are domain entities |
| 05-Platform/001-State-Machine.md | State machine — entity lifecycles are state machines |
| Physics/002-Missions.md | Mission invariants — mission domain foundations |
| Physics/003-Organizations.md | Organization invariants — organization domain foundations |
| Physics/006-Lifecycles.md | Lifecycle invariants — entity lifecycle foundations |
| Physics/007-Capabilities.md | Capability invariants — capability model foundations |
