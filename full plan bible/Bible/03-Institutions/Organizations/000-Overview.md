# AIOS Bible â€” Institutions
## Organizations 000 â€” Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Institutions |
| Document ID | AIOS-BBL-003-ORG-000 |
| Source Laws | Law 2 â€” Law of Non-Execution, Law 5 â€” Law of Identity, Law 6 â€” Law of Lifecycle Compliance, Law 10 â€” Law of Tenure |
| Source Physics | Physics/003-Organizations.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Organizations are the constitutional units of collective action in AIOS. An Organization transforms strategic intent into coordinated execution by owning Missions, employing Workers, managing resources, and governing member entities. Unlike Workers (temporary) and Missions (finite), Organizations endure â€” they are the permanent operational fabric of AIOS.

This volume defines the Organization architecture: how Organizations are structured (OOM), how they stay healthy (OHS), how they are discovered (ODS), how they make decisions (ORG), how they compose sub-units (DOM), how they interact (OIS), how they employ Engines (EEE), and how they are evaluated (OPE).

## Organization Lifecycle (from Core/OSYS)

Organizations follow a 7-state lifecycle managed by OSYS (Core/OSYS/002-Org-Lifecycle.md):

```
Created â†’ Verified â†’ Active â†’ Suspended â†’ Restored â†’ Dissolved â†’ Archived
```

| State | Description | Operational Capability |
|-------|-------------|----------------------|
| **Created** | Organization record exists. Identity assigned by IDS. Not yet operational. | None |
| **Verified** | Structure and constitutional compliance verified. Ready for activation. | Read-only (self-structure query) |
| **Active** | Fully operational. Owns Missions, employs Workers, manages resources. | Full capability scope per Genome |
| **Suspended** | Operations suspended due to violation or Security Council order. | None (except compliance reporting) |
| **Restored** | Organization is restored from Suspended. Returning to Active. | Read-only (remediation actions) |
| **Dissolved** | Permanently dissolved. Missions terminated or transferred. Resources returned. | None |
| **Archived** | Record preserved for constitutional audit. Terminal state. | None |

## Organization Types

Organizations are categorized by type (from Core/OSYS/000-Overview.md):

| Type | Description | Can Own Missions? | Can Employ Workers? |
|------|-------------|-------------------|---------------------|
| **ORG** â€” Root Organization | Top-level strategic entity | Yes | Yes |
| **ODS** â€” Department/Squad | Functional sub-Organization | Yes (within parent bounds) | Yes (within parent bounds) |
| **OHS** â€” Hub/Shared Service | Shared capability center | Limited | Yes |
| **OOM** â€” Operational Oversight | Monitoring and governance body | No | Yes (limited) |
| **OPE** â€” Project/Program Entity | Temporary project structure | Yes | Yes (temporary) |
| **EEE** â€” Engine Execution Environment | Engine hosting entity | No | Yes (engines only) |
| **OIS** â€” Isolation/Sandbox | Sandboxed execution environment | No | Yes (sandboxed) |
| **DOM** â€” Domain Organization | Domain-specific operational unit | Yes | Yes |

## Hierarchy Rules

The Organization hierarchy enforces strict structural rules:

| Rule | Constraint | Violation Consequence |
|------|-----------|----------------------|
| Single Parent | Every Organization has exactly one parent (except root) | OOM_HIE_002 â€” creation denied |
| Tree Structure | No cycles or cross-links between branches | OOM_HIE_003 â€” move denied |
| Depth Limit | Maximum 7 levels from root to deepest leaf | OOM_HIE_001 â€” creation denied |
| Parent Scope | Parent defines policy bounds for children | ORG_GOV_005 â€” policy rejected |
| Resource Flow | Resources flow from parent to child | ROS allocation enforced |

## Organization Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        Organization                              â”‚
â”‚                                                                â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”            â”‚
â”‚  â”‚ OOM (001)   â”‚  â”‚ OHS (002)   â”‚  â”‚ ODS (003)   â”‚            â”‚
â”‚  â”‚ Object Modelâ”‚  â”‚ Health Svc  â”‚  â”‚ Directory   â”‚            â”‚
â”‚  â”‚ Structure,  â”‚  â”‚ Monitoring, â”‚  â”‚ Lookup,     â”‚            â”‚
â”‚  â”‚ Depts, Rolesâ”‚  â”‚ Self-Healingâ”‚  â”‚ Hierarchy   â”‚            â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜            â”‚
â”‚                                                                â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”            â”‚
â”‚  â”‚ ORG (004)   â”‚  â”‚ DOM (005)   â”‚  â”‚ OIS (006)   â”‚            â”‚
â”‚  â”‚ Governance  â”‚  â”‚ Department  â”‚  â”‚ Interaction â”‚            â”‚
â”‚  â”‚ Decisions,  â”‚  â”‚ Sub-Org     â”‚  â”‚ Cross-Org   â”‚            â”‚
â”‚  â”‚ Voting      â”‚  â”‚ Structure   â”‚  â”‚ Comms       â”‚            â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜            â”‚
â”‚                                                                â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                              â”‚
â”‚  â”‚ EEE (007)   â”‚  â”‚ OPE (008)   â”‚                              â”‚
â”‚  â”‚ Engine      â”‚  â”‚ Performance â”‚                              â”‚
â”‚  â”‚ Employment  â”‚  â”‚ Evaluator   â”‚                              â”‚
â”‚  â”‚ Exchange    â”‚  â”‚ Metrics     â”‚                              â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                              â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Relationship to Core/OSYS

OSYS (Core/OSYS) manages the Organization lifecycle â€” creation, verification, activation, suspension, restoration, dissolution, and archival. OSYS is the administrative backbone. The Institutions/Organizations volume defines the operational model of Organizations once they are created:

| Aspect | Core/OSYS | Institutions/Organizations |
|--------|-----------|---------------------------|
| Lifecycle | Created â†’ Verified â†’ Active â†’ Suspended â†’ Restored â†’ Dissolved â†’ Archived | Uses Active state to operate |
| Identity | IDS creates and manages | Uses identity for all operations |
| Structure | Factory creates skeleton | OOM defines structure, departments, roles |
| Health | OSYS monitors lifecycle compliance | OHS monitors operational health |
| Governance | Governance Enforcer audits compliance | ORG defines how decisions are made |

## Organizations Own Missions, Employ Engines, Manage Resources, Govern Workers

| Responsibility | Description | Cross-Reference |
|--------------|-------------|-----------------|
| Own Missions | Every Mission belongs to exactly one Organization | Missions/000-Lifecycle.md |
| Employ Engines | Organizations employ execution Engines via EEE | EEE (007) |
| Manage Resources | Organizations operate within ROS-allocated budgets | ROS/005-Budget.md |
| Govern Workers | Organizations create, assign, and terminate Workers | Workers/000-Overview.md |

## 5 Invariants

1. **Constitutional Identity**: Every Organization has exactly one immutable identity assigned by IRS. Identity persists for the Organization's lifetime. (PHI-004, Physics/003 Invariant 14)

2. **Hierarchy Without Bypass**: Organizations form a tree hierarchy. Sub-Organizations communicate through their parent. No direct child-to-child communication without parent mediation. Max depth: 7 levels. (Physics/003 Invariant 11)

3. **Lifecycle Compliance**: Every Organization follows the canonical lifecycle: Created â†’ Verified â†’ Active â†’ Suspended â†’ Restored â†’ Dissolved â†’ Archived. All transitions require authorization and produce Events. (PHI-006)

4. **Resource Accountability**: Organizations manage resources through ROS. Resource allocations are tracked per Organization. No resource is unowned. (Physics/003 Invariant 12)

5. **Constitutional Governance**: Organizations operate within constitutional bounds. The Governance Enforcer (OSYS) audits compliance. Violations trigger suspension or dissolution. (GOV-001, GOV-005)

## Component Map

| File | Document | Function |
|------|----------|----------|
| 001-OOM.md | Organization Object Model | Structure, departments, roles, schema, operations |
| 002-OHS.md | Organization Health Service | Monitoring, health states, self-healing |
| 003-ODS.md | Organization Directory Service | Lookup, hierarchy resolution, caching |
| 004-ORG.md | Organization Governance | Decision authority, voting, escalation |
| 005-DOM.md | Department Object Model | Sub-organization structure, types, lifecycle |
| 006-OIS.md | Organization Interaction Service | Cross-Org communication, cooperation |
| 007-EEE.md | Engine Employment Exchange | Engine assignment, employment lifecycle |
| 008-OPE.md | Organization Performance Evaluator | Metrics, reporting, improvement |

## Organization Data Flow

The following describes how data flows through the Organization components during a typical operation:

```
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚  External   â”‚
                     â”‚  Request    â”‚
                     â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜
                            â”‚ ACF
                            â–¼
               â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
               â”‚   ODS (Directory)     â”‚
               â”‚   resolveOrg()        â”‚
               â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                      â”‚
                      â–¼
               â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
               â”‚   OOM (Object Model)  â”‚
               â”‚   validate + update   â”‚
               â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                      â”‚
              â”Œâ”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”
              â–¼       â–¼       â–¼
       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”
       â”‚ OHS    â”‚ â”‚ ORG    â”‚ â”‚ DOM    â”‚
       â”‚ Health â”‚ â”‚Governanâ”‚ â”‚Dept    â”‚
       â”‚ Check  â”‚ â”‚ Auth   â”‚ â”‚ Update â”‚
       â””â”€â”€â”€â”€â”¬â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”¬â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”¬â”€â”€â”€â”˜
            â”‚          â”‚          â”‚
            â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â–¼
               â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
               â”‚   OIS / EEE / OPE     â”‚
               â”‚   cross-cutting ops   â”‚
               â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Organization Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Org.MissionOwned` | Organization is assigned a Mission | org_id, mission_id, assignment_time |
| `Org.WorkerEmployed` | Organization employs a Worker | org_id, worker_id, employment_type |
| `Org.BudgetAdjusted` | Organization resource budget changes | org_id, resource_type, old_budget, new_budget |
| `Org.PolicyChanged` | Organization governance policy changes | org_id, policy_type, old_hash, new_hash |
| `Org.StructureChanged` | Department hierarchy modified | org_id, change_type, affected_dept |

## Cross-Cutting Concerns

### Security

Organization operations require Security Council authorization for creation, suspension, dissolution, and structural changes. Cross-branch Organization visibility requires Council authorization. (Physics/008-Security.md)

### Evidence

Every Organization operation produces an Event. The complete lifecycle and operational history of every Organization is recorded in the Event Store. Organization audits are supported by immutable Events. (PHI-008)

### Lifecycle

Organizations follow the lifecycle defined in Core/OSYS/002-Org-Lifecycle.md. The operational specifications in this volume apply primarily to Organizations in Active state. (PHI-006)

### Capability Bounds

Organizations have defined capability scopes per their Genome (AGS). An Organization may not exceed its constitutional bounds. Capability bounds cascade to sub-Organizations and Workers. (Physics/007-Capabilities.md)

### Communication

All Organization communication flows through ACF. Inter-Organization communication requires parent Organization routing. OIS is the cross-Organization communication service. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Organization component (OOM, OHS, ODS, etc.) has a single responsibility |
| R2 (Dependency Order) | Organizations depend on Core (OSYS, ROS, LMS) which depends on Physics |
| R5 (Liskov) | All Organization types implement the Organization interface |
| R10 (Simpler Over Complex) | Organization hierarchy is a tree â€” no complex graph structures |
| R13 (Design for Failure) | ODS is read-replicated for query availability; OHS degrades gracefully |
| R14 (Paved Path) | Single paved path for Organization operations |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/003-Organizations.md | Organizations Physics â€” canonical definitions and 14 invariants |
| Physics/005-Events.md | Evidence â€” all Organization operations produce Events |
| Physics/006-Lifecycles.md | Lifecycles â€” Organizations follow canonical lifecycle |
| Physics/007-Capabilities.md | Capabilities â€” Organizations are capability containers |
| Physics/008-Security.md | Security â€” Organization operations require authorization |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
| Bible/01-Governance/000-Overview.md | GOV-001â€“005 â€” governance identifiers |
| Bible/02-Core/OSYS/000-Overview.md | OSYS overview â€” Organization creation and lifecycle |
| Bible/02-Core/OSYS/001-Architecture.md | OSYS architecture â€” Factory, Registry, Lifecycle Manager |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle â€” 7-state model |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” Organization Genomes |
| Bible/02-Core/ROS/005-Budget.md | ROS â€” Organization resource budgets |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Missions â€” Organizations own Missions |
| Bible/03-Institutions/Workers/000-Overview.md | Workers â€” Organizations employ Workers |
| Bible/04-Execution/Security/IDS | IDS â€” Organization identity
