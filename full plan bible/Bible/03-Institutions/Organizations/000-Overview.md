# AIOS Bible — Institutions
## Organizations 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-ORG-000 |
| Source Laws | Law 2 — Law of Non-Execution, Law 5 — Law of Identity, Law 6 — Law of Lifecycle Compliance, Law 10 — Law of Tenure |
| Source Physics | Physics/003-Organizations.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Organizations are the constitutional units of collective action in AIOS. An Organization transforms strategic intent into coordinated execution by owning Missions, employing Workers, managing resources, and governing member entities. Unlike Workers (temporary) and Missions (finite), Organizations endure — they are the permanent operational fabric of AIOS.

This volume defines the Organization architecture: how Organizations are structured, how they stay healthy, how they are discovered, how they make decisions, how they compose sub-units, how they interact, how they employ Engines, and how they are evaluated.

## Organization Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Organization                              │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ OOM (001)   │  │ OHS (002)   │  │ ODS (003)   │            │
│  │ Object Model│  │ Health Svc  │  │ Directory   │            │
│  │ Structure,  │  │ Monitoring, │  │ Lookup,     │            │
│  │ Depts, Roles│  │ Self-Healing│  │ Hierarchy   │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ ORG (004)   │  │ DOM (005)   │  │ OIS (006)   │            │
│  │ Governance  │  │ Department  │  │ Interaction │            │
│  │ Decisions,  │  │ Sub-Org     │  │ Cross-Org   │            │
│  │ Voting      │  │ Structure   │  │ Comms       │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐                              │
│  │ EEE (007)   │  │ OPE (008)   │                              │
│  │ Engine      │  │ Performance │                              │
│  │ Employment  │  │ Evaluator   │                              │
│  │ Exchange    │  │ Metrics     │                              │
│  └─────────────┘  └─────────────┘                              │
└────────────────────────────────────────────────────────────────┘
```

## Relationship to Core/OSYS

OSYS (Core/OSYS) manages the Organization lifecycle — creation, verification, activation, suspension, restoration, dissolution, and archival. OSYS is the administrative backbone. The Institutions/Organizations volume defines the operational model of Organizations once they are created:

| Aspect | Core/OSYS | Institutions/Organizations |
|--------|-----------|---------------------------|
| Lifecycle | Created → Verified → Active → Suspended → Restored → Dissolved → Archived | Uses Active state to operate |
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

3. **Lifecycle Compliance**: Every Organization follows the canonical lifecycle: Created → Verified → Active → Suspended → Restored → Dissolved → Archived. All transitions require authorization and produce Events. (PHI-006)

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

All Organization communication flows through ACF. Inter-Organization communication requires parent Organization routing. OIS is the cross-Organization communication service. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Organization component (OOM, OHS, ODS, etc.) has a single responsibility |
| R2 (Dependency Order) | Organizations depend on Core (OSYS, ROS, LMS) which depends on Physics |
| R5 (Liskov) | All Organization types implement the Organization interface |
| R10 (Simpler Over Complex) | Organization hierarchy is a tree — no complex graph structures |
| R13 (Design for Failure) | ODS is read-replicated for query availability; OHS degrades gracefully |
| R14 (Paved Path) | Single paved path for Organization operations |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/003-Organizations.md | Organizations Physics — canonical definitions and 14 invariants |
| Physics/005-Events.md | Evidence — all Organization operations produce Events |
| Physics/006-Lifecycles.md | Lifecycles — Organizations follow canonical lifecycle |
| Physics/007-Capabilities.md | Capabilities — Organizations are capability containers |
| Physics/008-Security.md | Security — Organization operations require authorization |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
| Bible/01-Governance/000-Overview.md | GOV-001–005 — governance identifiers |
| Bible/02-Core/OSYS/000-Overview.md | OSYS overview — Organization creation and lifecycle |
| Bible/02-Core/OSYS/001-Architecture.md | OSYS architecture — Factory, Registry, Lifecycle Manager |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — 7-state model |
| Bible/02-Core/AGS/000-Overview.md | AGS — Organization Genomes |
| Bible/02-Core/ROS/005-Budget.md | ROS — Organization resource budgets |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Missions — Organizations own Missions |
| Bible/03-Institutions/Workers/000-Overview.md | Workers — Organizations employ Workers |
| Bible/04-Execution/Security/IDS | IDS — Organization identity
