# AIOS Physics
## 003 — Organization Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-003 |
| Applies To | All Organizations, OSYS, Sou, Workers, ACF, Security Kernel |
| Source Laws | Law 2 — Law of Non-Execution, Law 5 — Law of Identity, Law 6 — Law of Lifecycle Compliance, Law 10 — Law of Tenure |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Organizations within AIOS. An Organization is the permanent operational society responsible for accomplishing Missions within a specialized domain. Organizations transform strategic intent into coordinated execution by combining leadership, Workers, Operational Intelligence, and governed collaboration.

These invariants extend Laws 2, 5, 6, and 10 of Physics/000-Laws.md. Organizations are the enduring structural units of AIOS — the entities that persist across Missions, outlive Workers, and preserve domain expertise.

---

## What Is an Organization?

An Organization is a constitutionally recognized operational entity that:

- Transforms strategic objectives into coordinated execution within a specialized domain
- Owns and preserves Operational Intelligence — domain knowledge, experience patterns, and lessons learned
- Creates, manages, and terminates Workers for Mission execution
- Operates under a Director and defined leadership hierarchy (Director → Managers → Supervisors)
- Communicates exclusively through ACF with other Organizations and Institutions
- Endures beyond individual Workers and Missions but is subject to dissolution by OSYS

An Organization is not a team, not a project, not a temporary group. It is the permanent operational fabric of AIOS.

---

## The Organization Invariants

### Invariant 1 — Organizations Are Created by OSYS

**Organizations do not create themselves. Workers do not organize themselves. OSYS governs the operational society.**

Sou determines strategic direction — what Organizations are needed. OSYS transforms that strategy into operational structure. OSYS creates Organizations, assigns leadership, instantiates Organization Genomes, and manages the complete Organization lifecycle.

An Organization that exists outside OSYS governance is a violation. No Organization may self-create, self-dissolve, or self-modify its constitutional structure.

*Constitutional Expression*: Article III, Part A, Section 004 (OSYS) establishes OSYS as the Constitutional Institution responsible for creating, governing, evolving, and retiring Organizations. Sou vs OSYS split — Sou decides *what* Organizations are needed; OSYS creates them.

*Enforcement*: IRS requires OSYS authorization for identity creation of new Organizations. The Security Kernel validates that every Organization has a verified OSYS provenance. ACF does not route messages for unregistered Organizations.

*Edge Case*: An Organization template instantiation — the template is a Genome, but OSYS must explicitly instantiate it. The template does not self-execute. OSYS validates the template against current strategic needs before instantiation.

*Edge Case*: Recovery of a failed Organization — OSYS may recreate an Organization from its archived Genome and Operational Intelligence. The new instance receives a new identity (Law 5 — identity is immutable) but inherits the recovered knowledge.

*Violation*: An Organization attempting to create a sub-Organization without OSYS authorization. Sou directly instantiating an Organization bypassing OSYS. A Worker group declaring itself an Organization without OSYS approval.

---

### Invariant 2 — Every Organization Originates from a Validated Organization Genome

**Every Organization is instantiated from an Organization Genome. The Genome defines the Organization's type, behavior, structure, and constraints.**

An Organization Genome specifies: Identity, Purpose, Mission Domains, Departments, Leadership Structure, Default Skills, Default Worker configurations, Quality Standards, Risk Profile, Communication Style, Decision Strategy, Scaling Strategy, Health Rules, Growth Rules, Learning Rules, Collaboration Rules, Security Policies, Preferred Runtime Policies, Preferred Models, Budget Policies, Resource Policies, Operational Intelligence Rules, and Version.

The Genome is the immutable blueprint of the Organization. When OSYS instantiates a new Organization, it expresses that Organization's Genome. This ensures reproducible, consistent Organizations.

*Constitutional Expression*: The AIOS Genome System (AGS), under Article III, Part A, Section 007, governs Genome creation, validation, versioning, and inheritance.

*Enforcement*: OSYS validates the Genome before instantiation. An Organization with an invalid, expired, or unsigned Genome is denied. AGS versioning ensures that Organization instances are traceable to a specific Genome version.

*Edge Case*: An Organization Genome updated after instantiation — the existing Organization is not automatically modified. A formal template upgrade through OSYS is required, triggering the Organization's Updating lifecycle state.

*Edge Case*: Custom Organizations — OSYS may create Organizations from custom Genomes, but the Genome must pass AGS validation, security scanning, and constitutional compliance checks.

*Violation*: An Organization operating without a genome. An Organization whose Genome has expired. An Organization whose Genome fails constitutional compliance.

---

### Invariant 3 — An Organization Cannot Exist Without a Mission

**Every Organization exists to accomplish Missions. An Organization without at least one Mission is a violation.**

This is the foundational purpose invariant. Organizations do not exist for their own sake — they exist to transform Human Intent into completed work. If an Organization completes all its Missions and has no new Missions assigned, OSYS places it under review for potential dissolution.

The owning Organization is constitutionally responsible for Mission lifecycle, resource allocation, Worker assignment, and completion verification. Multiple Organizations may participate in a Mission (cooperation), but exactly one Organization owns it.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) establishes the Mission-Organization relationship. Article III, Part B, Section 005 (Missions) defines Mission governance within Organizations.

*Enforcement*: OSYS monitors the Organization-to-Mission mapping continuously. An Organization with no Missions is flagged. If no Mission is assigned within a configurable grace period, OSYS initiates the Organization Suspension → Retirement lifecycle.

*Edge Case*: A newly created Organization that has not yet received its first Mission — the grace period begins after Leadership Assignment and Operational Readiness are complete. The Organization cannot enter Active state without at least one assigned Mission.

*Edge Case*: An Organization whose last Mission completes — the Organization may remain in Active state for a grace period while OSYS assigns new Missions. If none arrives, the Organization transitions to Suspended.

*Violation*: An Organization in Active state with zero Missions beyond the grace period. An Organization that refuses to accept Mission assignments. An Organization completing its last Mission and remaining indefinitely without purpose.

---

### Invariant 4 — Organizations Endure

**Organizations outlive individual Missions, Workers, leadership, Runtime providers, and infrastructure upgrades.**

Organizations are the permanent operational fabric. Directors may change, Workers come and go, Missions complete and archive, Runtime providers are replaced — the Organization persists. Operational continuity belongs to the Organization, not to any individual entity within it.

Endurance is not infinity — Organizations may be dissolved by OSYS (Invariant 13). But within their operational lifespan, Organizations are the stable structural unit around which everything else revolves.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) defines organizational permanence. Law 10 of Physics/000-Laws.md (Law of Tenure) distinguishes Organization endurance from Worker ephemerality.

*Enforcement*: OSYS preserves Operational Intelligence when leadership changes. The Organization Genome version history tracks structural evolution. The Security Kernel ensures that changes in leadership or Worker composition do not affect the Organization's constitutional identity.

*Edge Case*: A complete leadership replacement (Director, all Managers, all Supervisors replaced) — the Organization continues. Its Operational Intelligence, Genome, policies, and Mission commitments persist.

*Edge Case*: A Runtime provider shutdown — the Organization switches to a compatible Runtime. Its Mission continuity is preserved even if individual Workers need to restart on the new Runtime.

*Violation*: An Organization dissolving because its Director left (the Organization outlives the Director). An Organization losing its Operational Intelligence because leadership changed without knowledge transfer. Workers being terminated due to Mission completion when the Organization could reassign them.

---

### Invariant 5 — Organizations Coordinate; Workers Execute

**Organizations coordinate execution. Workers execute work. This separation is constitutional.**

An Organization does not execute code, allocate hardware at the kernel level, or directly invoke Runtime. It plans, assigns, monitors, and verifies. Workers perform the actual execution. The Organization is the operational brain; Workers are the hands.

This separation mirrors the Sou/OSYS/Worker strategy-execution split at a higher level: Sou plans strategy, OSYS creates Organizations, Organizations coordinate Workers, Workers execute.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) defines the coordination role. Article III, Part B, Section 004 (Workers) defines the execution role. Law 2 of Physics/000-Laws.md (Law of Non-Execution) establishes the principle.

*Enforcement*: The Security Council verifies that every execution request originates from a Worker, not from an Organization. ACF blocks execution messages with Organization identity as the source. OSYS validates that Organizations create Workers for execution rather than executing themselves.

*Edge Case*: An Organization's internal decision logic (ODS — Organization Decision System) — decisions are coordination, not execution. The decision output is a Worker assignment or Mission instruction, not a Runtime invocation.

*Violation*: An Organization directly invoking a Runtime. An Organization executing code without creating a Worker. An Organization bypassing the Security Council verification step.

---

### Invariant 6 — Organizations Own Workers

**Workers belong to Organizations. Organizations create, assign, and terminate Workers.**

A Mission may reference Workers, but Workers remain owned by the Organization. The Organization is responsible for Worker creation from appropriate Genomes, Worker skill assignment, Worker lifecycle management, and Worker termination when Missions complete or conditions are met.

When a Mission completes, its assigned Workers are returned to the Organization's Worker pool or terminated per the Worker lifecycle. Workers do not own organizational knowledge — they contribute experience back to the Organization through governed operational processes.

*Constitutional Expression*: Article III, Part B, Section 004 (Workers) establishes Worker ownership. Article III, Part B, Section 002 (Governance Hierarchy) defines the leadership chain through which Organizations govern Workers.

*Enforcement*: OSYS verifies that every Worker is registered under an Organization identity. IRS validates Worker-Organization binding. ACF routes Worker messages through Organization context. The Security Council verifies that Worker authorization derives from Organization authorization.

*Edge Case*: A Mission spanning multiple Organizations — Workers belong to their respective Organizations. Cooperative agreements between Organizations are required for shared Mission execution. Cross-Organization Worker pools require explicit OSYS authorization.

*Edge Case*: An Organization that has no active Missions but maintains a Worker pool for readiness — OSYS validates that the Worker pool is within budget and that the Organization has pending Mission assignments or anticipated work.

*Violation*: A Worker claiming ownership of itself. An Organization claiming another Organization's Workers without a cooperation agreement. A Mission owning Workers directly without Organization mediation.

---

### Invariant 7 — Every Organization Has a Director

**Every Organization has exactly one Director. The Director serves the Organization.**

The Director is the constitutional leader of the Organization — responsible for operational governance, Mission coordination, resource management, and constitutional compliance. The Organization is not the Director; the Director serves the Organization. This preserves institutional continuity across leadership changes.

The Director may delegate authority to Managers and Supervisors through the Governance Hierarchy, but accountability ultimately rests with the Director. If a Worker fails, the Supervisor is accountable. If the Supervisor fails, the Manager is accountable. If the Manager fails, the Director is accountable. Accountability propagates upward.

*Constitutional Expression*: Article III, Part B, Section 002 (Governance Hierarchy) defines the Director → Manager → Supervisor → Worker hierarchy. Law 2 of Physics/000-Laws.md (Law of Non-Execution) ensures the Director does not execute personally.

*Edge Case*: A Director transition — when a Director is replaced, the new Director inherits the Organization's constitutional authority. The Organization's identity, missions, and Operational Intelligence are unchanged. The transition is recorded as evidence.

*Edge Case*: An Organization without a Director — OSYS must assign a Director before the Organization can achieve Operational Readiness. An Organization without a Director is not constitutionally operational.

*Violation*: A Director executing Workers directly without going through authorized delegation. A Director claiming personal ownership of the Organization. A Director refusing to delegate or accept accountability.

---

### Invariant 8 — Organizations Communicate Only Through ACF

**No Organization communicates directly with another Organization, Institution, or entity outside ACF.**

All inter-entity communication — Organizations talking to each other, Organizations talking to Sou, Organizations talking to Workers, Organizations talking to the Security Council — flows through the AIOS Communication Fabric. No direct IPC, no shared memory, no side channels.

This invariant extends Law 3 of Physics/000-Laws.md (Law of Communication) to the organizational layer. ACF is the universal switchboard for all organizational interactions.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) mandates ACF for all organizational communication. The ACF specification (Bible/06-Services/ACF/) defines the implementation.

*Enforcement*: ACF validates every message from an Organization. Messages without ACF envelopes are rejected. The Security Council audits ACF routes for compliance. OSYS monitors communication patterns for anomalies.

*Edge Case*: Intra-Organization communication between Departments — flows through ACF with Organization-scoped routing. Departments within the same Organization communicate through ACF Department channels, not through direct function calls.

*Edge Case*: Worker-to-Organization feedback — Workers communicate execution results through ACF to the Organization. The Worker does not write directly to the Organization's Operational Intelligence store.

*Violation*: Two Organizations communicating through Unix pipes. An Organization writing directly to another Organization's Operational Intelligence store. A Worker reporting results outside ACF.

---

### Invariant 9 — Organizations Operate Under Constitutional Governance

**Every Organization action requiring constitutional authorization is verified by the Security Council. OSYS never authorizes its own actions.**

Organizations are constitutional entities that must comply with all constitutional articles. They cannot bypass the Security Council, cannot override Human sovereignty, cannot modify their own constitutional constraints, and cannot operate outside OSYS governance.

The Security Council verifies: Are actions authorized by the Organization's current policies? Do they comply with Mission constraints? Are they within the Workers' capability bounds? Are they consistent with the Organization's Genome?

*Constitutional Expression*: Article II, Section 004 (Constitutional Compliance) requires all entities to comply. Article IV (Security) establishes the verification framework.

*Enforcement*: The Security Council validates every significant Organization action — Mission acceptance, resource requests, leadership changes, policy modifications, cooperation agreements. Actions without Security Council authorization are denied.

*Edge Case*: An Organization's internal operational decisions (Worker task assignment, progress tracking, routine reporting) — these require the Organization's own authorization policies, which must be derived from constitutional constraints. Routine operations do not require per-action Security Council verification, but the policies governing them must be Security Council-validated.

*Edge Case*: An Organization in Suspended state — no constitutional governance actions are permitted. The Organization may not accept Missions, assign Workers, or modify policies.

*Violation*: An Organization modifying its Genome without OSYS authorization. An Organization bypassing the Security Council for a resource allocation. An Organization operating outside its delegated authority.

---

### Invariant 10 — Organizations Own Operational Intelligence

**Every Organization owns and preserves Operational Intelligence — domain-specific knowledge, experience, patterns, and lessons learned that persist beyond individual Workers and Missions.**

Operational Intelligence includes: Mission histories, Worker performance patterns, operational decisions and their outcomes, collaboration patterns, resource utilization trends, quality metrics, communication latencies, and process improvements.

Operational Intelligence is distinct from Academy Knowledge. The Academy holds cross-Organizational institutional knowledge. The Organization owns its own operational history and domain-specific expertise. Operational Intelligence is Organization-scoped, evolves with the Organization, and is preserved even when all Workers and Missions are replaced.

*Constitutional Expression*: Article III, Part B, Section 009 (Operational Intelligence) establishes Operational Intelligence as a constitutional responsibility of Organizations. The OIS (Operational Intelligence System) in the Organizations Bible defines implementation.

*Enforcement*: OSYS validates that Organizational dissolution or leadership changes do not destroy Operational Intelligence. Before dissolution, Operational Intelligence must be transferred to the Academy for cross-system learning or archived. The Security Council ensures that Operational Intelligence access is scoped to the owning Organization and authorized institutions (Academy, Sou) only.

*Edge Case*: An Organization that is dissolved — its Operational Intelligence must be either transferred to another Organization in the same domain, ingested into Academy knowledge, or preserved in an archived state. It cannot be destroyed.

*Edge Case*: A Worker that produces novel knowledge during execution — the Worker's execution evidence is preserved, and the extracted experience (via EEE — Experience Extraction Engine) feeds into the Organization's Operational Intelligence. The Worker does not own the extracted knowledge.

*Violation*: Dissolving an Organization without preserving Operational Intelligence. A Worker claiming ownership of Operational Intelligence it helped create. An Organization refusing to share Operational Intelligence with the Academy for cross-system improvement.

---

### Invariant 11 — Organizations Have Structural Hierarchy

**Every Organization contains a defined structural hierarchy: Departments, Leadership, Workers, Operational Intelligence, Policies, Metrics, Resources.**

Organizations are not flat. They contain:

- **Departments** — functional specialization units (e.g., Backend, Frontend, Security, Testing within a Coding Organization)
- **Leadership** — Director, Managers, Supervisors forming the Governance Hierarchy
- **Worker Pools** — collections of Workers organized by skill and availability
- **Operational Intelligence** — the Organization's knowledge base
- **Policies** — operational, security, quality, and communication policies
- **Metrics** — health indicators (OHS), success rates, utilization
- **Resources** — allocated through ROS, managed within organizational budgets

Departments belong to Organizations. Departments specialize in capabilities (e.g., Backend Department owns backend development capability), while Organizations own domains (e.g., Coding Organization owns the software development domain). Departments serve as the operational sub-units that allow Organizations to scale beyond 500+ Workers without losing structure.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) defines the organizational structure. Article III, Part B, Section 003 (Departments) defines Departments as operational sub-units.

*Enforcement*: OSYS validates Organizational structure during Instantiation and through periodic reviews. Structural changes (new Departments, Department merging, hierarchy restructuring) require OSYS authorization.

*Edge Case*: A small Organization without Departments — acceptable if the Organization has fewer Workers than the Department creation threshold. The threshold is configurable per Organization type.

*Edge Case*: A Department that becomes larger than its parent Organization — OSYS may trigger a Department promotion to full Organization status or restructure to maintain balanced hierarchy.

*Violation*: An Organization that grows beyond the threshold without creating Departments. A Department claiming independence from its parent Organization. A Director creating a hierarchy that violates the Governance Hierarchy constraints.

---

### Invariant 12 — Organizations Operate Within Resource Budgets

**ROS allocates resources to Organizations. Organizations operate within their allocated budgets. No Organization may consume resources without constitutional allocation.**

Every Organization has a resource budget managed through ROS. The budget includes: CPU, memory, network, storage, GPU, API credits, and external service consumption. The Organization's Genome defines preferred providers, budget policies, and resource constraints.

When an Organization needs resources for a Mission, it requests allocation from ROS. ROS validates availability and performs allocation against the Organization's budget. The Organization cannot exceed its budget without OSYS- or Sou-approved budget modification.

*Constitutional Expression*: Article III, Part A, Section 006 (ROS — Resource Orchestrator) defines resource governance. ROS allocates resources to Organizations within constitutional bounds.

*Enforcement*: ROS monitors resource consumption per Organization. The Security Council validates every resource allocation against the Organization's budget. Exceeding the budget triggers denial, escalation to OSYS, and potential Mission suspension.

*Edge Case*: An Organization that consistently underutilizes its budget — ROS may reallocate unused resources to other Organizations through the Resource Marketplace. The budget is not revoked but surplus resources may be redistributed.

*Edge Case*: An Organization that needs to exceed its budget for a high-priority Mission — Sou must approve a budget extension, or the Mission must be replanned with fewer resources. The Organization cannot self-extend.

*Violation*: An Organization consuming resources without ROS allocation. An Organization exceeding its CPU or memory budget. An Organization allocating resources to a Mission without authorization.

---

### Invariant 13 — Organizations Are Subject to Dissolution

**Organizations may endure beyond individual Workers and Missions, but they are not permanent. OSYS may dissolve an Organization.**

An Organization is dissolved when: its last Mission completes and no new Missions are assigned (expiry of the formation grace period); its strategic purpose no longer exists (Sou determines the Organization's mission is complete); the Organization becomes unhealthy beyond recovery (OSYS health evaluation); or Human override explicitly commands dissolution.

Organization dissolution follows a defined lifecycle: Suspension → Notification → Resource Release → Worker Termination → Mission Reassignment → Operational Intelligence Archival → Retirement → Archival.

Before dissolution, all Missions must be reassigned or retired. All Workers must be terminated or transferred. All resources must be released. Operational Intelligence must be archived or transferred to Academy.

*Constitutional Expression*: Law 10 of Physics/000-Laws.md (Law of Tenure) establishes that Organizations are subject to dissolution. OSYS is the authority for Organization dissolution per Article III, Part A, Section 004.

*Enforcement*: OSYS validates that all preconditions are met before initiating dissolution. The Security Council verifies that no Missions are orphaned, no Workers are stranded, and no resources are leaked. IRS archives the Organization's identity for audit purposes.

*Edge Case*: A dissolved Organization that needs to be restored — OSYS may re-create the Organization from its archived Genome and recovered Operational Intelligence. The new instance receives a new identity but inherits the archived knowledge.

*Edge Case*: An Organization that fails abruptly (catastrophic failure) — OSYS emergency procedures isolate the Organization, preserve Operational Intelligence, terminate Workers, and reassign Missions. The Security Council conducts a post-mortem.

*Violation*: Dissolving an Organization without reassigning its Missions. Archiving Operational Intelligence without transferring it to Academy. Dissolving an Organization without a complete evidence record.

---

### Invariant 14 — Organizations Preserve Constitutional Identity

**Every Organization has exactly one immutable identity assigned by IRS. Identity persists for the Organization's constitutional lifetime.**

The Organization's identity is established at creation by IRS, verified before every constitutional action, and preserved through leadership changes, structural reorganizations, and Mission cycles. The identity does not change. A re-instantiated Organization receives a new identity.

Organization identity is distinct from organization structure. The identity remains stable even as the Organization evolves internally.

*Constitutional Expression*: Law 5 of Physics/000-Laws.md (Law of Identity) and Physics/001-Identity.md (Identity Invariants) apply fully to Organizations. Article IV, Part A, Section 003 (Identity) defines the constitutional identity framework.

*Enforcement*: IRS validates Organization identity on every constitutional action. The Security Council verifies identity before authorization. ACF routes Organization messages based on verified identity.

*Edge Case*: An Organization that undergoes a complete structural reorganization (Departments restructured, leadership replaced, Genome upgraded) — its identity remains the same. Identity is not tied to structure.

*Violation*: Two Organizations sharing the same identity. An Organization operating without a verified identity. An Organization whose identity has been retired attempting to act.

---

## The Organization Lifecycle

The canonical Organization lifecycle, managed by OSYS:

```
Draft → Validation → Approval → Instantiation → Initialization →
Leadership Assignment → Operational Readiness → Active → Scaling →
Suspension → Retirement → Archival
```

| State | Description |
|-------|-------------|
| Draft | Organization concept is created. Identity reserved but not yet active. |
| Validation | Genome is validated, policies are checked, resource feasibility is verified. |
| Approval | OSYS approves the Organization for creation. |
| Instantiation | Organization is created from its Genome. Identity is issued by IRS. |
| Initialization | Base structure is established. Leadership roles are prepared. |
| Leadership Assignment | Director is assigned. Leadership hierarchy is formed. |
| Operational Readiness | Organization is ready to accept Missions. |
| Active | Organization is operational. Missions are accepted and executed. |
| Scaling | Organization is expanding. More Departments, Workers, or resources added. |
| Suspension | Organization is temporarily disabled. No Missions accepted. |
| Retirement | Organization is being dissolved. Missions reassigned, Workers terminated. |
| Archival | Organization record is preserved for audit. Identity is retired. |

---

## Departments and Their Invariants

Departments are the functional specialization units within Organizations. When an Organization grows beyond a threshold (~500+ Workers or when functional specialization is needed), Departments structure the hierarchy:

```
Organization
└── Departments (Backend, Frontend, Security, Testing, Documentation, DevOps, AI, Embedded)
    ├── Managers
    │   ├── Supervisors
    │   │   └── Workers
    │   └── ...
    └── ...
```

Department invariants (derived from Organization invariants):

| Department Invariant | Source | Description |
|--------------------|--------|-------------|
| Departments belong to Organizations | Organization Invariant 11 | Departments are sub-units of their parent Organization |
| Departments originate from Department Genomes | Invariant 2 (analogous) | Departments are created from Department Genomes via AGS |
| Departments preserve Functional Intelligence | Invariant 10 (analogous) | Departments maintain domain-specific operational intelligence |
| Departments specialize | Organization Invariant 11 | Departments own capabilities within the Organization's domain |
| Departments coordinate | Invariant 5 (analogous) | Departments coordinate through the Organization's ACF channels |
| Departments are governed by Organization leadership | Invariant 7 (analogous) | Director governs all Departments through the management chain |

---

## Organization Identity and Structure

Every Organization has the following constitutional attributes:

| Attribute | Mutable? | Description |
|-----------|----------|-------------|
| Organization ID | NEVER | Globally unique, immutable identity assigned by IRS |
| Organization Genome | Versioned | Blueprint that defines Organization type, behavior, constraints |
| Name | YES | Human-readable identifier |
| Mission Domains | YES | Domains in which the Organization operates |
| Purpose | YES | Constitutional purpose statement |
| Departments | YES | Functional sub-units (add/remove/restructure) |
| Leadership | YES | Director, Managers, Supervisors |
| Worker Pool | YES | Workers available for Mission assignment |
| Operational Intelligence | Immutable content | Knowledge preserved across reorganizations |
| Policies | YES | Operational, quality, security, communication policies |
| Metrics | YES | Health and performance indicators |
| Resources | YES | ROS-allocated budgets |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 6 (Lifecycle Compliance), Law 10 (Tenure) — source laws |
| Physics/001-Identity.md | Identity invariants — Organizations have immutable identity (Invariant 14) |
| Physics/002-Missions.md | Mission invariants — Organizations own Missions (Invariant 3) |
| Physics/004-Sessions.md | Session invariants — Sessions within Organizations |
| Physics/005-Events.md | Evidence invariants — Organizational actions produce evidence |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants — Organization lifecycle (Invariant lifecycle section) |
| Physics/007-Capabilities.md | Capability bound invariants — Organizational resource budgets |
| Physics/008-Security.md | Security invariants — Organizations comply with Security Council (Invariant 9) |
| Physics/009-Interaction.md | Interaction invariants — ACF communication (Invariant 8) |
| Physics/010-Execution.md | Execution invariants — Organizations coordinate, not execute (Invariant 5) |
| Physics/011-Design-DNA.md | 15 Design DNA Rules — engineering principles applied to Organizations |
| Constitution, Article III, Part A, Section 004 (OSYS) | OSYS creates and governs Organizations |
| Constitution, Article III, Part A, Section 006 (ROS) | ROS allocates resources to Organizations |
| Constitution, Article III, Part A, Section 007 (AGS) | AGS governs Organization Genomes |
| Constitution, Article III, Part B, Section 001 (Organizations) | Constitutional definition of Organizations |
| Constitution, Article III, Part B, Section 002 (Governance Hierarchy) | Leadership structure: Director → Manager → Supervisor |
| Constitution, Article III, Part B, Section 003 (Departments) | Department structure and governance |
| Constitution, Article III, Part B, Section 004 (Workers) | Worker ownership and lifecycle |
| Constitution, Article III, Part B, Section 006 (Lifecycles) | Lifecycle requirements |
| Constitution, Article III, Part B, Section 009 (Operational Intelligence) | Operational Intelligence ownership |
| Constitution, Article IV, Part A, Section 003 (Identity) | Constitutional identity framework |

---

## Future Extensions

These invariants are expected to remain stable. Future Organization-related specifications in the Bible (Bible/03-Institutions/Organizations/) will define the Organizations Operating Model (OOM), Organization Health System (OHS), Organization Decision System (ODS), Organizational Responsibility Graph (ORG), Department Operating Model (DOM), Operational Intelligence System (OIS), Experience Extraction Engine (EEE), Operational Pattern Engine (OPE), cross-Organization cooperation protocols, and Organization SDK.

---

*End of AIOS Physics 003 — Organization Invariants*