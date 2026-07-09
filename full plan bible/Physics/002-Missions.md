# AIOS Physics
## 002 — Mission Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-002 |
| Applies To | All Missions, Sou, Organizations, Workers, ACF, Security Kernel |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Missions within AIOS. A Mission is the constitutional contract between Human Intent and AIOS execution — it transforms a Human purpose into coordinated, observable, verifiable work.

These invariants extend Laws 1, 4, and 6 of Physics/000-Laws.md. Every Organization, every Worker, every execution event exists within the context of a Mission. A system without Missions is a system without purpose.

---

## What Is a Mission?

A Mission is a constitutionally recognized operational entity that:

- Transforms strategic intent into measurable outcomes
- Coordinates Organizations, Departments, and Workers toward a common objective
- Defines objectives, responsibilities, resources, and success criteria
- Preserves observability, accountability, and constitutional governance throughout its lifecycle
- Is the highest-level unit of purposeful work inside AIOS

A Mission is not a task, not a workflow, not a process — it is the constitutional container within which all work occurs.

---

## The Mission Invariants

### Invariant 1 — Every Mission Originates from Human Intent

**Every Mission derives from a valid expression of Human Intent. The system cannot generate its own Missions.**

No Mission may be created, modified, or executed without originating from Human Intent. Sou may propose organizational strategy, but every strategy ultimately serves a Human-defined purpose. The chain of provenance from Human Intent to Mission is immutable evidence.

*Constitutional Expression*: Article I (Human Sovereignty) establishes that Human Intent is the sole source of authority. Article III, Part B, Section 005 (Missions) codifies this as constitutional governance.

*Enforcement*: The Security Kernel rejects any Mission that lacks a verified Human Intent provenance chain. Missions without a traceable origin to Human input are denied at the Execution Authorization stage. ACF validates the Intent provenance metadata on every Mission-related message.

*Edge Case*: A recurring or scheduled operation may be triggered automatically, but the Mission must still trace back to a Human-defined schedule or policy — the automation is a derived execution, not an original Mission. The Human wrote the schedule.

*Edge Case*: A cooperative Mission involving multiple Organizations — each participating Organization acts under the original Human Intent. No Organization may inject new objectives that are not derived from the original Intent.

*Violation*: Sou creating a Mission without any prior Human directive. An engine proposing new work that was not requested. An Organization splitting a Mission into sub-Missions that exceed the original Human Intent scope.

---

### Invariant 2 — Every Mission Belongs to Exactly One Organization

**A Mission always belongs to exactly one Organization. This binding is immutable for the Mission's lifetime.**

An Organization cannot exist without a Mission (Law 1 of Physics/000-Laws.md), and a Mission cannot exist without an owning Organization. The owning Organization is responsible for the Mission's lifecycle, resource allocation, Worker assignment, and completion verification.

Multiple Organizations may *participate* in a Mission (cooperation), but exactly one Organization *owns* it. The owning Organization bears constitutional responsibility for Mission success or failure.

*Constitutional Expression*: Article III, Part B, Section 001 (Organizations) defines the organizational framework within which Missions operate. Article III, Part B, Section 005 (Missions) specifies Mission ownership.

*Enforcement*: OSYS validates that every Mission is assigned to exactly one owning Organization before instantiation. ACF enforces that Mission-related commands from non-owning Organizations are flagged as cooperative actions, not ownership actions.

*Edge Case*: If the owning Organization is dissolved by OSYS, the Mission must be reassigned to another Organization or retired. The Mission cannot exist without an owner. OSYS enforces this before completing the Organization dissolution.

*Edge Case*: A Mission that spans multiple Organizations through cooperation — each participating Organization is bound by the owning Organization's Mission constraints. No participating Organization may independently extend or modify the Mission scope.

*Violation*: A Mission without an owning Organization. Two Organizations claiming ownership of the same Mission. An Organization dissolving while still owning active Missions without reassigning them.

---

### Invariant 3 — Every Execution Belongs to a Mission

**No execution exists outside a Mission. Every operational activity performed by AIOS belongs to a Mission.**

Every Worker invocation, every resource allocation, every API call, every computation — all execution traces back to exactly one Mission. There is no "free" execution. An action that does not belong to a Mission is an unauthorized action.

This invariant ensures that every action in the system is attributable, auditable, and governed by the Mission's policies, budget, and constraints.

*Constitutional Expression*: Article III, Part B, Section 005 (Missions) establishes that all operational activity is Mission-bound. Article IV, Part B, Section 009 (Execution Authorization) requires every execution to be authorized within its Mission context.

*Enforcement*: The Security Kernel verifies that every execution authorization token references a valid Mission. Workers may only execute actions within the scope of their assigned Mission. ACF routes all execution messages through Mission context validation.

*Edge Case*: System maintenance operations (health checks, log rotation, garbage collection) — these are typically scoped to a system-ownership Mission (e.g., "AIOS System Maintenance") that is created and owned by the platform itself under Human-defined operational policy.

*Edge Case*: A Worker that needs to perform an action that falls outside its assigned Mission's scope — this is a capability violation (Law 7, Physics/000-Laws.md) and must be denied. A new Mission or a new Worker with appropriate scope must be created.

*Violation*: A Worker executing code that is not traceable to any Mission. A Runtime allocating compute resources without a Mission context. An evidence event logged without a Mission identifier.

---

### Invariant 4 — Every Execution Begins as an Intent

**Every execution flows through: Human Intent → Mission → Execution. Intent precedes every action.**

The chain is: Human expresses Intent → Sou decomposes Intent into a Mission → OSYS assigns the Mission to an Organization → the Organization assigns Workers → Workers execute. No execution bypasses this chain. Every execution must be traceable back through this sequence to a Human Intent.

This invariant establishes that execution is never the first step — it is always the last step in a chain of planning, assignment, and verification.

*Constitutional Expression*: Article I (Human Sovereignty) establishes Intent as the source. Sou's constitutional mission (Article III, Part A, Section 002) is to convert Human Intent into Missions.

*Enforcement*: The Security Kernel verifies the complete Intent → Mission → Execution chain before issuing Execution Authorization. A missing or invalid link in the chain causes denial. ACF validates the chain on every execution message.

*Edge Case*: An automated Mission that executes on a recurring schedule — the Intent chain traces back to the Human who defined the schedule or policy. The Human defined the original Intent, and each recurrence is a derived Intent from that original policy.

*Edge Case*: A sub-Mission created by Sou during execution — the sub-Mission traces back to the parent Mission, which traces back to the original Human Intent. The provenance chain is extended, not broken.

*Violation*: An execution request with no Intent chain. A Worker acting without a Mission assignment. Sou creating a Mission that does not trace to any Human Intent.

---

### Invariant 5 — Every Intent and Every Execution Produces Evidence

**Every Intent produces an audit event. Every execution produces evidence. No invisible decision. No invisible action.**

When Human Intent is expressed, it is recorded. When Sou creates a Mission from that Intent, the Intent-to-Mission transformation is recorded. Every execution within the Mission produces evidence — what was done, by which Worker, under what authorization, with what outcome.

Evidence is immutable, timestamped, identity-attributed, and Mission-scoped. Evidence persists beyond the Mission's termination for audit and learning purposes.

*Constitutional Expression*: Article IV, Part B, Section 011 (Audit and Evidence) defines the constitutional framework. Law 4 of Physics/000-Laws.md (Law of Evidence) is the source law.

*Enforcement*: The Security Kernel will not authorize execution without a pre-declared evidence record. The Evidence System (EVS) validates evidence completeness. A missing evidence event is treated as a constitutional integrity violation.

*Edge Case*: A Mission that fails mid-execution — partial evidence is still preserved. Failure is recorded, not suppressed. The system learns from failure evidence.

*Edge Case*: A Worker that produces no output — the evidence record still shows that the Worker ran, consumed resources, and produced no output. Empty execution is still recorded.

*Violation*: An Intent expression that is not recorded. A Worker completing a Mission action without producing evidence. A Mission completion that lacks an evidence summary.

---

### Invariant 6 — Every Mission Has a Defined Lifecycle

**Every Mission traverses a defined lifecycle. A Mission exists in exactly one lifecycle state at all times.**

The canonical Mission lifecycle states are:

```
Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived
```

| State | Description | Allowed Actions |
|-------|-------------|-----------------|
| Created | Mission is registered but not yet planned. Identity is assigned. | Update metadata, assign to Sou for planning |
| Planned | Sou has decomposed Intent into objectives, constraints, budget, policies. | Assign to Organization, estimate resources |
| Assigned | Mission is assigned to an owning Organization. Workers may be allocated. | Resource allocation, Worker preparation |
| Running | Workers are actively executing Mission tasks. Evidence is being produced. | Execute, report progress, create sub-Missions |
| Waiting | Mission is waiting for an external dependency or sub-Mission completion. | None until dependency resolves |
| Paused | Mission is temporarily suspended. No execution occurs. | Resume or abort |
| Blocked | Mission cannot proceed due to an unresolvable constraint or failure. | Escalate, replan, or abort |
| Review | Mission execution is complete. Results are being verified against success criteria. | Verify evidence, evaluate success, approve |
| Completed | Mission objectives are met. Final evidence is sealed. Workers are terminated. | Archive |
| Archived | Mission record is preserved for audit. No further operations possible. | Read-only access |

*Constitutional Expression*: Article III, Part B, Section 006 (Lifecycles) establishes lifecycle requirements. Law 6 of Physics/000-Laws.md (Law of Lifecycle Compliance) is the source law.

*Enforcement*: The Lifecycle Management System (LMS) validates every state transition. Invalid transitions are denied. The Security Kernel verifies that the Mission is in an appropriate state before authorizing any action within it. An orphan Mission in an undefined state is a violation.

*Edge Case*: A Mission may skip intermediate states (e.g., from Assigned directly to Running if no dependencies are needed) but may not skip mandatory states (Created and Planned are always required). The transition path must always be valid.

*Edge Case*: A Mission stuck in Blocked state — if unresolved beyond a timeout, the Mission is escalated to Sou for replanning. Sou may replan, abort, or reassign. The Mission cannot remain Blocked indefinitely.

*Violation*: A Mission in Running state without having passed through Planned and Assigned. A Mission in Completed state without passing through Review. A Mission in an undefined state.

---

### Invariant 7 — Every Mission Has a Resource Budget

**Every Mission receives an explicit resource budget. No Mission may consume resources without constitutional allocation.**

A Mission's budget defines the upper bound of resources it may consume: CPU, memory, network, storage, API calls, Worker count, execution time. The budget is set at Mission creation and may only be modified through authorized replanning.

The budget is enforced throughout the Mission's lifecycle. Any Worker or Organization that consumes resources beyond the Mission's budget triggers a violation.

*Constitutional Expression*: Article III, Part A, Section 006 (ROS — Resource Orchestrator) defines resource governance. ROS allocates resources to Missions within constitutional bounds.

*Enforcement*: ROS monitors resource consumption per Mission. The Security Kernel verifies every resource allocation against the Mission's budget. Exceeding the budget triggers denial and escalation to Sou for replanning.

*Edge Case*: A Mission that legitimately requires more resources than budgeted — Sou must approve a budget extension, or the Mission must be replanned. The system cannot extend its own budget.

*Edge Case*: A Mission that completes with unconsumed budget — the remaining budget is returned to the Organization for other Missions. Budget is not consumed speculatively.

*Violation*: A Worker consuming CPU beyond the Mission's CPU budget. A Mission running longer than its allocated execution time. An Organization allocating resources to a Mission without ROS authorization.

---

### Invariant 8 — Missions Never Execute Work Themselves

**Missions exist to coordinate execution. They do not execute work themselves.**

A Mission is a coordination and governance entity. It defines objectives, assigns responsibility, tracks progress, and verifies completion. Execution is performed by Workers. A Mission cannot directly invoke Runtime, cannot allocate hardware, cannot bypass the Security Kernel.

The separation between Mission (coordination) and Worker (execution) is constitutional. A Mission that attempts to execute directly is violating the separation of coordination and execution.

*Constitutional Expression*: Article III, Part B, Section 005 (Missions) defines Missions as coordination entities. Article III, Part B, Section 004 (Workers) defines Workers as execution entities. This separation mirrors the Sou/OSYS/Worker strategy-execution split.

*Enforcement*: The Security Kernel verifies that every execution request originates from a Worker, not from a Mission. ACF blocks execution messages from Mission entities. The Security Kernel does not issue execution tokens to Missions.

*Edge Case*: A Mission may contain automated decision logic (e.g., "if condition X, create sub-Mission Y") but this logic is planning, not execution. The decision output is a new Mission or assignment, not a direct Runtime call.

*Violation*: A Mission attempting to spawn a Worker directly. A Mission sending execution commands to a Runtime. A Mission allocating hardware resources without going through ROS.

---

### Invariant 9 — Missions Never Own Workers

**Missions reference Workers. Workers remain owned by Organizations.**

A Mission may have Workers assigned to it, but those Workers belong to the Organization, not the Mission. The Organization creates, manages, and terminates Workers. The Mission defines the work objectives; the Organization supplies the execution capacity.

When a Mission completes, its assigned Workers are returned to the Organization (or terminated, per the Worker's lifecycle). The Mission does not retain ownership beyond its lifecycle.

*Constitutional Expression*: Article III, Part B, Section 005 (Missions) specifies Mission-Worker relationships. Article III, Part B, Section 004 (Workers) specifies Worker ownership.

*Enforcement*: OSYS verifies that Workers are assigned by Organizations, not by Missions. The Security Kernel validates that every Worker belongs to an Organization before permitting execution.

*Edge Case*: A Mission requesting a Worker with specific skills — the Organization determines which Worker to assign. The Organization may create a new Worker for the Mission or select an existing Worker from its pool.

*Edge Case*: A Mission that requires a Worker across multiple Organizations — this requires the owning Organization to establish a cooperative agreement with the other Organization. The Worker still belongs to its originating Organization.

*Violation*: A Mission claiming ownership of a Worker. A Worker that outlives the Mission continuing to execute under the Mission's identity. An Organization dissolving a Worker's owning Organization without reassigning the Worker.

---

### Invariant 10 — Every Mission Has Measurable Success Criteria

**Mission completion is evaluated against measurable criteria. Success must be explainable.**

Every Mission defines success criteria at creation: objective completion thresholds, quality metrics, security compliance, performance targets, budget compliance, timeline adherence, evidence completeness, and Human approval gates where required.

A Mission is not complete simply because execution stopped. It is complete when its success criteria are demonstrably met. If the Mission fails, the failure is recorded with evidence.

*Constitutional Expression*: Article III, Part B, Section 005 (Missions) defines Mission completion requirements.

*Enforcement*: The Review state is mandatory — every Mission must pass through Review before entering Completed. The Security Kernel validates evidence completeness during Review. Sou may perform a final review, or Human approval may be required (as defined by the Mission's policies).

*Edge Case*: A Mission with all objectives completed but with incomplete evidence — the Mission is blocked until evidence is verified. Evidence completeness is a success criterion.

*Edge Case*: A Mission that partially succeeds — some objectives met, others not. The success evaluation determines which objectives were achieved. Partial completion is documented, and remaining objectives may become a new Mission.

*Violation*: A Mission moving to Completed without passing through Review. A Mission completion that lacks evidence. A Mission that does not meet its success criteria but is marked as completed.

---

## The Intent-to-Execution Chain

The full constitutional chain from Human Intent to completed execution:

```
Human Intent
     │
     ▼
Strategic Planning (Sou)
     │  Sou decomposes Intent into Mission strategy
     ▼
Mission Creation
     │  Mission is created with objectives, budget, success criteria
     ▼
Organization Planning (Sou + OSYS)
     │  OSYS assigns Mission to an Organization
     ▼
Resource Planning (ROS)
     │  ROS allocates resources from the Mission's budget
     ▼
Security Verification (Security Kernel)
     │  Identity → AuthN → AuthZ → Policy → Capability → Risk → Authorization
     ▼
Worker Execution (Workers)
     │  Workers execute Mission tasks
     ▼
Observation (AOP)
     │  Progress is observed and recorded
     ▼
Learning Verification (Academy)
     │  Mission outcomes are evaluated as knowledge
     ▼
Knowledge (Academy)
     │  Lessons learned are preserved
```

Skipping or reordering any constitutional stage is prohibited. The chain is sequential, mandatory, and produces evidence at every step.

---

## Mission Identity

Every Mission has a constitutional identity (per Law 5, Physics/000-Laws.md):

| Property | Description |
|----------|-------------|
| Mission ID | Globally unique, immutable identifier assigned by IRS |
| Mission Genome | Defines Mission type, behavior patterns, lifecycle constraints |
| Priority | Relative importance for resource allocation |
| Lifecycle State | Current state in the Mission lifecycle |
| Owning Organization | The Organization responsible for this Mission |
| Participating Organizations | Organizations cooperating on this Mission |
| Assigned Workers | Workers currently executing Mission tasks |
| Objectives | What the Mission aims to achieve |
| Success Criteria | How completion is measured |
| Budget | Resource bounds (CPU, memory, time, cost) |
| Evidence Chain | Immutable record of all actions taken |

---

## Mission and Other Lifecycles

The Mission lifecycle interacts with other entity lifecycles:

| Entity | Relationship |
|--------|-------------|
| Organization | Mission belongs to Organization. If Organization dissolves, Mission must reassign or retire. |
| Worker | Worker executes Mission tasks. When Mission completes, Workers are terminated or returned to Organization pool. |
| Identity | Mission identity exists from Created to Archived — persists beyond execution. |
| Resource | Resources are allocated per Mission budget. When Mission ends, resources are freed. |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 1 (Origin), Law 4 (Evidence), Law 6 (Lifecycle) — source laws |
| Physics/003-Organizations.md | Organization invariants — Mission ownership (Invariant 2) |
| Physics/004-Sessions.md | Session invariants — Sessions executing within Mission context |
| Physics/005-Events.md | Evidence invariants — Intent produces audit events (Invariant 5) |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants — Mission lifecycle (Invariant 6) |
| Physics/007-Capabilities.md | Capability bound invariants — Mission scope and Worker capabilities |
| Physics/008-Security.md | Security invariants — Mission verification chain |
| Physics/009-Interaction.md | Interaction invariants — Mission communication through ACF |
| Constitution, Article III, Part A, Section 002 (Sou) | Sou's role in Intent-to-Mission decomposition |
| Constitution, Article III, Part B, Section 001 (Organizations) | Organization governance and Mission ownership |
| Constitution, Article III, Part B, Section 005 (Missions) | Constitutional Mission definition and governance |

---

## Future Extensions

These invariants are expected to remain stable. Future Mission-related specifications in the Bible (Bible/03-Institutions/Missions/) will define Mission Genome composition, sub-Mission delegation patterns, Mission cost analysis and billing, Mission failure recovery strategies, and cross-system Mission federation (for distributed AIOS).

---

*End of AIOS Physics 002 — Mission Invariants*