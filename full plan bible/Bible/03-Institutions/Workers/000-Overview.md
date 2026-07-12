# AIOS Bible â€” Institutions
## Workers 000 â€” Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Institutions |
| Document ID | AIOS-BBL-003-WKR-000 |
| Source Laws | Law 3 â€” Law of Communication, Law 5 â€” Law of Identity, Law 6 â€” Law of Lifecycle Compliance, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/004-Sessions.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

A Worker is a Session (from Physics/004-Sessions.md) instantiated from a Template Genome (Core/AGS). Workers are the executing entities of AIOS â€” they perform actions within Missions under the authority of an Organization. Workers are temporary by design: they are created for a purpose, execute that purpose, and terminate when the purpose is complete.

This volume defines the Worker architecture: the Worker Object Model (structure, capabilities, lifecycle), Worker Health Service (health monitoring, timeouts, shutdown), Worker Security Service (isolation, boundaries), Worker Communication Service (inter-session messaging), and Playbook Manager (automated runbook execution).

## Worker Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                          Worker Instance                           â”‚
â”‚                                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”           â”‚
â”‚  â”‚ WOM (001)    â”‚  â”‚ WHS (002)    â”‚  â”‚ WSS (003)    â”‚           â”‚
â”‚  â”‚ Object Model â”‚  â”‚ Health Svc   â”‚  â”‚ Security Svc â”‚           â”‚
â”‚  â”‚ Session      â”‚  â”‚ Heartbeat,   â”‚  â”‚ Isolation,   â”‚           â”‚
â”‚  â”‚ Structure    â”‚  â”‚ Timeout,     â”‚  â”‚ Boundaries,  â”‚           â”‚
â”‚  â”‚ Lifecycle    â”‚  â”‚ Shutdown     â”‚  â”‚ Sandboxing   â”‚           â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜           â”‚
â”‚                                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                              â”‚
â”‚  â”‚ WCS (004)    â”‚  â”‚ Playbook     â”‚                              â”‚
â”‚  â”‚ Comm Service â”‚  â”‚ Manager (005)â”‚                              â”‚
â”‚  â”‚ Inter-       â”‚  â”‚ Automated    â”‚                              â”‚
â”‚  â”‚ Session Msg  â”‚  â”‚ Runbook Exec â”‚                              â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                              â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## What Is a Worker?

A Worker is a Session (per Physics/004-Sessions.md Invariants 1-10):

- **Created from a Template Genome** (AGS) â€” the Genome defines capabilities, bounds, policies, and provenance
- **Has a unique identity** (IDS) â€” globally unique, immutable, persists for the Worker's lifetime
- **Runs on a Runtime** â€” a concrete execution backend (Claude Code, Codex, Ollama, etc.)
- **Has context, permissions, and history** â€” isolated from all other Workers
- **Operates within capability bounds** â€” resource limits, execution time, autonomy level
- **Verified by Security Council** â€” every action passes through the verification pipeline
- **Temporary** â€” created for a Mission and destroyed when the Mission task is complete
- **Communicates through ACF** â€” no direct communication outside ACF
- **Has a defined lifecycle** â€” follows the canonical 10-state model

## Component Map

| File | Document | Function |
|------|----------|----------|
| 001-WOM.md | Worker Object Model | Session structure, capabilities, lifecycle, CRUD operations |
| 002-WHS.md | Worker Health Service | Heartbeat monitoring, timeouts, graceful shutdown |
| 003-WSS.md | Worker Security Service | Session isolation, sandboxing, boundary enforcement |
| 004-WCS.md | Worker Communication Service | Inter-session messaging via ACF |
| 005-Playbook-Manager.md | Playbook Manager | Runbook lifecycle, automated ops, step execution |

## 5 Invariants

1. **Session Identity**: Every Worker is a Session with a unique, immutable identity assigned by IRS. Identity is established at creation and retired at termination. No Worker operates without identity. (PHI-004, Physics/004 Invariant 2)

2. **Template Provenance**: Every Worker is instantiated from exactly one Template Genome (AGS). The Genome defines capabilities, bounds, policies, and runtime requirements. No Worker exists without a verified Genome. (Physics/004 Invariant 1)

3. **Mission Binding**: Every Worker executes within exactly one Mission. A Worker's actions are scoped to the Mission's objectives, budget, and constraints. No Worker executes outside a Mission. (Physics/002 Invariant 3)

4. **Organizational Authority**: Every Worker belongs to exactly one Organization. The Organization creates the Worker, assigns it to Missions, manages its lifecycle, and terminates it when work is complete. (Physics/003 Invariant 6)

5. **Lifecycle Compliance**: Every Worker follows the canonical 10-state lifecycle (Created â†’ Planned â†’ Assigned â†’ Running â†’ Waiting â†’ Paused â†’ Blocked â†’ Review â†’ Completed â†’ Archived). Workers exist in exactly one state at all times. (PHI-006, Physics/004 Invariant 9)

## Worker Lifecycle (10-State Model)

```
Created â†’ Planned â†’ Assigned â†’ Running â†’ Waiting â†’ Paused â†’ Blocked â†’ Review â†’ Completed â†’ Archived
```

| State | Description | Can Execute? |
|-------|-------------|-------------|
| Created | Session record exists. Identity assigned. Template loaded. | No |
| Planned | Purpose and scope defined. Runtime selected. Resources estimated. | No |
| Assigned | Mission and Organization assigned. Resources allocated. | No |
| Running | Worker is actively executing tasks. Producing evidence. | Yes |
| Waiting | Worker waiting for external input or dependency. | No |
| Paused | Execution suspended by supervisor. Context preserved. | No |
| Blocked | Worker cannot proceed due to failure or constraint. | No |
| Review | Worker output being verified against success criteria. | Limited |
| Completed | Worker purpose fulfilled. Evidence sealed. | No |
| Archived | Worker record preserved for audit. | No |

## Worker Creation Flow

The full Worker creation flow involves multiple systems coordinating through ACF:

```
1. Need identified (Org needs a Worker for a Mission task)
2. Org Admin or Manager requests Worker creation
   â†’ request includes: template_id, org_id, mission_id, capability_overrides

3. AGS validates template:
   â†’ template_id is a valid, Active Worker Genome
   â†’ Genome capabilities match Mission requirements

4. IDS creates identity:
   â†’ session_id assigned (globally unique, immutable)
   â†’ Identity lifecycle: Created â†’ Active

5. ROS allocates budget:
   â†’ Resource budget assigned from Org's allocation
   â†’ Token budget, compute, storage allocated per Genome defaults

6. ATS generates tokens:
   â†’ Authentication tokens for ACF communication
   â†’ Authorization tokens scoped to Mission + Org

7. LMS registers lifecycle:
   â†’ Worker enters Created state
   â†’ Transitions to Planned (automatic if plan provided)

8. Runtime binding:
   â†’ Runtime selected based on Genome requirements
   â†’ Worker sandbox initialized with isolation configuration

9. Worker is ready (Assigned state):
   â†’ Capabilities activated
   â†’ Worker added to Mission's Worker pool
   â†’ Event broadcast: WOM.WorkerCreated
```

## Worker Lifecycle Transitions Authorization

| Transition | Authorized By | Requires Evidence? |
|-----------|--------------|-------------------|
| Created â†’ Planned | Org Admin or Manager | Yes (Mission assignment, resource plan) |
| Planned â†’ Assigned | LMS (automatic when resources ready) | Yes (resource allocation confirmation) |
| Assigned â†’ Running | LMS (automatic when Mission is Running) | No |
| Running â†’ Waiting | Worker itself | Yes (dependency identified) |
| Running â†’ Paused | Org Supervisor or Security Council | Yes (pause reason) |
| Running â†’ Blocked | Worker itself (failure detection) | Yes (error details) |
| Running â†’ Review | Policy trigger or Worker itself | Yes (completion claim) |
| Waiting â†’ Running | LMS (automatic on dependency resolution) | Yes (dependency completion) |
| Paused â†’ Running | Org Supervisor | No |
| Blocked â†’ Running | Worker or Org Supervisor | Yes (resolution evidence) |
| Blocked â†’ Review | Org Supervisor | Yes (block details) |
| Review â†’ Running | Reviewer | Yes (review decision) |
| Review â†’ Completed | Reviewer | Yes (approval) |
| Completed â†’ Archived | LMS (automatic, timer-based) | Yes (retention policy) |

## Worker Capability Sources

Worker capabilities are determined by three sources (in order of precedence):

| Source | Description | Constraints |
|--------|-------------|-------------|
| Template Genome (AGS) | Base capabilities defined by the Genome | Cannot exceed Genome bounds |
| Org Policy | Organization adds or restricts capabilities | Cannot exceed Org's capability scope |
| Mission Context | Mission scopes capabilities to objectives | Cannot exceed Mission's resource budget |

Capabilities are verified by the Security Council before every action (Physics/007 Invariant 4).

## Worker Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Worker.Created` | Worker Session is created | worker_id, template_id, org_id, mission_id |
| `Worker.Activated` | Worker enters Running state | worker_id, runtime_id, activated_at |
| `Worker.Deactivated` | Worker leaves Running state | worker_id, from_state, to_state, reason |
| `Worker.Completed` | Worker purpose is fulfilled | worker_id, outcome, evidence_hash |
| `Worker.Terminated` | Worker is terminated | worker_id, reason, terminated_by |
| `Worker.Heartbeat` | Periodic health signal from Worker | worker_id, health_metrics, timestamp |
| `Worker.StateChanged` | Worker lifecycle state transitions | worker_id, from_state, to_state, authorized_by |


## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Compliant |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Compliant |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Compliant |
| R10 - Simpler Over Complex | Compliant |
| R13 - Design for Failure | Compliant |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

| R1 | Compliant |
| R2 | Compliant |
| R3 | Compliant |
| R4 | Compliant |
| R5 | Compliant |
| R6 | Compliant |
| R9 | Compliant |
| R10 | Compliant |
| R13 | Compliant |
| R14 | Compliant |
| R15 | Compliant |
## Cross-Cutting Concerns

### Security

Every Worker action is verified by the Security Council through the 7-stage verification pipeline. Workers are isolated execution contexts â€” no Worker may access another Worker's state, memory, or files. All Worker communication flows through ACF with Security Council authorization. (Physics/008-Security.md)

### Evidence

Every Worker action produces an Event. The complete lifecycle â€” from creation through termination â€” is recorded in the Event Store. Evidence is scoped to the Worker's Mission and Organization. (PHI-008)

### Lifecycle

Workers follow the canonical 10-state lifecycle. All lifecycle invariants apply: ordered states, authorized transitions, state-dependent capabilities. Worker lifecycle is constrained by parent Mission lifecycle. (PHI-006)

### Capability Bounds

Worker capabilities are bounded by three sources (Genome, Org policy, Mission context). Capabilities are state-dependent â€” a Worker in Paused state has no execution capabilities. All capability use is verified and recorded. (Physics/007-Capabilities.md)

### Communication

Workers communicate exclusively through ACF. No direct IPC, no shared memory, no side channels. Inter-Worker communication is managed by WCS and requires Mission-scope or Security Council authorization. (Law 3 â€” Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Worker component has a single responsibility |
| R4 (Builder) | Worker construction (via AGS â†’ IDS â†’ LMS) is separate from execution |
| R6 (DI over Singletons) | Worker dependencies are injected â€” no global state access |
| R10 (Simpler Over Complex) | Workers follow linear lifecycle â€” no branching complexity |
| R12 (Embrace Errors) | All errors have unique codes |
| R13 (Design for Failure) | Workers fail closed â€” deny on uncertainty, preserve evidence |
| R14 (Paved Path) | Paved path: Create â†’ Plan â†’ Assign â†’ Run â†’ Complete â†’ Archive |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/004-Sessions.md | Session Physics â€” canonical Worker invariants |
| Physics/005-Events.md | Evidence â€” every Worker action produces Events |
| Physics/006-Lifecycles.md | Lifecycles â€” canonical 10-state lifecycle |
| Physics/007-Capabilities.md | Capabilities â€” Worker capability bounds |
| Physics/008-Security.md | Security â€” Worker verification pipeline |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles |
| Bible/01-Governance/000-Overview.md | GOV-001â€“005 â€” governance identifiers |
| Bible/02-Core/AGS/000-Overview.md | AGS â€” Worker Template Genomes |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle â€” Workers belong to Orgs |
| Bible/02-Core/Sou/003-Missions.md | Missions â€” Workers execute Mission tasks |
| Bible/02-Core/ROS/005-Budget.md | ROS â€” Worker resource budgets |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Missions â€” Mission lifecycle constrains Workers |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations â€” Workers belong to Orgs |
| Bible/04-Execution/Security/IDS | IDS â€” Worker identity creation |
| Bible/04-Execution/Security/ATS | ATS â€” Worker authentication tokens
