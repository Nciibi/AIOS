# AIOS Bible — Institutions
## Workers 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-WKR-000 |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity, Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/004-Sessions.md, Physics/005-Events.md, Physics/006-Lifecycles.md, Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

A Worker is a Session (from Physics/004-Sessions.md) instantiated from a Template Genome (Core/AGS). Workers are the executing entities of AIOS — they perform actions within Missions under the authority of an Organization. Workers are temporary by design: they are created for a purpose, execute that purpose, and terminate when the purpose is complete.

This volume defines the Worker architecture: the Worker Object Model (structure, capabilities, lifecycle), Worker Health Service (health monitoring, timeouts, shutdown), Worker Security Service (isolation, boundaries), Worker Communication Service (inter-session messaging), and Playbook Manager (automated runbook execution).

## Worker Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Worker Instance                           │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ WOM (001)    │  │ WHS (002)    │  │ WSS (003)    │           │
│  │ Object Model │  │ Health Svc   │  │ Security Svc │           │
│  │ Session      │  │ Heartbeat,   │  │ Isolation,   │           │
│  │ Structure    │  │ Timeout,     │  │ Boundaries,  │           │
│  │ Lifecycle    │  │ Shutdown     │  │ Sandboxing   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐                              │
│  │ WCS (004)    │  │ Playbook     │                              │
│  │ Comm Service │  │ Manager (005)│                              │
│  │ Inter-       │  │ Automated    │                              │
│  │ Session Msg  │  │ Runbook Exec │                              │
│  └──────────────┘  └──────────────┘                              │
└──────────────────────────────────────────────────────────────────┘
```

## What Is a Worker?

A Worker is a Session (per Physics/004-Sessions.md Invariants 1-10):

- **Created from a Template Genome** (AGS) — the Genome defines capabilities, bounds, policies, and provenance
- **Has a unique identity** (IDS) — globally unique, immutable, persists for the Worker's lifetime
- **Runs on a Runtime** — a concrete execution backend (Claude Code, Codex, Ollama, etc.)
- **Has context, permissions, and history** — isolated from all other Workers
- **Operates within capability bounds** — resource limits, execution time, autonomy level
- **Verified by Security Council** — every action passes through the verification pipeline
- **Temporary** — created for a Mission and destroyed when the Mission task is complete
- **Communicates through ACF** — no direct communication outside ACF
- **Has a defined lifecycle** — follows the canonical 10-state model

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

5. **Lifecycle Compliance**: Every Worker follows the canonical 10-state lifecycle (Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived). Workers exist in exactly one state at all times. (PHI-006, Physics/004 Invariant 9)

## Worker Lifecycle (10-State Model)

```
Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived
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

## Cross-Cutting Concerns

### Security

Every Worker action is verified by the Security Council through the 7-stage verification pipeline. Workers are isolated execution contexts — no Worker may access another Worker's state, memory, or files. All Worker communication flows through ACF with Security Council authorization. (Physics/008-Security.md)

### Evidence

Every Worker action produces an Event. The complete lifecycle — from creation through termination — is recorded in the Event Store. Evidence is scoped to the Worker's Mission and Organization. (PHI-008)

### Lifecycle

Workers follow the canonical 10-state lifecycle. All lifecycle invariants apply: ordered states, authorized transitions, state-dependent capabilities. Worker lifecycle is constrained by parent Mission lifecycle. (PHI-006)

### Capability Bounds

Worker capabilities are bounded by three sources (Genome, Org policy, Mission context). Capabilities are state-dependent — a Worker in Paused state has no execution capabilities. All capability use is verified and recorded. (Physics/007-Capabilities.md)

### Communication

Workers communicate exclusively through ACF. No direct IPC, no shared memory, no side channels. Inter-Worker communication is managed by WCS and requires Mission-scope or Security Council authorization. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each Worker component has a single responsibility |
| R4 (Builder) | Worker construction (via AGS → IDS → LMS) is separate from execution |
| R6 (DI over Singletons) | Worker dependencies are injected — no global state access |
| R10 (Simpler Over Complex) | Workers follow linear lifecycle — no branching complexity |
| R12 (Embrace Errors) | All errors have unique codes |
| R13 (Design for Failure) | Workers fail closed — deny on uncertainty, preserve evidence |
| R14 (Paved Path) | Paved path: Create → Plan → Assign → Run → Complete → Archive |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/004-Sessions.md | Session Physics — canonical Worker invariants |
| Physics/005-Events.md | Evidence — every Worker action produces Events |
| Physics/006-Lifecycles.md | Lifecycles — canonical 10-state lifecycle |
| Physics/007-Capabilities.md | Capabilities — Worker capability bounds |
| Physics/008-Security.md | Security — Worker verification pipeline |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
| Bible/01-Governance/000-Overview.md | GOV-001–005 — governance identifiers |
| Bible/02-Core/AGS/000-Overview.md | AGS — Worker Template Genomes |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle — Workers belong to Orgs |
| Bible/02-Core/Sou/003-Missions.md | Missions — Workers execute Mission tasks |
| Bible/02-Core/ROS/005-Budget.md | ROS — Worker resource budgets |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Missions — Mission lifecycle constrains Workers |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations — Workers belong to Orgs |
| Bible/04-Execution/Security/IDS | IDS — Worker identity creation |
| Bible/04-Execution/Security/ATS | ATS — Worker authentication tokens
