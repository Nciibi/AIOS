# AIOS DNA
## 002 — Entity Lifecycle Genetics

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | DNA |
| Document ID | DNA-002 |
| Source Laws | Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Every constitutional entity in AIOS inherits from a shared lifecycle model governed by LMS (Lifecycle Management Service). This document defines the genetic blueprint — the common lifecycle pattern that all entities share and the entity-specific specializations that derive from it. Entities that do not follow this lifecycle model are not constitutional entities.

## Canonical Lifecycle (The Base Genome)

```
Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived
```

| State | Description | Can Act? |
|-------|-------------|----------|
| Created | Entity record exists. Identity assigned. | No |
| Planned | Purpose, scope, and resources defined. | No |
| Assigned | Resources and capabilities allocated. | No |
| Running | Actively performing function. | Yes |
| Waiting | Waiting for external input or dependency. | No |
| Paused | Suspended by supervisor. Resumable. | No |
| Blocked | Cannot proceed due to failure. | No |
| Review | Requires review before completion. | Limited |
| Completed | Function fulfilled. Terminal. | No |
| Archived | Record preserved for audit. Terminal. | No |

## Entity-Specific Lifecycles

Each entity type inherits from the canonical model and specializes it — adding, removing, or constraining states and transitions.

### Worker Lifecycle (10-State)

```
Created → Planned → Assigned → Running ↔ Waiting ↔ Paused ↔ Blocked → Review → Completed → Archived
```

| Specialization | Detail |
|----------------|--------|
| States | All 10 canonical states |
| Running → Waiting | Worker identifies external dependency |
| Running → Paused | Supervisor pauses execution |
| Running → Blocked | Runtime failure, capability violation |
| Running → Review | Worker completion claim or policy trigger |
| Paused → Running | Supervisor resumes |
| Blocked → Running | Blocker resolved (by worker or supervisor) |
| Blocked → Review | Requires human assessment |
| Review → Running | Reviewer approves continuation |
| Review → Completed | Reviewer approves completion |
| Completed → Archived | Automatic, timer-based (retention policy) |

### Organization Lifecycle (7-State)

```
Created → Verified → Active → Suspended → Restored → Dissolved → Archived
```

| Specialization | Detail |
|----------------|--------|
| States | 7 states (no Planned, Assigned, Waiting, Paused, Blocked, Review) |
| Created → Verified | Structure and constitutional compliance verified |
| Verified → Active | Activated by Security Council |
| Active → Suspended | Violation or Security Council order |
| Suspended → Restored | Remediation complete |
| Active → Dissolved | Permanent dissolution |
| Dissolved → Archived | Automatic, timer-based |

### Mission Lifecycle (10-State)

```
Created → Planned → Staffed → Running → Waiting → Paused → Blocked → Review → Completed → Archived
```

| Specialization | Detail |
|----------------|--------|
| States | All 10 canonical, with Assigned replaced by Staffed |
| Staffed | Workers assigned and resourced |
| Running | Mission execution underway |
| Completed | All goals met |
| Archived | Mission record preserved, includes all worker outputs |

### Sou Lifecycle (Simplified)

```
Initialized → Active → Reflecting → Idle → Suspended → Archived
```

| Specialization | Detail |
|----------------|--------|
| States | 6 states (simplified — Sou is permanent, not task-bound) |
| Initialized | Brain startup, identity loaded |
| Active | Fully operational, reasoning, deciding, delegating |
| Reflecting | Learning from completed missions, integrating knowledge |
| Idle | No active input, waiting for user or event |
| Suspended | Human override or Security Council hold |
| Archived | Instance shutdown, state preserved |

### Session Lifecycle (Short-Lived)

```
Created → Starting → Running ↔ Paused → Terminating → Terminated
```

| Specialization | Detail |
|----------------|--------|
| States | 6 states (streamlined for transient sessions) |
| Starting | Sandbox initialization, resource allocation |
| Terminating | Graceful shutdown, resource cleanup |
| Terminated | Final state, all resources released |

### Genome Lifecycle (Template)

```
Drafted → Reviewed → Approved → Active → Superseded → Retired
```

| Specialization | Detail |
|----------------|--------|
| States | 6 states (template — not an executing entity) |
| Drafted | Initial authoring |
| Reviewed | Peer review for correctness and completeness |
| Approved | Security Council certification |
| Superseded | Replaced by newer genome version |
| Retired | No longer available for instantiation |

## Entity State Transition Matrix

| State | Entity Type | Allowed | Description |
|-------|-------------|---------|-------------|
| Created → * | Worker, Mission, Org | Planned, Archived | Standard forward path |
| Running → * | All | Waiting, Paused, Blocked, Review | Depends on trigger |
| Blocked → * | All | Running, Review, Archived | Resolution or escalation |
| Completed → Archived | All | Timer-based | Automatic after retention |
| Archived → * | All | None | Terminal — no exit |

## Design DNA Compliance

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each entity lifecycle is a focused state machine with one responsibility |
| R2 (Dependency Order) | Entity lifecycles depend on LMS which depends on Physics/006-Lifecycles.md |
| R3 (DRY) | Canonical lifecycle is defined once; entity types inherit and specialize |
| R4 (Builder Pattern) | Entity construction (IDS → AGS → LMS) is separate from lifecycle execution |
| R5 (Liskov) | Any entity at a given state behaves consistently regardless of type |
| R10 (Simpler Over Complex) | Lifecycles are linear — no branching complexity unless required by entity type |
| R13 (Design for Failure) | Blocked state exists for every executing entity type |
| R14 (Paved Path) | Canonical lifecycle is the paved path; entity specializations are documented deviations |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/00-Foundations/008-Object-Lifecycle.md | Canonical lifecycle specification |
| Bible/05-Platform/000-LMS.md | LMS — Lifecycle Management Service implementation |
| Bible/05-Platform/001-State-Machine.md | State machine framework |
| Bible/05-Platform/002-Transition-Validator.md | Transition validation rules |
| Physics/006-Lifecycles.md | Lifecycle Physics — normative invariants |
| Bible/03-Institutions/Workers/000-Overview.md | Worker lifecycle (10-state) |
| Bible/03-Institutions/Missions/000-Lifecycle.md | Mission lifecycle (10-state) |
| Bible/02-Core/OSYS/002-Org-Lifecycle.md | Organization lifecycle (7-state) |
| Bible/02-Core/Brain/Sou/000-Overview.md | Sou lifecycle (simplified) |
| Bible/04-Execution/Runtime/000-Overview.md | Session lifecycle (short-lived) |
| Bible/02-Core/AGS/004-Versioning.md | Genome lifecycle (template) |
| DNA/000-AIOS-DNA.md | Design DNA — R1–R15 foundational rules |
| DNA/001-Brain-DNA.md | Brain architectural invariants |
