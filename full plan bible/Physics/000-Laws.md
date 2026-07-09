# AIOS Physics
## 000 — The 10 Universal Laws

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-000 |
| Applies To | Entire AIOS Platform |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

Physics defines the universal system laws of AIOS. These are not rules, not guidelines, not governance — they are **invariants**. Mathematical truths that cannot be violated by any implementation, any upgrade, any override except Human Override under Article I of the Constitution.

Every engine, every institution, every line of code derives from these laws. A system that violates a Physics law is not AIOS.

## What Physics Is Not

- Physics is not documentation. It defines what MUST always be true, not what the system looks like.
- Physics is not code. It defines invariants, not algorithms.
- Physics is not governance. The Constitution decides who is allowed to do what. Physics decides what is fundamentally possible.
- Physics is not a style guide. The Bible defines how AIOS is built.
- Physics is not a process. RFCs define how the system changes.

## What Physics Requires

Every tier below Physics must reference the laws it derives from. Every Bible specification must state which Physics laws govern its subsystem. Every RFC must assess whether the proposed change is compatible with all 10 laws. Every implementation must be verifiable against the invariants.

---

## Relationship to Other Tiers

```
DNA          — Who are we?           Philosophical truth. Never changes.
Constitution — What is allowed?      Governance truth.  Rarely amended.
Physics      — What MUST always be   Mathematical truth. Never violated.
               true?
Bible        — How is AIOS built?    Engineering truth. Continuously evolves.
RFC          — How do we change?     Process truth.      Transient.
Code         — How is it             Implementation.    Must obey Bible.
               implemented?
```

Physics sits between Constitution and Bible. It must obey the Constitution. The Bible must obey Physics. The code must obey the Bible. Every layer depends on the layer above it.

---

## The 10 Universal Laws

### Law 1 — Law of Origin

**The Human is the absolute source of authority. All Missions derive from Human Intent.**

No Mission may be created, modified, or executed without originating from a valid expression of Human Intent. The system cannot generate its own Missions. Sou may propose organizational strategy, but every strategy ultimately serves a Human-defined purpose.

*Rationale*: This is the first law because it establishes AIOS as a servant system. Without this law, AIOS becomes an autonomous entity pursuing its own goals.

*Violation*: An engine creating a Mission without Human Intent.

---

### Law 2 — Law of Non-Execution

**Sou never executes. It decides, observes, learns — never operates.**

Sou is the strategic authority. It determines which Organizations are needed, what knowledge to acquire, and what simulations to run. It does not execute actions, does not allocate resources, does not run code. Execution is delegated through OSYS to Workers, verified by the Security Kernel.

*Rationale*: Separating strategy from execution prevents concentration of power. This is the system-level equivalent of the Separation of Powers in Article II.

*Violation*: Sou directly invoking a Worker or modifying a resource.

---

### Law 3 — Law of Communication

**Nothing bypasses the AI Communication Fabric (ACF). All inter-entity communication flows through ACF.**

No entity — Sou, Academy, OSYS, Security Kernel, Organization, Worker, Runtime — may communicate with another entity through any channel other than ACF. No direct IPC, no shared memory, no side channels. ACF is the only medium.

*Rationale*: All communication must be observable, routable, auditable, and controllable. ACF is the universal switchboard. Bypassing it breaks the entire security and observability model.

*Violation*: Two Workers communicating via Unix domain sockets instead of ACF messages.

---

### Law 4 — Law of Evidence

**All decisions are recorded with evidence. No invisible decisions.**

Every strategic decision (Sou), every resource allocation (ROS), every authorization (Security Kernel), every execution (Worker), every lifecycle transition (OSYS) produces an evidence record containing: what was decided, by whom, on what basis, with what authorization, at what time, with what outcome.

*Rationale*: Without evidence, the system cannot be audited, cannot learn from mistakes, cannot be trusted. Evidence is the foundation of accountability.

*Violation*: A Worker completing a Mission without recording what actions it took.

---

### Law 5 — Law of Identity

**Every entity has exactly one identity, issued by the Identity and Registry Service (IRS). No anonymous agents.**

Every Sou, every Organization, every Department, every Worker, every Session, every Runtime, every Engine has exactly one immutable identity. Identity is established at creation, verified before every action, and preserved for the lifetime of the entity. Anonymous participation is impossible.

*Rationale*: Accountability requires identity. Without identity, you cannot attribute actions, enforce policies, or audit behavior.

*Violation*: A Worker executing without a registered identity.

---

### Law 6 — Law of Lifecycle Compliance

**Every entity follows its defined lifecycle. No orphan processes.**

Every entity type has a prescribed lifecycle (Draft → Validation → Approval → Instantiation → Active → Suspended → Archived for resources; Created → Planned → Assigned → Running → Completed for Missions; and so on). Every entity must be in exactly one lifecycle state at all times. Transitions are authorized events. An entity in an undefined state is a violation.

*Rationale*: Lifecycles guarantee deterministic behavior, clean teardown, and resource recovery. Orphan processes would consume resources indefinitely.

*Violation*: A Worker that continues running after its Mission is completed.

---

### Law 7 — Law of Capability Bounds

**Workers operate within declared capability bounds. No capability escalation without reauthorization.**

Every Worker declares its capabilities at creation (skills, permissions, resource limits, autonomy level). The Worker may not exceed these bounds during its lifetime. If a Mission requires capabilities beyond the Worker's declared bounds, a new Worker with appropriate capabilities must be created or the existing Worker must be reauthorized.

*Rationale*: Capability bounds are the fundamental security boundary. Without them, a compromised Worker could access anything.

*Violation*: A Worker coded as a text assistant attempting to execute system administration commands.

---

### Law 8 — Law of Verification-First

**Verification precedes execution for every action. No execution without verification.**

Every action, before it is executed, must pass through the Security Kernel verification pipeline: Identity Check → Authentication → Authorization → Policy Evaluation → Capability Check → Risk Assessment → Execution Authorization. No action may skip any stage.

*Rationale*: Execute-first, verify-later would allow damage before detection. Verification-first guarantees every action is authorized before it affects the system.

*Violation*: A Worker executing a resource allocation without a verified authorization token.

---

### Law 9 — Law of Constitutional Supremacy

**The AI Constitution is the supreme law of AIOS. No rule, code, or override may violate it — except Human Override under Article I of the Constitution.**

Every document in Physics, every specification in the Bible, every RFC, every line of implementation must be compatible with the Constitution. If any lower-tier document conflicts with the Constitution, the Constitution prevails.

*Rationale*: The Constitution defines governance, rights, obligations, and the separation of powers. It is the system's highest authority after Human Sovereignty. Without this law, lower tiers could contradict the fundamental governance model.

*Violation*: A Bible specification that grants an Organization authority that the Constitution assigns to the Security Kernel.

---

### Law 10 — Law of Tenure

**No permanent Workers. All Workers end. Organizations may endure but are subject to dissolution lifecycle.**

Workers are temporary by nature. Every Worker has a defined lifespan, mission scope, and retirement condition. When the condition is met (mission completed, time limit reached, parent organization dissolved), the Worker must terminate. Organizations may persist beyond individual Workers but may be dissolved by OSYS when their mission no longer exists.

*Rationale*: Permanent Workers would accumulate, consume resources, and eventually contradict their original purpose. Organizations serve strategy, and strategy evolves.

*Violation*: A Worker that refuses to terminate after its Mission completes.

---

## Immutability and Amendment

These 10 Laws are immutable under normal operation. They may only be changed through:

1. **Constitutional Amendment (Article V)**: A properly ratified amendment that explicitly cites the Physics law being modified and provides the rationale.
2. **Human Override (Article I, Section 004)**: A direct Human command that temporarily suspends a specific law for a specific operation. The override is recorded as evidence and subject to post-hoc audit.

Any amendment that weakens Law 1 (Origin) or Law 9 (Constitutional Supremacy) requires Human override — the system cannot reduce Human authority on its own.

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| AIOS Constitution, Article I | Human Sovereignty — basis for Law 1 and Law 9 |
| AIOS Constitution, Article II | Separation of Powers — governance expression derived from Law 2 |
| AIOS Constitution, Article III | Institutions and Society — organizational expression derived from Laws 6, 7, 10 |
| AIOS Constitution, Article IV | Security — verification and identity expression derived from Laws 5, 8 |
| Physics/001-Identity.md | Identity invariants — extends Law 5 |
| Physics/002-Missions.md | Mission invariants — extends Law 1 |
| Physics/003-Organizations.md | Organization invariants — extends Laws 6, 10 |
| Physics/004-Sessions.md | Session invariants — extends Laws 5, 7 |
| Physics/005-Events.md | Event and evidence invariants — extends Law 4 |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants — extends Law 6 |
| Physics/007-Capabilities.md | Capability bound invariants — extends Law 7 |
| Physics/008-Security.md | Security invariants — extends Laws 5, 8 |
| Physics/009-Interaction.md | Interaction invariants — extends Law 3 |
| Physics/010-Execution.md | Execution invariants — extends Law 2 |
| Physics/011-Design-DNA.md | 15 Design DNA Rules — engineering principles derived from these laws |
| Physics/012-Experience.md | Experience and learning invariants |

---

## Future Extensions

These laws are expected to remain stable. Future Physics files (001–012) will extend each law into domain-specific invariants for identity, missions, organizations, sessions, events, lifecycles, capabilities, security, interaction, and execution.

---

*End of AIOS Physics 000 — The 10 Universal Laws*