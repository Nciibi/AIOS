# AIOS Physics
## 006 — Lifecycle Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-006 |
| Applies To | All Lifecycles, Session Lifecycle, Mission Lifecycle, Organization Lifecycle, Entity Lifecycle, Lifecycle Management System (LMS) |
| Source Laws | Law 6 — Law of Lifecycle Compliance |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Lifecycles across all entity types within AIOS. A Lifecycle is the finite, ordered sequence of states that an entity traverses from creation to destruction. Every constitutional entity has a Lifecycle. Every Lifecycle is managed by the Lifecycle Management System (LMS).

These invariants extend Law 6 of Physics/000-Laws.md (Law of Lifecycle Compliance). They apply to Sessions (004), Missions (002), Organizations (003), Templates, Capabilities, Security Credentials, and all other constitutional entities.

---

## What Is a Lifecycle?

A Lifecycle is a constitutional state machine governing an entity from creation to destruction. Every entity exists in exactly one lifecycle state at all times. Lifecycle transitions are constitutional events — each transition is recorded as an Event, authorized by the Security Council, and managed by LMS.

The LMS is the constitutional authority for lifecycle management. It validates transitions, enforces invariants, and provides lifecycle query access.

---

## The Lifecycle Invariants

### Invariant 1 — Every Constitutional Entity Has a Lifecycle

**Every constitutional entity — Identity, Mission, Organization, Session, Template, Capability, Credential — has a defined Lifecycle. No entity exists outside the Lifecycle framework.**

Every entity type has a canonical set of states and allowed transitions. These are defined in this document and in the Bible (Bible/04-Execution/Lifecycle/).

Entity types and their lifecycles:

| Entity Type | Source Physics | Lifecycle States |
|------------|---------------|-----------------|
| Identity | 001-Identity | Created → Active → Suspended → Retired |
| Mission | 002-Missions | Created → Planned → Assigned → Running → Waiting → Paused → Blocked → Review → Completed → Archived |
| Organization | 003-Organizations | Draft → Provisional → Active → Suspended → Dissolved |
| Session | 004-Sessions | Created → Initialized → Active → Paused → Restarting → Completed → Failed → Destroyed |
| Template | (Bible) | Draft → Validated → Published → Deprecated → Retired |
| Capability | 007-Capabilities | Applied → Verified → Granted → Suspended → Revoked |
| Credential | (Bible) | Created → Active → Expired → Revoked |

*Constitutional Expression*: Law 6 of Physics/000-Laws.md. Article III, Part B, Section 006 (Lifecycles) explicitly states: "All AIOS entities have a defined lifecycle. Entities are always in exactly one lifecycle state. Lifecycle transitions are constitutional events."

*Enforcement*: LMS validates that every entity has a lifecycle definition. Entity creation fails without a lifecycle. LMS rejects state queries for entities without registered lifecycles.

*Edge Case*: An entity type not yet registered in LMS — the entity cannot be created until its lifecycle is defined. Adding a new entity type requires: defining canonical states, defining allowed transitions, registering with LMS, and updating this document.

*Edge Case*: An entity that transitions to an undefined state — LMS rejects the transition. The entity remains in its current state. The event is logged as a failed transition attempt.

*Violation*: An entity operating without a lifecycle. An entity created before its lifecycle type is registered. An entity in a state not defined in its lifecycle.

---

### Invariant 2 — Every Entity Is in Exactly One Lifecycle State

**At any moment, an entity exists in exactly one lifecycle state. No entity exists in multiple states simultaneously. No entity exists in no state.**

The current state represents the entity's constitutional status. All decisions about the entity — what it can do, who can interact with it, what resources it can access — are determined by its current lifecycle state.

Entity states are discrete and non-overlapping. An entity cannot be in both "Active" and "Paused" simultaneously. An entity cannot be "betwixt" states — every state change transitions the entity to a defined next state.

*Constitutional Expression*: "All entities are always in exactly one lifecycle state" (Article III, Part B, Section 006). This is restated in every lifecycle discussion throughout the Constitution.

*Enforcement*: LMS maintains the authoritative state for every entity. State is recorded as an Event (Invariant 2 of Events). The Event stream is the source of truth for state. LMS rejects state queries that return multiple states.

*Edge Case*: An entity whose state query returns no state — this is a system error. The entity was created but LMS lost its state. LMS recovers by replaying the entity's Event stream to reconstruct its current state.

*Edge Case*: An entity whose Event stream shows ambiguity (e.g., two concurrent "Active" transitions) — LMS uses the monotonic clock to order transitions. The last Event in the causal chain is authoritative.

*Violation*: An entity reported as being in two states simultaneously. An entity with no state after creation. An entity that is acted upon before its state is established.

---

### Invariant 3 — Every Lifecycle Transition Is Authorized

**No lifecycle transition occurs without authorization. Every transition is verified by the Security Council before execution.**

Transitions require authorization for the: entity identity (is this entity allowed to transition?), current state (does the current state allow this transition?), target state (is the target state a valid transition from the current state?), authorizing entity (does the requester have authority to request this transition?), and context (is the transition appropriate given the entity's context?).

Authorization is not automatic. Even valid transitions must pass Security Council verification. A transition that is grammatically valid (the state machine allows it) may be denied if the Security Council determines it is not constitutionally appropriate.

*Constitutional Expression*: Law 6 (Lifecycle Compliance): "Every lifecycle transition is a constitutional event, authorized by the Security Council." Law 8 (Verification-First) applies to all constitutional events including lifecycle transitions.

*Enforcement*: LMS submits every transition request to the Security Council. The Security Council verifies transition authorization and returns an authorization token. LMS performs the transition only with a valid token. Unauthorized transitions are rejected.

*Edge Case*: A transition that is part of an automatic process (e.g., Session expires → Session Terminated) — the authorization is pre-approved by the conditions triggering the transition. The Security Council's verification confirms the conditions are met.

*Edge Case*: A transition that is requested by an entity without authority (e.g., a Mission requesting to transition an Organization) — LMS rejects the transition. The requesting entity's identity is logged. The unauthorized request produces a Security Event.

*Violation*: A lifecycle transition that occurs without Security Council authorization. An entity that self-transitions without authorization. A LMS that performs transitions without verification.

---

### Invariant 4 — Lifecycle States Are Ordered

**Lifecycle states are ordered. Forward transitions move toward termination or entropy. Backward transitions are explicitly defined and restricted.**

States have an inherent directionality:
- **Forward transitions** move an entity toward its natural completion (Active → Completed, Mission active → Mission complete)
- **Backward transitions** move an entity backward in its lifecycle (Active → Paused, Completed → Active). Backward transitions are restricted and require higher authorization.
- **Terminal states** are the end of an entity's lifecycle (Destroyed, Dissolved, Retired). No transitions from terminal states.

Forward transitions are standard operations. Backward transitions are exceptional and require justification.

*Constitutional Expression*: Article III, Part B, Section 006 reinforces directional ordering: "Backward transitions are allowed only when the outcome preserves the entity." This is reflected in the canonical state machines.

*Enforcement*: LMS maintains a transition directionality matrix. Backward transitions require a rationale and higher authorization level. LMS logs the authorization level for every transition.

| Entity | Forward Examples | Backward Examples | Terminal |
|--------|-----------------|-------------------|----------|
| Session | Created → Active → Completed | Active → Paused (authorized), Paused → Active (authorized) | Destroyed |
| Mission | Active → Completed | Active → Paused (authorized only), Completed → Active (never) | Completed, Failed, Abandoned |
| Organization | Draft → Active | Active → Draft (never), Active → Suspended → Active (authorized) | Dissolved |
| Identity | Created → Active → Retired | Active → Suspended → Active (authorized) | Retired |

*Edge Case*: A backward transition that would violate the entity's constitutional integrity (e.g., reactivating a dissolved Organization) — the transition is denied. Dissolution is a terminal state. A new Organization must be formed.

*Edge Case*: A backward transition that is part of a natural lifecycle rhythm (e.g., Session Active → Paused → Active) — this is a forward-backward-forward pattern. The Paused state is a temporary suspension, not a reversal. Paused → Active is forward relative to the Paused state.

*Violation*: A backward transition that is not defined in the state machine. A terminal-to-non-terminal transition. An entity that is revived after terminal destruction without a constitutional amendment.

---

### Invariant 5 — Lifecycle Transitions Produce Events

**Every lifecycle transition produces exactly one Event. The Event records the from-state, to-state, entity, authorizing entity, timestamp, and rationale.**

The Event schema for lifecycle transitions includes: Event ID (globally unique), Entity ID (the entity being transitioned), From State (previous state of the entity), To State (new state of the entity), Authorizing Entity (the entity that authorized the transition), Rationale (why the transition was made), Timestamp (IRS-assigned monotonic timestamp), and Authorization Token (the Security Council token authorizing the transition).

*Constitutional Expression*: Law 1 (Evidence) — all constitutional processes produce evidence. Law 6 (Lifecycle Compliance) — lifecycle transitions are constitutional events.

*Enforcement*: LMS instruments every transition to produce an Event before and after the transition. The Event Store stores lifecycle transition Events. Lifecycle transition Events are immutable (per Event Invariant 2).

*Edge Case*: A lifecycle transition that fails partway through — the Event records the transition attempt and the failure. The entity remains in its original state. The failure Event links to the attempted transition.

*Edge Case*: A lifecycle transition that is rolled back — the rollback is a separate transition Event. The entity goes from the new state back to the original state. The rollback is logged with both transitions.

*Violation*: A lifecycle transition that occurs without a corresponding Event. An Event that records a transition that did not happen. An Event that records the wrong state for a transition.

---

### Invariant 6 — Entity Capabilities Are State-Dependent

**An entity's capabilities, permissions, and responsibilities depend on its current lifecycle state. An entity in one state has different capabilities than the same entity in another state.**

The capability-state mapping defines what an entity can do in each state. For example, a Mission in "Active" state can assign tasks to Sessions. A Mission in "Completed" state cannot. An Organization in "Draft" state cannot receive Missions. An Organization in "Active" state can.

*Constitutional Expression*: Law 6 (Lifecycle Compliance) states that "capabilities, permissions, and responsibilities" are state-dependent. Article IV, Part B, Section 007 (Capability Verification) applies per-state.

*Enforcement*: The Security Council checks the entity's current state before authorizing any action. Action authorization includes state verification. LMS provides state-to-capability mapping queries.

**Capability-State Matrix (Mission):**

| State | Assign Tasks | Execute Tasks | Accept New Instructions | Request Resources | Transition State |
|-------|-------------|---------------|------------------------|-------------------|-----------------|
| Created | No | No | No | No | To Planned |
| Planned | Yes (Initial) | No | Yes | Yes | To Assigned |
| Assigned | Yes | No | Yes | Yes | To Running |
| Running | Yes | Yes | Yes | Yes | To Waiting/Paused/Blocked/Review |
| Waiting | No | No | Yes (status only) | No | To Running (dependency resolved) |
| Paused | No | No | No | Yes (resources preserved) | To Running, Blocked |
| Blocked | No | No | No | Yes (resources held) | To Review (escalated), Planned (replan) |
| Review | No | No | No | No | To Completed, Running (rework) |
| Completed | No | No | No | No | To Archived (terminal) |
| Archived | No | No | No | No | (terminal) |

**Capability-State Matrix (Session):**

| State | Execute | Receive Messages | Produce Events | Manage Resources | Transition State |
|-------|---------|-----------------|---------------|------------------|-----------------|
| Created | No | No | No | No | Yes (to Initialized) |
| Initialized | No | No | No | Yes (pre-allocation) | Yes (to Active) |
| Active | Yes | Yes | Yes | Yes | Yes (to Paused, Restarting, Completed, Failed) |
| Paused | No | No | No | Yes (resources held) | Yes (to Active, Restarting, Failed) |
| Restarting | Recovery only | No | No | Yes (restore) | Yes (to Active, Failed) |
| Completed | No | No | No | No | Yes (to Destroyed) |
| Failed | No | No | No | No | Yes (to Restarting, Destroyed) |
| Destroyed | No | No | No | No | (terminal) |

*Edge Case*: An entity that needs to perform an action in a state that normally does not allow that action (e.g., a Paused Mission receiving critical instructions) — the entity must first transition to an appropriate state. The Security Council may authorize an exceptional transition.

*Edge Case*: An entity in a transitional state (e.g., Restarting) that needs limited capabilities — the transition state itself may have a small subset of capabilities. Restarting allows recovery capabilities but not execution capabilities.

*Violation*: An entity performing actions not allowed in its current state. A Session in Paused state executing tasks. A Mission in Completed state attempting to assign tasks.

---

### Invariant 7 — Lifecycles Are Managed by LMS

**The Lifecycle Management System (LMS) is the constitutional authority for lifecycle management. All lifecycle operations go through LMS.**

LMS is responsible for: registering entity lifecycle types, tracking current state for every entity, validating transition requests, submitting transitions to the Security Council for authorization, executing authorized transitions, producing lifecycle transition Events, providing lifecycle query API to authorized entities, managing lifecycle state recovery, and enforcing state-dependent capability matrices.

LMS is a constitutional institution. No other entity performs lifecycle management. No entity bypasses LMS for state transitions.

*Constitutional Expression*: Law 6 (Lifecycle Compliance) establishes LMS. Article III, Part A, Section 004 (LMS) defines LMS's constitutional responsibilities. Article III, Part B, Section 006 (Lifecycles) identifies LMS as the constitutional authority.

*Enforcement*: LMS validates all lifecycle operations. Bypassing LMS is a constitutional violation. The Security Council validates that LMS is the only entity performing lifecycle operations.

*Edge Case*: A Runtime that directly transitions a Session's state (e.g., the Runtime detects the Session is unresponsive and marks it as failed) — the Runtime reports the condition to LMS. LMS processes the transition. The Runtime does not directly modify state.

*Edge Case*: A failure in LMS itself — LMS is a redundant system. A standby LMS instance takes over. Lifecycle operations are paused until the takeover is complete. The Event stream ensures no transitions are lost.

*Violation*: An entity that directly modifies its own lifecycle state. An entity that bypasses LMS for a state transition. A system that manages lifecycles without constitutional authority.

---

### Invariant 8 — State Machines Are Hierarchical

**Lifecycle state machines compose hierarchically. An entity's lifecycle state constrains and is constrained by its parent entities' lifecycle states.**

A hierarchy exists: Organization → Mission → Session. An Organization's lifecycle state constrains the Missions and Sessions under it. A Mission's lifecycle state constrains the Sessions executing it. A Session's lifecycle state is independent within the constraints of its parent entities' states.

| Parent State | Child Constraint |
|------------|-------------------|
| Organization: Active | Missions and Sessions can be Active |
| Organization: Suspended | Missions and Sessions are Paused or Suspended |
| Organization: Dissolved | Missions and Sessions are terminated |
| Mission: Active | Sessions can be Active |
| Mission: Paused | Sessions are Paused |
| Mission: Completed | Sessions are completed or terminated |
| Mission: Failed | Sessions are terminated |

Hierarchical constraints are enforced by LMS. An Organization transition to Dissolved triggers cascading transitions for all child entities. The cascading transitions are processed through LMS in order, with each transition individually authorized.

*Constitutional Expression*: Hierarchical lifecycle constraints are implicit in the constitutional structure (Organizations contain Missions, Missions contain Sessions). Article III, Part A, Section 003 (Organizations) and Section 004 (LMS) establish the hierarchy.

*Enforcement*: LMS validates hierarchical constraints on every parent transition. Cascading transitions are authorized by the same Security Council authorization that authorized the parent transition. LMS processes cascading transitions atomically — all children transition or none.

*Edge Case*: An Organization transitioning from Active to Suspended — all child Missions and Sessions are transitioned to Paused. The cascading transitions preserve entity state. When the Organization returns to Active, child entities may be returned to their previous active states.

*Edge Case*: An Organization that is dissolved while it has active Missions — the Missions are terminated. The Session contexts are sealed. Evidence is preserved. The Organization's dissolution Event records the cascading termination.

*Violation*: A Session that remains Active while its parent Mission is Completed. An Organization that is dissolved while children continue executing. A child entity that ignores a parent state change.

---

### Invariant 9 — Lifecycle Definitions Are Themselves Governed by Lifecycles

**Lifecycle definitions (the state machines themselves) have a lifecycle. Definitions are versioned. Definition changes are constitutional events.**

A lifecycle definition goes through its own lifecycle: Draft → Review → Approved → Published → Active → Deprecated → Retired. Changes to a lifecycle definition do not affect entities currently in that lifecycle — entities continue with the version of the lifecycle definition they started under.

Lifecycle definitions are versioned artifacts stored in the Lifecycle Registry. Version increments occur when: states are added or removed, transitions are added or removed, capability-state mappings are modified, or authorization requirements are changed.

*Constitutional Expression*: Lifecycles themselves are constitutional artifacts. Changes to the constitutional definition of lifecycles require constitutional process (Article VI).

*Enforcement*: The LMS Lifecycle Registry validates that new lifecycles comply with Lifecycle Physics. Lifecycle definition changes are recorded as constitutional Events. Entities reference their lifecycle definition version.

*Edge Case*: A lifecycle definition that needs to be updated for new entity types — the new definition goes through Draft → Review → Approved → Published → Active. Existing entities continue under the old version. New entities use the new version.

*Edge Case*: A lifecycle definition that is found to contain an error — the error is corrected in a new version. Entities currently in the erroneous state are transitioned through a constitutionally authorized migration process. The migration process produces Events for each entity transitioned.

*Violation*: A lifecycle definition that is modified while entities are actively using it. A lifecycle definition that is published without going through the definition lifecycle. A lifecycle definition that violates Lifecycle invariants.

---

### Invariant 10 — Lifecycle States Are Observable

**Any entity's lifecycle state is observable through constitutional query. State is not hidden. State queries are authorized but not denied to in-network entities.**

Every entity's current state is accessible through LMS queries. State is not private — it is a constitutional fact that affects interaction. An entity can query the state of any other entity within its authorized scope. A Session can query its own state. An Organization can query the state of its child Missions and Sessions.

State queries are authorized (Invariant 7 — Event Access), but authorization is broad for in-network entities. An entity's state is visible to: the entity itself, the entity's parent Organization, the Security Council, any entity with constitutional authority over the entity type, and LMS.

*Constitutional Expression*: State observability is inherent in the Lifecycle framework. Article IV, Part B, Section 006 (Lifecycles) defines state access.

*Enforcement*: LMS provides a State Query API. The API is protected by Security Council authorization. LMS logs all state queries as Events.

*Edge Case*: An entity whose state is sensitive (e.g., a Security Council investigation entity) — state visibility is restricted. The Security Council may limit state queries for specific entities. The restriction is logged as an Event.

*Edge Case*: An entity that queries the state of an entity outside its constitutional scope — the query is denied. The denial is logged as a Security Event.

*Violation*: A lifecycle state that is accessible without authorization. An entity that is prevented from querying its own state. A state query that returns the wrong state.

---

## Lifecycle Transition Authorization Levels

| Level | Authorizing Entity | Use Case |
|-------|-------------------|-----------|
| L1 — Automatic | Condition-based | Idle timeout, resource exhaustion, mission completion |
| L2 — Entity Self | Session or Mission | Mission pause, session pause |
| L3 — Organization | Parent Organization | Mission reassignment, session extension |
| L4 — Security Council | Security Council | Suspension, force termination, emergency transitions |
| L5 — Constitutional | Council | Dissolution, constitutional exemption |

---

## Cross-Entity Lifecycle Dependency Table

| Parent Entity State | Child Entity Allowed States |
|--------------------|---------------------------|
| Organization: Draft | None (children cannot exist) |
| Organization: Active | Mission: Created, Active, Paused, Suspended; Session: any |
| Organization: Suspended | Mission: Paused, Suspended; Session: Paused |
| Organization: Dissolved | All children: terminal states |
| Mission: Created | Session: Created |
| Mission: Assigned | Session: Created, Initialized |
| Mission: Active | Session: any non-terminal |
| Mission: Paused | Session: Paused, Restarting |
| Mission: Completed | Session: Completed, Destroyed |
| Mission: Failed | Session: Failed, Destroyed |
| Mission: Abandoned | Session: Destroyed |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 6 (Lifecycle Compliance) — source law |
| Physics/001-Identity.md | Identity lifecycle governed by Lifecycle invariants |
| Physics/002-Missions.md | Mission lifecycle (Invariant 9) |
| Physics/003-Organizations.md | Organization lifecycle (Invariant 8) |
| Physics/004-Sessions.md | Session lifecycle (Invariant 9) — 8 states |
| Physics/005-Events.md | Lifecycle transitions produce Events (Invariant 5) |
| Physics/007-Capabilities.md | Capability lifecycle (Invariant 3) |
| Physics/008-Security.md | Security credentials lifecycle |
| Physics/010-Execution.md | Execution state machine |
| Constitution, Article III, Part A, Section 004 (LMS) | LMS's constitutional authority |
| Constitution, Article III, Part B, Section 006 (Lifecycles) | Core lifecycle definitions |
| Bible/04-Execution/Lifecycle/ | LMS implementation, lifecycle definitions |

---

*End of AIOS Physics 006 — Lifecycle Invariants*