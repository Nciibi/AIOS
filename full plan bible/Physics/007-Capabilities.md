# AIOS Physics
## 007 — Capability Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-007 |
| Applies To | All Capabilities, Capability Verification, Capability Resolution, Capability Certification Authority (CCA), Resource OS (ROS), Autonomy Levels |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Capabilities within AIOS. A Capability is a constitutional authorization — a verified, bounded permission for an entity to perform a specific action or access a specific resource. Capabilities are the unit of authorization. Every action requires a Capability. Every Capability is verified before use.

These invariants extend Law 7 (Capability Bounds) and Law 8 (Verification-First) of Physics/000-Laws.md. They supersede all earlier Capability definitions in the Constitution corpus.

---

## What Is a Capability?

A Capability is a constitutional fact that grants an entity the authority to perform a defined set of actions within defined bounds:

- **Tool Capabilities**: Permission to invoke a tool (read_file, write_file, execute_command, browse_web)
- **Model Capabilities**: Permission to invoke a specific model with specific parameters
- **Resource Capabilities**: Permission to consume resources (token budget, compute, memory, storage, network)
- **Data Capabilities**: Permission to access data (read, write, modify, share)
- **Interaction Capabilities**: Permission to interact with Users or other entities
- **Autonomy Capabilities**: Permission to operate at a specific autonomy level

Every capability declares: what action is authorized, what entity is authorized, under what conditions the capability applies, what bounds constrain the capability (limits, duration, expiry), what level is assigned (L0-L4 autonomy), what Template or Session the capability belongs to, and what Organization or Mission authorized the capability.

---

## The Capability Invariants

### Invariant 1 — Every Action Requires a Capability

**Every action — every tool invocation, every model call, every resource consumption, every data access, every interaction — requires a verified capability.**

No entity performs an action without first having a capability that authorizes that action. The capability is verified before the action is executed. An action without a verified capability is a constitutional violation.

This is absolute. The inverse is not true — an entity may have capabilities it does not use. But an entity cannot perform an action it does not have a capability for.

*Constitutional Expression*: Law 7 (Capability Bounds) — "Every Session is bounded by its capabilities. Every capability is declared at creation." Law 8 (Verification-First) — "Every constitutional action must be verified before execution."

*Enforcement*: The Security Council verifies the capability before every action. The Security Council verifies that the capability is valid, unexpired, authorized for the entity and the specific action, and within the capability's declared bounds. Actions without verified capabilities are denied.

*Edge Case*: An action that consists of multiple sub-actions (e.g., "write this file" involves check permissions + open file handle + write content + close file handle) — each sub-action requires its own capability verification. The Security Council may pre-authorize a set of capabilities for a compound action, but each sub-action remains individually verified.

*Edge Case*: A capability that is needed but not yet applied for — the entity must request the capability through the Capability Certification Authority (CCA). The action is deferred until the capability is granted.

*Violation*: An action performed without a verified capability. An entity that bypasses capability verification by invoking a sub-action directly. An entity that performs an action outside the scope of its granted capabilities.

---

### Invariant 2 — Capabilities Are Granted, Not Assumed

**No capability is assumed. Every capability must be actively granted by a constitutional authority.**

Capabilities are granted through a formal process:

1. **Application**: The entity (or entity's Organization) applies for a capability through CCA
2. **Verification**: CCA verifies that the entity's Template, Organization, and Mission authorize the requested capability
3. **Security Review**: The Security Council reviews the application for safety, compliance, and constitutional alignment
4. **Bound Assignment**: The capability is granted with specific bounds — resource limits, duration, conditions, autonomy constraints
5. **Recording**: The granted capability is recorded in the Capability Registry and linked to the entity's constitutionally recognized identity

Capabilities are granted to entities. An entity cannot grant capabilities to itself. An entity cannot inherit capabilities from another entity without formal authorization.

*Constitutional Expression*: "Capabilities are assigned by templates, verified by the Security Council, and trackable through the Capability Registry" (Article IV, Part B, Section 007). This establishes the granting process.

*Enforcement*: CCA validates every capability grant request. The Security Council reviews every grant. The Capability Registry records every grant. No capability is active without a Capability Registry record.

*Edge Case*: A capability requested by an Organization for a child Mission — the Organization has the authority to apply for capabilities on behalf of its Missions. The capability is granted to the Mission, not the Organization. The Organization manages the capability but the Mission executes with it.

*Edge Case*: A capability that is granted automatically by the entity's Template (Template-defined capabilities) — the automatic grant is still a formal grant. The Template is the constitutional authority for the grant (Article III, Part B, Section 009 — Templates). The CCA verifies and records the automatic grant.

*Violation*: An entity assuming a capability without a grant. An entity granting capabilities to itself. A capability that is used before it is recorded in the Capability Registry.

---

### Invariant 3 — Capabilities Are Bounded

**Every capability has explicit, declared bounds. Bounds constrain what the capability can do, how much it can consume, and how long it is valid.**

Capability bounds include:

| Bound Type | Description | Examples |
|-----------|-------------|---------|
| Resource | Maximum consumption per action or per session | Max tokens: 100k, Max memory: 512MB, Max compute: 30s |
 | Duration | Maximum lifetime of the capability | Expires: 24h from grant, Expires: mission_end |
| Scope | What actions the capability authorizes | Read file only, Write file only, Execute specific command |
| Frequency | How often the capability can be used | Max 10 calls/min, Max 100 calls/session |
| Conditions | Under what circumstances the capability applies | User-approved actions only, Audit-required actions |
| Quality | Quality constraints on the capability | Model: GPT-4, Temperature: 0.0-0.7 |

Bounds are set at capability grant time. Bounds may be refined but must remain within the original grant's constraints. A bound that is set at grant time is the maximum — a Session may not exceed it.

*Constitutional Expression*: Law 7 (Capability Bounds) — "Capabilities have bounds: resource, duration, scope, frequency, quality, autonomy. These bounds are the maximum."

*Enforcement*: CCA sets bounds at grant time. ROS enforces resource bounds. The Security Council enforces scope bounds. LMS enforces duration bounds. ACF enforces frequency bounds.

*Edge Case*: A capability whose bounds need to be increased — the entity requests a capability upgrade through CCA. The upgrade goes through the full verification process. The original capability remains valid during the upgrade review.

*Edge Case*: A capability whose bounds contradict each other (e.g., maximum tokens and maximum duration produce a conflict) — the more restrictive bound applies. The entity operates within both bounds.

*Violation*: A capability used beyond its bounds. A capability whose bounds are exceeded silently. A capability with no declared bounds.

---

### Invariant 4 — Capabilities Are Verified Before Every Use

**Every capability is verified before every use. Verification is not a one-time event — it is per-action.**

Before an entity performs an action requiring a capability, the following is verified: the capability exists and is recorded in the Capability Registry, the capability has not expired, the capability authorizes this specific action, the capability's bounds are not exceeded, the requesting entity matches the granted entity, the capability is not suspended or revoked, and the entity's lifecycle state permits using this capability.

Verification is performed by the Security Council. The verification produces an Event. The Event records the capability ID, the action, the entity, and the verification result.

*Constitutional Expression*: Law 8 (Verification-First). Article IV, Part B, Section 007 (Capability Verification).

*Enforcement*: The Security Council verifies capabilities on every action. Actions without verification are denied. The Runtime refuses to execute without a verified capability token. ACF validates capability tokens in message envelopes.

*Edge Case*: A frequently used capability (e.g., read_file for a Session that reads many files) — verification is still per-action. The Security Council may use a verified capability token that covers multiple uses within a short time window, but the token is scoped and time-limited.

*Edge Case*: A capability that is verified but the action fails before execution — the verification is consumed. The entity must request re-verification for the next attempt. The failed verification is logged as an Event.

*Violation*: An action that uses a capability without per-use verification. A capability that is verified once and used multiple times without re-verification. A capability verification that is not logged.

---

### Invariant 5 — Capabilities Are Revocable

**Any granted capability may be revoked at any time by the granting authority. Revocation is immediate and does not require the entity's consent.**

Revocation triggers: capability is marked as revoked in the Capability Registry, capability becomes invalid for future actions, active actions using the capability continue but new actions are denied, the revoked entity is notified through ACF, and the revocation is recorded as a Security Event.

Grounds for revocation include: entity violates its capability bounds, entity's parent entity's capability is revoked, Security Council determines the capability is no longer safe, the Template or Mission that granted the capability is modified, or the entity's lifecycle state changes to one that does not support the capability.

*Constitutional Expression*: Article IV, Part B, Section 007 (Capability Verification) — "Capabilities can be revoked at any time by the Security Council or the granting Organization."

*Enforcement*: CCA manages revocation. The Security Council can trigger revocation. The granting Organization can trigger revocation. Revocations are immediate. In-flight actions complete under the revoked capability but new actions are denied.

*Edge Case*: A capability that is revoked while a Session is using it — the Session's current action is allowed to complete. The Session is notified of the revocation. The Session's capability bounds are recalculated. The Session may request a new capability.

*Edge Case*: A capability that is revoked in error — the entity can request reinstatement through CCA. The reinstatement is a new capability grant, not an un-revocation. The revocation Event remains in the Event stream.

*Violation*: A capability that continues to be used after revocation. A revocation that is not recorded. A capability that is surreptitiously re-enabled without a new grant.

---

### Invariant 6 — Capabilities Are Hierarchical

**Capabilities compose in a hierarchy. A parent capability constrains child capabilities. A child capability cannot exceed its parent's bounds.**

The capability hierarchy mirrors the entity hierarchy: Organization capabilities constrain Mission capabilities, Mission capabilities constrain Session capabilities, Template-defined capabilities constrain Session capabilities, and constitutional capabilities constrain all.

A child capability's bounds must be within the parent capability's bounds. A Session's read_file capability cannot have a higher token limit than the Mission's read_file capability. A Mission's read_file capability cannot have a higher token limit than the Organization's read_file capability.

*Constitutional Expression*: Implicit in Law 7 (Capability Bounds) — capabilities are bounded by Templates, Missions, and Organizations. Article III, Part B, Section 007 (Capabilities) establishes the hierarchy.

*Enforcement*: CCA validates parent-child capability constraints at grant time. A child capability grant is rejected if it exceeds its parent's capability. The Security Council enforces hierarchical constraints during verification.

*Edge Case*: A child capability that is narrower than its parent capability — this is valid. A child capability can be more restrictive than its parent. The parent capability enables the broader scope; the child capability narrows it.

*Edge Case*: A parent capability that is revoked — all child capabilities are revoked. The cascading revocation follows the hierarchy. Child entities are notified.

*Violation*: A child capability with bounds wider than its parent capability. A Session using a capability not granted by its Mission. A Mission using a capability not granted by its Organization.

---

### Invariant 7 — Capabilities Are Resource-Coupled

**Every capability has a resource budget. Resource consumption is tracked against the capability's budget. Budgets are enforced by ROS.**

A capability's resource budget declares: token budget (input + output tokens), compute budget (CPU seconds, GPU seconds), memory budget (RAM, VRAM), storage budget (temporary workspace, persistent data), network budget (bandwidth, requests), and call budget (API calls, tool invocations).

ROS tracks consumption against every budget. When a budget is exhausted, the capability is suspended. The entity must request a budget increase or wait for budget refresh.

*Constitutional Expression*: Law 7 (Capability Bounds). Article III, Part B, Section 009 (ROA) — ROS manages resource allocation and consumption tracking.

*Enforcement*: ROS monitors resource consumption in real-time. ROS enforces budget limits per capability. When a budget is exceeded, ROS notifies the Security Council, which suspends the capability. Budget exhaustion is recorded as a Resource Event.

*Edge Case*: A capability with a shared budget across multiple Sessions (e.g., all Sessions in a Mission share a token budget) — ROS tracks shared budgets. Each Session's consumption is deducted from the shared pool. When the pool is exhausted, all Sessions' capabilities are suspended.

*Edge Case*: A capability with a per-Session budget that is refreshed — the refresh schedule is defined at capability grant time. Daily, weekly, or per-Mission budgets are refreshed automatically. Refresh is recorded as a Resource Event.

*Violation*: A capability that exceeds its resource budget without enforcement. A Session that consumes resources outside its declared budgets. A budget that is exceeded silently.

---

### Invariant 8 — Capabilities Enable Autonomy Levels

**Every capability has an autonomy level (L0–L4). An entity's autonomy is the maximum autonomy level among its capabilities.**

| Level | Name | Description |
|-------|------|-------------|
| L0 | None | No autonomy. Every action requires pre-approval. Read-only. |
| L1 | Suggest | Can suggest actions. All actions require confirmation. |
| L2 | Execute | Can execute pre-approved actions. Can suggest new actions. |
| L3 | Manage | Can manage tasks and resources within bounds. Can approve L1-2 actions. |
| L4 | Autonomous | Full autonomy within declared capability bounds. Self-directed. |

Autonomy levels are set at the capability level, not the entity level. An entity may have L4 read_file capability (read any file autonomously) but L0 execute_command capability (every command requires approval).

Autonomy level determines the verification pipeline — L0 actions require full Security Council verification including risk assessment, L2 actions require capability verification but not user approval, and L4 actions require only capability existence verification.

*Constitutional Expression*: Law 7 (Capability Bounds). Article IV, Part B, Section 007 defines autonomy levels L0–L4.

*Enforcement*: The Security Council applies different verification pipelines based on autonomy level. ACF routes actions to appropriate approval channels. User approval is required for L0–L1 actions. L2+ actions are routed through the verification pipeline without user interaction.

*Edge Case*: An entity with mixed autonomy levels — the Security Council applies per-action verification based on the specific capability's autonomy level. An L4 action is not held up by L0 verification requirements.

*Edge Case*: An entity operating at L4 autonomy but encountering a novel situation — the entity may voluntarily downgrade its autonomy for the novel action. The downgrade is temporary and specific to the action.

*Violation*: An entity operating at a higher autonomy level than its capabilities support. An entity bypassing approval for an L0 action. An entity claiming L4 autonomy without verified L4 capabilities.

---

### Invariant 9 — Capabilities Are Auditable

**Every capability grant, use, suspension, revocation, and change is recorded as an Event. Capability audit trails are complete and transparent.**

The capability audit trail includes: the entity requesting the capability, the entity granting the capability, the capability bounds, the capability's lifecycle state (Applied → Verified → Granted → Active → Suspended → Revoked → Expired), every use of the capability (action + verification + resource consumption), every suspension (reason + duration), every revocation (reason + authority), and every change (bound change, scope change, level change).

Capability audit trails are accessible to the granting authority, the entity's parent Organization, the Security Council, and CCA.

*Constitutional Expression*: Law 1 (Evidence) — all actions produce Events. Article IV, Part B, Section 007 (Capability Verification) — "Capabilities are recorded in the Capability Registry."

*Enforcement*: The Capability Registry records all capability events. The Event Store stores capability Events. Capability audit trails are queryable through the Capability Registry API.

*Edge Case*: A capability that is used millions of times (e.g., read_file) — each use produces an Event. The Event volume is high. The Capability Registry aggregates usage Events for query performance. The individual Events remain in the Event Store.

*Edge Case*: A capability that is transferred from one entity to another — the transfer is recorded as a Revocation Event (from the original entity) + a Grant Event (to the new entity). The transfer audit trail links the two Events.

*Violation*: A capability that is used without recording. A capability grant that is not recorded in the Capability Registry. An audit trail that is incomplete.

---

### Invariant 10 — Capabilities Define Communication Boundaries

**Every entity's communication scope is bounded by its capabilities. An entity cannot communicate beyond its capability scope.**

The capability scope defines what information the entity can receive, what information it can send, which entities it can communicate with, and through which channels (ACF, direct, broadcast). An entity cannot communicate with an entity outside its capability-defined communication scope. An entity cannot receive information that it does not have a capability to process. An entity cannot send information that it does not have a capability to share.

Communication capabilities include: command capability (who can send commands to this entity), data sharing capability (what data can be shared and with whom), and interaction capability (which communication channels are available).

*Constitutional Expression*: Law 3 (Communication) requires all communication through ACF and lawfully authorized capabilities. Law 7 (Capability Bounds) extends bounds to communication.

*Enforcement*: ACF enforces communication capabilities. An entity cannot send a message to another entity without ACF verifying the sender's communication capability. An entity cannot receive a message without ACF verifying the receiver's communication capability.

*Edge Case*: An entity that needs to communicate with an entity outside its communication scope — the entity must request a communication capability extension through CCA. The extension must be authorized by both entities' parent Organizations.

*Edge Case*: A broadcast message (Organization to all Missions) — the broadcast is within the Organization's communication capability. Individual Missions receive the broadcast through ACF. Each Mission's capability to receive the broadcast is verified.

*Violation*: An entity communicating with another entity without communication capability. An entity receiving a message from an unauthorized sender. An entity sharing data beyond its data sharing capability.

---

## Capability Lifecycle

| State | Description | Transitions Allowed |
|-------|-------------|-------------------|
| Applied | Capability application submitted to CCA | → Verified, → Rejected |
| Verified | CCA verified capability meets Template + Mission bounds | → Granted, → Rejected |
| Granted | Security Council approved the capability. Bounds assigned | → Active |
| Active | Capability is usable by the entity | → Suspended, → Revoked, → Expired |
| Suspended | Capability temporarily disabled | → Active, → Revoked |
| Revoked | Capability permanently withdrawn | (terminal) |
| Expired | Capability lifetime expired | (terminal) |
| Rejected | Capability application or verification denied | (terminal) |

---

## Autonomy Level Matrix by Entity Type

| Entity Type | Default Level | Max Level | Escalation Path |
|-------------|-----------|-----------|-----------------|
| Worker Session | L2 | L3 | Organization approval |
| Interaction Session | L1 | L2 | User approval |
| Voice Session | L1 | L2 | User voice confirmation |
| Organization | L3 | L4 | Constitutional Council |
| Mission | L2 | L3 | Organization approval |
| Template | N/A | N/A | Templates define Session levels |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 7 (Capability Bounds), Law 8 (Verification-First) — source laws |
| Physics/002-Missions.md | Missions scope Capabilities |
| Physics/003-Organizations.md | Organizations authorize Capabilities |
| Physics/004-Sessions.md | Sessions execute with Capabilities |
| Physics/005-Events.md | Capability use produces Events (Invariant 9) |
| Physics/008-Security.md | Capability verification (Invariant 4) |
| Physics/009-Interaction.md | Communication capabilities (Invariant 10) |
| Physics/010-Execution.md | Capability-driven execution |
| Constitution, Article III, Part B, Section 007 (Capabilities) | Capability framework, CCA, Capability Registry |
| Constitution, Article IV, Part B, Section 007 (Capability Verification) | Verification pipeline |
| Bible/06-Services/Capabilities/ | CCA implementation, Capability Registry |
| Bible/08-Standards/Capabilities/ | Capability schema, bounds definitions |

---

*End of AIOS Physics 007 — Capability Invariants*