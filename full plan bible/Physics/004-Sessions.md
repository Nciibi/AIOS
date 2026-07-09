# AIOS Physics
## 004 — Session Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-004 |
| Applies To | All Sessions, Worker Sessions, Interaction Sessions, Voice Sessions, Runtime Sessions, Templates, Runtimes, Interaction Engine |
| Source Laws | Law 3 — Law of Communication, Law 5 — Law of Identity, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Sessions within AIOS. A Session is a live execution instance — a running entity created from a Template, operating on a Runtime, with its own identity, context, permissions, and history. Sessions are the active entities through which all work is performed.

These invariants extend Laws 3, 5, 7, and 8 of Physics/000-Laws.md. Every Worker, every interaction, every model invocation exists as a Session.

---

## What Is a Session?

A Session is a constitutionally recognized execution instance that:

- Is created from a **Template** (a reusable blueprint defining capabilities, runtime requirements, policies, and constraints)
- Runs on a **Runtime** (a concrete execution backend such as Claude Code, Codex, OpenClaw, Ollama, Browser Automation, or Robotics Runtime)
- Has its own **identity**, context, workspace, and history independent of other Sessions created from the same Template
- Operates within defined **capability bounds** — resource limits, execution time, and autonomy level
- Is **temporary** — created for a purpose and destroyed when that purpose is complete

Session types include: Worker Sessions (execute Mission tasks), Interaction Sessions (Human-facing: Voice, CLI, GUI, API), Voice Sessions (continuous conversation), Runtime Sessions (model-specific execution), and Desktop/CLI/API Sessions (interaction modalities).

---

## The Session Invariants

### Invariant 1 — Every Session Comes from Exactly One Template

**A Session cannot exist without a Template. Every Session is created from exactly one Template.**

A Template is a reusable blueprint that defines: Runtime requirements, capability requirements, policies, workspace rules, skill requirements, resource limits, lifecycle configuration, and environment variables. The Template never executes — it is the definition. The Session is the execution.

A Session that does not trace to a verified Template is an unauthorized execution. Templates provide reproducibility — the same Template produces consistently configured Sessions.

*Constitutional Expression*: This invariant is present in every version of the Physics laws — from the earliest ("An Agent Session cannot exist without an Agent Template," Law 2, line 8273) through every subsequent iteration ("Every Session comes from one Template," line 10177). Templates are constitutional entities classified as Knowledge Entities in Article III, Part B.

*Enforcement*: The Security Kernel verifies that every Session creation request includes a valid Template identifier. Sessions without Template provenance are denied. The Template Registry validates that the referenced Template is active, unexpired, and constitutionally compliant.

*Edge Case*: A Template that is updated after Sessions have been created from it — existing Sessions continue with the Template version they were created from. New Sessions use the updated Template. Sessions are not retroactively modified by Template changes.

*Edge Case*: A Template that is deleted or retired — existing Sessions from that Template continue for their remaining lifetime. No new Sessions can be created from the retired Template. The system logs the Template dependency for audit.

*Violation*: A Session created without a Template. A Template that executes itself without creating a Session. A Session claiming a Template it was not created from.

---

### Invariant 2 — Every Session Has Exactly One Identity

**Every Session has a globally unique, immutable identity assigned by IRS. Identity persists for the Session's lifetime.**

The Session's identity is independent of the Template it came from. Two Sessions from the same Template have different identities. The identity is assigned at creation and retired when the Session is destroyed. Identity is immutable — it does not change during the Session's lifetime.

A Session without an identity cannot participate in constitutional operations — it cannot be authenticated, authorized, or audited.

*Constitutional Expression*: Law 5 of Physics/000-Laws.md (Law of Identity) and Physics/001-Identity.md (Identity Invariants). Sessions are constitutional entities under Article III.

*Enforcement*: IRS validates identity on Session creation. The Security Council verifies Session identity before every authorized action. ACF routes Session messages based on verified identity.

*Edge Case*: A Session that is restored from a failed Runtime — the Session retains its original identity. A new Session is not created; the existing Session is recovered with its identity intact.

*Violation*: A Session operating without an identity. A Session whose identity has been retired attempting to execute. Two Sessions sharing the same identity.

---

### Invariant 3 — Every Session Runs on Exactly One Runtime

**A Session executes on a Runtime. The Runtime implements the Runtime Interface. Every Runtime implements the Runtime Interface.**

The Runtime is the concrete execution backend that provides capabilities to the Session. Each Runtime implements a standard Runtime Interface that defines how Sessions are launched, how capabilities are requested, how execution is monitored, and how Sessions are terminated.

The Session-Runtime binding is established at creation. A Session may switch Runtimes during its lifetime (within constraints), but at any given moment, a Session runs on exactly one Runtime.

*Constitutional Expression*: "Every runtime implements the Runtime Interface" appears in the Physics lists (lines 9436, 12012). Article III, Part B, Section 010 (Runtime Neutrality) establishes that no entity depends on a specific Runtime.

*Enforcement*: The Runtime Engine validates that the Runtime correctly implements the Runtime Interface before accepting Session assignments. The Security Council verifies that Runtime-capability mappings match Session requirements. ACF validates Runtime identity for every Session message.

*Edge Case*: A Session that needs to switch Runtimes (Runtime failure, capability mismatch, cost optimization) — the Session is paused, its context is saved, a new Runtime is bound, and the Session resumes. The Session's identity and Template remain unchanged.

*Edge Case*: Multiple Sessions on the same Runtime — each Session is isolated. Sessions do not share context, memory, or workspace. The Runtime provides session-level isolation.

*Violation*: A Session operating without an assigned Runtime. A Runtime that does not implement the Runtime Interface. A Session directly accessing another Session's context on the same Runtime.

---

### Invariant 4 — Every Session Has Context, Permissions, and History

**Each Session maintains its own execution context, authorization scope, and operational history independent of all other Sessions.**

A Session's context includes: workspace, conversation history, memory, active tasks, environment variables, and intermediate state. Its permissions are derived from the Template and scoped to the Entity's authorization. Its history includes all actions taken within the Session, all evidence produced, and the complete audit trail.

Session isolation is constitutional. No Session may access another Session's context, permissions, or history without explicit authorization.

*Constitutional Expression*: Article IV, Part B, Section 012 (Sandboxing and Isolation) defines the isolation framework. Article III, Part B, Section 010 (Runtime Neutrality) ensures isolation is maintained across Runtime boundaries.

*Enforcement*: The Security Council validates that Session context access is authorized. ACF enforces session-scoped routing — messages are tagged with Session identity and routing rules prevent cross-Session access. The Runtime enforces process-level isolation between Sessions.

*Edge Case*: A cooperative pattern where one Session needs to share data with another Session — this requires explicit authorization through ACF with a shared context agreement. Sessions do not share context by default.

*Edge Case*: A Session that spawns a sub-Session — the sub-Session has its own independent context. The parent Session may have visibility into the sub-Session's evidence through ACF-scoped queries, but not into the sub-Session's active context.

*Violation*: A Session reading another Session's workspace. A Session accessing another Session's conversation history. A Session executing with permissions it inherited from another Session without authorization.

---

### Invariant 5 — Every Session Operates Within Capability Bounds

**Every Session declares its capability bounds at creation. The Session may not exceed these bounds during its lifetime.**

Capability bounds include: resource consumption limits (CPU, memory, network, storage, token budget), execution duration limit (maximum lifetime), autonomy level (L0-L4), skills (declared skills from Template), and runtime requirements (compatible Runtimes).

Bounds are established by the Template and may be refined by the Organization or Mission at Session creation. Bounds cannot be exceeded without a formal reauthorization process — creation of a new Session with appropriate bounds or explicit capability upgrade.

*Constitutional Expression*: Law 7 of Physics/000-Laws.md (Law of Capability Bounds). Article IV, Part B, Section 007 (Capability Verification) defines the constitutional requirement.

*Enforcement*: The Security Council verifies that every action requested by a Session falls within its declared capability bounds. ROS monitors resource consumption per Session. Actions exceeding bounds are denied and logged. Exceeding resource bounds triggers Session pause and escalation.

*Edge Case*: A Session that requires a temporary capability beyond its declared bounds — the Session requests a capability upgrade through the Capability Certification Authority. If approved, the Session's bounds are extended. If denied, the action is refused.

*Edge Case*: A Session that runs longer than its execution duration limit — the Session is paused and escalated. It may be extended through authorized replanning, or a new Session may be created for continued work.

*Violation*: A Session consuming memory beyond its declared limit. A Session running past its maximum lifetime without authorization. A Session using a skill it did not declare.

---

### Invariant 6 — Every Session Operates Under the Security Council

**Every Session action is subject to the constitutional verification pipeline. No Session bypasses the Security Council.**

Before any Session executes an action, the Security Council verifies: Is the Session identity valid? Is the Session context authorized? Is the action within capability bounds? Does the action comply with applicable policies? Is the action within the Mission's scope? Is the risk acceptable?

The verification pipeline applies to every action, not just Session creation. Each action is individually verified.

*Constitutional Expression*: Law 8 of Physics/000-Laws.md (Law of Verification-First). Article IV, Part A, Section 001 (Security) establishes the Security Council's verification authority.

*Enforcement*: The Security Council issues execution authorization tokens for every verified action. The Runtime refuses to execute without a valid token. ACF validates token presence on every execution message. Unauthorized execution attempts trigger Session suspension.

*Edge Case*: A long-running Session performing many small actions — the verification pipeline applies to the authorization token, which may cover a batch of actions within defined bounds. The token's scope is explicit and time-limited.

*Edge Case*: A Session that is pre-authorized for a specific Mission scope — the authorization is scoped to the Mission's defined actions. Actions outside that scope require individual verification.

*Violation*: A Session executing without a verification token. A Session that continues executing after its authorization token expires. A Session that performs an action outside its authorization scope.

---

### Invariant 7 — Sessions Are Temporary

**All Sessions are temporary. Every Session ends.**

A Session is created for a specific purpose and destroyed when that purpose is complete. Session types have defined lifetimes: Worker Sessions terminate when the Mission task is complete; Interaction Sessions terminate when the User interaction ends; Voice Sessions terminate when the conversation ends; Runtime Sessions terminate when the Runtime session expires.

No Session is permanent. Sessions end through: natural completion, idle timeout, maximum lifetime expiry, explicit termination (User, Organization, or Security Council), Runtime failure (Session recovery may create a new Session), or Organization or Mission dissolution.

When a Session terminates, its execution context is destroyed. Evidence and knowledge extracted from the Session are preserved through the Organization's Operational Intelligence and the Academy.

*Constitutional Expression*: Law 10 of Physics/000-Laws.md (Law of Tenure) establishes that all execution entities are temporary. Article III, Part B, Section 006 (Lifecycles) defines the lifecycle framework.

*Enforcement*: The Session Lifecycle Manager (part of LMS) monitors Session lifetime. Idle timeouts are enforced. Maximum lifetime is enforced. Force termination is executed by the Runtime when the Security Council or OSYS initiates it.

*Edge Case*: A Session that should not end because its work is not complete — the Session must be formally extended through its Organization. Extension is authorized up to the maximum lifetime. Beyond that, a new Session must be created.

*Edge Case*: A Session that fails unexpectedly — OSYS may attempt recovery. If recovery fails, a new Session is created from the same Template. The failed Session's evidence is preserved.

*Violation*: A Session that refuses to terminate. A Session that continues executing after its lifetime expires. A Session that self-reinstates without authorization.

---

### Invariant 8 — Sessions Communicate Through ACF

**Every Session communicates through ACF. No direct communication outside ACF is permitted.**

A Session sends and receives all messages through ACF — receiving Mission instructions from its Organization, reporting progress, requesting resources, communicating with other Sessions, and interacting with the User (for Interaction Sessions). No direct IPC, no shared memory outside ACF channels, no side channels.

*Constitutional Expression*: Law 3 of Physics/000-Laws.md (Law of Communication). Article III, Part B, Section 001 (Organizations) extends ACF requirements to all entities including Sessions.

*Enforcement*: ACF validates every message from a Session against the Session's identity and authorization. Messages without ACF envelopes are rejected. The Runtime enforces that Session output goes through ACF.

*Edge Case*: A Session that needs to share data with another Session on the same Runtime — the data must flow through ACF, not through shared memory or the Runtime's internal process channels. ACF provides a Session-to-Session communication channel.

*Edge Case*: A Session that produces output for the User — the output flows through ACF to the Interaction Engine, which delivers it through the appropriate interaction modality (voice, CLI, GUI). The Session does not write directly to the user interface.

*Violation*: Two Sessions communicating directly through shared memory. A Session writing directly to a User interface without going through ACF. A Session receiving Mission instructions outside ACF.

---

### Invariant 9 — Every Session Has a Defined Lifecycle

**Every Session traverses a defined lifecycle. A Session exists in exactly one lifecycle state at all times.**

The canonical Session lifecycle states:

```
Created → Initialized → Active → Paused → Restarting → Completed → Failed → Destroyed
```

| State | Description |
|-------|-------------|
| Created | Session identity is assigned. Template is loaded. Runtime is not yet bound. |
| Initialized | Runtime is bound. Context is initialized. Capabilities are verified. |
| Active | Session is executing. Actions are being performed. Evidence is recorded. |
| Paused | Session is temporarily suspended. Context is preserved. No execution. |
| Restarting | Session is recovering from a failure. Context is being restored. |
| Completed | Session purpose is fulfilled. Execution is complete. Context is sealed. |
| Failed | Session terminated due to an unrecoverable error. Evidence is preserved. |
| Destroyed | Session context is released. Identity is retired. |

*Constitutional Expression*: Law 6 of Physics/000-Laws.md (Law of Lifecycle Compliance). The Lifecycle Management System (LMS) in the Bible implements this for all entity types including Runtime Sessions.

*Enforcement*: LMS validates every lifecycle transition. Invalid transitions are denied. The Security Council verifies Session lifecycle state before authorizing actions. Stuck Sessions are flagged and escalated.

*Edge Case*: A Session transitioning from Active directly to Failed without passing through recovery attempts — this is valid for unrecoverable failures. The Failure state must be logged with the reason and evidence.

*Edge Case*: A Session in Paused state for longer than the platform's pause timeout — the Session is force-terminated (transitioned to Failed) to prevent indefinite suspension.

*Violation*: A Session in Destroyed state still executing. A Session that was never initialized attempting execution. A Session that claims Completed state without having performed any work.

---

### Invariant 10 — Interaction Sessions Are Sessions

**All user-facing interaction modalities are Sessions. Every User interaction — Voice, CLI, GUI, API, Discord, Email — is an Interaction Session managed by the Interaction Engine.**

Interaction Sessions follow the same invariants as all other Sessions: they come from Templates, have identity, run on Runtimes, have context/permissions/history, operate within capability bounds, are verified by the Security Council, are temporary, communicate through ACF, and have a defined lifecycle.

The Interaction Engine manages all Interaction Sessions. Multiple concurrent Interaction Sessions can coexist — each has its own identity, context, permissions, and history.

*Constitutional Expression*: The Interaction Engine is defined under the Intelligence group of Engines (Article III, Part A, Section 008). Interaction Sessions are core AIOS objects defined in the AIOS Object Model.

*Edge Case*: A Voice Session that is transferred from one Runtime to another (e.g., from speech-to-text processing to language model processing) — the Session identity and context persist across Runtimes. The Interaction Engine manages the Runtime handoff.

*Edge Case*: A User interacting through multiple modalities simultaneously (voice + GUI + CLI) — each modality is a separate Interaction Session. They are not merged into a single Session. The Interaction Engine may correlate sessions for context but each Session retains its independent identity and history.

*Violation*: An Interaction Session created without a Template. An Interaction Session operating outside ACF. An Interaction Session that persists indefinitely without User activity.

---

## The Session Lifecycle (Detailed)

The canonical Session lifecycle managed by LMS:

```
Created → Initialized → Active → Paused → Restarting → Completed → Failed → Destroyed
```

| State | Transitions Allowed | Description |
|------|--------------------|-------------|
| Created | → Initialized | Session is registered. Identity assigned. Template verified. |
| Initialized | → Active, → Failed | Runtime bound. Capabilities verified. Context initialized. |
| Active | → Paused, → Restarting, → Completed, → Failed | Execution in progress. Actions verified. |
| Paused | → Active, → Failed | Session is suspended. Context preserved. |
| Restarting | → Active, → Failed | Recovery in progress. Context being restored. |
| Completed | → Destroyed | Work done. Evidence sealed. |
| Failed | → Restarting, → Destroyed | Unrecoverable error. Evidence preserved. |
| Destroyed | (terminal) | Context released. Identity retired. Evidence archived. |

---

## Session Types

| Session Type | Template Source | Responsible Entity | Lifetime |
|-------------|---------------|-------------------|----------|
| Worker Session | Worker Template | Organization | Mission task duration |
| Interaction Session | Interaction Template | Interaction Engine | User interaction duration |
| Voice Session | Voice Template | Interaction Engine | Conversation duration |
| Runtime Session | Runtime Template | Runtime Engine | Model session duration |
| CLI Session | CLI Template | Interaction Engine | CLI command session |
| API Session | API Template | Interaction Engine | API request session |

---

## Session Identity and Attributes

Every Session has the following constitutional attributes:

| Attribute | Mutable? | Description |
|-----------|----------|-------------|
| Session ID | NEVER | Globally unique, immutable identity assigned by IRS |
| Template ID | NEVER | The Template from which this Session was created |
| Runtime ID | Changed on Runtime switch | Current Runtime executing this Session |
| Session Type | NEVER | Worker, Interaction, Voice, Runtime, CLI, API |
| Context | YES | Active execution context (workspace, history, memory) |
| Permissions | Derived from Template | Authorization scope |
| Capability Bounds | Upgradeable | Resource, duration, skill, autonomy limits |
| Lifecycle State | YES (via LMS) | Current state in the lifecycle |
| Budget | YES | Resource consumption limits and current usage |
| Health | Monitored | Runtime health indicators |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 5 (Identity), Law 7 (Capability Bounds), Law 8 (Verification) — source laws |
| Physics/001-Identity.md | Identity invariants — Sessions have immutable identity (Invariant 2) |
| Physics/002-Missions.md | Mission invariants — Sessions execute Mission tasks |
| Physics/003-Organizations.md | Organization invariants — Sessions belong to Organizations |
| Physics/005-Events.md | Evidence invariants — Session actions produce evidence |
| Physics/006-Lifecycles.md | Lifecycle invariants — Session lifecycle (Invariant 9) |
| Physics/007-Capabilities.md | Capability invariants — Session capability bounds (Invariant 5) |
| Physics/008-Security.md | Security invariants — Sessions are verified (Invariant 6) |
| Physics/009-Interaction.md | Interaction invariants — Interaction Sessions (Invariant 10) |
| Physics/010-Execution.md | Execution invariants — Sessions are the execution unit |
| Physics/011-Design-DNA.md | Design DNA rules — engineering principles applied to Sessions |
| Constitution, Article III, Part B, Section 004 (Workers) | Worker Sessions are the execution entity |
| Constitution, Article III, Part B, Section 010 (Runtime Neutrality) | Session-Runtime independence |
| Constitution, Article IV, Part A, Section 003 (Identity) | Session identity framework |
| Constitution, Article IV, Part B, Section 007 (Capability Verification) | Capability bounds for Sessions |

---

## Future Extensions

These invariants are expected to remain stable. Future Session-related specifications in the Bible (Bible/03-Institutions/Workers/, Bible/06-Services/ACF/, Bible/04-Execution/Runtime/) will define Worker Operating Model (WOM), Worker Health System (WHS), Worker Skill System (WSS), Worker Context System (WCS), Session isolation implementation, cross-Session communication protocols, and Session recovery strategies.

---

*End of AIOS Physics 004 — Session Invariants*