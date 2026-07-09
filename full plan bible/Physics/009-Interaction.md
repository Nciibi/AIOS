# AIOS Physics
## 009 — Interaction Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-009 |
| Applies To | All Interactions, Interaction Engine, Interaction Sessions, User Interfaces, Voice, CLI, GUI, API, Channel Adapters, Message Routing |
| Source Laws | Law 3 — Law of Communication, Law 4 — Law of Evidence, Law 2 — Law of Constitution-First |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Interactions within AIOS. An Interaction is any communication between a User and the system, or between entities, that passes through the Interaction Engine. The Interaction Engine is the constitutional authority for managing all interactions — routing messages, managing Interaction Sessions, adapting to modalities, and preserving interaction evidence.

These invariants extend Law 3 (Communication), Law 4 (Evidence), and Law 2 (Constitution-First) of Physics/000-Laws.md. All interactions are constitutionally bound.

---

## What Is an Interaction?

An Interaction is a constitutionally recognized communication exchange between a User (human) and the AIOS system. Interactions are:

- **Modality-independent**: Voice, CLI, GUI, API, Discord, Email, SMS — the Interaction Engine adapts to the channel
- **Session-mapped**: Every Interaction belongs to an Interaction Session
- **Evidence-producing**: Every Interaction produces Events — User input, model output, tool calls, approvals
- **ACF-routed**: All Interactions flow through ACF
- **Secured**: All Interactions are authenticated, authorized, and verified

Interaction types include: Chat Interaction (back-and-forth conversation between User and system), Command Interaction (User issues a command, system executes), Request Interaction (User requests information or action), Approval Interaction (User approves or rejects a proposed action), Notification Interaction (system sends information to User), and Multi-modal Interaction (User switches between modalities in the same conversation).

---

## The Interaction Invariants

### Invariant 1 — All Interactions Flow Through the Interaction Engine

**Every User interaction — every message, every command, every request, every response — flows through the Interaction Engine. No direct communication between User and any other entity bypasses the Interaction Engine.**

The Interaction Engine is the gate for all user-facing communication. It accepts input from any channel adapter (voice, CLI, GUI, API, Discord, Email), routes the input through the constitutional pipeline (ACF → Security Council → appropriate entity), manages Interaction Sessions that track the conversation, adapts output to the appropriate channel, and records all interaction evidence.

An input that does not flow through the Interaction Engine is an unauthorized interaction. A response that bypasses the Interaction Engine is an unauthorized communication.

*Constitutional Expression*: Article III, Part A, Section 008 (Interaction Engine) — "The Interaction Engine handles all interactions." Article III actually lists the Interaction Engine under the Intelligence group of Engines.

*Enforcement*: ACF routes all user-facing communication through the Interaction Engine. Channel adapters integrate only through the Interaction Engine's API. Bypassing the Interaction Engine is a constitutional violation.

*Edge Case*: A system-to-system communication that looks like a user interaction (e.g., an automated script calling the API) — the communication still flows through the Interaction Engine if it uses an Interaction channel. The Interaction Engine distinguishes between human and automated interactions through authentication context.

*Edge Case*: A User interaction that begins on one channel and continues on another (e.g., starts on CLI, continues on GUI) — the Interaction Engine correlates the two channels through the User's identity. The Interaction Session persists across channels.

*Violation*: A User sending a message directly to a Session without passing through the Interaction Engine. An entity responding directly to a User without going through the Interaction Engine. A channel adapter that bypasses the Interaction Engine.

---

### Invariant 2 — Every Interaction Belongs to Exactly One Interaction Session

**Every interaction message belongs to exactly one Interaction Session. No interaction exists outside a Session.**

An Interaction Session is created when a User begins an interaction (login, connect, send first message). All interactions from that User during that conversation belong to the same Interaction Session. The Interaction Session has exactly one Template, one identity, one context, one lifecycle state, and one modality (at creation, though it may adapt).

The Interaction Session provides: conversation context (history of the interaction), User context (who is interacting), authentication context (how the User was authenticated), authorization scope (what the User is authorized to do), and interaction evidence (record of all messages).

*Constitutional Expression*: Invariant 2 of Sessions (004) — every Interaction Session has identity. Invariant 4 of Sessions — every Session has context, permissions, history. Invariant 10 of Sessions — Interaction Sessions are Sessions.

*Enforcement*: The Interaction Engine creates an Interaction Session for every new User interaction. Messages without a Session ID are rejected. Session ID is verified by ACF.

*Edge Case*: A User who sends a message after their Interaction Session has expired (e.g., session timeout) — the Interaction Engine creates a new Interaction Session. The previous Session's context is preserved for reference but the new Session starts fresh.

*Edge Case*: A User interaction that spans multiple modalities — the Interaction Session's modality is the primary modality. Messages from other modalities are correlated through the User's identity and attributed to the same Interaction Session.

*Violation*: A message that claims a Session ID that does not exist. A message that belongs to an expired Session. A User interaction without a Session.

---

### Invariant 3 — Every Interaction Is Authenticated

**Every interaction message carries verified User identity. The User is authenticated before the interaction begins. Every message within the session is attributed to the authenticated User.**

Authentication establishes: who the User is (User identity), how the User authenticated (method: password, SSO, OAuth, device, biometric), the User's constitutional status (active, suspended, expired), and the User's authorization scope (Organizations, capabilities, Missions).

Authentication happens at Session creation. Re-authentication is required for sensitive actions within the Session (approvals, capability upgrades, policy overrides). Authentication tokens are verified on every message.

*Constitutional Expression*: Law 5 (Identity) extends to Users. Law 8 (Verification-First) requires authentication. Article IV, Part A, Section 003 (Identity) includes User identity.

*Enforcement*: The Interaction Engine authenticates users through IRS. Authentication tokens are verified by ACF on every message. Failed authentication results in Session termination.

*Edge Case*: A User who authenticates through SSO — SSO authentication is accepted. The SSO provider is verified by the Security Council. The User's identity is linked to their SSO identity.

*Edge Case*: A User who is authenticated for one Organization but requests an action in another Organization — the authentication covers the User's identity. Authorization is a separate step. The User's authorization scope determines which Organizations they can interact with.

*Violation*: A User sending messages without authentication. A User whose authentication token has expired. A User who authenticates but is not authorized for the current scope.

---

### Invariant 4 — Every Interaction Is Authorized

**Every interaction action is authorized before execution. The User's authorization scope determines what actions the User can take within the Interaction Session.**

Authorization scope is determined at Session creation and includes: what capabilities the User has (tool, model, resource, data), what Organizations the User belongs to, what Missions the User is associated with, what sensitivity clearance the User has, and what autonomy level the User can delegate.

Authorization is per-action. A User may have authorization to read files but not write files within the same Session. A User may have authorization to interact in Organization A but not Organization B.

*Constitutional Expression*: Law 3 (Communication) — interactions are bound by lawful authorization. Law 8 (Verification-First) — every action is verified. Invariant 1 of Capabilities (007) — every action requires a capability.

*Enforcement*: The Security Council verifies every interaction action. Actions outside the User's authorization scope are denied. Authorization checks are recorded as Events.

*Edge Case*: A User requesting an action that is within their authorization scope but outside the Interaction Session's scope — the action is denied. The Interaction Session scope is determined at creation. Broader actions require a new Session with broader scope.

*Edge Case*: A User requesting an action that requires additional authorization (e.g., approving a high-cost execution) — the action is escalated for re-authorization. The User must explicitly re-authenticate for the sensitive action.

*Violation*: A User performing an action outside their authorization scope. An Interaction Session executing an action without User authorization. A User authorization scope that is broader than constitutional limits.

---

### Invariant 5 — Every Interaction Produces Evidence

**Every interaction — every message, every response, every tool call, every approval, every failure — produces an Event. Interaction evidence is complete.**

Interaction evidence includes: User input (every message the User sends, the channel it was sent on, the timestamp), AI output (every model response, every tool call result, every action taken), approval actions (every approval or rejection with the User's identity and timestamp), lifecycle events (Session creation, state transitions, termination), and authorization events (every authorization check and its result).

Interaction events are Events (Physics/005-Events.md). They are immutable, ordered, structured, and auditable.

*Constitutional Expression*: Law 1 (Evidence) — all actions produce evidence. Invariant 1 of Events (005) — every action produces an Event. Invariant 6 of Events — evidence is actionable.

*Enforcement*: The Interaction Engine instruments every interaction to produce Events. The Event Store stores interaction Events. Interaction evidence is accessible to the User, the Security Council, and the parent Organization.

*Edge Case*: A User input that is rejected before being processed (e.g., profanity filter, policy violation) — the rejected input is still recorded as an Event. The Event records the input, the rejection reason, and the timestamp.

*Edge Case*: A User input that is received but not processed because the Interaction Session is terminated — the input is recorded as an Event. The Session termination Event is also recorded. The causal chain preserves the sequence.

*Violation*: An interaction that produces no Event. An interaction Event that is not recorded in the Event Store. An interaction Event that is recorded incorrectly.

---

### Invariant 6 — Interactions Are Modality-Adaptive

**The Interaction Engine adapts to the User's channel. The same interaction can be delivered through any channel. The Interaction Engine handles modality differences transparently.**

Channel adapters handle modality-specific concerns: Voice input is transcribed to text, model output is delivered as synthesized speech, CLI output is formatted as text, GUI output includes UI components, and API output is structured as JSON.

The core interaction logic (authentication, authorization, routing, policy enforcement) is modality-independent. The channel adapter transforms input/output for the specific channel. The Interaction Engine maintains modality-awareness for context (e.g., voice has tone and pacing, GUI has layout).

*Constitutional Expression*: Article III, Part A, Section 008 (Interaction Engine) — "Managing all interactions." The Interaction Engine architecture includes channel adapters.

*Enforcement*: Channel adapters implement the Interaction Engine's channel API. Adapters validate message format. Adapters are verified by the Interaction Engine.

*Edge Case*: A multi-modal interaction (voice + GUI simultaneously) — each channel has its own InputOutputAdapter. The Interaction Engine correlates the channels through the User's identity and Interaction Session. Each channel's input is processed independently.

*Edge Case*: A User switching channels mid-conversation (e.g., CLI to GUI) — the Interaction Engine detects the channel switch. The new channel's adapter takes over the Interaction Session. The conversation context is preserved.

*Violation*: A channel adapter that modifies the interaction content. A channel adapter that bypasses authentication. A channel adapter that does not preserve interaction context.

---

### Invariant 7 — Interactions Are Real-Time

> User interactions are processed in real-time. The Interaction Engine maintains conversational tempo. Responses are delivered without unnecessary delay.

Real-time means: user input is received and acknowledged immediately, processing begins within the Interaction Engine's latency budget, model responses are streamed incrementally when possible, user-facing delays are minimized, and timeouts are enforced for stalled interactions.

Real-time does not mean instant. Real-time means predictable, responsive, and bounded. The Interaction Engine's latency budget is defined per modality (voice: <500ms, CLI: <2s, GUI: <1s).

*Constitutional Expression*: The conversational nature of AIOS (Article I, Part A) implies real-time interaction. This invariant ensures constitutional usability — the Constitution is not theoretical but operational.

*Enforcement*: The Interaction Engine monitors latency per modality. Latency violations are escalated. Backpressure mechanisms prevent overload. User feedback (typing indicator, streaming) is provided during processing.

*Edge Case*: A model response that takes longer than the latency budget — the Interaction Engine sends a progress indicator to the User. When the response is ready, it is delivered. The latency Event is recorded.

*Edge Case*: An interaction that stalls (User stops responding, network interruption) — the Interaction Session enters a Paused state. The User is notified when they reconnect. The Session is terminated after the idle timeout.

*Violation*: An interaction that takes longer than the maximum allowed processing time. An interaction that stalls without notification. A channel adapter that introduces unnecessary latency.

---

### Invariant 8 — Interactions Can Be Interrupted

> Users can interrupt interactions at any time. Interruption is a constitutional right. Interrupted interactions are preserved for context.

Interruption means: the User sends a new message while a previous message is being processed, the previous processing is stopped, the new message is processed in the current context, and the interrupted processing's partial results are preserved for context.

Interruption is constitutional. A User cannot be forced to wait for a response before sending a new message. An interrupted interaction does not leave the system in an inconsistent state.

*Constitutional Expression*: Article I, Part II (User Sovereignty) — "Users can interrupt interactions at any time." This is a fundamental User right.

*Enforcement*: The Interaction Engine supports interruption. When an interruption is received, the current processing is gracefully terminated. The new input is processed. The interruption is recorded as an Event.

*Edge Case*: A model call that is interrupted mid-stream — the partial response is discarded. The model call is cancelled. The new input is processed with the pre-interruption context. The interaction flow continues.

*Edge Case*: A tool call that is interrupted mid-execution — the tool call is completed (if safe) or terminated (if possible). The tool call result is discarded. The new input is processed. Tool call side effects are handled according to safety policies.

*Violation*: An interaction that cannot be interrupted. An interaction that loses context after interruption. An interruption that is not recorded as an Event.

---

### Invariant 9 — Interactions Are Evidence for the Academy

> Interaction evidence feeds the Academy. The Academy learns from interactions without retaining User-identifiable information.

The Academy's consumption of interaction evidence follows: interactions produce Events (Invariant 5), the Academy subscribes to interaction Event streams (via ACF Streams), the Academy extracts patterns and insights from interactions, User-identifiable information is stripped before training (the Interaction Engine provides anonymized evidence), and the Academy improves the system based on interaction patterns.

The Academy does not retain raw interaction data. Only anonymized, aggregated evidence is used for training. Users are informed that their interactions contribute to system improvement.

*Constitutional Expression*: Article III, Part B, Section 020 (Academy) — "The Academy learns from experience." Law 4 (Evidence) — evidence is the basis for learning.

*Enforcement*: The Interaction Engine provides anonymized evidence streams to the Academy. The Academy only accesses anonymized data. User-identifiable information is stripped.

*Edge Case*: A User who opts out of Academy training — the User's interactions are excluded from the Academy's evidence stream. The exclusion is honored by the Interaction Engine. The User's interactions still produce Events but are filtered from Academy subscriptions.

*Edge Case*: An interaction that contains sensitive User data — the sensitive data is stripped from the anonymized evidence stream. The Interaction Engine applies privacy filters before sharing with the Academy.

*Violation*: The Academy accessing User-identifiable information. An interaction whose evidence is shared without anonymization. A User whose opt-out preference is ignored.

---

### Invariant 10 — Interactions Reflect the Constitution

> All interactions reflect the Constitution. The Interaction Engine operates constitutionally. Users experience the Constitution through interactions.

The Constitution is not theoretical — it is operational. Users experience the Constitution through their interactions: authentication and privacy (Article I), boundaries (capabilities are verified, actions are authorized), rights (interruption, sovereignty, evidence preservation), transparency (explanations, evidence access, audit trails), and adaptation (modality-aware, multi-channel).

The Interaction Engine is the User's interface to the Constitution. Every interaction reinforces constitutional values: transparency, security, sovereignty, auditability, and adaptability.

*Constitutional Expression*: Law 2 (Constitution-First) — everything operates under the Constitution. Article I, Part II (User Sovereignty) — User interactions are the primary expression of the Constitution.

*Enforcement*: The Interaction Engine implements constitutional requirements. The Security Council verifies that interactions comply with the Constitution. The Interaction Engine's constitutional compliance is audited.

*Edge Case*: A User who requests an action that is constitutionally impermissible — the Interaction Engine explains why the action is not permitted. The explanation cites the constitutional basis. The User can escalate through constitutional channels.

*Edge Case*: A constitutional requirement that conflicts with a User's request (e.g., User asks the system to bypass security) — the constitutional requirement takes precedence. The system explains the constitutional basis for denying the request.

*Violation*: An interaction that violates constitutional requirements. An Interaction Engine that bypasses constitutional checks. A User who is not informed of their constitutional rights.

---

## Interaction Flow

```
User Input (via channel adapter)
    ↓
Interaction Engine:
    1. Receive input from channel adapter
    2. Create or identify Interaction Session
    3. Authenticate User (IRS)
    4. Authorize action (Security Council)
    5. Route to appropriate entity (ACF)
    6. Execute action (Session → Runtime)
    7. Produce Event (Evidence Store)
    8. Format response (channel adapter)
    9. Deliver response to User
    ↓
User receives response
```

---

## Interaction Modalities

| Modality | Input Adapter | Output Adapter | Latency Budget | Session Type |
|----------|--------------|---------------|----------------|-------------|
| Voice | Speech-to-Text | Text-to-Speech | <200ms | Voice Session |
| CLI | Terminal Parser | Text Formatter | <2s | CLI Session |
| GUI | Browser/App Input | HTML/Render | <1s | GUI Session |
| API | REST/gRPC Parser | JSON/Proto | <500ms | API Session |
| Discord | Bot Input Adapter | Bot Output Adapter | <2s | Discord Session |
| Email | Inbound Parser | Outbound Formatter | <5s | Email Session |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 3 (Communication), Law 4 (Evidence), Law 2 (Constitution-First) — source laws |
| Physics/001-Identity.md | User authentication in interactions (Invariant 3) |
| Physics/004-Sessions.md | Interaction Sessions (Invariant 10) |
| Physics/005-Events.md | Interaction evidence (Invariant 5) |
| Physics/006-Lifecycles.md | Interaction Session lifecycle |
| Physics/007-Capabilities.md | User capabilities (Invariant 4) |
| Physics/008-Security.md | Interaction security |
| Physics/012-Experience.md | Academy learning from interactions (Invariant 9) |
| Constitution, Article I, Part II (User Sovereignty) | User rights in interactions |
| Constitution, Article III, Part A, Section 008 (Interaction Engine) | Interaction Engine charter |
| Bible/06-Services/ACF/ | Communication routing |
| Bible/06-Services/Interaction/ | Interaction Engine implementation |

---

*End of AIOS Physics 009 — Interaction Invariants*