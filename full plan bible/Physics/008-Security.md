# AIOS Physics
## 008 — Security Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-008 |
| Applies To | Security Council, Authentication, Authorization, Verification, Boundaries, Access Control, Security Events, Escalation |
| Source Laws | Law 8 — Law of Verification-First, Law 7 — Law of Capability Bounds, Law 5 — Law of Identity |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing Security within AIOS. Security is the constitutional framework for authentication, authorization, verification, access control, boundary enforcement, and escalation. The Security Council is the constitutional authority for all security operations. Every action is verified before execution.

These invariants extend Law 8 (Verification-First), Law 7 (Capability Bounds), and Law 5 (Identity) of Physics/000-Laws.md.

---

## What Is Security in AIOS?

Security is not a feature — it is a constitutional requirement. Security means:

- **Authentication**: Every entity is authenticated before acting. Identity is verified.
- **Authorization**: Every action is authorized before execution. Capability is verified.
- **Verification**: Every action is verified against constitutional rules. Compliance is checked.
- **Boundary Enforcement**: Every entity operates within defined boundaries. No entity escapes its bounds.
- **Escalation**: Unauthorized actions are escalated. Violations are investigated. Consequences are enforced.
- **Audit**: Every security action is recorded as an Event. Audit trails are complete.

These invariants apply to all entities — Users, Sessions, Missions, Organizations, Engines, Templates, and the Security Council itself.

---

## The Security Invariants

### Invariant 1 — Every Action Is Verified Before Execution

**No action executes without verification. Verification is the constitutional gate for all actions.**

The verification pipeline is: capture the action request, authenticate the requesting entity (who is asking?), authorize the action (does this entity have permission?), verify the action against policies (is this action safe?), verify the action against capability bounds (is this within the entity's declared bounds?), verify the action against lifecycle state (is the entity in a state that permits this action?), and then issue an execution authorization token.

Every action passes through this pipeline. There are no shortcuts. There are no wholesale exemptions.

*Constitutional Expression*: Law 8 (Verification-First) — "Every constitutional action must be verified before execution." This is referenced throughout the Constitution — in the ACF charter, in Capability Verification, in the Security Council mandate.

*Enforcement*: The Security Council operates the verification pipeline. ACF routes all action requests through the Security Council. The Runtime refuses execution without a valid verification token. Actions without tokens are denied. Verification violations are escalated.

*Edge Case*: An action that is part of a verified batch — each individual action in the batch is verified. Batch verification does not mean the batch is verified once. Each action has an individual verification record.

*Edge Case*: An action that is verified but the verification expires before execution — the action must be re-verified. Verification tokens have a time-to-live. Expired tokens require re-verification.

*Violation*: An action executing without verification. A verification bypass. A Runtime executing without a verification token. An action that is verified once and executed multiple times.

---

### Invariant 2 — Identity Is Verified Before Every Action

**The identity of the requesting entity is verified before every action. Identity verification is not optional.**

Identity verification establishes: who is requesting the action (entity ID), is the identity valid (active, not retired, not suspended), is the identity authentic (not spoofed, not a forgery), is the identity authorized for the action (by the entity's parent Organization, by the Session's Mission), and has the identity been verified by IRS.

Identity verification is the first step in the verification pipeline. If identity verification fails, the rest of the pipeline is not executed. The failed identity verification is recorded as a Security Event.

*Constitutional Expression*: Law 5 (Identity) — "Every entity has one immutable identity. Identity is constitutionally recognized by IRS." Article IV, Part A, Section 003 (Identity).

*Enforcement*: The Security Council validates identity through IRS. Requests without valid identity are rejected. Identity assertions are verified against IRS. Identity spoofing attempts are escalated.

*Edge Case*: An action requested by a batch process on behalf of multiple entities — each entity's identity is individually verified. Batch processes carry identity tokens for each represented entity.

*Edge Case*: An action requested by a system component that has no direct entity identity (e.g., a background process) — the component is authenticated by its parent Engine. The Engine's identity is verified. The action is attributed to the Engine.

*Violation*: An action from an unverified identity. An identity assertion that does not match IRS records. An action performed under a forged identity.

---

### Invariant 3 — Capabilities Are Verified Before Every Action

**The action is verified against the entity's capabilities. The entity must have a valid capability for the specific action being requested.**

Capability verification checks: Does the entity have a capability authorizing this action? Is the capability active (not expired, revoked, or suspended)? Does the capability's scope cover this specific action? Does the capability's bounds allow this specific use (resource consumption within budget, frequency within limits)? Is the capability's autonomy level sufficient for this action? Is the capability's verification token valid?

Capability verification is part of the verification pipeline. It occurs after identity verification. It is performed by the Capability Verification subsystem of the Security Council (Article IV, Part B, Section 007).

*Constitutional Expression*: Invariant 4 of Capabilities (007) — "Capabilities are verified before every use." Law 7 (Capability Bounds).

*Enforcement*: The Security Council checks the Capability Registry for every action. Capabilities that fail verification result in action denial. Verification failures are recorded as Security Events.

*Edge Case*: An action that is authorized by multiple capabilities (e.g., read_file authorized by both tool capability and data access capability) — the Security Council verifies all relevant capabilities. If any capability fails, the action is denied.

*Edge Case*: A capability that is verified for the action but the capability's resource budget is exhausted during the action — the action is allowed to complete (or is paused). Future actions are denied until the budget is refreshed.

*Violation*: An action that uses a capability that has been revoked. An action that exceeds a capability's bounds. An action that uses a capability not granted to the requesting entity.

---

### Invariant 4 — Policy Is Verified Before Every Action

**Every action is verified against applicable policies. No action bypasses policy enforcement.**

Policies include: constitutional policies (all actions must comply with the Constitution), organizational policies (each Organization may define additional policies within constitutional bounds), Mission policies (each Mission may define task-level policies), safety policies (no action that can cause harm to Users, data, or the system), compliance policies (actions must comply with applicable regulations, data protection, privacy, security standards), and governance policies (actions must comply with the entity's governance framework).

Policy verification is part of the verification pipeline. It occurs after capability verification. It is performed by the Security Council's Policy Engine.

*Constitutional Expression*: Law 8 (Verification-First) extends to policy compliance. Article III, Part A, Section 008 (SEC) — "SEC enforces all policies."

*Enforcement*: The Security Council's Policy Engine evaluates actions against all applicable policies. Failed policy checks result in action denial. Denials are recorded as Security Events with the policy that was violated.

*Edge Case*: An action that triggers a policy ambiguity (two policies with conflicting requirements) — the more restrictive policy applies. The ambiguity is escalated to the Organization for resolution. The resolution is recorded as a Policy Event.

*Edge Case*: A policy that is temporarily overridden for emergency operations — the override is authorized by the Security Council. The override is time-limited and action-scoped. The override is recorded as a Security Event.

*Violation*: An action that bypasses policy verification. An action that violates a policy without detection. A policy that is not enforced.

---

### Invariant 5 — Boundaries Are Verified Before Every Action

**Every action is verified against the entity's constitutional boundaries. No entity acts outside its boundaries.**

Boundaries include: lifecycle state boundaries (entities cannot act in disallowed states), scope boundaries (entities cannot act on entities outside their scope), resource boundaries (entities cannot consume resources outside their allocation), authorization boundaries (entities cannot authorize actions they do not have authority for), and jurisdiction boundaries (entities cannot act outside their constitutional jurisdiction).

Boundary verification is part of the verification pipeline. It occurs after policy verification. It ensures the entity is constitutionally permitted to perform the action given its current context.

*Constitutional Expression*: Law 6 (Lifecycle Compliance) — capabilities are state-dependent. Law 7 (Capability Bounds) — entities are bounded. Article IV, Part A, Section 001 (Security).

*Enforcement*: The Security Council checks lifecycle state, scope, resources, authorization, and jurisdiction. Boundary violations are denied and escalated.

*Edge Case*: An action that spans jurisdictional boundaries (e.g., an Organization requesting an action on a Session managed by another Organization) — the Security Council checks both jurisdictions. The action is allowed only if both jurisdictions authorize it.

*Edge Case*: An action that is within the entity's capability bounds but outside its lifecycle state boundaries — the action is denied. The entity must first transition to the appropriate lifecycle state.

*Violation*: An entity acting outside its lifecycle state. An entity acting on an entity outside its constitutional scope. An entity consuming resources outside its allocation.

---

### Invariant 6 — Enforcement Is Immediate and Consistent

**Security enforcement is immediate. Violations are detected in real-time. Consequences are applied consistently.**

Security enforcement operates in real-time. There is no delay between detection and enforcement. There is no gap between policy and practice.

Enforcement actions include: action denial (the action is not executed), entity suspension (the entity's capabilities are suspended), entity termination (the Session is terminated), capability revocation (the entity's capabilities are revoked), escalation (the violation is escalated to the parent Organization, Security Council, or Constitutional Council), and notification (the affected entities are notified).

*Constitutional Expression*: Law 8 (Verification-First) — enforcement is immediate and consistent. Article IV, Part A, Section 001 (Security).

*Enforcement*: The Security Council enforces constitutional actions. Enforcement actions are recorded as Security Events. Enforcement is auditable.

*Edge Case*: A violation that occurs in a distributed system with latency — the Security Council detects the violation after the action has executed. The violation is retroactively enforced. The action is reversed if possible or compensated. The enforcement is recorded.

*Edge Case*: A violation that is detected but enforcement is not possible (e.g., the violating entity is in a terminal state) — the enforcement is escalated to the parent Organization. The parent Organization takes remedial action.

*Violation*: An enforcement action that is delayed. An enforcement action that is inconsistent with past enforcement for the same violation type. An enforcement action that is not recorded.

---

### Invariant 7 — Security Council Is Subject to Security

**The Security Council itself is subject to verification, audit, and accountability. No entity is above security.**

The Security Council is not exempt from security invariants. Every action by the Security Council: is verified (actions by the Security Council are verified through the constitutional verification pipeline — the same pipeline, operated by a different division of the Council), is auditable (Security Council actions produce Events and are auditable by the Constitutional Council and the AIOS Council), is accountable (Security Council actions are accountable to the Constitution and the AIOS Council, with oversight from the AI Council), and is bounded (Security Council actions are bounded by constitutional authority — the Council cannot exceed its constitutional mandate).

The Security Council's own security is verified by: the Council of Engines (cross-checks Security Council actions), the Constitutional Council (constitutional review), the Audit Engine (independent audit), and IRS (identity verification for Security Council entities).

*Constitutional Expression*: Article III, Part A, Section 008 (SEC) acknowledges the constitutional mandate and its limits. Article VII (Amendments) provides for accountability mechanisms.

*Enforcement*: The Security Council's actions are logged. The Council of Engines monitors Security Council actions for constitutional compliance. The AI Council oversees the Security Council.

*Edge Case*: A Security Council action that is necessary but violates a security invariant (e.g., reading a sensitive Event without authorization) — the action requires a constitutional exemption. The exemption is authorized by the AI Council. The exemption is recorded as a Constitutional Event.

*Edge Case*: A Security Council entity that violates security invariants due to a bug or misconfiguration — the entity is suspended. The incident is investigated by the Council of Engines. The entity is repaired or replaced.

*Violation*: A Security Council action that is not verified. A Security Council action that is not auditable. A Security Council entity that bypasses security checks.

---

### Invariant 8 — Security Events Are Escalated

**Every security event is escalated according to its severity. No security event is ignored.**

Severity levels:

| Level | Name | Description | Response |
|-------|------|-------------|----------|
| S0 | Informational | Security event with no impact. | Logged only. |
| S1 | Low | Minor violation. First offense. | Logged. Entity warned. |
| S2 | Medium | Repeated minor violation or single significant violation. | Capability temporarily suspended. Parent notified. |
| S3 | High | Significant violation. Pattern of violations. Intentional violation. | Entity suspended. Parent Organization notified. Investigation initiated. |
| S4 | Critical | Constitutional violation. System-wide threat. | Entity terminated. Full investigation. Escalated to AI Council. |

Escalation path: entity parent Organization → Security Council → Constitutional Council → AI Council. Escalation is automatic based on severity. Response is required at each level.

*Constitutional Expression*: Article IV, Part A, Section 001 (Security) — escalation paths are defined. Article IV, Part B, Section 009 (Escalation) — escalation is integrated with Security.

*Enforcement*: The Security Council classifies security events. Escalation is automatic. Failure to escalate is itself a security event.

*Edge Case*: A security event that crosses severity levels during investigation — the event is reclassified. Escalation is updated to match the new severity level.

*Edge Case*: A security event that is detected but the responsible entity cannot be identified — the event is escalated as an unknown entity security event. The Security Council investigates. Parent Organizations are notified.

*Violation*: A security event that is not classified. A security event that is not escalated to the appropriate level. An escalation that is ignored.

---

### Invariant 9 — Security Is Layered

**Security is implemented in multiple layers. No single point of failure exists in the security framework.**

Security layers:

1. **ACF Layer**: Communication security, message verification, routing authorization
2. **Security Council Layer**: Action verification, capability verification, policy enforcement, identity verification
3. **Runtime Layer**: Execution security, resource isolation, sandboxing
4. **IRS Layer**: Identity verification, entity authentication
5. **Event Store Layer**: Audit trail, evidence integrity
6. **Constitutional Layer**: Constitutional compliance, amendment process, oversight

Each layer provides independent security. A failure in one layer does not compromise security. Layers are designed to catch each other's failures.

*Constitutional Expression*: Layered security is inherent in the constitutional design. Each constitutional institution provides independent security verification.

*Enforcement*: Each layer verifies its own security. The Security Council verifies the ACF layer. The Council of Engines verifies the Security Council. The Constitutional Council verifies constitutional compliance.

*Edge Case*: A failure in the ACF layer that bypasses message verification — the Security Council layer catches the unverified message when the action is requested. The failure is flagged.

*Edge Case*: A failure in multiple layers simultaneously — the system enters a security-critical state. All non-essential operations are paused. The Emergency Response Team is activated.

*Violation*: A security layer that is not implemented. A security layer that trusts the output of a compromised layer. A security layer that does not verify the layers beneath it.

---

### Invariant 10 — Security Is Universal

**Security applies to every entity, every action, every communication, every resource. No entity is exempt.**

There is no security exemption for: Users (all Users are authenticated, authorized, and verified — even root users, even administrators), Sessions (all Sessions are verified — no Session bypasses security), Engines (all Engines are subject to security — the Security Council itself is not exempt), Organizations (all Organizations operate within the security framework — no Organization bypasses security), external integrations (all integrations, APIs, webhooks pass through the security framework — no direct access, no back doors), or the system itself (the system is subject to security — security patches, security updates, security reviews).

*Constitutional Expression*: The Constitution does not create security exemptions. All entities are equal under security (Article I, Part A, Section 004 — No special class exemptions).

*Enforcement*: The Security Council verifies all entities. There is no bypass channel. Security violations are enforced universally.

*Edge Case*: A backdoor discovered in production — the backdoor is a critical security event. The backdoor is closed. The system is audited for unauthorized access. The backdoor's use is traced.

*Edge Case*: A security patch that introduces a new security vulnerability — the patch is rolled back. The vulnerability is investigated. The patch is re-released with the vulnerability fixed.

*Violation*: An entity that is exempted from security. A backdoor that bypasses security. A security patch that introduces a vulnerability.

---

## Security Verification Pipeline

```
Action Request
    ↓
Step 1: Identity Verification (IRS)
  - Entity ID exists? → Yes/No
  - Identity active? → Yes/No
  - Identity authentic? → Yes/No
    ↓
Step 2: Capability Verification (CCA)
  - Capability exists? → Yes/No
  - Capability active? → Yes/No
  - Capability covers action? → Yes/No
  - Capability bounds allow? → Yes/No
    ↓
Step 3: Policy Verification (Policy Engine)
  - Constitutional compliance? → Yes/No
  - Organizational policy? → Yes/No
  - Safety policy? → Yes/No
  - Compliance policy? → Yes/No
    ↓
Step 4: Boundary Verification (LMS + ROS)
  - Lifecycle state allows? → Yes/No
  - Scope permits? → Yes/No
  - Resources available? → Yes/No
  - Jurisdiction? → Yes/No
    ↓
Action Allowed or Denied
```

---

## Security Event Severity Reference

| Event | Severity | Escalation Path |
|-------|----------|-----------------|
| Failed identity verification | S2 → S3 (escalates on repeat) | Security Council |
| Expired capability used | S1 → S2 (repeat) | Parent Organization |
| Capability bounds exceeded | S2 | Security Council |
| Policy violation (first) | S1 | Entity warned |
| Policy violation (third) | S3 | Entity suspended |
| Constitutional violation | S4 | AI Council |
| Unauthorized access | S3 | Security Council |
| Entity termination | S3 | Parent Organization |
| System-wide threat | S4 | AI Council |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 8 (Verification-First), Law 9 (Design DNA) — source laws |
| Physics/001-Identity.md | Identity verification (Invariant 2) |
| Physics/004-Sessions.md | Session security (Invariant 6) |
| Physics/005-Events.md | Security Events (Invariant 8) |
| Physics/007-Capabilities.md | Capability verification (Invariant 3) |
| Physics/009-Interaction.md | Communication security |
| Physics/010-Execution.md | Execution verification |
| Constitution, Article III, Part A, Section 008 (SEC) | Security Council mandate |
| Constitution, Article IV | Security framework, verification, escalation |
| Bible/06-Services/Security/ | Security Council implementation |
| Bible/06-Services/ACF/ | ACF security layer |

---

*End of AIOS Physics 008 — Security Invariants*