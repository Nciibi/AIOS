# AIOS Physics
## 001 — Identity Invariants

| Property | Value |
|----------|-------|
| Status | Immutable |
| Version | 1.0 |
| Category | Physics |
| Document ID | AIOS-PHY-001 |
| Applies To | Identity & Registry Service (IRS), All Constitutional Entities |
| Source Law | Law 5 — Law of Identity |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | None |

---

## Purpose

This document defines the universal invariants governing identity within AIOS. Identity is not authentication, not authorization, not trust — it is the fundamental answer to one question: *Who or what is this constitutional entity?*

These invariants extend Law 5 of Physics/000-Laws.md. Every entity, every interaction, every evidence record depends on these truths.

---

## The Identity Invariants

### Invariant 1 — Identity Precedes Implementation

**Every entity SHALL receive its constitutional identity before it exists as an implementation.**

The identity is assigned first by IRS — the entity becomes a constitutional participant the moment its identity is registered. Implementation (process creation, memory allocation, Runtime binding) follows identity assignment. An entity that exists as a running process without an assigned identity is an unauthorized process.

The reverse ordering is also possible: a newly created identity may briefly precede the entity's physical implementation. Identity can exist in "Created" state before the entity is fully instantiated. But identity must be established before any constitutional operation.

*Violation*: A Worker spawned without first being registered with IRS.

---

### Invariant 2 — One Identity Per Entity

**Every Constitutional Entity has exactly one identity.**

No entity has more than one identity. No identity is shared by more than one entity. Identity is the one-to-one mapping between the constitutional entity and its unique representation in AIOS.

*Violation*: Two Organizations sharing the same identity because of a registry error.

---

### Invariant 3 — Identity Is Immutable

**The constitutional identity itself never changes.**

Metadata may evolve. Ownership may evolve. Trust may evolve. Authentication credentials may change. The identity — the fundamental constitutional identifier — does not change for the lifetime of the entity.

An entity that loses its identity ceases to exist as a constitutional participant. An entity whose identity changes becomes a different constitutional entity.

*Violation*: Reassigning an identity from one Worker to another after the first Worker terminates.

---

### Invariant 4 — Identity Precedes Authentication

**Identity is established before authentication. Identity is not authentication.**

Authentication answers "prove you are who you claim to be." Identity answers "who are you, constitutionally?" An entity cannot authenticate without first having an identity. Identity is the immutable root upon which authentication, authorization, and trust are built.

*Violation*: Attempting to authenticate an entity that has no registered identity.

---

### Invariant 5 — Identity Precedes Authorization

**Authorization transforms verified identity into governed operational authority. Identity is not authorization.**

An entity must first be identified, then authenticated, then authorized. Authorization is the granting of specific capabilities to a specific identity. Identity alone grants nothing.

*Violation*: An authorization check that bypasses identity verification.

---

### Invariant 6 — Identity Is the Root of Constitutional Trust

**Identity is the root of constitutional trust. Without identity, no constitutional operation may occur.**

Every access, every execution, every audit record traces back to an identity. Trust is built upon identity. If identity is compromised, every other security layer is operating on an unreliable foundation.

*Violation*: Any constitutional operation performed by an entity whose identity is unverifiable.

---

### Invariant 7 — No Anonymous Constitutional Entities

**Identity transforms anonymous entities into governed constitutional participants. No constitutional entity may exist without identity.**

Anonymous entities cannot be audited, cannot be governed, cannot be trusted. Every entity that participates in AIOS must have a registered identity before it can act.

*Violation*: A transient Worker created without registration, performing operations and terminating.

---

### Invariant 8 — Identity Remains Traceable

**Identity persists throughout the entity lifecycle and enables secure governance, accountability, and constitutional continuity.**

Even after an entity is retired or archived, its identity remains in the evidence record. Past actions attributed to that identity remain attributable. Identity never disappears — it transitions to inactive states.

*Violation*: Purging an identity record after the entity terminates, breaking audit chains.

---

### Invariant 9 — Only IRS Owns Global Identity

**Identity capabilities belong exclusively to the Identity and Registry Service (IRS).**

IRS is the sole authority for identity creation, registration, resolution, and lifecycle management. No other entity may assign identity. No other entity may modify the identity registry. IRS manages identity; it never executes logic beyond identity administration.

*Violation*: An Organization creating its own identity identifiers outside IRS.

---

### Invariant 10 — Identity Is the Foundation of the Security Pipeline

**Identity verification is the first stage of every security pipeline.**

The Security Kernel execution pipeline begins with identity verification: Identity → Authentication → Authorization → Policy Evaluation → Capability Verification → Risk Assessment → Execution Authorization. No action may skip identity verification.

*Violation*: An execution request that skips identity verification and proceeds directly to authorization.

---

## The Identity Lifecycle

Every identity traverses these states:

```
Created → Verified → Active → Suspended → Restored → Retired → Archived
```

| State | Description |
|-------|-------------|
| Created | Identity is assigned to a new entity. Entity may not act yet. |
| Verified | The identity and its binding to the entity are confirmed. |
| Active | The entity may operate under this identity. |
| Suspended | Identity is temporarily disabled. Entity may not act. |
| Restored | A suspended identity is reactivated. |
| Retired | The entity has ceased operation. Identity remains for audit. |
| Archived | Identity is preserved in the evidence record. No longer active. |

The identity lifecycle is independent of but parallel to the entity lifecycle. An identity may exist briefly before its entity exists (Invariant 1) and persist long after its entity terminates (Invariant 8).

---

## Identity Metadata vs Identity Itself

| Property | Mutable? | Example |
|----------|----------|---------|
| Identity ID (constitutional identifier) | NEVER | `aios:org:001:a3f7c...` |
| Display Name | YES | "Web Search Org v2" |
| Owner | YES | Transferred to another Sou |
| Trust Level | YES | Trusted → Restricted |
| Authentication Keys | YES | Rotated quarterly |
| Capability Set | YES | Expanded with reauthorization |

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md | Law 5 — Law of Identity (source) |
| Physics/004-Sessions.md | Identity applied to Sessions (Invariant 3) |
| Physics/005-Events.md | Identity in evidence (Invariant 8) |
| Physics/006-Lifecycles.md | Identity lifecycle states (extends Invariant 4) |
| Physics/007-Capabilities.md | Identity as capability owner (Invariant 5) |
| Physics/008-Security.md | Identity in the verification pipeline (Invariant 10) |
| Physics/009-Interaction.md | Identity in inter-entity communication |
| Constitution, Article IV, 003-Identity.md | Constitutional identity principles |
| Constitution, Article IV, 003-Identity.md — Identity Lifecycle | Canonical identity lifecycle definition |

---

## Future Extensions

These invariants are expected to remain stable. Future identity-related specifications in the Bible (Bible/04-Execution/Security/IDS/) will define the implementation of identity resolution, federation, provenance, and cross-instance identity.

---

*End of AIOS Physics 001 — Identity Invariants*