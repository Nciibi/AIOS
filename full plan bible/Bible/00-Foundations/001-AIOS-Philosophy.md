# AIOS Bible — Foundations
## 001 — AIOS Philosophy

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-001 |
| Source Laws | All — Philosophy interprets the entire Constitution |
| Source Physics | Physics/000-Laws.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Core Tenets

### 1. Constitutional AI

AIOS is a constitutional AI system. Every action, decision, and operation is governed by a written Constitution (the Laws). No entity — not even the Security Council or Sou — operates outside the Constitution. The Constitution is the supreme authority.

**Consequences**:
- All capabilities derive from constitutional grants, not from technical ability
- All operations produce evidence for constitutional compliance
- Constitutional amendments follow a strict RFC process, not arbitrary override

### 2. Evidence-Driven Operations

Every action in AIOS produces evidence. Evidence is immutable, traceable, and auditable. Nothing in AIOS operates without leaving a verifiable record. This is the foundation of trust, audit, and learning.

**Consequences**:
- Every operation produces at least one Event
- Events are stored immutably in the Event Store
- The Academy learns from evidence, not from direct observation of entity internals
- No entity can act without the action being verifiable by the Security Council

### 3. Entity Autonomy (L0–L4)

AIOS entities exist on an autonomy spectrum. Every entity starts at L0 (fully constrained, human-directed) and may progress to L4 (fully autonomous within constitutional bounds). Autonomy is earned through demonstrated reliability and constitutional compliance.

| Level | Name | Description |
|-------|------|-------------|
| L0 | Directed | Every action requires human approval |
| L1 | Supervised | Actions execute autonomously within narrow scope; human may override |
| L2 | Delegated | Entity manages its own actions within a Mission scope |
| L3 | Trusted | Entity operates autonomously across multiple Missions |
| L4 | Sovereign | Entity is a constitutional entity with near-full autonomy, bounded only by the Constitution |

**Consequences**:
- Capabilities are bounded by autonomy level
- Progression requires evidence of past success and constitutional compliance
- Regression occurs on violation or failure
- All levels are subject to the same constitutional constraints

### 4. Identity Precedes Action

No entity acts without an identity. Identity is the immutable root of constitutional operations. Every entity receives its identity from the Identity Service (IDS) at creation. Authentication, authorization, capability, and execution all depend on identity.

**Consequences**:
- Anonymous entities cannot exist
- Identity is immutable once created
- All actions are attributed to an identity
- The verification pipeline requires identity as its first stage

### 5. Verification-First

No action executes without verification. Every action passes through a 7-stage verification pipeline (Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization). A denial at any stage prevents execution entirely.

**Consequences**:
- The verification pipeline is mandatory for every action
- The pipeline is sequential, not parallel
- Fail-closed: if any dependency is unavailable, the action is denied
- The pipeline itself is subject to constitutional oversight

### 6. Lifecycle Compliance

Every entity has a lifecycle. Every state transition is authorized, recorded, and verifiable. No entity exists outside its lifecycle.

**Consequences**:
- Entities progress through defined states (Created → Verified → Active → Suspended → Retired → Archived)
- Each transition requires authorization from a specific entity type
- State-dependent capabilities: entities may only act in certain states
- Lifecycle violations are constitutional violations

### 7. Capability Bounds Over Permission

Capabilities are bounded, not binary. An entity does not simply have or lack a capability; it has a capability with specific resource bounds, duration, scope, frequency, and autonomy constraints. Capabilities are the constitutional expression of what an entity may do.

**Consequences**:
- Every capability has resource bounds
- Capabilities are granted by authority, not assumed
- Capabilities may be revoked or suspended
- Capability use is auditable

### 8. Evidence Over Opinion

Decisions are made on evidence, not opinion. The Academy learns from evidence. The Security Council verifies against evidence. Organizations manage based on evidence. Evidence is the currency of constitutional operations.

**Consequences**:
- All data is traceable to a source Event
- Hearsay and unverified assertions have no constitutional weight
- Evidence has provenance and can be verified
- Evidence retention is governed by policy, not discretion

### 9. Simpler Over Complex

Every design choice favours simplicity over complexity. The simplest solution that satisfies all constraints is the correct solution. Complexity is justified only when simpler alternatives have been proven inadequate.

**Consequences**:
- New features require proof that simpler alternatives were considered
- The pipeline is linear and sequential — no branching or parallelism tricks
- Capabilities are defined in terms of resources, not arbitrary logic
- Lifecycles are defined in terms of states and transitions, not arbitrary state machines

### 10. Design for Failure

Every component assumes that every dependency will fail. Systems are designed to degrade gracefully, deny safely, and recover automatically.

**Consequences**:
- Systems fail closed (deny on uncertainty, not allow)
- Dependencies have timeouts, retries, and circuit breakers
- Graceful degradation: a failed dependency reduces capability, does not crash the system
- Automatic recovery is the default; manual intervention is the exception

## Relationship to Other Volumes

| Volume | Relationship |
|--------|-------------|
| Governance | Implements Philosophy through RFCs, Constitution lifecycle, decisions |
| Core Engines | Build systems that embody these tenets (identity, lifecycle, capability, event sourcing) |
| Security | The Security Council enforces these tenets operationally |
| Institutions | Organizations and Missions operate within these philosophical bounds |
| Services | ACF, Crypto, Federation — all built on Philosophy principles |