# AIOS Bible — Reference
## 000 — Decision Log

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Reference |
| Document ID | AIOS-BBL-009-DEC-000 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Decision Log records all Architectural Decision Records (ADRs) made during the design and evolution of AIOS. Every ADR captures a significant architectural decision, the context in which it was made, the alternatives considered, and the rationale for the chosen approach. This log ensures traceability of the system's architectural evolution.

## ADR Format

Every ADR follows this template:

```
ADR-NNNN: Title
Date: YYYY-MM-DD
Status: [Proposed | Approved | Deprecated | Superseded]
Author: [identity_id]
Source Laws: [Law(s)]
Source Physics: [Physics document(s)]

## Context
  - What is the architectural problem?
  - What constraints apply?
  - What is the current architecture?

## Decision
  - What is the chosen approach?
  - Why is this approach correct?

## Alternatives Considered
  - Alternative 1 (with rationale for rejection)
  - Alternative 2 (with rationale for rejection)

## Design DNA Compliance
  - R1: How does this respect single responsibility?
  - R2: Is the dependency graph still acyclic?
  - R10: Why is this the simplest valid solution?
  - R15: Does this allow future extension without modification?

## Consequences
  - What changes are required?
  - What other decisions depend on this?
  - What are the trade-offs accepted?
```

## ADR Registry

### ADR-0001: ACF as Universal Communication Backbone

| Property | Value |
|----------|-------|
| Date | 2026-01-15 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: AIOS requires a single communication fabric to satisfy Law 3 (Communication). Multiple candidates existed including gRPC, message queues, and direct IPC.

**Decision**: ACF (AI Communication Fabric) is the exclusive communication channel. All inter-entity communication flows through ACF topics. No direct IPC, shared memory, or side channels.

**Rationale**: ACF provides observability, routing, audit, and security in a single layer. Direct communication would break the security model — the Security Kernel cannot verify what it cannot observe.

**Alternatives Considered**: gRPC (rejected — no built-in event sourcing), RabbitMQ (rejected — single point of failure without AIOS lifecycle integration), direct IPC (rejected — violates Law 3).

### ADR-0002: Event Store as Single Source of Truth

| Property | Value |
|----------|-------|
| Date | 2026-01-20 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: AIOS needs an immutable, append-only record of all actions to satisfy Law 4 (Evidence). Traditional databases with UPDATE operations would lose the audit trail.

**Decision**: All system state is derived from an append-only Event Store. No entity mutates state directly. State is a projection of the event stream.

**Rationale**: Immutable event sourcing provides a perfect audit trail, enables time-travel debugging, and satisfies Law 4 (Evidence). Every action produces one or more Events that are stored immutably.

**Alternatives Considered**: Traditional RDBMS (rejected — loses history on UPDATE), hybrid approach with audit tables (rejected — audit can be bypassed).

### ADR-0003: Seven-Stage Security Pipeline

| Property | Value |
|----------|-------|
| Date | 2026-02-01 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Law 8 (Verification-First) requires that every action is verified before execution. The pipeline stages and their ordering must be defined.

**Decision**: The Security Kernel implements a seven-stage linear pipeline: Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization. No stage may be skipped.

**Rationale**: Sequential verification ensures each stage builds on the previous. Identity must be verified before authentication can occur. Authorization requires identity and authentication. Capability requires authorization. Each stage produces evidence.

**Alternatives Considered**: Parallel verification (rejected — stages are dependent), two-stage pipeline (rejected — insufficient granularity for audit).

### ADR-0004: State Machine as Universal Lifecycle Model

| Property | Value |
|----------|-------|
| Date | 2026-02-10 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Law 6 (Lifecycle Compliance) requires every entity to follow a defined lifecycle. Multiple state machine implementations were considered.

**Decision**: All entity lifecycles are modeled as deterministic state machines using the LMS (Lifecycle Management System) framework. Every entity type defines its states, valid transitions, and transition guards.

**Rationale**: A unified state machine framework ensures consistency across entity types, enables automated enforcement, and provides clear audit trails for every state transition.

**Alternatives Considered**: Ad-hoc lifecycle logic per entity (rejected — violates DRY/R3), external workflow engine (rejected — adds external dependency, violates R1).

### ADR-0005: Identity and Registry Service (IRS) as Single Identity Authority

| Property | Value |
|----------|-------|
| Date | 2026-02-15 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Law 5 (Identity) requires every entity to have exactly one immutable identity. Multiple identity schemes were evaluated.

**Decision**: IRS is the sole authority for identity issuance, verification, and retirement. All entities receive their identity from IRS at creation. Identities are UUID-based, immutable, and never reused.

**Rationale**: A single identity authority prevents identity collisions, ensures uniqueness, and provides a central registry for all entity identities. UUIDs provide collision-free generation without coordination.

**Alternatives Considered**: Decentralized identity (rejected — cannot guarantee uniqueness), sequential IDs (rejected — reveals system information).

### ADR-0006: Separation of Sou and OSYS

| Property | Value |
|----------|-------|
| Date | 2026-03-01 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Law 2 (Non-Execution) mandates that Sou never executes. The boundary between strategic decision-making and operational execution must be clearly defined.

**Decision**: Sou proposes strategy and Missions. OSYS (Operating System) handles all execution: resource allocation, Worker lifecycle, Organization management. Sou communicates intent; OSYS executes operations.

**Rationale**: This separation satisfies Law 2 (Non-Execution) and implements the constitutional Separation of Powers. Sou focuses on strategy; OSYS focuses on operations. Neither crosses into the other's domain.

**Alternatives Considered**: Combined Sou-OSYS (rejected — violates Law 2), Sou with limited execution (rejected — slippery slope to full execution authority).

### ADR-0007: Capability Bounds as Declared Properties

| Property | Value |
|----------|-------|
| Date | 2026-03-10 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Law 7 (Capability Bounds) requires Workers to operate within declared bounds. The mechanism for declaring, storing, and enforcing capability bounds must be defined.

**Decision**: Every Worker declares its capability bounds at creation (skills, permissions, resource limits, autonomy level). Bounds are stored in the Capability Registry and enforced by the Security Kernel at every action.

**Rationale**: Declared bounds provide a clear contract between the Worker and the platform. The Security Kernel can verify every action against these bounds without querying external systems.

**Alternatives Considered**: Implicit bounds inferred from role (rejected — not auditable), runtime negotiation (rejected — violates Law 8 — Verification-First).

### ADR-0008: Autonomy Levels L0–L4

| Property | Value |
|----------|-------|
| Date | 2026-03-20 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: AIOS entities exist on an autonomy spectrum. The levels and progression criteria must be formally defined.

**Decision**: Five autonomy levels are defined: L0 (Directed), L1 (Supervised), L2 (Delegated), L3 (Trusted), L4 (Sovereign). Progression requires evidence of constitutional compliance. Regression occurs on violation.

**Rationale**: A graduated autonomy model allows entities to earn trust over time. L0 ensures human control. L4 enables full constitutional entity status. Each level adds capabilities while maintaining constitutional bounds.

**Alternatives Considered**: Binary human-in-the-loop (rejected — too coarse), continuous autonomy score (rejected — hard to audit and enforce).

### ADR-0009: SDK-Based Runtime Interface

| Property | Value |
|----------|-------|
| Date | 2026-04-01 |
| Status | Approved |
| Author | Security Council |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: Runtimes need a standardized interface to the AIOS platform. Without a defined SDK, every Runtime would need to implement platform integration from scratch.

**Decision**: AIOS provides four SDKs: Runtime SDK (platform integration), Audit SDK (evidence recording), Knowledge SDK (Academy access), and Provider SDK (resource provider interface). Every Runtime must use the SDKs.

**Rationale**: SDKs provide a paved path (R14) for platform integration. They encapsulate ACF communication, evidence recording, and identity verification. This satisfies R3 (DRY) by providing reusable components.

**Alternatives Considered**: Direct API access (rejected — every Runtime would duplicate platform integration code), shared libraries (rejected — versioning conflicts).

### ADR-0010: Academy Learning from Evidence Only

| Property | Value |
|----------|-------|
| Date | 2026-04-10 |
| Status | Approved |
| Author | Academy |
| Supersedes | Nothing |
| Superseded By | Nothing |

**Context**: The Academy must learn from system operations to improve AIOS. Direct observation of entity internals would violate privacy and increase coupling.

**Decision**: The Academy learns exclusively from Evidence (Events). It never observes entity internals directly. The Knowledge pipeline processes Events to extract patterns, identify improvements, and generate knowledge.

**Rationale**: Evidence-based learning preserves entity autonomy, maintains privacy, and satisfies Law 4 (Evidence). The Event Store provides a complete, immutable record of all operations.

**Alternatives Considered**: Direct entity inspection (rejected — violates autonomy), log scraping (rejected — logs are not structured evidence).

## Cross-Cutting Concerns

### Security
ADR decisions are reviewed by the Security Council. Every ADR must pass a security impact assessment before approval. ADRs involving cryptography, identity, or authorization require additional Security Council review.

### Evidence
Every ADR is recorded in this log with date, author, status, and rationale. Status changes are versioned. The complete history of every ADR is preserved. Superseded ADRs remain in the log with a reference to the superseding ADR.

### Lifecycle
ADRs follow a defined lifecycle: Proposed → Reviewed → Approved → Active → Deprecated → Superseded. An ADR may be reopened if new context emerges. Deprecated ADRs remain as historical records.

### Capability Bounds
ADRs define boundaries of the architecture. No implementation may exceed the bounds established by approved ADRs without a new ADR. Capability bound decisions are the most frequently reviewed ADR type.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R3 | ADRs prevent DRY violations by documenting architectural decisions once. |
| R10 | ADRs must justify why the chosen approach is the simplest valid solution. |
| R12 | Every ADR explicitly documents consequences and trade-offs. |
| R15 | ADRs must demonstrate that the decision allows future extension without modification. |

### Interoperability
ADRs that affect interface contracts, message schemas, or protocols must include an interoperability impact statement. Changes to public APIs require an ADR before RFC submission.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 002-ADG-Index.md | ADG index — architectural decisions are reviewed through ADG before becoming ADRs |
| 01-Governance/005-ADG.md | Architectural Decision Gateway — governance process for architectural decisions |
| 01-Governance/003-CRP.md | RFC pipeline — approved ADRs may require RFCs for implementation |
| 00-Foundations/002-Design-DNA.md | Design DNA rules — every ADR must comply with R1–R15 |
| Physics/011-Design-DNA.md | Physics source of Design DNA |
| 10-Research/001-Autonomy-Evolution.md | Autonomy research — informs ADR-0008 |
