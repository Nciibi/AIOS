# AIOS Reference
## 000 — Architecture Decision Log

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Reference |
| Document ID | REF-ADL-000 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This log records every significant architectural decision made during the design and evolution of AIOS. Each entry captures the decision, the context, alternatives considered, rationale, and consequences. This is the authoritative index — the Bible and Physics documents contain the full specification; this log provides traceability for why the architecture is what it is.

## Decision Status Key

| Status | Meaning |
|--------|---------|
| Proposed | Decision drafted, not yet reviewed |
| Reviewed | Under review by the Architecture Review Board |
| Approved | Accepted and implemented |
| Deprecated | No longer recommended; kept for history |
| Superseded | Replaced by a newer ADR |

## Architecture Decisions

### ADR-001: ACF as Universal Communication Backbone

| Property | Value |
|----------|-------|
| Date | 2026-01-15 |
| Status | Approved |

**Decision**: ACF is the exclusive communication channel for all inter-entity communication. No direct IPC, shared memory, or side channels.

**Rationale**: ACF provides observability, routing, audit, and security in a single layer. Direct communication would break the security model — the Security Kernel cannot verify what it cannot observe.

**Bible Reference**: `Bible/06-Services/ACF/000-Overview.md`

### ADR-002: Event Store as Single Source of Truth

| Property | Value |
|----------|-------|
| Date | 2026-01-20 |
| Status | Approved |

**Decision**: All system state is derived from an append-only Event Store. No entity mutates state directly.

**Rationale**: Immutable event sourcing provides a perfect audit trail (Law 4), enables time-travel debugging, and prevents data loss.

**Bible Reference**: `Bible/05-Platform/004-EVS.md`

### ADR-003: Seven-Stage Security Pipeline

| Property | Value |
|----------|-------|
| Date | 2026-02-01 |
| Status | Approved |

**Decision**: The Security Kernel implements a linear seven-stage pipeline: Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization. No stage may be skipped.

**Rationale**: Sequential verification ensures each stage builds on the previous. Each stage produces evidence (Law 4).

**Alternatives Considered**: Parallel verification (rejected — stages are dependent), two-stage pipeline (rejected — insufficient granularity for audit).

**Bible Reference**: `Bible/04-Execution/Security/001-Architecture.md`

### ADR-004: State Machine as Universal Lifecycle Model

| Property | Value |
|----------|-------|
| Date | 2026-02-10 |
| Status | Approved |

**Decision**: All entity lifecycles are modeled as deterministic state machines via the LMS framework. Every entity type defines its states, valid transitions, and transition guards.

**Rationale**: Unified state machines ensure consistency, enable automated enforcement, and provide clear audit trails (Law 6).

**Bible Reference**: `Bible/05-Platform/000-LMS.md`

### ADR-005: Identity Service (IDS) as Single Identity Authority

| Property | Value |
|----------|-------|
| Date | 2026-02-15 |
| Status | Approved |

**Decision**: IDS is the sole authority for identity issuance, verification, and retirement. Identities are UUID-based, immutable, and never reused.

**Rationale**: A single authority prevents collisions and ensures uniqueness (Law 5). UUIDs provide collision-free generation without coordination.

**Alternatives Considered**: Decentralized identity (rejected — cannot guarantee uniqueness), sequential IDs (rejected — reveals system information).

**Bible Reference**: `Bible/04-Execution/Security/IDS/000-Overview.md`

### ADR-006: Separation of Sou and OSYS

| Property | Value |
|----------|-------|
| Date | 2026-03-01 |
| Status | Approved |

**Decision**: Sou proposes strategy and Missions. OSYS handles execution. Sou communicates intent; OSYS executes operations. Neither crosses into the other's domain.

**Rationale**: Satisfies Law 2 (Non-Execution). Implements constitutional Separation of Powers.

**Bible Reference**: `Bible/02-Core/Sou/000-Overview.md`, `Bible/02-Core/OSYS/000-Overview.md`

### ADR-007: Capability Bounds as Declared Properties

| Property | Value |
|----------|-------|
| Date | 2026-03-10 |
| Status | Approved |

**Decision**: Every Worker declares its capability bounds at creation. Bounds are enforced by the Security Kernel at every action.

**Rationale**: Declared bounds provide a clear contract. The Security Kernel can verify every action without querying external systems (Law 7, Law 8).

**Bible Reference**: `Bible/04-Execution/Security/AZS/002-Capability.md`

### ADR-008: Autonomy Levels L0–L4

| Property | Value |
|----------|-------|
| Date | 2026-03-20 |
| Status | Approved |

**Decision**: Five autonomy levels: L0 (Directed), L1 (Supervised), L2 (Delegated), L3 (Trusted), L4 (Sovereign). Progression requires evidence of constitutional compliance.

**Rationale**: Graduated autonomy allows entities to earn trust over time while maintaining constitutional bounds.

**Bible Reference**: `Bible/03-Institutions/Workers/000-Overview.md`

### ADR-009: SDK-Based Runtime Interface

| Property | Value |
|----------|-------|
| Date | 2026-04-01 |
| Status | Approved |

**Decision**: AIOS provides four SDKs: Runtime, Audit, Knowledge, Provider. Every Runtime must use the SDKs for platform integration.

**Rationale**: SDKs provide a paved path (R14), encapsulate ACF communication and identity verification, and satisfy R3 (DRY).

**Bible Reference**: `Bible/08-Interfaces/SDK/000-Runtime-SDK.md`

### ADR-010: Academy Learning from Evidence Only

| Property | Value |
|----------|-------|
| Date | 2026-04-10 |
| Status | Approved |

**Decision**: The Academy learns exclusively from Evidence (Events). It never observes entity internals directly.

**Rationale**: Preserves entity autonomy, maintains privacy, and satisfies Law 4 (Evidence).

**Bible Reference**: `Bible/02-Core/Academy/000-Overview.md`

### ADR-011: Constitution as Immutable Foundation

| Property | Value |
|----------|-------|
| Date | 2026-05-01 |
| Status | Approved |

**Decision**: The Constitution is the supreme governing document. Physics derives from it. Bible derives from Physics. Code implements Bible. No tier may violate the tier above it.

**Rationale**: Hierarchical layering enforces constitutional supremacy (Law 9). Each tier provides clear constraints for the tier below.

**Bible Reference**: `Bible/00-Foundations/001-AIOS-Philosophy.md`

### ADR-012: Human Override as Only Exception Mechanism

| Property | Value |
|----------|-------|
| Date | 2026-05-15 |
| Status | Approved |

**Decision**: Human Override is the only mechanism that can suspend a Physics Law. Overrides must be time-bound, scope-bound, recorded as evidence, and subject to post-hoc audit.

**Rationale**: Preserves human sovereignty (Law 1) while allowing emergency exceptions. Evidence recording ensures accountability (Law 4).

**Bible Reference**: `Bible/01-Governance/002-DGP.md`

### ADR-013: Resource Allocation — Two-Phase Model

| Property | Value |
|----------|-------|
| Date | 2026-06-01 |
| Status | Approved |

**Decision**: Resources are allocated through Reservation (budget at Organization/Mission level) then Assignment (concrete binding at Worker execution time).

**Rationale**: Separates strategic planning from operational binding. Organizations plan needs without knowing execution details. Workers receive resources at execution time.

**Bible Reference**: `Bible/02-Core/ROS/000-Overview.md`

### ADR-014: Organization Hierarchy — Four-Level Maximum

| Property | Value |
|----------|-------|
| Date | 2026-06-10 |
| Status | Approved |

**Decision**: Organization hierarchy is limited to four levels: Root → Domain → Department → Team.

**Rationale**: Prevents excessive nesting that complicates governance, slows decision-making, and obscures accountability. ADG exception required for deeper hierarchies.

**Bible Reference**: `Bible/03-Institutions/Organizations/001-OOM.md`

### ADR-015: Event Retention — Tiered Classification

| Property | Value |
|----------|-------|
| Date | 2026-06-20 |
| Status | Approved |

**Decision**: Event retention is tiered by classification: Critical (indefinite), Operational (90d hot + 7yr cold), Debug (30d hot + 1yr cold), Transient (7d, no archive).

**Rationale**: Balances storage efficiency with regulatory requirements. Critical events retained indefinitely (Law 4).

**Bible Reference**: `Bible/05-Platform/004-EVS.md`

## Cross-Cutting Concerns

### Security
Every ADR undergoes Security Council review. ADRs affecting identity, cryptography, or authorization require additional review.

### Evidence
Every ADR is recorded with date, author, status, and rationale. Status changes are versioned. Superseded ADRs remain in the log.

### Lifecycle
ADRs follow: Proposed → Reviewed → Approved → Active → Deprecated → Superseded.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R3 | ADRs document decisions once, preventing DRY violations |
| R10 | ADRs must justify why the chosen approach is the simplest valid solution |
| R12 | Every ADR documents consequences and trade-offs |
| R15 | ADRs must allow future extension without modification |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/09-Reference/000-Decision-Log.md | Full ADR log with detailed entries |
| Bible/09-Reference/002-ADG-Index.md | ADG index — architectural decisions reviewed through ADG |
| Bible/01-Governance/005-ADG.md | ADG governance process |
| Bible/01-Governance/003-CRP.md | RFC pipeline — approved ADRs may require RFCs |
| Bible/00-Foundations/002-Design-DNA.md | Design DNA rules — every ADR must comply with R1–R15 |
| Physics/011-Design-DNA.md | Physics source of Design DNA |
