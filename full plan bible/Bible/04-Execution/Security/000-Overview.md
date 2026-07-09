# AIOS Bible — Security
## 000 — Security Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security |
| Document ID | AIOS-BBL-004-SEC-000 |
| Source Laws | Law 5 — Law of Identity, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Security volume defines the complete security architecture of AIOS. Every action, every message, every resource access is secured through a multi-layered framework that spans identity management, authentication, authorization, policy enforcement, risk evaluation, cryptographic operations, and trust management. Security is not an add-on — it is baked into every layer of the architecture.

Security in AIOS follows three constitutional principles: **Verification-First** (every action is verified before execution), **Capability Bounds** (every entity operates within declared bounds), and **Evidence** (every security decision produces an auditable Event).

## Security Architecture

The Security Council is the constitutional authority for all security operations. It operates the verification pipeline and coordinates the following sub-services:

### Identity & Authentication

| Service | Function |
|---------|----------|
| IDS (Identity Service) | Identity creation, registration, resolution, lifecycle, federation, provenance |
| ATS (Authentication Service) | Token issuance, validation, MFA, session management |

### Authorization & Policy

| Service | Function |
|---------|----------|
| AZS (Authorization Service) | RBAC, ABAC, capability-based authorization |
| Policy System | Policy definition grammar, validation engine, policy storage |
| Execution Auth | Verification pipeline — 7-stage action verification |

### Risk & Trust

| Service | Function |
|---------|----------|
| Risk Engine | Risk scoring, tiers, escalation, automated evaluation |
| Trust Lifecycle Manager | Trust establishment, verification, revocation, chain management |

### Audit & Crypto

| Service | Function |
|---------|----------|
| Audit Service | Evidence audit trail, query, retention, export |
| Crypto Service Provider | Cryptographic operations, key management, HSM integration, certificates |

### Runtime Security

| Service | Function |
|---------|----------|
| Sandbox | Execution isolation, process/namespace/resource isolation |
| SSM | Session and secret management, credential lifecycle |

## Verification Pipeline

The 7-stage verification pipeline is the constitutional gate for all execution:

```
Identity → Authentication → Authorization → Policy → Capability → Risk → Execution Authorization
```

| Stage | Service | Description |
|-------|---------|-------------|
| 1 — Identity | IDS | Verify actor identity exists and is active |
| 2 — Authentication | ATS | Verify authentication token is valid |
| 3 — Authorization | AZS | Verify actor is authorized for this action |
| 4 — Policy | Policy System | Verify action complies with active policies |
| 5 — Capability | CCA | Verify actor has required capabilities |
| 6 — Risk | Risk Engine | Evaluate risk level; escalate if above threshold |
| 7 — Execution Auth | Execution Auth | Issue execution token; reserve resources via ROS |

## Cross-Cutting Concerns

### Security

Security is self-referential at this level. The Security Council enforces the security of all sub-services through mutual authentication (all inter-service communication uses mTLS via ACF), cryptographic verification (all service identities are cryptographically signed), and audit (every security operation produces Events).

### Evidence

Every security decision — grant, deny, escalate, revoke — produces a Security Event. Events are immutable, stored in the Event Store, and retained per sensitivity classification. The full verification pipeline produces a chain of evidence for every action.

### Lifecycle

Security services follow the canonical Platform lifecycle. Identity, key, certificate, and trust lifecycles are governed by Law 6. Security policy versions follow the CRP lifecycle.

### Capability Bounds

Every security service operates within defined bounds. IDS cannot issue tokens (ATS does). AZS cannot create identities (IDS does). The verification pipeline components are strictly separated per R1 (Modulsingularity).

### Communication

All security inter-service communication flows through ACF. The verification pipeline uses synchronous ACF calls. Security alerts and critical Events use ACF streams with guaranteed delivery.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Each security sub-service does exactly one thing |
| R2 — Dependency Order | Security depends on Platform (ACF, EVS); no upward deps |
| R3 — DRY | Security policies and capability definitions are defined once |
| R4 — Builder Pattern | Pipeline stages built by Security Council with dependency injection |
| R5 — Liskov | All auth providers implement the same AuthProvider interface |
| R6 — DI over Singletons | Services receive dependencies via constructor injection |
| R7 — Tests Exist | Every pipeline stage has unit and integration tests |
| R8 — Tests Fast | Pipeline stage tests complete in <100ms |
| R9 — Deterministic | Same inputs always produce same security decision |
| R10 — Simpler Over Complex | Security model uses simple hierarchical checks |
| R11 — Refactor Over Rewrite | Security services evolve through RFC process |
| R12 — Embrace Errors | Every denial has a unique error code |
| R13 — Design for Failure | Pipeline stages have configurable timeouts |
| R14 — Paved Path | The verification pipeline is the only execution path |
| R15 — Open/Closed | New security services integrate without modifying pipeline |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 001-Architecture.md | Security Council component architecture |
| 002-Trust-Model.md | Trust levels, chains, cross-instance trust |
| IDS/000-Overview.md | Identity management — foundation of all security |
| ATS/000-Auth-Methods.md | Authentication methods — verification pipeline stage 2 |
| AZS/000-RBAC.md | Authorization — verification pipeline stage 3 |
| Policy-System/000-PS.md | Policy engine — verification pipeline stage 4 |
| Risk/000-RE.md | Risk evaluation — verification pipeline stage 6 |
| Execution-Auth/000-EAS.md | Execution authorization — verification pipeline stage 7 |
| 00-Foundations/001-AIOS-Philosophy.md | PHI-004 (Identity), PHI-007 (Capability Bounds), PHI-005 (Verification-First) |
