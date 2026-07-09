# AIOS Bible — Foundations
## 003 — Core Principles

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Foundations |
| Document ID | AIOS-BBL-000-003 |
| Source Laws | All — Core Principles interpret every Law |
| Source Physics | All |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

Stable identifiers: CPR-001 through CPR-010.

## CPR-001 — Separation of Concerns

Every concern belongs to exactly one system:

| Concern | Owner |
|---------|-------|
| Identity | IDS |
| Authentication | ATS |
| Authorization | AZS |
| Policy | Policy-System |
| Capabilities | CCA |
| Risk | Risk Engine |
| Lifecycles | LMS |
| Events | Event Store |
| Communication | ACF |
| Resources | ROS |
| Knowledge | Academy |
| Decisions | DTS |
| Templates | AGS |
| Organizations | OSYS |
| Missions | Missions |
| Workers | Workers |

**Principle**: No concern is owned by more than one system. No system owns more than one concern.

## CPR-002 — Law-Driven Design

Every feature, every module, every operation is derived from a constitutional law. If a feature cannot be traced to a specific law, it must go through the constitutional amendment process before it can be implemented.

**Hierarchy**: Law → Physics (invariants) → Bible (specification) → Implementation → Runtime

## CPR-003 — Deterministic Execution

Given the same inputs and the same state, AIOS always produces the same outputs. Nondeterminism is explicitly bounded to specific, documented locations (e.g., random ID generation).

**Exceptions**: Identity ID suffix generation, token nonce generation. All other operations are deterministic.

## 4. Evidence Is Immutable

Evidence (Events) cannot be modified, deleted, or reordered. The Event Store is an append-only log. Tampering with evidence is a constitutional violation.

**Corollary**: Evidence may be redacted (by Security Council order) but never deleted. Redaction preserves the original evidence plus the redaction record.

## CPR-005 — Verify Every Action

No action executes without passing through the full 7-stage verification pipeline. This applies to every entity, including the Security Council itself.

**Corollary**: The Security Council does not skip stages for itself. If the Security Council authenticates, it must pass through the authentication stage.

## CPR-006 — Capabilities Bound by Constitution

An entity's capabilities are limited by its constitutional authority, not by its technical capabilities. An engine may be technically capable of executing arbitrary code, but its constitutional capability may limit it to read-only operations.

**Corollary**: Capability grants must be traceable to a constitutional source (e.g., a template genome, an organization policy, a direct grant from the Security Council).

## CPR-007 — Evidence Over Authority

When evidence and authority conflict, evidence wins. If an authority claims an action was permitted, but the evidence shows the verification pipeline denied it, the evidence is correct.

**Corollary**: All authority must be evidenced. An authority's claim is only as good as the evidence supporting it.

## CPR-008 — Graduated Autonomy

Autonomy is earned, not granted. Entities start at L0 (fully directed) and may progress to higher levels through demonstrated constitutional compliance. Autonomy may be revoked on violation.

**Corollary**: Higher autonomy levels require more evidence, stricter verification, and more comprehensive audit trails.

## CPR-009 — Constitutional Supremacy

The Constitution (Laws of AIOS) is the supreme authority. No entity, no Engine, no Institution may violate the Constitution. Constitutional amendments require a rigorous RFC process.

**Corollary**: If a design choice cannot be justified by the Constitution, it must go through the constitutional amendment process before implementation.

## CPR-010 — Evidence Privacy

Evidence is private to the entity and organization that produced it, unless:
- The evidence is required for constitutional processes (Security Council audit)
- The entity has consented to sharing (Academy learning)
- The evidence is anonymised (by policy-compliant anonymisation)

**Corollary**: Evidence is not shared across organizational boundaries without explicit policy. Academy learning is per-Organization unless federation is established.