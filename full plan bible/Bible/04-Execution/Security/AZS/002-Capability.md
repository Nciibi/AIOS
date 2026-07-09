# AIOS Bible — Authorization (AZS)
## 002 — Capability-Based Authorization

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Authorization |
| Document ID | AIOS-BBL-AZS-002 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Capability-Based Authorization provides the third layer of the authorization stack — delegated, scoped, and transferable authorization. While RBAC (000-RBAC.md) establishes baseline permissions through role assignment and ABAC (001-ABAC.md) refines decisions through contextual attributes, capability-based authorization enables one entity to delegate a bounded subset of its authority to another entity for a specific purpose. This is the mechanism by which a Mission Owner grants a Worker the authority to act on specific resources without granting the Worker the Owner's full role set.

A capability is an unforgeable token that confers authority to perform a specific action on a specific resource, optionally with constraints on duration, intensity, depth, and further delegation. Capabilities are central to Law 7 (Capability Bounds): every Worker must operate within declared capability bounds, and capabilities are the mechanism by which those bounds are established and verified.

Capabilities are not permissions — they are tokens of delegated authority. A capability is created by an entity that holds the authority to delegate, transferred to a recipient entity, and verified by the Security Council at execution time. The recipient exercises authority by presenting the capability, not by virtue of who they are. This object-capability model ensures that authority is explicit, bounded, and auditable.

## Capability Model

### Capability Structure

```typescript
interface Capability {
  id: string;                          // UUIDv7
  type: "resource" | "action" | "composite";
  issuer: string;                      // Entity ID of issuer
  subject: string;                     // Entity ID of recipient
  grant: Grant;                        // The authority being delegated
  constraints: CapabilityConstraint[]; // Bounds on the delegation
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  parentCapabilityId?: string;         // For delegation chains
  signature: string;                   // Issuer's cryptographic signature
}
```

### Grant Types

| Grant Type | Description | Example |
|-----------|-------------|---------|
| `ActionGrant` | Authority to perform a specific action | `read session:abc123` |
| `ResourceGrant` | Authority over a specific resource | `manage worker:def456` |
| `CompositeGrant` | Authority composed of multiple sub-authorities | `read session:abc123 + write session:abc123` |

### Constraint Types

| Constraint | Description | Evaluation |
|-----------|-------------|------------|
| `TimeWindow` | Capability valid only within a time range | `issuedAt >= start AND expiresAt <= end` |
| `MaxDepth` | Maximum delegation chain depth | `chainDepth <= maxDepth` |
| `ResourceBudget` | Maximum resource consumption | `tokens <= budget.tokens AND memory <= budget.memory` |
| `ScopeLimit` | Restricts which sub-resources are accessible | `scopePath startsWith allowedPath` |
| `OneTime` | Capability is consumed after one use | `remainingUses > 0` |
| `Condition` | Arbitrary Boolean condition over attributes | Evaluated by ABAC engine |

## Delegation Chain

### Delegation Flow

```
Issuer (authority holder)
  → Creates Capability for Recipient
  → Recipient (now authority holder for this scope)
    → May further delegate (if constraints allow)
    → Or present capability for execution
```

Each delegation link extends the chain. The chain has a maximum depth (default 3, configurable per capability category). Depth is tracked in the `MaxDepth` constraint.

### Delegation Invariants

- A capability cannot grant more authority than the issuer possesses
- Delegation depth counts from the root authority (original grant) to the leaf (executing entity)
- A capability may constrain but never expand the constraints of its parent
- When a parent capability is revoked, all derived capabilities are invalidated
- Delegation must be explicit — implicit authority does not propagate

### Revocation Propagation

Revocation follows the chain upward: revoking a capability at any level revokes all descendant capabilities. Revocation is propagated through the Revocation Graph maintained by the Capability Certification Authority (CCA). Each capability node tracks its parent and all children. Revocation produces a `CapabilityRevoked` event that invalidates the subgraph.

## Capability Verification

### Verification Process (Stage 5)

Stage 5 of the verification pipeline validates capabilities:

1. Extract capability from the action context (presented by subject)
2. Verify capability signature against issuer's public key (via IDS)
3. Verify capability is within its `TimeWindow`
4. Verify delegation chain integrity (each link signed, no broken chain)
5. Verify all `Constraint` predicates evaluate to true
6. Verify parent capabilities have not been revoked (via CCA)
7. Verify the action matches the capability's `Grant`
8. Return verification result

### Capability Resolution Order

When a request presents multiple capabilities, the system resolves the effective authority:

1. All valid, non-expired, non-revoked capabilities for the subject
2. Union of all grants — if any capability grants the requested action, the subject holds authority
3. Intersection of constraints — the most restrictive constraint from any matching capability applies

## Capability Categories

| Category | Max Depth | Max Duration | Delegable | Requires |
|----------|-----------|-------------|-----------|----------|
| `mission` | 3 | Mission lifetime | Yes | Mission Owner authorization |
| `session` | 2 | Session lifetime | Yes | Session Creator authorization |
| `tool` | 1 | 24 hours | No | Organization Admin authorization |
| `delegated` | Configurable | Configurable | Depends | Two-party authorization |
| `constitutional` | 0 (non-delegable) | Permanent | No | Security Council authorization |

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `AZS.CapabilityIssued` | A capability is created | capability_id, issuer_id, subject_id, grant_type, constraints |
| `AZS.CapabilityPresented` | A capability is presented for verification | capability_id, subject_id, action, verification_result |
| `AZS.CapabilityVerified` | Capability passes Stage 5 verification | capability_id, subject_id, chain_depth, resource_budget_checked |
| `AZS.CapabilityDenied` | Capability fails verification | capability_id, subject_id, reason_code, chain_issue? |
| `AZS.CapabilityRevoked` | A capability or its parent is revoked | capability_id, revoke_authority, reason, affected_descendants |
| `AZS.CapabilityExpired` | A capability reaches its expiration | capability_id, subject_id |
| `AZS.DelegationExtended` | A recipient delegates to another entity | child_capability_id, parent_capability_id, new_subject_id, depth |
| `AZS.CapabilityConsumed` | A one-time capability is consumed | capability_id, action_id, remaining_uses |

## Cross-Cutting Concerns

### Security

- Capabilities are cryptographically signed by the issuer. Forgery requires compromising the issuer's key.
- The delegation chain is verified end-to-end. A single broken link invalidates the entire chain.
- One-time capabilities are consumed atomically. If the action fails, the capability is still consumed (prevent replay).
- Capability keys are managed by CCA. Private keys never leave the HSM.

### Evidence

- All capability operations produce immutable events logged to the Event Store.
- Revocation propagation is recorded as a graph of events, enabling post-hoc audit of why a capability was invalidated.
- Capability verification results are included in the Stage 5 evidence record.

### Lifecycle

- Capabilities have explicit lifetimes (`issuedAt` to `expiresAt`). Expired capabilities are rejected at Stage 5.
- Entity termination triggers cascade revocation of all capabilities issued to or by the terminated entity.
- Capabilities scoped to a session are invalidated when the session ends.

### Capability Bounds

- Capabilities are the direct operational expression of Law 7. Every action authorized through a capability stays within the bounds declared by the issuer.
- Resource budgets in capability constraints are checked against ROS at execution time.
- Autonomy level constraints ensure that a capability cannot authorize actions above the recipient's autonomy level.

### Communication

- Capability issuance, verification, and revocation messages flow through ACF.
- ACF ensures that capability presentations are tamper-evident by including them in the signed ACF envelope.
- Revocation broadcasts use ACF fan-out to invalidate cached capabilities across all pipeline instances.

### Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | Capability authorization does one thing: verify delegated authority tokens |
| R2 — Dependency Order | Compliant | Depends on CCA and IDS; no circular dependency |
| R3 — DRY | Compliant | Capability grant definitions stored in CCA, referenced by ID |
| R4 — Builder Pattern | Compliant | Capabilities constructed by CapabilityBuilder with validation |
| R5 — Liskov Substitution | Compliant | Any capability type implements the verified Capability interface |
| R6 — DI over Singletons | Compliant | Capability verification service injected into pipeline Stage 5 |
| R7 — Tests Exist | Compliant | Unit tests for chain verification, integration tests for delegation propagation |
| R8 — Tests Fast | Compliant | Capability verification target <15ms; test suite in <60s |
| R9 — Deterministic Tests | Compliant | Same capability + same action always yields same verification result |
| R10 — Prefer Simpler | Compliant | Linear delegation chain, no delegation loops or cycles |
| R11 — Refactor over Rewrite | Compliant | Capability model evolves through new constraint types, not pipeline rewrites |
| R12 — Embrace Errors | Compliant | Every denial has chain position, node ID, and reason code |
| R13 — Design for Failure | Compliant | If CCA unreachable, capability verification denies (fail closed) |
| R14 — Paved Path | Compliant | Capability presentation follows the single paved path through Stage 5 |
| R15 — Open/Closed | Compliant | New constraint types added via Constraint interface without modifying verification |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-RBAC.md | Baseline role-based authorization |
| 001-ABAC.md | Attribute-based authorization overlay |
| ../Execution-Auth/000-EAS.md | Pipeline Stage 5 consumes capability verification |
| ../CCA/000-CCA.md | Capability Certification Authority issues and manages capabilities |
| Physics/007-Capabilities.md | Capability Bound invariants |
| Physics/008-Security.md | Security verification invariants |
