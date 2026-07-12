# AIOS Bible — Security
## 002 — Trust Model

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security |
| Document ID | AIOS-BBL-004-SEC-002 |
| Source Laws | Law 5 — Law of Identity, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The trust model defines how trust is established, verified, maintained, and revoked across AIOS. Trust is not implicit — it is cryptographic, evidence-based, and bounded. Every trust relationship has a defined trust level, a cryptographic foundation, and a lifecycle.

Trust applies at three levels: entity-to-entity (within an instance), instance-to-instance (cross-instance federation), and entity-to-external (integration with external systems).

## Trust Levels

Trust is expressed as a numeric level (T0 through T4). Higher trust levels grant access to more sensitive operations and data.

| Level | Name | Description | Requirements |
|-------|------|-------------|--------------|
| T0 | None | No trust established | No identity verification |
| T1 | Minimum | Basic identity verified | Valid identity, valid token |
| T2 | Standard | Identity + capability profile | T1 + capability verification |
| T3 | Elevated | Verified + attested | T2 + hardware attestation |
| T4 | Maximum | Full cryptographic trust | T3 + multi-party verification |

### Entity Trust Assignment

| Entity Type | Default Trust Level | Maximum Trust Level |
|-------------|--------------------|--------------------|
| Worker (standard) | T1 | T2 |
| Worker (high-security) | T2 | T3 |
| Organization | T2 | T3 |
| Sou | T3 | T4 |
| Security Council | T4 | T4 |
| Academy | T2 | T3 |
| External system | T0 | T1 |

## Trust Establishment

Trust is established through a cryptographic handshake verified by the Security Council:

```
1. Entity A presents identity (IDS verified)
2. Entity A presents capabilities (CCA verified)
3. Entity A presents attestation (if T3+ required)
4. Security Council evaluates trust level
5. Trust binding created, signed by Council
6. Trust binding stored in TLM
```

### Trust Binding

| Field | Type | Description |
|-------|------|-------------|
| binding_id | UUID v4 | Unique binding identifier |
| subject_id | IdentityID | Trusted entity |
| issuer_id | IdentityID | Security Council (issuer) |
| trust_level | T0-T4 | Assigned trust level |
| not_before | Timestamp | When trust becomes valid |
| not_after | Timestamp | When trust expires |
| capabilities | Capability[] | Bounds for this trust level |
| signature | Signature | Council cryptographic signature |

## Cross-Instance Trust

Cross-instance trust extends the trust model to federation. Instance A trusts Instance B through a mutual trust agreement verified by both instances' Security Councils.

### Cross-Instance Trust Levels

| Level | Description | Allowed Protocols |
|-------|-------------|-------------------|
| T0 | No trust | CXP only (handshake) |
| T1 | Instance identity verified | CXP, IXP |
| T2 | Instance capabilities verified | CXP, IXP, PXP, AIP |
| T3 | Instance attested | All protocols except EXP |
| T4 | Full mutual trust | All protocols |

### Trust Chain

Cross-instance trust follows a chain: Root CA → Instance CA → Instance Council → Trust Binding. Each link in the chain is cryptographically verified.

## Trust Verification

Trust is verified on every interaction. The verification includes:

1. Trust binding exists and is valid (not expired, not revoked)
2. Signatures valid (cryptographic verification)
3. Trust level sufficient for the requested operation
4. Capability bounds not exceeded
5. No intervening revocation

## Trust Revocation

Trust can be revoked by the Security Council at any time. Revocation is immediate.

| Reason | Effect | Notification |
|--------|--------|-------------|
| Security violation | Trust revoked, all levels | Immediate, all parties |
| Entity termination | Trust binding destroyed | Part of entity lifecycle |
| Trust expiry | Automatic revocation | Warning at 80% expiry |
| Council order | Targeted revocation | Immediate, audited |
| Cross-instance breach | Instance-level revocation | Federation-wide broadcast |

## Trust Model Invariants

1. **TRU-INV-001 — No Implicit Trust**: All trust must be established through the defined handshake process. No entity is trusted by default.

2. **TRU-INV-002 — Time-Bound Trust**: All trust bindings have an expiration. No permanent trust.

3. **TRU-INV-003 — Bounded Trust**: Trust level determines maximum capability. No trust level grants unlimited access.

4. **TRU-INV-004 — Revocable Trust**: All trust can be revoked. Revocation is always possible.

5. **TRU-INV-005 — Verified Trust**: Trust is verified on every interaction. Cached trust has a maximum TTL of 5 minutes.

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Trust.BindingCreated | Trust established | binding_id, subject, issuer, trust_level, valid_until |
| Trust.BindingVerified | Trust verified | binding_id, subject, trust_level, cached |
| Trust.BindingExpired | Trust expired | binding_id, subject, expired_at |
| Trust.BindingRevoked | Trust revoked | binding_id, subject, revoked_by, reason |
| Trust.CrossInstanceEstablished | Cross-instance trust | local_instance, remote_instance, trust_level, protocol |
| Trust.CrossInstanceRevoked | Cross-instance trust revoked | local_instance, remote_instance, reason |
| Trust.VerificationFailed | Trust verification failure | binding_id, subject, reason, action_denied |

## Cross-Cutting Concerns

### Security

Trust is the foundation of all security decisions. Trust bindings are cryptographically signed by the Security Council. Trust verification is part of the verification pipeline. Revocation is immediate and audited.

### Evidence

Every trust operation produces Events. Trust verification failures are logged with full context. Cross-instance trust agreements are recorded in both instances.

### Lifecycle

Trust follows a defined lifecycle: Requested → Established → Verified → Expired/Revoked. Trust bindings have hard expiration. Renewal requires re-establishment.

### Capability Bounds

Trust level gates capability access. A T1 entity cannot access T3-gated capabilities. Trust bounds are enforced at the verification pipeline stage 5 (capability verification).

### Communication

Trust verification uses ACF synchronous calls. Cross-instance trust handshakes use federation protocols (CXP). Trust revocation broadcasts use ACF event streams with guaranteed delivery.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Trust is a single concern: who to trust and at what level |
| R2 — Dependency Order | Trust depends on IDS, CSP; no upward deps |
| R3 — DRY | Trust model defined once in TLM |
| R4 — Builder Pattern | Trust bindings are built by TLM with Council signature |
| R5 — Liskov | All trust levels follow the same verification interface |
| R6 — DI over Singletons | TLM receives IDS, CSP, EVS as injected deps |
| R7 — Tests Exist | Every trust level combination has tests |
| R8 — Tests Fast | Trust verification completes in <50ms |
| R9 — Deterministic | Same entity identity always produces same trust level |
| R10 — Simpler Over Complex | 5 trust levels with clear progression |
| R11 — Refactor Over Rewrite | Trust model evolves via RFC |
| R12 — Embrace Errors | Every verification failure has a unique error code |
| R13 — Design for Failure | Trust verification degraded → default to T0 |
| R14 — Paved Path | TLM is the only trust management path |
| R15 — Open/Closed | New trust verification methods extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Overview.md | Security overview — trust is a foundational concern |
| 001-Architecture.md | Security Council architecture — Council issues trust bindings |
| IDS/000-Overview.md | Identity verification — prerequisite for trust |
| Trust/000-TLM.md | Trust Lifecycle Manager — trust binding lifecycle |
| Bible/06-Services/Federation/000-Overview.md | Cross-instance trust — federation trust model |
| Crypto/000-CSP.md | Cryptographic signing of trust bindings |
| Crypto/001-CAM.md | CA certificates for trust chain |
| Physics/008-Security.md | Security invariants |
