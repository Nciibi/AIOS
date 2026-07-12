# AIOS Bible — Authentication Service (ATS)
## 000 — Overview

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible — Execution/Security/Authentication |
| Document ID | AIOS-BBL-004-ATS-000 |
| Source Laws | Law 5 — Law of Identity, Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Authentication Service (ATS) proves that a presenter is genuinely the identity it claims to be. Where IDS establishes *identity* (the immutable root), ATS establishes *authentication* (the evidence that a presented identity is genuine for this session, request, or token). ATS issues, validates, rotates, and revokes authentication tokens used across ACF, the API surface, and Worker sessions.

ATS answers one question: *Is this presenter genuinely the identity it claims?*

ATS does not create identities (IDS), does not authorize actions (the Security Council verification pipeline decides that), and does not evaluate trust posture (Trust Model). It binds a verified identity to a time-boxed, capability-scoped credential.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────┐
│                    ATS Instance                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Token Issuer  │  │ Token Validator│  │ Credential  │  │
│  │              │  │              │  │ Store      │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                  │                │         │
│         ▼                  ▼                ▼         │
│  ┌──────────────────────────────────────────────────┐│
│  │                  ACF Gateway                     ││
│  └──────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

| Component | Responsibility |
|-----------|---------------|
| **Token Issuer** | Mints session, API, and Worker tokens after verifying identity with IDS |
| **Token Validator** | Verifies signature, expiry, scope, and revocation status on every request |
| **Credential Store** | Holds hashed secrets, public keys, and rotation metadata (backed by SSM) |
| **Session Broker** | Bridges authenticated identities to Runtime sessions |

### Token Model

- **Session Token**: short-lived (≤15 min), bound to a Worker/User session, scoped to Mission + Org.
- **API Token**: longer-lived service credential, scoped to an API capability set.
- **Refresh Token**: rotates session tokens without re-authenticating.

### 5 Invariants

1. **Identity Precedes Authentication**: No token is issued without a verified IDS identity. (Physics/008-Security.md)
2. **Single Presenter**: A token is bound to exactly one identity for its entire lifetime.
3. **Enforced Expiry**: Session tokens expire; expiry is enforced by the Validator, never trusted from the client.
4. **Revocation Wins**: A revoked token is rejected even when signature and expiry are valid.
5. **No Secret in Token**: Tokens carry no long-term secret; validation uses asymmetric signatures verified against the IDS public key.

## Authentication Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `ATS.TokenIssued` | A token is minted for a verified identity | token_id, identity_id, scope, expires_at |
| `ATS.TokenValidated` | A token passes validation on a request | token_id, identity_id, request_id |
| `ATS.TokenRevoked` | A token is revoked before expiry | token_id, identity_id, reason |
| `ATS.AuthFailed` | Authentication fails (bad credential / unknown identity) | identity_id, reason, source |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Compliant |
| R2 - Dependency Order | Compliant |
| R3 - DRY | Compliant |
| R4 - Builder Pattern | Compliant |
| R5 - Liskov Substitution | Compliant |
| R6 - DI over Singletons | Compliant |
| R9 - Deterministic | Compliant |
| R10 - Simpler Over Complex | Compliant |
| R13 - Design for Failure | Compliant |
| R14 - Paved Path | Compliant |
| R15 - Open/Closed | Compliant |

## Cross-Cutting Concerns

### Security

All token operations pass through the Security Council verification pipeline. Tokens are signed asymmetrically; the private key is held in SSM and never leaves the secure boundary. (Physics/008-Security.md)

### Evidence

Every token issuance, validation failure, and revocation produces an `ATS.*` Event recorded in the Event Store for full auditability.

### Lifecycle

Tokens follow Issue → Active → Revoked/Expired. Revocation is immediate and propagated to all Validators. Expired tokens are rejected by the Validator regardless of client claims.

### Capability Bounds

Token scope is bounded by the presenting identity's capability set from IDS and the requesting Org/Mission context. No token may exceed the authority of its issuer.

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/008-Security.md | Security framework — ATS is the authentication stage |
| Physics/001-Identity.md | Identity — ATS authenticates IDS identities |
| Bible/04-Execution/Security/000-Overview.md | Security Overview — ATS is one security layer |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS — identity source for all tokens |
| Bible/04-Execution/Security/Verification/000-Overview.md | Verification Pipeline — ATS feeds AuthN stage |
| Bible/04-Execution/Security/SSM/000-SSM.md | SSM — secret and key storage for ATS |
| Bible/08-Interfaces/API/000-Specifications.md | API — ATS issues API authentication tokens |
