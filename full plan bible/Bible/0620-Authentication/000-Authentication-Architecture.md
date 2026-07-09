# AIOS Bible
## 0620 — Authentication Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security |
| Document ID | AIOS-BBL-0620 |
| Source Laws | Law 5 — Law of Identity, Law 8 — Law of Verification-First |
| Source Physics | Physics/001-Identity.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

---

## Purpose

This document specifies the Authentication system for AIOS. Authentication is the second stage of the Security Council's verification pipeline — the act of proving that an entity is who or what it claims to be.

Authentication builds on identity (Physics/001-Identity.md, BBL-0610). Identity answers *who are you?* Authentication answers *prove it*. Without authentication, identity is an unverified assertion.

---

## Authentication Model

### Core Principle

**Identity precedes authentication.** An entity cannot authenticate without first having an identity registered with IRS. The verification pipeline enforces this ordering:

```
Identity (IRS) → Authentication → Authorization → Policy → Capability → Risk → Execution
```

### Authentication Factors

AIOS supports four authentication factors:

| Factor | Description | Strength | Use Case |
|--------|-------------|----------|----------|
| **Possession** | Entity possesses a secret (API key, token, private key) | Medium | Session-to-Session, Engine-to-Engine, automated operations |
| **Knowledge** | Entity knows a secret (password, passphrase, PIN) | Medium | User authentication (primary), low-security operations |
| **Inherence** | Entity is a specific identity through cryptographic proof | High | Engine-to-Engine, IRS-to-IRS, cross-instance trust |
| **Multi-Factor** | Combination of two or more factors | Very High | Security Council actions, critical operations, User overrides |

Every entity type has a minimum required authentication factor level:

| Entity Type | Minimum Factor | Default Factor | Notes |
|------------|---------------|----------------|-------|
| User | Knowledge | Knowledge + Possession (MFA) | MFA required for sensitive operations |
| Engine | Possession (signed JWT) | Inherence (cryptographic identity) | Engines authenticate with RSA-signed JWTs |
| Session | Possession (session token) | Possession | Session tokens issued by Security Council |
| Organization | Inherence (cryptographic identity) | Inherence | Organization identity is hardware-anchored |
| Mission | Possession (delegated token) | Possession | Mission tokens delegated by Organization |
| Template | Inherence (cryptographic signature) | Inherence | Template Genomes are signed |
| Security Council | Multi-Factor | Multi-Factor | Highest assurance level |

---

## Authentication Token Types

### 1. Session Token

Issued to Sessions at creation. Used for all Session-to-entity communication.

```
Header: { "typ": "JWT", "alg": "ES256" }
Payload: {
  "sub": "aios:session:worker:004:d1e2f3a4",
  "iss": "aios:engine:sec:council:001",
  "iat": 1700000000,
  "exp": 1700003600,
  "session_id": "aios:session:worker:004:d1e2f3a4",
  "capability_ids": ["aios:cap:read:001", "aios:cap:write:002"],
  "template_id": "aios:tpl:worker:005",
  "mission_id": "aios:msn:003:c7d4e9f0"
}
Signature: ECDSA(SEC_private_key, header + "." + payload)
```

**Lifetime**: 1 hour (configurable per entity type, min 5 min, max 24h). Renewed automatically by LMS on behalf of the Session.

**Revocation**: On Session termination, capability revocation, Mission completion, or Security Council suspension.

### 2. Engine Token

Issued to Engines at startup. Used for Engine-to-Engine and Engine-to-Institution communication.

```
Header: { "typ": "JWT", "alg": "ES256" }
Payload: {
  "sub": "aios:engine:sec:irs:001",
  "iss": "aios:engine:sec:irs:001",
  "iat": 1700000000,
  "exp": 1700086400,
  "engine_id": "aios:engine:sec:irs:001",
  "engine_type": "irs",
  "public_key_hash": "sha256:abc123..."
}
```

**Lifetime**: 24 hours. Renewed on expiry through automatic re-authentication.

**Revocation**: On Engine shutdown or Security Council order.

### 3. User Token

Issued to Users after authentication. Used for all User-facing Interaction Sessions.

```
Header: { "typ": "JWT", "alg": "ES256" }
Payload: {
  "sub": "aios:user:008:a1b2c3d4",
  "iss": "aios:engine:interaction:001",
  "iat": 1700000000,
  "exp": 1700036000,
  "user_id": "aios:user:008:a1b2c3d4",
  "auth_method": "password+sso",
  "organizations": ["aios:org:001:a3f2c9d2", "aios:org:002:b8e2f1a3"],
  "capabilities": ["read_files", "write_files", "execute_commands"],
  "session_id": "aios:session:user_int:005:e5f6a7b8"
}
```

**Lifetime**: 10 hours (configurable). Maximum 24 hours. Re-authentication required after expiry.

**Revocation**: On logout, Session timeout, capability revocation, or Security Council suspension.

### 4. API Key

Used for automated integrations, webhooks, and programmatic access.

Format: `aios_api_{version}_{random_40_hex}`

```
Example: aios_api_v1_a3f2c9d1b8e2f1a3c7d4e9f0d1e2f3a4b5c6d7
```

**Lifetime**: No expiry (configurable). Can be revoked by Organization or Security Council.

**Revocation**: On key rotation, Organization dissolution, or Security Council order.

### 5. Delegated Token

A token issued by an Organization or Mission to allow a Session to act on its behalf. Used when a Session needs to perform actions under the authority of its parent entity.

```
Header: { "typ": "JWT", "alg": "ES256" }
Payload: {
  "sub": "aios:session:worker:004:d1e2f3a4",
  "iss": "aios:org:001:a3f2c9d2",
  "delegated_from": "aios:org:001:a3f2c9d2",
  "iat": 1700000000,
  "exp": 1700003600,
  "scope": "org:001:missions:*:read",
  "capability_ids": ["aios:cap:read:001"],
  "mission_id": "aios:msn:003:c7d4e9f0"
}
```

**Lifetime**: Same as the parent token, capped at 1 hour.

**Revocation**: On parent token revocation, parent entity lifecycle change, or scope violation.

---

## Authentication Operations

### authenticateEntity(request)

Authenticate an entity and issue a token.

**Request**: `{ identity_id, auth_method, credentials, context }`

**Authorization**: Any entity may request authentication for itself. An Organization may request authentication for its child Missions/Sessions.

**Process**:

1. Resolve identity from IRS: `resolveIdentity(identity_id)`
2. Validate identity status is `Active`
3. Determine authentication method based on entity type and context
4. Validate credentials against the method's verification:
   - **Password**: Hash and compare against stored hash
   - **API Key**: Look up key in API Key store, verify match
   - **Token**: Verify cryptographic signature, validate expiry
   - **Biometric**: Verify biometric proof against registered template
   - **MFA**: Verify primary factor + at least one secondary factor
5. On success: issue authentication token, record Authentication Event
6. On failure: increment failure counter, if threshold exceeded, suspend identity

**Authentication Failure Threshold**:

| Entity Type | Max Failures | Window | Action on Exceed |
|------------|-------------|--------|-----------------|
| User | 5 | 15 minutes | Identity suspended for 30 minutes |
| Session | 3 | 5 minutes | Session terminated |
| Engine | 10 | 1 hour | Security Council notified |
| Organization | 3 | 1 hour | Organization suspended |

**Response**: `{ token, expires_at, identity }` on success. `{ error_code, retry_after }` on failure.

### validateToken(token)

Validates an authentication token and returns the authenticated identity.

**Called by**: Security Council (verification pipeline), ACF (message routing), Runtime Engine (execution authorization).

**Process**:

1. Parse token and extract header
2. Verify token signature against the issuing authority's public key
3. Validate expiry: `exp > current_time`
4. Validate revocation: check token against revocation list (bloom filter for performance)
5. Resolve identity: `resolveIdentity(payload.sub)`
6. Validate identity status is `Active`
7. On success: return `{ identity_id, entity_type, capabilities, session_id }`
8. On failure: return `{ error: "invalid_token" | "expired" | "revoked" }`

**Caching**: Token verification results are cached for the token's remaining TTL (capped at 5 minutes maximum cache). Cache is invalidated on token revocation.

### renewToken(token)

Renews an expiring token before it expires.

**Parameters**: `{ token }`

**Authorization**: The token's owner.

**Process**:

1. Verify token is still valid (not expired, not revoked)
2. Check if token is eligible for renewal (within renewal window — last 10% of lifetime)
3. Issue new token with extended expiry
4. Record old token as consumed (soft-revoke)
5. Return new token

### revokeToken(token)

Revokes a token immediately.

**Parameters**: `{ token, reason, authorizing_entity }`

**Authorization**: Security Council, the token's issuing entity, or the token's owner.

**Process**:

1. Validate authorization
2. Add token to revocation list
3. Notify ACF to reject messages with this token
4. Record Revocation Event

### revokeAllEntityTokens(identity_id)

Revokes all tokens for a given identity.

**Parameters**: `{ identity_id, reason }`

**Authorization**: Security Council or entity's parent Organization.

**Use Cases**: Identity suspension, identity retirement, security breach.

**Process**:

1. Query active tokens for the identity
2. Revoke each token
3. Notify ACF
4. Record BulkRevocation Event

---

## Authentication Methods

### Password Authentication (Users)

**Storage**: Passwords are hashed with bcrypt (cost factor 12). Never stored in plaintext.

**Policy**:

- Minimum length: 12 characters
- Complexity: at least 1 uppercase, 1 lowercase, 1 digit, 1 special character
- Maximum age: 90 days
- History: 10 previous passwords (cannot reuse)
- Lockout: 5 failures in 15 minutes → 30-minute lockout

**Flow**:

```
User sends { identity_id, password }
  → IRS resolves identity
  → Auth system looks up password hash
  → bcrypt.compare(password, hash)
  → If match: issue User token
  → If no match: increment failure counter
```

### API Key Authentication (Programmatic Access)

**Generation**: Keys are generated by IRS on request. Format: `aios_api_{version}_{random_40_hex}` (48 chars total).

**Storage**: Keys are stored as bcrypt hashes (cost factor 10). The plaintext key is shown once at creation.

**Rotation**: Keys should be rotated every 90 days. Old keys remain valid for a 7-day overlap period.

**Flow**:

```
Entity sends { api_key }
  → Auth system hashes the key (not stored in plaintext)
  → Compare against stored hashes
  → If match: identify the Organization/Session, issue token
  → If no match: failure
```

### Cryptographic Authentication (Engine/Institution)

**Mechanism**: Each Engine and Institution has an ECDSA key pair (P-256 curve). The public key is registered with IRS at Engine startup. Authentication is performed by signing a challenge.

**Flow**:

```
Engine A wants to authenticate to Engine B:
  → Engine B sends a random challenge (nonce + timestamp)
  → Engine A signs the challenge with its private key
  → Engine B verifies the signature against Engine A's public key (resolved via IRS)
  → If valid: Engine A is authenticated
```

**Key Management**:
- Keys are generated at Engine deployment time
- Private keys are stored in hardware security module (HSM) or secure enclave where available
- Public keys are registered with IRS
- Key rotation triggers a new identity registration (old identity is retired)

### Multi-Factor Authentication (High-Security)

**Factors**:
1. **Primary**: Password (User) or cryptographic key (Engine)
2. **Secondary**: TOTP (Time-based One-Time Password), SMS code, push notification, biometric, hardware key (FIDO2/WebAuthn)

**Policy**:
- MFA is required for: Security Council actions, User override of constitutional decisions, Organization dissolution, user role changes (admin, super-admin), and cross-instance federation operations.
- MFA is optional for: standard Interaction Sessions (configurable per Organization), and read-only queries.
- MFA session: once authenticated with MFA, secondary factor is cached for 15 minutes (configurable).

**Flow**:

```
User authenticates with password (primary factor)
  → If MFA required: prompt for secondary factor
  → User provides TOTP (or other secondary factor)
  → Verify TOTP against shared secret
  → If valid: issue MFA-enhanced token
  → Cache MFA for 15 minutes
```

---

## Token Revocation List (TRL)

The TRL is a distributed data structure shared across Security Council instances, ACF nodes, and Runtime Engines.

### Structure

```
┌────────────────────────────────────────────────────┐
│               Token Revocation List                  │
│  ┌────────────────────────────────────────────────┐ │
│  │ Bloom Filter (fast rejection)                   │ │
│  │   false positive rate: 0.1%                     │ │
│  │   size: 1MB per 100k revoked tokens             │ │
│  └────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────┐ │
│  │ Cuckoo Filter (positive confirmation)           │ │
│  │   deterministic membership check                │ │
│  │   size: 2MB per 100k revoked tokens             │ │
│  └────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────┐ │
│  │ Backing Store (full record)                     │ │
│  │   token_id, revoked_at, reason, authorizing_entity│
│  │   PostgreSQL or equivalent                      │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Propagation

Revocations are propagated to all Security Council instances through ACF Event Streams within 1 second. The TRL is replicated to ACF nodes and Runtime Engines for local token verification.

### Cleanup

Revoked tokens are retained in the TRL for `max_token_lifetime` (24 hours) plus 7 days. After that, the token record is moved to the long-term evidence store (Event Store) and removed from the TRL.

---

## Authentication Event Schema

Every authentication operation produces an Event:

| Event Type | Produced When | Key Fields |
|-----------|--------------|------------|
| `Authentication.Success` | Authentication succeeds | identity_id, method, token_id, source_ip |
| `Authentication.Failure` | Authentication fails | identity_id, method, failure_reason, failure_count |
| `Authentication.Lockout` | Entity is locked out | identity_id, method, lockout_duration |
| `Authentication.TokenIssued` | Token is issued | identity_id, token_type, expires_at |
| `Authentication.TokenRevoked` | Token is revoked | identity_id, token_id, reason, authorizing_entity |
| `Authentication.TokenExpired` | Token expires | token_id (automatically detected) |
| `Authentication.KeyRotated` | API key is rotated | identity_id, old_key_hash, new_key_hash |

---

## ACF Integration

Authentication is integrated with ACF at multiple levels:

### Message-Level Authentication

Every ACF message carries an authentication token in its envelope:

```json
{
  "acf": {
    "version": "1.0",
    "message_id": "msg_001",
    "sender": "aios:session:worker:004:d1e2f3a4",
    "target": "aios:engine:runtime:001",
    "timestamp": 1700000000,
    "auth_token": "eyJhbGciOiJFUzI1NiJ9...",
    "auth_type": "session"
  },
  "payload": { ... }
}
```

ACF validates the authentication token before routing the message:

1. Parse `auth_type` and `auth_token` from envelope
2. Call `verifyToken(auth_token)`
3. If invalid: reject message, return error to sender
4. If valid: extract identity from token, continue routing

### Channel Authentication

Each interaction channel has its own authentication mechanism:

| Channel | Auth Mechanism | Token Type |
|---------|---------------|------------|
| CLI | Password or API Key | User token or API key |
| GUI | Web session (SSO + OAuth) | User token |
| API | API Key or JWT | API key or Engine token |
| Voice | Pre-authenticated session | User token (from prior GUI/CLI auth) |

---

## Cross-Cutting Concerns

### Security
- Authentication tokens are signed with ECDSA (P-256) — quantum-safe alternative (Ed25519) available.
- Tokens are never transmitted in query strings. They are sent in ACF message envelopes (secure channel) or HTTP headers (for API).
- Revoked tokens are rejected at the ACF gateway — no need to reach the target service.
- Authentication failures are logged and subject to lockout policy.
- Authentication rate limiting: maximum 10 authentication attempts per identity per second.

### Evidence
- Every authentication operation produces an Event (Success, Failure, Lockout, Token Issue, Token Revoke).
- Token revocation and expiry Events are recorded immutably.

### Lifecycle
- Authentication tokens have defined lifetimes. Expired tokens are automatically invalidated.
- Identity lifecycle changes (suspend, retire, archive) trigger token revocation.
- Session lifecycle changes (termination, destroy) trigger token revocation.

### Capability Bounds
- Authentication tokens carry capability references. The Security Council uses these for authorization.
- Token scope limits what the entity can do. A read-only token cannot authorize write operations.

### Communication
- All authentication operations flow through ACF. IRS and the Security Council are reachable through ACF.
- Token verification is embedded in ACF message routing for performance.

### Design DNA Compliance
- **R1 — Modulsingularity**: Authentication does one thing: prove identity. Token management is a sub-module.
- **R2 — Dependency Order**: Authentication depends on IRS (identity resolution). Nothing depends on authentication for implementation — only verification.
- **R3 — DRY**: Token format, authentication flow, and failure handling are defined once.
- **R4 — Builder Pattern**: Tokens are built by the Token Factory. Clients receive validated tokens.
- **R5 — Liskov**: All authentication methods implement the same AuthMethod interface. Password, API key, and cryptographic auth are interchangeable.
- **R6 — DI over Singletons**: Auth service is injected into ACF, Security Council, and Runtime.
- **R7 — Tests Exist**: Unit tests for each auth method. Integration tests for token lifecycle. Security tests for token forgery resistance.
- **R8 — Tests Fast**: Auth tests complete in under 10 seconds.
- **R9 — Deterministic**: The same credentials always produce the same authentication result (pass or fail). Random salts are deterministic for verification.
- **R10 — Simpler**: 4 auth methods. 5 token operations. No over-design.
- **R11 — Refactor over Rewrite**: Auth evolves through RFCs. No rewrite.
- **R12 — Embrace Errors**: Every auth error has a unique code: `AUTH_001` (invalid identity), `AUTH_002` (invalid password), `AUTH_003` (expired token), `AUTH_004` (revoked token), `AUTH_005` (locked out), `AUTH_006` (MFA required).
- **R13 — Design for Failure**: Token verification is designed to fail open (deny on error, not allow on error). If ACF cannot reach the TRL, tokens are treated as revoked.
- **R14 — Paved Path**: The paved path for authentication is: resolve identity → validate credentials → issue token. All 4 methods follow this path.
- **R15 — Open/Closed**: Auth methods are added through the AuthMethod interface without modifying the auth core. Password, API key, and cryptographic auth are extensions, not modifications.

---

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/000-Laws.md, Law 5 (Identity), Law 8 (Verification-First) | Source laws |
| Physics/001-Identity.md | Identity — authentication builds on it |
| Physics/008-Security.md | Security framework — authentication is Stage 2 |
| Bible/0000-Master-Architecture-Plan.md | Phase 0 — Identity & Security |
| Bible/0610-IRS.md | Identity resolution — authentication depends on it |
| Bible/0640-Verification-Pipeline.md | Verification pipeline — authentication is Stage 2 |
| Bible/0280-ACF.md | ACF — authentication tokens are carried in ACF messages |
| Bible/0710-Interaction-Engine.md | User authentication in Interaction Sessions |
| Constitution, Article IV, Part A, Section 003 | Constitutional identity principles |
| RFC-XXXX | Amendments to this specification |

---

## Future Work

| Topic | Description | Priority |
|-------|-------------|----------|
| WebAuthn/FIDO2 support | Biometric and hardware key authentication for Users | High |
| OAuth2/OpenID Connect integration | External identity provider federation | High |
| Token introspection endpoint | Standardized token verification for external services | Medium |
| Adaptive authentication | Risk-based authentication that adjusts factors | Medium |
| Zero-downtime key rotation | Rotate authentication keys without invalidating active sessions | Medium |
| Authentication for sub-millisecond operations | Performance optimization for high-frequency auth verification | Low |

---

*End of AIOS Bible 0620 — Authentication Architecture*