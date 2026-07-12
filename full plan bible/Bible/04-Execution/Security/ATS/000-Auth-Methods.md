# AIOS Bible — Authentication Token Service (ATS)
## 000 — Authentication Methods

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Authentication |
| Document ID | AIOS-BBL-ATS-000 |
| Source Laws | Law 5 — Law of Identity, Law 8 — Law of Verification-First |
| Source Physics | Physics/001-Identity.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Authentication is the second stage of the Security Council's verification pipeline — the act of proving that an entity is who or what it claims to be. Authentication builds on identity. Identity answers *who are you?* Authentication answers *prove it*.

## Core Principle

**Identity precedes authentication.** An entity cannot authenticate without first having an identity registered with IDS. The verification pipeline enforces this ordering:

```
Identity (IDS) → Authentication → Authorization → Policy → Capability → Risk → Execution
```

## Authentication Factors

| Factor | Description | Strength | Use Case |
|--------|-------------|----------|----------|
| **Possession** | Entity possesses a secret (API key, token, private key) | Medium | Session-to-Session, Engine-to-Engine, automated operations |
| **Knowledge** | Entity knows a secret (password, passphrase, PIN) | Medium | User authentication (primary), low-security operations |
| **Inherence** | Entity is a specific identity through cryptographic proof | High | Engine-to-Engine, IDS-to-IDS, cross-instance trust |
| **Multi-Factor** | Combination of two or more factors | Very High | Security Council actions, critical operations, User overrides |

### Minimum Factor by Entity Type

| Entity Type | Minimum Factor | Default Factor | Notes |
|------------|---------------|----------------|-------|
| User | Knowledge | Knowledge + Possession (MFA) | MFA required for sensitive operations |
| Engine | Possession (signed JWT) | Inherence (cryptographic identity) | Engines authenticate with RSA-signed JWTs |
| Session | Possession (session token) | Possession | Session tokens issued by Security Council |
| Organization | Inherence (cryptographic identity) | Inherence | Organization identity is hardware-anchored |
| Mission | Possession (delegated token) | Possession | Mission tokens delegated by Organization |
| Template | Inherence (cryptographic signature) | Inherence | Template Genomes are signed |
| Security Council | Multi-Factor | Multi-Factor | Highest assurance level |

## Authentication Methods

### Password Authentication (Users)

**Storage**: bcrypt hashes (cost factor 12). Never stored in plaintext.

**Policy**:
- Minimum length: 12 characters
- Complexity: at least 1 uppercase, 1 lowercase, 1 digit, 1 special character
- Maximum age: 90 days
- History: 10 previous passwords (cannot reuse)
- Lockout: 5 failures in 15 minutes → 30-minute lockout

**Flow**:
```
User sends { identity_id, password }
  → IDS resolves identity
  → Auth system looks up password hash
  → bcrypt.compare(password, hash)
  → If match: issue User token
  → If no match: increment failure counter
```

### API Key Authentication (Programmatic Access)

**Generation**: Format `aios_api_{version}_{random_40_hex}` (48 chars). Shown once at creation.

**Storage**: bcrypt hashes (cost factor 10).

**Rotation**: Every 90 days. 7-day overlap period for old keys.

**Flow**:
```
Entity sends { api_key }
  → Auth system hashes the key
  → Compare against stored hashes
  → If match: identify Organization/Session, issue token
  → If no match: failure
```

### Cryptographic Authentication (Engine/Institution)

**Mechanism**: ECDSA key pair (P-256 curve). Public key registered with IDS at Engine startup. Authentication by signing a challenge.

**Flow**:
```
Engine A wants to authenticate to Engine B:
  → Engine B sends random challenge (nonce + timestamp)
  → Engine A signs challenge with its private key
  → Engine B verifies signature against Engine A's public key (via IDS)
  → If valid: Engine A is authenticated
```

**Key Management**:
- Keys generated at Engine deployment time
- Private keys in HSM or secure enclave where available
- Public keys registered with IDS
- Key rotation triggers new identity registration (old identity retired)

### Multi-Factor Authentication (High-Security)

**Factors**:
1. **Primary**: Password (User) or cryptographic key (Engine)
2. **Secondary**: TOTP, SMS code, push notification, biometric, hardware key (FIDO2/WebAuthn)

**Policy**:
- MFA required for: Security Council actions, User overrides of constitutional decisions, Organization dissolution, user role changes, cross-instance federation
- MFA optional for: standard Interaction Sessions (configurable), read-only queries
- MFA session cache: 15 minutes (configurable)

## Authentication Events

| Event Type | Produced When | Key Fields |
|-----------|--------------|------------|
| `Authentication.Success` | Authentication succeeds | identity_id, method, token_id, source_ip |
| `Authentication.Failure` | Authentication fails | identity_id, method, failure_reason, failure_count |
| `Authentication.Lockout` | Entity is locked out | identity_id, method, lockout_duration |
| `Authentication.TokenIssued` | Token is issued | identity_id, token_type, expires_at |
| `Authentication.TokenRevoked` | Token is revoked | identity_id, token_id, reason, authorizing_entity |
| `Authentication.TokenExpired` | Token expires | token_id (automatically detected) |
| `Authentication.KeyRotated` | API key is rotated | identity_id, old_key_hash, new_key_hash |

## ACF Integration

Every ACF message carries an authentication token:

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

ACF validates the authentication token before routing:
1. Parse `auth_type` and `auth_token` from envelope
2. Call `verifyToken(auth_token)`
3. If invalid: reject message, return error to sender
4. If valid: extract identity from token, continue routing

### Channel Authentication

| Channel | Auth Mechanism | Token Type |
|---------|---------------|------------|
| CLI | Password or API Key | User token or API key |
| GUI | Web session (SSO + OAuth) | User token |
| API | API Key or JWT | API key or Engine token |
| Voice | Pre-authenticated session | User token (from prior GUI/CLI auth) |

## Cross-Cutting Concerns

### Security
- Tokens are signed with ECDSA (P-256) — Ed25519 available as alternative
- Tokens never transmitted in query strings; always in ACF envelopes or HTTP headers
- Revoked tokens rejected at ACF gateway
- Rate limiting: max 10 auth attempts per identity per second

### Evidence
- Every authentication operation produces an Event
- Token revocation and expiry Events recorded immutably

### Lifecycle
- Tokens have defined lifetimes. Expired tokens invalidated automatically
- Identity lifecycle changes trigger token revocation
- Session termination triggers token revocation

### Design DNA Compliance
- **R1**: Authentication does one thing: prove identity
- **R2**: Depends on IDS (identity resolution); nothing depends on authentication for implementation
- **R5**: All auth methods implement the same AuthMethod interface
- **R6**: Auth service injected into ACF, Security Council, Runtime
- **R10**: 4 auth methods, 5 token operations — no over-design
- **R13**: Fail closed — if ACF cannot reach TRL, tokens treated as revoked
- **R15**: Auth methods added through AuthMethod interface without modifying core

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/04-Execution/Security/000-Overview.md | Security overview — ATS is one security layer |
| Bible/04-Execution/Security/IDS/000-Overview.md | IDS — identity source for all tokens |
| Bible/04-Execution/Security/ATS/001-MFA.md | MFA — second factor for token issuance |
| Bible/04-Execution/Security/ATS/002-Session-Mgmt.md | Session & token management |
| Physics/008-Security.md | Security framework — ATS enforces authentication stage |
| Physics/001-Identity.md | Identity — ATS authenticates IDS identities |