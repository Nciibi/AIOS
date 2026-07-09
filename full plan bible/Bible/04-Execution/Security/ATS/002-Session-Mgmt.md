# AIOS Bible — Authentication Token Service (ATS)
## 002 — Session & Token Management

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Authentication |
| Document ID | AIOS-BBL-ATS-002 |
| Source Laws | Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md, Physics/006-Lifecycles.md |

## Token Types

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

**Lifetime**: 10 hours (configurable, max 24h). Re-authentication required after expiry.

**Revocation**: On logout, Session timeout, capability revocation, or Security Council suspension.

### 4. API Key

Used for automated integrations, webhooks, programmatic access.

Format: `aios_api_{version}_{random_40_hex}` — e.g., `aios_api_v1_a3f2c9d1b8e2f1a3c7d4e9f0d1e2f3a4b5c6d7`

**Lifetime**: No expiry (configurable). Revocable by Organization or Security Council.

**Revocation**: On key rotation, Organization dissolution, or Security Council order.

### 5. Delegated Token

Token issued by an Organization or Mission allowing a Session to act on its behalf.

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

**Lifetime**: Same as parent token, capped at 1 hour.
**Revocation**: On parent token revocation, parent entity lifecycle change, or scope violation.

## Token Operations

### authenticateEntity(request)

Authenticate an entity and issue a token.

**Request**: `{ identity_id, auth_method, credentials, context }`

**Process**:
1. Resolve identity: `resolveIdentity(identity_id)`
2. Validate identity status is `Active`
3. Determine auth method based on entity type and context
4. Validate credentials against the method's verification
5. On success: issue token, record Authentication Event
6. On failure: increment failure counter, if threshold exceeded, suspend identity

**Failure Thresholds**:

| Entity Type | Max Failures | Window | Action |
|------------|-------------|--------|--------|
| User | 5 | 15 min | Identity suspended for 30 min |
| Session | 3 | 5 min | Session terminated |
| Engine | 10 | 1 hour | Security Council notified |
| Organization | 3 | 1 hour | Organization suspended |

### validateToken(token)

**Called by**: Security Council (verification pipeline), ACF (message routing), Runtime Engine.

**Process**:
1. Parse token, verify signature
2. Validate expiry
3. Validate revocation (bloom filter + cuckoo filter)
4. Resolve identity: `resolveIdentity(payload.sub)`
5. Validate identity status is `Active`
6. Return identity info or error

**Caching**: Token verification results cached for remaining TTL (max 5 minutes). Invalidated on token revocation.

### renewToken(token)

**Process**:
1. Verify token still valid
2. Check eligibility (within last 10% of lifetime)
3. Issue new token with extended expiry
4. Soft-revoke old token
5. Return new token

### revokeToken(token)

**Authorization**: Security Council, issuing entity, or token owner.

**Process**:
1. Validate authorization
2. Add token to TRL
3. Notify ACF to reject with this token
4. Record Revocation Event

### revokeAllEntityTokens(identity_id)

**Use Cases**: Identity suspension, retirement, security breach.

**Process**:
1. Query active tokens for the identity
2. Revoke each token
3. Notify ACF
4. Record BulkRevocation Event

## Token Revocation List (TRL)

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
│  │ Backing Store (full record)                    │ │
│  │   PostgreSQL or equivalent                    │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Propagation

Revocations propagated through ACF Event Streams within 1 second. Replicated to ACF nodes and Runtime Engines for local token verification.

### Cleanup

Revoked tokens retained for `max_token_lifetime` (24h) + 7 days. Then moved to long-term evidence store.