# AIOS Bible — Brain
## 001 — Identity Profile

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Brain/Personality |
| Document ID | AIOS-BBL-002-PER-001 |
| Source Laws | Law 1 — Law of Strategic Autonomy, Law 5 — Law of Identity, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/009-Interaction.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Identity Store holds Sou's immutable core identity — the fixed, constitutional attributes that define who Sou is. Identity is established at Sou's instantiation and cannot be changed without constitutional authority. It is the anchor of the Personality System: every expression of Sou's behavior, values, and style flows from this identity core.

Under PER-001, Sou's identity is immutable after instantiation. The Identity Store enforces this by design: identity fields are write-once, with append-only history.

## Data Model

### IdentityCore

```typescript
IdentityCore {
  name: string                    // Sou's display name, set at instantiation
  purpose: string                 // Sou's constitutional purpose (e.g., "Assist user autonomously")
  history: string                 // Origin and context — append-only log of experiences
  creator: string                 // Constitutional authority that instantiated Sou
  instance_id: string             // Globally unique identifier for this Sou instance (UUIDv7)
  created_at: timestamp           // Instantiation timestamp
  version: number                 // Identity version — incremented on constitutional amendment
}
```

### IdentityField

```typescript
IdentityField {
  name: string
  value: unknown
  mutability: "immutable" | "append_only" | "amendment_only"
  change_authority: "none" | "security_council" | "constitutional_amendment" | "sou"
  last_amended?: timestamp
}
```

### IdentityAccessLog

```typescript
IdentityAccessLog {
  access_id: string
  field: string
  caller: string                 // Component that accessed the field
  access_type: "read" | "write_attempt"
  timestamp: timestamp
  allowed: boolean
  reason?: string
}
```

### IdentityVerificationResult

```typescript
IdentityVerificationResult {
  verified: boolean
  instance_id: string
  checksum: string               // Hash of identity payload for integrity check
  discrepancies: string[]        // Any fields that failed verification
  last_verified: timestamp
}
```

## Identity Immutability (PER-001)

Identity immutability is the foundational invariant of the Personality System. The Identity Store enforces three tiers of mutability:

| Field | Mutability | Change Authority | Notes |
|-------|-----------|-----------------|-------|
| name | Immutable | Security Council override | Only changed by constitutional exception |
| purpose | Immutable | Constitutional amendment | Amended by RFC with Security Council approval |
| history | Append-only | Sou | Experiences added; nothing removed |
| creator | Immutable | Never changeable | Set at instantiation, fixed forever |
| instance_id | Immutable | Never changeable | Globally unique, generated at instantiation |
| created_at | Immutable | Never changeable | Set at instantiation, fixed forever |

Any attempt to write to an immutable field produces `PER_IDENTITY_IMMUTABLE` and is logged as a security event.

## Identity Loading on Startup

Identity loading is the first operation in the Brain startup sequence:

```
Brain Startup
    │
    ▼
Load Identity from Memory OS
    │
    ├── Read IdentityCore from persistent storage
    ├── Verify payload checksum (integrity check)
    ├── Verify instance_id matches expected value
    ├── Cache IdentityCore in Personality System
    ├── Emit PER.ProfileLoaded
    └── If load fails → fallback to built-in emergency identity
    │
    ▼
Identity ready for session
```

### Failure Modes

| Condition | Behavior |
|-----------|----------|
| Memory OS unavailable | Retry up to 3 times; fallback to emergency identity |
| Checksum mismatch | Reject; load emergency identity; log security alert |
| instance_id mismatch | Reject; emit security event; request re-instantiation |
| Identity version upgrade | Apply migration from version N to N+1 |

## Identity Injection into LLMOS Prompts

The Prompt Compiler injects identity into every LLMOS system prompt to ensure Sou acts as a coherent identity:

```typescript
// Example prompt injection template
SYSTEM: You are {{identity.name}}.
INSTANCE: {{identity.instance_id}}
PURPOSE: {{identity.purpose}}
CREATOR: {{identity.creator}}
HISTORY: {{identity.history}}
VERSION: {{identity.version}}
```

Identity injection is governed by PER-005: Personality is injected into every LLMOS prompt. The Prompt Compiler reads the cached identity on every context build.

### Injection Security

- Identity is injected at `system` level — invisible to user
- Identity fields are never exposed to user-facing responses
- Prompt Compiler wraps identity in a secure system context block
- Identity metadata (instance_id, version) is available for debugging but filtered from user output

## Identity Access Control

Identity access is restricted by the Personality System API via ACF:

| Method | Authorized Callers | Description |
|--------|-------------------|-------------|
| `getProfile()` | Sou only | Full identity + personality profile |
| `getIdentity()` | Sou only | Raw IdentityCore |
| `loadProfile()` | Personality System (internal) | Load from Memory OS on startup |
| `verifyIdentity()` | Sou, Security Council | Cryptographic identity verification |

Authentication works through ACF token validation. Unauthorized access attempts are logged as security events.

### Access Levels

| Level | Permissions | Example Caller |
|-------|-------------|---------------|
| Sou | Read all identity fields, append to history | Sou decisions, Prompt Compiler |
| Academy | Read name, read purpose | Trait evolution context |
| Security Council | Read all, amend identity (override) | Constitutional amendments |
| User | None (identity is never exposed) | — |

## Internal Interface

```typescript
interface IdentityStore {
  // Loading
  loadProfile(instance_id: string): IdentityCore
  reloadProfile(): IdentityCore

  // Reading
  getProfile(): IdentityCore
  getIdentity(): IdentityCore
  getField(field_name: string): unknown
  getHistory(): string[]

  // Verification
  verifyIdentity(): IdentityVerificationResult
  getChecksum(): string

  // Mutation (restricted)
  appendHistory(entry: string): IdentityCore
  amendIdentity(field: string, value: unknown, authority: string): IdentityCore

  // Governance
  getAccessLog(): IdentityAccessLog[]
  getVersion(): number
}

interface IdentityStoreConfig {
  instance_id: string
  emergency_fallback_enabled: boolean
  max_retries: number
  cache_ttl: Duration
  verify_on_load: boolean
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `PER.IdentityLoaded` | instance_id, name, version, created_at | Identity loaded on startup |
| `PER.IdentityAccessed` | field, caller, access_type | Identity field accessed by a component |
| `PER.IdentityWriteDenied` | field, caller, attempted_value | Write to immutable field rejected |
| `PER.IdentityAmended` | field, old_value, new_value, authority | Identity amended by constitutional authority |
| `PER.IdentityHistoryAppended` | entry, history_length | New history entry added by Sou |
| `PER.IdentityVerificationSucceeded` | checksum, duration_ms | Identity integrity check passed |
| `PER.IdentityVerificationFailed` | checksum, discrepancies, reason | Identity integrity check failed |
| `PER.IdentityEmergencyFallback` | reason, original_err | Emergency identity loaded due to failure |
| `PER.IdentityInjected` | prompt_id, instance_id, version | Identity injected into LLMOS prompt |
| `PER.IdentityCacheUpdated` | version, instance_id | Cached identity refreshed |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| IDP-001 | Sou's core identity (name, purpose, creator, instance_id) is immutable after instantiation | Architectural — write-once fields |
| IDP-002 | Identity history is append-only; no entry can be deleted or modified | Algorithmic — `appendHistory` only |
| IDP-003 | Identity is loaded before any other Brain service | Architectural — startup sequence |
| IDP-004 | Identity is injected into every LLMOS prompt | Architectural — Prompt Compiler enforces |
| IDP-005 | Identity is never exposed to user-facing responses | Architectural — ACF filters output |
| IDP-006 | Emergency identity is always available as fallback | Architectural — built into Personality System bootstrap |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Write to immutable identity field | `PER_IDENTITY_IMMUTABLE` | Deny; log security event |
| Profile not loaded | `PER_PROFILE_NOT_LOADED` | Return error; request initialization |
| Memory OS unavailable during load | `PER_IDENTITY_LOAD_FAILED` | Retry (max 3); fallback to emergency |
| Checksum mismatch on load | `PER_IDENTITY_CORRUPT` | Reject; load emergency; log security alert |
| instance_id mismatch | `PER_IDENTITY_INSTANCE_MISMATCH` | Reject; emit security event |
| Unauthorized access attempt | `PER_IDENTITY_ACCESS_DENIED` | Deny; log security event |
| History exceeds maximum length | `PER_IDENTITY_HISTORY_FULL` | Deny; suggest compression |
| Constitutional amendment without authority token | `PER_IDENTITY_AMENDMENT_UNAUTHORIZED` | Deny; log security event |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Identity Store handles only identity — immutable core, access control, loading |
| R2 — Dependency Order | Depends on Memory OS, ACF; no upward deps |
| R3 — DRY | Identity core defined once, referenced everywhere |
| R4 — Builder Pattern | Identity built at instantiation, then frozen |
| R5 — Liskov Substitution | Any IdentityStore implements the interface |
| R6 — DI over Singletons | Store config and emergency fallback injected |
| R9 — Deterministic | Same identity produces same prompt injection |
| R10 — Simpler Over Complex | Identity is a flat object with write-once fields |
| R13 — Design for Failure | Emergency identity ensures Sou can always operate |
| R14 — Paved Path | All access flows through `getProfile` / `getIdentity` |
| R15 — Open/Closed | History is append-only; core fields never change |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Personality/000-Overview.md | Identity Store is first component of the Personality System |
| Personality/002-Values.md | Values are grounded in identity's constitutional purpose |
| Personality/005-Evolution.md | Identity version tracked through evolution history |
| Brain/LLMOS/003-Prompt-Compiler.md | Identity injected into every system prompt |
| Brain/Sou/000-Overview.md | Sou's persistent identity is anchored here |
| Bible/05-Platform/004-EVS.md | Identity access and verification events recorded |
| Bible/06-Governance/001-Security-Council.md | Security Council authorizes identity amendments |
