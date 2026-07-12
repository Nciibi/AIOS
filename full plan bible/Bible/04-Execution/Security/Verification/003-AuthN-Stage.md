# AIOS Bible — Security
## 003 — Authentication Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-003 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Authenticate the requesting entity — credential validation, token verification, multi-factor verification.

## Architecture

```
Authentication Request
        │
        ▼
┌──────────────────┐
│ Credential Type  │
│ Detection        │
└──────┬───────────┘
        │
        ├── API Key ──────► API Key Validation
        ├── JWT ──────────► Signature + Expiry + Issuer
        ├── Session Token ─► Session Validation
        └── Certificate ──► Chain Validation
                │
                ▼
        ┌───────────────┐
        │ Credential    │
        │ Validated     │
        └───────┬───────┘
                │
        ┌───────▼───────┐
        │ MFA Required? │──No──► Authentication Passed
        └───────┬───────┘
                │ Yes
                ▼
        ┌───────────────┐
        │ MFA Challenge │
        │ ┌─────────┐   │
        │ │ Timeout? │──► MFA Timed Out
        │ └─────────┘   │
        │ │ Completed   │
        │ ▼             │
        │ Verify Code   │──► Authentication Passed
        └───────────────┘
```

## Data Model

```typescript
interface AuthenticationRequest {
  identityId: string;
  credential: Credential;
  mfaResponse: MFAChallenge | null;
  requestTime: Timestamp;
}

interface Credential {
  type: 'api-key' | 'jwt' | 'session-token' | 'certificate';
  value: string;
  metadata: Record<string, unknown>;
}

interface AuthNToken {
  tokenId: string;
  identityId: string;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  signature: string;
  issuer: string;
}

interface MFAChallenge {
  challengeId: string;
  type: 'totp' | 'sms' | 'email' | 'push';
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  completedAt: Timestamp | null;
  verified: boolean;
}

interface AuthenticationResult {
  passed: boolean;
  identityId: string | null;
  strength: number; // 0.0 - 1.0
  methodsUsed: string[];
  mfaRequired: boolean;
  mfaCompleted: boolean;
  errorCode: string | null;
  evidenceRef: string | null;
}
```

## Core Concepts / Operations

- **Credential Types Supported**: API keys, JWTs, session tokens, certificates. Each type has a dedicated validation path.
- **Token Validation**: Validates signature, expiry, and issuer for JWT tokens using CSP.
- **JWT Verification Flow**: Decode header → verify signature via CSP → check expiry → validate issuer → extract claims.
- **Multi-Factor Authentication Challenges**: Issue MFA challenge when policy requires step-up authentication. Supports TOTP, SMS, email, and push.
- **Credential Replay Detection**: Detect and reject replayed credentials using nonce/timestamp tracking.
- **Authentication Strength Scoring**: Compute a strength score (0.0–1.0) based on methods used (e.g., password only = 0.4, password + MFA = 0.9).
- **Failure Modes**: Expired token, invalid signature, MFA timeout.

## Internal Interfaces

```typescript
interface AuthNStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface CredentialValidator {
  validate(credential: Credential): Promise<boolean>;
  detectType(raw: string): Credential['type'];
}

interface JWTVerifier {
  verify(token: string): Promise<AuthNToken>;
  decode(token: string): Record<string, unknown>;
}

interface MFAProvider {
  issueChallenge(identityId: string, type: string): Promise<MFAChallenge>;
  verifyResponse(challenge: MFAChallenge, response: string): Promise<boolean>;
  isMFARequired(identityId: string): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.AuthN.AuthenticationRequested` | identityId, credentialType | Authentication flow initiated |
| `FV.AuthN.CredentialValidated` | credentialType, valid | Credential format and integrity checked |
| `FV.AuthN.TokenVerified` | tokenId, identityId, issuer | JWT/token verified successfully |
| `FV.AuthN.MFAChallengeIssued` | challengeId, type, identityId | MFA challenge dispatched |
| `FV.AuthN.MFACompleted` | challengeId, verified | MFA response received and verified |
| `FV.AuthN.MFATimedOut` | challengeId, identityId | MFA challenge expired without response |
| `FV.AuthN.AuthenticationPassed` | identityId, strength | Authentication succeeded |
| `FV.AuthN.AuthenticationFailed` | identityId, errorCode | Authentication failed |
| `FV.AuthN.ReplayDetected` | credentialId, identityId | Replayed credential detected and blocked |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Expired token | `FV_AUTHN_001` | Stage failed; token expired |
| Invalid signature | `FV_AUTHN_002` | Stage failed; token tampered |
| MFA timeout | `FV_AUTHN_003` | Stage failed; MFA not completed in window |
| Unsupported credential type | `FV_AUTHN_004` | Stage failed; unknown credential format |
| Credential replay detected | `FV_AUTHN_005` | Stage failed; possible theft |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-AUTHN-001 | Every credential is validated against exactly one validator by type | Algorithmic — type dispatch is exhaustive |
| FV-AUTHN-002 | Token signature is always verified before claim extraction | Algorithmic — verify before decode |
| FV-AUTHN-003 | MFA challenge expires after configured TTL — no late acceptance | Algorithmic — expiresAt enforces deadline |
| FV-AUTHN-004 | Replayed credentials are rejected within the replay window | Algorithmic — nonce/timestamp deduplication |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | AuthN Stage owns credential validation; CSP owns cryptographic verification |
| R2 — Dependency Order | Depends on CSP for JWT verification; depends on Identity Stage for identityId |
| R3 — DRY | Credential validators are registered by type, not duplicated |
| R4 — Builder Pattern | AuthenticationResult built from validation steps |
| R9 — Deterministic | Same credential + same key state = same auth result |
| R10 — Simpler Over Complex | Credential type detection before validation path selection |
| R13 — Design for Failure | MFA timeout and replay detection are explicit failure modes |
| R14 — Paved Path | JWT is the standard token format; API keys for machine-to-machine |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — authentication invariants |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — AuthN is stage 2 |
| Bible/04-Execution/Security/Verification/002-Identity-Stage.md | Identity Stage — provides resolved identity for auth |
| Bible/04-Execution/Security/Verification/004-AuthZ-Stage.md | AuthZ Stage — next stage in pipeline |
| Bible/06-Services/Cryptography/000-CSP.md | CSP — JWT signature verification |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for auth results |
