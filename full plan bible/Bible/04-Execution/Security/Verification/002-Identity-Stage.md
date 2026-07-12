# AIOS Bible — Security
## 002 — Identity Verification Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-002 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Verify the identity of the requesting entity — identity lookup, format validation, revocation check.

## Architecture

```
Identity Claim ──► Format Validation ──► IDS Lookup ──► Revocation Check ──► Result
                        │                     │                │
                        ▼                     ▼                ▼
                   Malformed Claim      Identity Not       Revoked Entity
                   FV_ID_003            Found FV_ID_001    FV_ID_004
```

Identity Stage is the first stage of the 7-stage verification pipeline. It extracts the identity claim from the incoming request, validates its format, resolves it against the IDS, and checks revocation status before passing to the Authentication Stage.

## Data Model

```typescript
interface IdentityClaim {
  rawClaim: string;
  claimType: 'uuid' | 'did' | 'username' | 'email';
  issuer: string | null;
  presentedAt: Timestamp;
}

interface IdentityRecord {
  identityId: string;
  entityId: string;
  identityType: string;
  status: 'active' | 'suspended' | 'expired' | 'revoked';
  validFrom: Timestamp;
  validTo: Timestamp | null;
  metadata: Record<string, unknown>;
}

interface IdentityVerificationResult {
  passed: boolean;
  identityId: string | null;
  entityId: string | null;
  record: IdentityRecord | null;
  verificationTime: Timestamp;
  errorCode: string | null;
  evidenceRef: string | null;
}

interface RevocationStatus {
  identityId: string;
  revoked: boolean;
  revokedAt: Timestamp | null;
  revokedBy: string | null;
  reason: string | null;
}
```

## Core Concepts / Operations

- **Identity Claim Extraction**: Parse and extract identity claim from request headers, tokens, or parameters. Supported formats: UUID, DID, username, email.
- **IDS Lookup for Identity Record**: Resolve the identity claim against the Identity Registry Service (IDS) to retrieve the full IdentityRecord.
- **Identity Format Validation**: Validate identity format compliance — UUID format (v4), required fields presence, character encoding.
- **Revocation Status Check**: Query revocation status from IDS. Reject expired or revoked identities.
- **Identity Evidence Logging**: All identity verification results are logged to EVS as evidence (Law 4).
- **Failure Modes**: Identity not found, malformed claim, revoked identity.

## Internal Interfaces

```typescript
interface IdentityStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface IdentityResolver {
  resolve(claim: IdentityClaim): Promise<IdentityRecord | null>;
  validateFormat(claim: IdentityClaim): boolean;
}

interface RevocationChecker {
  check(identityId: string): Promise<RevocationStatus>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.ID.IdentityClaimReceived` | requestId, claimType | Identity claim extracted from request |
| `FV.ID.IdentityResolved` | identityId, entityId | Identity resolved against IDS |
| `FV.ID.IdentityValidated` | identityId, formatValid | Format validation completed |
| `FV.ID.IdentityVerificationPassed` | identityId, entityId | Identity verification succeeded |
| `FV.ID.IdentityVerificationFailed` | identityId, errorCode | Identity verification failed |
| `FV.ID.RevocationChecked` | identityId, revoked | Revocation status determined |
| `FV.ID.IdentityNotFound` | claimValue, claimType | No matching record in IDS |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Identity not found in IDS | `FV_ID_001` | Stage failed; abort pipeline |
| Revoked identity | `FV_ID_002` | Stage failed; reject request |
| Malformed identity claim | `FV_ID_003` | Stage failed; invalid input |
| Identity record expired | `FV_ID_004` | Stage failed; identity expired |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-ID-001 | Every identity claim is validated against format rules before IDS lookup | Algorithmic — validateFormat called before resolve |
| FV-ID-002 | No revoked identity passes the Identity Stage | Constitutional — revocation check is mandatory |
| FV-ID-003 | Identity Stage result is always logged to EVS | Architectural — evidenceRef produced on every execution |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Identity Stage owns identity verification; IDS owns identity storage |
| R2 — Dependency Order | Depends on IDS; no circular dependencies |
| R3 — DRY | Format validation rules defined once in IdentityResolver |
| R4 — Builder Pattern | IdentityClaim built from raw request data |
| R9 — Deterministic | Same identity claim + same IDS state = same result |
| R10 — Simpler Over Complex | Format validation before lookup reduces IDS load |
| R13 — Design for Failure | Revoked and expired identities are explicitly rejected |
| R14 — Paved Path | UUID format is the standard; DIDs supported for interop |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — identity uniqueness property |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — Identity is stage 1 |
| Bible/04-Execution/Security/Verification/003-AuthN-Stage.md | AuthN Stage — next stage in pipeline |
| Bible/04-Execution/Security/IDS/001-Registry.md | IDS — identity record source and revocation authority |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for verification results |
