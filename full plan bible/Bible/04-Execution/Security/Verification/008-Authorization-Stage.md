# AIOS Bible — Security
## 008 — Final Authorization Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-008 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Make the final authorization decision based on all stage results, produce the execution token, and record the complete verification chain.

## Architecture

```
All 6 Stage Results (Identity, AuthN, AuthZ, Policy, Capability, Risk)
        │
        ▼
┌────────────────────────────┐
│ Decision Aggregation       │──► Collect and verify all stage results
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Consistency Check          │──► Stage results must be internally consistent
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Execution Token Generation │──► Build signed, time-bound, scope-limited token
│ ┌──────────────────────┐   │
│ │ Token Structure:     │   │
│ │ - entity_id          │   │
│ │ - allowed_actions    │   │
│ │ - resource_scope     │   │
│ │ - expiry             │   │
│ │ - signature          │   │
│ └──────────────────────┘   │
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Verification Chain         │──► Record complete audit trail
│ Recording                  │
└───────────┬────────────────┘
            │
            ▼
┌────────────────────────────┐
│ Token Issuance             │──► Issue token to Runtime Engine
└───────────┬────────────────┘
            │
            ▼
  Authorization Decision
 (approved / denied / revoked)
```

## Data Model

```typescript
interface AuthorizationDecision {
  decisionId: string;
  pipelineId: string;
  approved: boolean;
  stageResults: Map<string, StageResult>;
  token: EASExecutionToken | null;
  decisionTime: Timestamp;
  decidedBy: 'pipeline' | 'security-council' | 'override';
  overriddenBy: string | null;
  reason: string | null;
}

interface EASExecutionToken {
  tokenId: string;
  entityId: string;
  allowedActions: string[];
  resourceScope: string;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  signature: string;
  chainRef: string;
}

interface VerificationChain {
  chainId: string;
  pipelineId: string;
  requestId: string;
  entries: ChainEntry[];
  totalStages: number;
  passedStages: number;
  finalDecision: boolean;
  recordedAt: Timestamp;
}

interface ChainEntry {
  stageId: string;
  stageName: string;
  passed: boolean;
  latencyMs: number;
  evidenceRef: string;
  timestamp: Timestamp;
}

interface DecisionRecord {
  decisionId: string;
  entityId: string;
  action: string;
  resourceRef: string;
  decision: 'granted' | 'denied' | 'revoked';
  tokenId: string | null;
  chainRef: string;
  recordedAt: Timestamp;
}
```

## Core Concepts / Operations

- **Decision Aggregation**: Collect StageResult from all 6 preceding stages. If any stage failed, decision is deny. If all passed, decision is grant.
- **Execution Token Generation**: Produce a signed EASExecutionToken containing entity_id, allowed_actions, resource_scope, expiry, and cryptographic signature.
- **Token Structure**: tokenId (UUIDv4), entityId, allowedActions (string[]), resourceScope (string), issuedAt, expiresAt, signature (CSP-signed), chainRef (link to VerificationChain).
- **Token Revocation Mechanism**: Tokens can be revoked via Security Council or on policy change. Revoked tokens are checked at execution time by EAS.
- **Verification Chain Recording**: Write a complete audit trail of every stage result to the VerificationChain. Each entry includes stageId, passed boolean, latency, evidenceRef, and timestamp.
- **Token Issuance to Runtime Engine**: The signed token is issued to the Runtime Engine via EAS for execution.
- **Token Validation at Execution Time**: EAS validates token signature, expiry, scope, and revocation status before allowing execution.
- **Failure Modes**: Stage result inconsistency, token generation failure, chain recording error.

## Internal Interfaces

```typescript
interface FinalAuthStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface DecisionAggregator {
  aggregate(results: Map<string, StageResult>): AuthorizationDecision;
  checkConsistency(results: Map<string, StageResult>): boolean;
}

interface TokenGenerator {
  generate(decision: AuthorizationDecision): Promise<EASExecutionToken>;
  sign(token: EASExecutionToken): Promise<string>;
  revoke(tokenId: string): Promise<void>;
  validate(token: EASExecutionToken): Promise<boolean>;
}

interface ChainRecorder {
  record(context: PipelineContext, decision: AuthorizationDecision, token: EASExecutionToken | null): Promise<string>;
  getChain(chainId: string): Promise<VerificationChain>;
}

interface TokenIssuer {
  issue(token: EASExecutionToken): Promise<void>;
  isRevoked(tokenId: string): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.Auth.DecisionAggregated` | decisionId, approved, stageCount | All stage results aggregated |
| `FV.Auth.TokenGenerated` | tokenId, entityId, expiry | Execution token created |
| `FV.Auth.TokenSigned` | tokenId, signature | Token cryptographically signed |
| `FV.Auth.TokenIssued` | tokenId, entityId, pipelineId | Token issued to Runtime Engine |
| `FV.Auth.TokenDenied` | pipelineId, entityId, reason | Token not issued; request denied |
| `FV.Auth.ChainRecorded` | chainId, entryCount | Verification chain persisted |
| `FV.Auth.TokenRevoked` | tokenId, revokedBy, reason | Token revoked after issuance |
| `FV.Auth.DecisionOverridden` | decisionId, overriddenBy, newDecision | Security Council overrode pipeline decision |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Stage result inconsistency | `FV_FINAL_001` | Abort; results contradict each other |
| Token generation failure | `FV_FINAL_002` | Abort; retry token generation |
| Chain recording error | `FV_FINAL_003` | Token not issued; recording must succeed first |
| Token signing failure | `FV_FINAL_004` | Abort; CSP unavailable |
| Revocation check unavailable | `FV_FINAL_005` | Deny; cannot validate token at execution time |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-FINAL-001 | Token is never issued unless all 6 preceding stages passed | Constitutional — DecisionAggregator enforces |
| FV-FINAL-002 | Every issued token is signed and verifiable | Algorithmic — signature mandatory on generation |
| FV-FINAL-003 | Verification chain is recorded before token issuance | Architectural — ChainRecorder called before TokenIssuer |
| FV-FINAL-004 | Token expiry is bounded — never exceeds configured max TTL | Algorithmic — expiresAt enforced at generation |
| FV-FINAL-005 | Decision override by Security Council is logged with override identity | Architectural — DecisionRecord captures overriddenBy |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Final Stage owns decision; EAS owns token validation at execution |
| R2 — Dependency Order | Depends on all 6 prior stages; depends on CSP for signing |
| R3 — DRY | Token schema defined once; structure reused by EAS and Runtime |
| R4 — Builder Pattern | AuthorizationDecision built from aggregated stage results |
| R9 — Deterministic | Same stage results = same token (different tokenId, same scope) |
| R10 — Simpler Over Complex | All-pass = grant; any-fail = deny; override via Council only |
| R13 — Design for Failure | Chain recording failure blocks issuance; signing failure aborts |
| R14 — Paved Path | Time-bound tokens with resource scope; revocation for emergencies |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — non-bypassability proof target |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — Final Authorization is stage 7 |
| Bible/04-Execution/Security/Verification/002-Identity-Stage.md | Identity Stage — stage 1 source |
| Bible/04-Execution/Security/Verification/003-AuthN-Stage.md | AuthN Stage — stage 2 source |
| Bible/04-Execution/Security/Verification/004-AuthZ-Stage.md | AuthZ Stage — stage 3 source |
| Bible/04-Execution/Security/Verification/005-Policy-Stage.md | Policy Stage — stage 4 source |
| Bible/04-Execution/Security/Verification/006-Capability-Stage.md | Capability Stage — stage 5 source |
| Bible/04-Execution/Security/Verification/007-Risk-Stage.md | Risk Stage — stage 6 source |
| Bible/04-Execution/Security/Execution-Auth/000-EAS.md | EAS — token consumer and execution-time validator |
| Bible/04-Execution/Security/000-Overview.md | Security Council — override authority for decisions |
| Bible/06-Services/Cryptography/000-CSP.md | CSP — token signing and signature verification |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for final decisions |
