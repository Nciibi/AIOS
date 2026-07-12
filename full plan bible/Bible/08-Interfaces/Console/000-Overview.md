# AIOS Bible â€” Interfaces
## Console â€” 000: Governance Console

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Interfaces |
| Document ID | AIOS-BBL-008-GC-000 |
| Source Laws | Law 1 â€” Law of Origin, Law 4 â€” Law of Evidence, Law 9 â€” Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Governance Console is the human-facing interface to AIOS's governance machinery. It is the bridge between human authority (Law 1 â€” Origin) and AIOS's constitutional governance services. Through the Console, humans review the Constitution, approve or reject RFCs, exercise Human Override (Article I, Section 004), certify agents, and inspect the audit trail that proves constitutional compliance.

The Governance Console is not a general-purpose UI â€” it is specifically the human-in-the-loop control surface for governance decisions that only a human may make. Routine operations happen through the Human Interface and Dashboard; governance-critical actions happen here.

## Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                  Governance Console                      â”‚
â”‚                                                         â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚ Constitutionâ”‚  â”‚   RFC      â”‚  â”‚   Human Override  â”‚  â”‚
â”‚  â”‚  Viewer    â”‚  â”‚  Review    â”‚  â”‚   Console        â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â”‚        â”‚                â”‚                 â”‚            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚   Audit     â”‚  â”‚  Agent     â”‚  â”‚   Decision        â”‚  â”‚
â”‚  â”‚   Explorer  â”‚  â”‚  Certificationâ”‚ â”‚   Log Viewer     â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â”‚        â”‚                â”‚                 â”‚            â”‚
â”‚        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜            â”‚
â”‚                         â”‚                              â”‚
â”‚                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”                     â”‚
â”‚                â”‚  Governance API  â”‚                     â”‚
â”‚                â”‚  (ACF-backed)    â”‚                     â”‚
â”‚                â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜                     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                          â”‚
                          â–¼
        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
        â”‚ 01-Governance Services (CLS, DGP, CRP,   â”‚
        â”‚  CKR, ADG, AKM) + 02-Core, 04-Execution  â”‚
        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Core Concepts

### 1. Constitution Viewer

Reads the active Constitution from the Constitutional Knowledge Repository (CKR). Shows the current text, version history, and amendment status. Humans can compare versions and see the rationale for each change. The viewer is read-only for humans â€” amendments go through the RFC pipeline.

### 2. RFC Review

Presents pending Change Requests (CRPs) for human review. Shows the proposed change, its constitutional impact assessment, affected subsystems, and risk level. Humans approve, reject, or request revisions. Approval triggers the CRP implementation pipeline.

### 3. Human Override

The most consequential console capability. Human Override (Article I, Section 004) temporarily suspends a specific Physics law or constitutional constraint for a specific, bounded operation. The override requires explicit human identity, justification, scope, and duration. Every override is recorded as evidence and subject to post-hoc audit. The console enforces that overrides are time-bound and scope-bound â€” they cannot be open-ended.

### 4. Agent Certification

Surfaces agents pending certification (from the Agent Evolution System) for human review. Shows the agent's performance history, competency coverage, and certification gate results. Humans approve or reject promotion. This is the human check on autonomous agent evolution.

### 5. Audit Explorer

Lets humans traverse the evidence graph: which decisions were made, by whom, on what basis, with what outcome. Built on the Audit System (AUS) and Evidence System (EVS). Supports filtering by entity, time range, and event type. This is the transparency surface that makes "no invisible decisions" (Law 4) real for humans.

### 6. Decision Log Viewer

Shows the decision log of strategic choices made by Sou and the governance services. Each entry links to its evidence trail. Humans can query "why was this decision made?" and trace it back to the source.

## Data Model

```typescript
interface OverrideRequest {
  overrideId: string;
  requestedBy: string;  // human identity
  lawSuspended: number;  // which Physics law is suspended (1-10)
  scope: OverrideScope;  // what the override applies to
  justification: string;
  durationSeconds: number;  // time-bound
  status: 'pending' | 'active' | 'expired' | 'revoked';
  evidenceRef: string;
}

interface RfcDecision {
  decisionId: string;
  rfcId: string;
  decision: 'approve' | 'reject' | 'revise';
  reviewerId: string;  // human identity
  comments: string;
  decidedAt: Timestamp;
  evidenceRef: string;
}

interface CertificationReview {
  reviewId: string;
  agentId: string;
  targetStage: number;
  performanceSummary: PerformanceSnapshot;
  gateResults: CertificationGateResult[];
  decision: 'approve' | 'reject';
  reviewerId: string;
  evidenceRef: string;
}

interface ConsoleSession {
  sessionId: string;
  humanId: string;  // verified human identity
  permissions: ConsolePermission[];
  startedAt: Timestamp;
  mfaVerified: boolean;
  evidenceRef: string;
}
```

## Interfaces

### Governance Console API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `viewConstitution(version?)` | Verified Human | Retrieve constitution text and history |
| `listPendingRFCs()` | Verified Human | List RFCs awaiting review |
| `decideRFC(rfcId, decision, comments)` | Verified Human + MFA | Approve/reject/revise an RFC |
| `requestOverride(params)` | Verified Human + MFA | Initiate human override of a law |
| `revokeOverride(overrideId)` | Verified Human + MFA | End an active override early |
| `listPendingCertifications()` | Verified Human | List agents awaiting certification |
| `decideCertification(agentId, decision)` | Verified Human + MFA | Approve/reject agent promotion |
| `exploreAudit(filter)` | Verified Human | Query the evidence graph |
| `viewDecisionLog(filter)` | Verified Human | Query the decision log |

### Internal Interfaces

```typescript
interface OverrideController {
  request(req: OverrideRequest): Promise<OverrideResult>;
  revoke(overrideId: string, by: string): Promise<void>;
  listActive(): Promise<OverrideRequest[]>;
}

interface RfcReviewer {
  listPending(): Promise<RfcSummary[]>;
  decide(rfcId: string, decision: RfcDecision): Promise<void>;
}

interface CertificationGate {
  listPending(): Promise<CertificationSummary[]>;
  review(agentId: string, review: CertificationReview): Promise<void>;
}

interface AuditExplorer {
  query(filter: AuditFilter): Promise<EvidenceRecord[]>;
  trace(entityId: string): Promise<DecisionTrace>;
}
```

## Component Map

| Component | Responsibility |
|-----------|---------------|
| Constitution Viewer | Renders active constitution and version history |
| RFC Review | Presents and collects human decisions on change requests |
| Override Controller | Manages human override lifecycle (request, active, expire, revoke) |
| Certification Gate | Surfaces agent certification decisions to humans |
| Audit Explorer | Enables evidence graph traversal for humans |
| Decision Viewer | Shows the governance decision log with evidence links |
| Console Session Manager | Authenticates humans, enforces MFA and permissions |

## Data Flow

```
Human opens Console (MFA-verified session)
        â”‚
        â–¼
Console loads pending governance actions
        â”‚
        â”œâ”€â”€ RFC pending â”€â”€â–º Human reviews â”€â”€â–º decideRFC() â”€â”€â–º CRP pipeline
        â”‚
        â”œâ”€â”€ Agent pending cert â”€â”€â–º Human reviews â”€â”€â–º decideCertification() â”€â”€â–º AGX promotion
        â”‚
        â”œâ”€â”€ Override needed â”€â”€â–º Human requests â”€â”€â–º requestOverride() â”€â”€â–º Law suspended (time-bound)
        â”‚
        â””â”€â”€ Audit query â”€â”€â–º Human explores â”€â”€â–º exploreAudit() â”€â”€â–º Evidence shown
        â”‚
        â–¼
All actions recorded as evidence (Law 4)
```

## Events

| CON.EventType | Produced When | Fields |
|-------|--------|-------------|
| `GC.SessionStarted` | sessionId, humanId, mfaVerified | Human opened governance console |
| `GC.RfcDecided` | rfcId, decision, reviewerId | Human decision on RFC recorded |
| `GC.OverrideRequested` | overrideId, lawSuspended, scope, duration | Human override initiated |
| `GC.OverrideActive` | overrideId, lawSuspended, expiresAt | Override now in effect |
| `GC.OverrideExpired` | overrideId | Override auto-expired at duration end |
| `GC.OverrideRevoked` | overrideId, revokedBy | Override ended early by human |
| `GC.CertificationDecided` | agentId, targetStage, decision, reviewerId | Agent promotion approved/rejected |
| `GC.AuditQueried` | humanId, filter, resultCount | Human ran an audit query |
| `GC.SessionEnded` | sessionId, humanId | Console session closed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Human not MFA-verified | `GC_MFA_REQUIRED` | Block action; require MFA before proceeding |
| Human lacks permission for action | `GC_PERMISSION_DENIED` | Reject; action requires higher clearance |
| Override scope too broad | `GC_OVERRIDE_SCOPE_INVALID` | Reject; scope must be specific and bounded |
| Override duration exceeds max | `GC_OVERRIDE_DURATION_EXCEEDED` | Reject; cap duration per policy |
| RFC already decided | `GC_RFC_ALREADY_DECIDED` | Reject; idempotent decision enforcement |
| Agent not pending certification | `GC_AGENT_NOT_PENDING` | Reject; no certification request active |
| Audit query timeout | `GC_AUDIT_TIMEOUT` | Return partial results with continuation token |
| Session expired mid-action | `GC_SESSION_EXPIRED` | Reject; human must re-authenticate |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| GC-001 | Every governance action requires a verified human identity | Constitutional â€” Human Override and RFC approval require human identity |
| GC-002 | Every console action produces an evidence record (Law 4) | Architectural â€” all actions logged to EVS |
| GC-003 | Human overrides are always time-bound and scope-bound | Algorithmic â€” override cannot be open-ended |
| GC-004 | MFA is required for all override and certification decisions | Architectural â€” session manager enforces MFA gate |
| GC-005 | Override can only suspend one law per request | Algorithmic â€” single law per override request |
| GC-006 | A decision on an RFC is idempotent â€” cannot be reversed by re-deciding | Architectural â€” decision state is terminal |
| GC-007 | Console sessions expire after configurable idle timeout | Algorithmic â€” session manager enforces timeout |


## Cross-Cutting Concerns

### Security

Console operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Console emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Console instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Console declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Console owns human governance interaction exclusively; governance services own the logic |
| R2 â€” Dependency Order | Depends on 01-Governance services, AUS, EVS, ACF; no circular deps |
| R3 â€” DRY | Constitution text sourced from CKR; console renders, does not duplicate |
| R4 â€” Builder Pattern | Override requests use builder for scope and duration validation |
| R9 â€” Deterministic | Same query returns same evidence; actions are replayable from evidence |
| R10 â€” Simpler Over Complex | Default console shows pending actions; advanced views are opt-in |
| R13 â€” Design for Failure | Session expiry and MFA failure preserve partial state; no silent overrides |
| R14 â€” Paved Path | RFC review and override request are the standard flows |
| R15 â€” Open/Closed | New governance action types register via Console API extension |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/01-Governance/000-Overview.md | Governance services that the Console surfaces to humans |
| Bible/01-Governance/001-CLS.md | Constitutional Lifecycle Service â€” constitution versioning |
| Bible/01-Governance/003-CRP.md | Change Request Pipeline â€” RFC lifecycle |
| Bible/02-Core/Brain/Autonomy/000-Overview.md | Autonomy escalation may trigger human override via Console |
| Bible/02-Core/Agents/000-Overview.md | Agent certification decisions surface here |
| Bible/05-Platform/005-AUS.md | Audit System â€” evidence explored by Console |
| Bible/05-Platform/004-EVS.md | Evidence System â€” source of audit data |
| Bible/06-Services/ACF/000-Overview.md | ACF transports all console actions |
| Bible/08-Interfaces/UI/000-Overview.md | General human interface â€” console is governance-specific |
| Bible/08-Interfaces/Dashboard/000-Overview.md | Dashboard surfaces governance alerts for human action |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants |
| Physics/005-Events.md | Evidence invariants â€” every console action is logged |
