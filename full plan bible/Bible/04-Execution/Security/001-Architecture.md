# AIOS Bible — Security
## 001 — Security Council Architecture

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security |
| Document ID | AIOS-BBL-004-SEC-001 |
| Source Laws | Law 0 — Constitutional Supremacy, Law 8 — Law of Verification-First |
| Source Physics | Physics/008-Security.md, Physics/011-Design-DNA.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Security Council is the constitutional authority for security in AIOS. It operates the verification pipeline, manages security sub-services, and enforces security policy across all entities. The Security Council is not an advisory body — it is the runtime enforcement layer of the Constitution. Every action, every message, every resource access is subject to Security Council verification.

## Council Structure

The Security Council is composed of designated Engine entities with security specialization. Council membership is established by the Constitution and governed by institutional rules (03-Institutions).

### Council Responsibilities

| Responsibility | Description | Sub-Service |
|---------------|-------------|-------------|
| Identity verification | Verify actor identity before any action | IDS |
| Authentication | Validate tokens and credentials | ATS |
| Authorization | Check permissions for every action | AZS |
| Policy enforcement | Validate actions against policies | Policy System |
| Capability verification | Check capability bounds | CCA |
| Risk evaluation | Assess and escalate risk | Risk Engine |
| Execution authorization | Issue execution tokens | Execution Auth |
| Cryptographic operations | Provide cryptographic primitives | CSP |
| Audit | Maintain evidence chain | Audit Service |
| Trust management | Establish and verify cross-instance trust | TLM |

## Verification Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Security Council                            │
│                                                              │
│  Request → Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5  │
│            (IDS)    (ATS)    (AZS)    (Policy)  (CCA)       │
│                                                              │
│            Stage 6 → Stage 7 → Token issued → Execution     │
│            (Risk)   (Exec Auth)          (Runtime)          │
│                                                              │
│  Failure at any stage → DENY with error code                │
│  Evidence produced at every stage                           │
└─────────────────────────────────────────────────────────────┘
```

### Stage Details

| Stage | Component | Input | Output | Failure Mode |
|-------|-----------|-------|--------|-------------|
| 1 | IDS Resolver | Entity identifier | Identity claim | UnknownIdentity |
| 2 | ATS Validator | Auth token | Token claims | InvalidToken |
| 3 | AZS Evaluator | Action + context | Authorization decision | Unauthorized |
| 4 | Policy Engine | Action + policies | Policy verdict | PolicyViolation |
| 5 | CCA Verifier | Capability request | Capability grant | InsufficientCapability |
| 6 | Risk Engine | Action + context | Risk score | RiskThresholdExceeded |
| 7 | Execution Auth | All prior results | Execution token | AuthorizationDenied |

## Pipeline Invariants

1. **SEC-ARC-001 — Sequential Order**: Stages execute in order. No stage may be skipped. No stage may execute before its predecessor completes.

2. **SEC-ARC-002 — Fail-Closed**: If any stage fails, the entire verification fails. No partial authorizations.

3. **SEC-ARC-003 — Evidence Per Stage**: Every stage produces at least one Event. The evidence chain covers all 7 stages.

4. **SEC-ARC-004 — Stage Isolation**: Stages are independent components. No stage shares state with another stage. All communication is through ACF.

5. **SEC-ARC-005 — Deterministic Evaluation**: Same inputs at every stage produce the same outputs. Nondeterminism is bounded to risk scoring (which is logged and auditable).

## Council Operations

### Session Management

The Security Council operates in active-passive configuration. The active Council handles all verification requests. The passive Council synchronises state and takes over on failure. Failover is automatic within 5 seconds.

### Scalability

Pipeline stages scale independently. High-volume stages (IDS resolution, ATS validation) may have multiple workers. Low-volume stages (Risk evaluation for complex actions) may be pooled.

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Council.VerificationStarted | Pipeline begins | request_id, entity_id, action, stages |
| Council.StageCompleted | Single stage passes | request_id, stage, duration_ms, result |
| Council.VerificationPassed | All 7 stages pass | request_id, token_id, stages_summary |
| Council.VerificationFailed | Any stage fails | request_id, failed_stage, reason, error_code |
| Council.EscalationTriggered | Risk exceeds threshold | request_id, risk_score, escalated_to |
| Council.FailoverOccurred | Active Council fails | previous_active, new_active, failover_reason |

## Cross-Cutting Concerns

### Security

The Security Council's own operations are verified by the same pipeline (recursive verification for Council-level actions). Council member identities are cryptographically bound. Council communications use mTLS.

### Evidence

Every pipeline invocation produces a chain of Events — one per stage plus the final verdict. Evidence is stored in the Event Store with critical retention classification.

### Lifecycle

The Security Council itself follows the Organization lifecycle. Pipeline stages follow Platform service lifecycle. Stage versions are managed through CRP.

### Capability Bounds

The Security Council cannot create entities (OSYS does), allocate resources (ROS does), or modify the Constitution (CLS does). Its authority is bounded to verification.

### Communication

All pipeline stage communication flows through ACF synchronous calls with timeouts. Council alerts and notifications use ACF event streams.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Council verifies actions; it does not execute them |
| R2 — Dependency Order | Depends on sub-services, no upward deps |
| R3 — DRY | Pipeline logic defined once per stage |
| R4 — Builder Pattern | Pipeline built by Council with stage injection |
| R5 — Liskov | Stages implement PipelineStage interface |
| R6 — DI over Singletons | Council receives stage instances as deps |
| R7 — Tests Exist | Every stage combination has integration tests |
| R8 — Tests Fast | Full pipeline completes in <200ms |
| R9 — Deterministic | Stages 1-5, 7 are fully deterministic |
| R10 — Simpler Over Complex | Linear pipeline, no branching |
| R11 — Refactor Over Rewrite | Stages evolve via RFC |
| R12 — Embrace Errors | Each denial has unique error code |
| R13 — Design for Failure | Stage timeouts prevent cascade failure |
| R14 — Paved Path | Pipeline is the only execution path |
| R15 — Open/Closed | New stages integrate without pipeline modification |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Overview.md | Security architecture overview |
| 002-Trust-Model.md | Trust model for cross-instance Council verification |
| IDS/000-Overview.md | Identity Service — pipeline stage 1 |
| ATS/000-Auth-Methods.md | Authentication — pipeline stage 2 |
| AZS/000-RBAC.md | Authorization — pipeline stage 3 |
| Policy-System/000-PS.md | Policy evaluation — pipeline stage 4 |
| Risk/000-RE.md | Risk evaluation — pipeline stage 6 |
| Execution-Auth/000-EAS.md | Execution authorization — pipeline stage 7 |
| Physics/008-Security.md | Security invariants |
