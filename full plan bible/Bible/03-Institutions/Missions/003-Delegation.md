# AIOS Bible — Institutions
## 003 — Mission Delegation

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Institutions |
| Document ID | AIOS-BBL-003-MSN-003 |
| Source Laws | Law 1 — Law of Origin, Law 4 — Law of Evidence, Law 6 — Law of Lifecycle Compliance |
| Source Physics | Physics/002-Missions.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Delegate Mission tasks to sub-Missions, Workers, Organizations, or external systems — with clear contracts, accountability, and result verification.

## Architecture

Delegation follows a contract-based pattern where the source Mission defines scope, deliverables, timeline, and success criteria in a formal DelegationContract. The delegate accepts or rejects the contract; upon acceptance, execution proceeds independently with periodic result checkpoints.

```
Source Mission               Delegate
    │                           │
    ├── createDelegation() ────►│
    │                           ├── accept / reject
    │◄── acceptance             │
    │                           │
    │   [delegated execution]   │
    │                           │
    │◄── result + evidence ─────┤
    │                           │
    └── verifyResult() ────────┘
```

Accountability is maintained through an immutable chain recording the source Mission, contract, delegate, and verification result. Escalation paths exist for failures at any stage.

## Data Model

```typescript
interface DelegationContract {
  contract_id: UUID;
  source_mission_id: UUID;
  target: DelegationTarget;
  scope: string;
  deliverables: Deliverable[];
  timeline: Timeline;
  success_criteria: Criterion[];
  budget: ResourceBudget;
  terms: string;
  status: ContractStatus;
}

interface DelegationTarget {
  type: DelegationTargetType;
  target_id: UUID;
  name: string;
  capabilities: Capability[];
}

interface SubMissionRecord {
  sub_mission_id: UUID;
  contract_id: UUID;
  parent_mission_id: UUID;
  status: SubMissionStatus;
  progress: ProgressSnapshot;
  evidence_chain: EvidenceRef[];
  started_at: Timestamp;
  completed_at?: Timestamp;
}

interface ResultVerification {
  verification_id: UUID;
  contract_id: UUID;
  results: DeliverableResult[];
  verification_status: VerificationStatus;
  verified_by: UUID;
  notes: string;
  timestamp: Timestamp;
}
```

## Core Concepts / Operations

### Delegation Patterns
- **Sub-Mission Delegation**: Delegate to a child Mission owned by the same Organization. Full lifecycle management. Most common pattern.
- **Worker Delegation**: Delegate to a specific Worker or Worker team. Limited scope, direct accountability.
- **Organization Delegation**: Delegate to another Organization. Requires cross-Organization agreement. Security Council oversight required.
- **External System**: Delegate to a system outside AIOS. Requires adapter interface. Increased risk profile.

### Delegation Contract Format
| Field | Required | Description |
|-------|----------|-------------|
| Scope | Yes | Clear boundary of delegated work |
| Deliverables | Yes | List of expected outputs with acceptance criteria |
| Timeline | Yes | Start date, end date, milestone schedule |
| Success Criteria | Yes | Measurable conditions for acceptance |
| Budget | Yes | Resource allocation for delegated work |
| Terms | Yes | Conditions, constraints, SLA requirements |

### Accountability Chain
Each delegation creates an accountability chain: source Mission → contract → target. The source Mission retains ultimate accountability. The delegate assumes execution accountability. Chain is recorded immutably in the Event Store.

### Result Verification at Handback
When delegated work completes, results are verified against the contract's success criteria. Verification produces a ResultVerification record. Verification may be:
- **Automatic**: Criteria are machine-evaluable (metrics, thresholds)
- **Manual**: Requires human reviewer evaluation
- **Hybrid**: Machine evaluation + human spot-check

### Failure Escalation Paths
Delegation failures follow a defined escalation path:
1. Delegate notifies source Mission of issue
2. Source Mission attempts mitigation (renegotiation, resource adjustment)
3. If unresolved, escalate to parent Organization
4. Final escalation to Security Council

## Lifecycle

Delegation can occur in any state from Planned through Running. Sub-Missions follow their own lifecycle (000-Lifecycle.md) with the parent Mission as observer. Delegation contracts are created, accepted, executed, and resolved.

## Internal Interfaces

```typescript
interface MissionDelegator {
  createDelegation(contract: DelegationContract): Promise<ContractID>;
  acceptDelegation(contractId: UUID): Promise<AcceptanceRecord>;
  rejectDelegation(contractId: UUID, reason: string): Promise<RejectionRecord>;
  recordResult(contractId: UUID, deliverables: Deliverable[]): Promise<ResultRecord>;
  verifyResult(contractId: UUID, criteria: Criterion[]): Promise<ResultVerification>;
  escalateFailure(contractId: UUID, level: EscalationLevel): Promise<EscalationRecord>;
}
```

## Events

| Event | Payload | Trigger |
|-------|---------|---------|
| MSN.Del.DelegationCreated | contract_id, source_mission, target, scope_hash | Delegation contract created |
| MSN.Del.DelegationAccepted | contract_id, accepted_by, acceptance_hash | Delegation accepted |
| MSN.Del.DelegationRejected | contract_id, rejected_by, reason | Delegation rejected |
| MSN.Del.SubMissionStarted | contract_id, sub_mission_id, started_at | Sub-Mission begins execution |
| MSN.Del.SubMissionCompleted | contract_id, sub_mission_id, result_summary | Sub-Mission completes |
| MSN.Del.SubMissionFailed | contract_id, sub_mission_id, error_code, details | Sub-Mission fails |
| MSN.Del.ResultReturned | contract_id, deliverables_hash, count | Results returned |
| MSN.Del.ResultVerified | contract_id, verification_status, score | Results verified |
| MSN.Del.ResultRejected | contract_id, verification_status, failures | Results rejected |
| MSN.Del.AccountabilityChain | contract_id, chain_hash, links | Chain recorded |

## Error Cases

| Code | Description |
|------|-------------|
| MSN_DEL_001 | Delegation target does not exist or is unreachable |
| MSN_DEL_002 | Contract scope overlaps with existing delegation |
| MSN_DEL_003 | Budget exceeds remaining Mission allocation |
| MSN_DEL_004 | Result verification failed — acceptance criteria not met |
| MSN_DEL_005 | Delegation timeout — no response within SLA |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| MSN-DEL-001 | Every delegation must have a signed contract before execution begins | Architectural — Contract status must be 'accepted' before work starts |
| MSN-DEL-002 | A Mission cannot delegate its entire scope — must retain at least one milestone | Algorithmic — Validation rejects delegation of all milestones |
| MSN-DEL-003 | Delegated budget must not exceed parent Mission's allocated budget | Algorithmic — Budget cross-check against parent allocation |
| MSN-DEL-004 | Accountability chain must be recorded before any work is transferred | Architectural — Event store write precedes worker dispatch |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Delegation is a single focused concern within the Mission system |
| R3 — DRY | Delegation contracts follow the same pattern as Mission plans |
| R9 — Deterministic | Same delegation contract with same target produces same outcome |
| R10 — Simpler Over Complex | Clear contract format with well-defined acceptance/rejection flow |
| R12 — Embrace Errors | All delegation errors have unique codes (MSN_DEL_001–005) |
| R13 — Design for Failure | Escalation paths defined for all delegation failure modes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Missions/000-Lifecycle.md | Base lifecycle doc |
| Missions/001-Planning.md | Sibling — delegation may be part of the plan |
| Missions/002-Execution.md | Sibling — delegated tasks execute in sub-Missions |
| Missions/004-Failure-Recovery.md | Sibling — delegation failures trigger recovery |
| Bible/03-Institutions/Organizations/000-Overview.md | Cross-Organization delegation |
| Bible/03-Institutions/Workers/000-Overview.md | Worker delegation |
| Physics/002-Missions.md | Mission canonical definitions |
| Physics/005-Events.md | Event system |
