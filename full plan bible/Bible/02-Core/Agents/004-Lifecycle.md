# AIOS Bible — Core
## 004 — Agent Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core/Agents |
| Document ID | AIOS-BBL-002-AGX-004 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 7 — Law of Capability Bounds, Law 10 — Law of Tenure |
| Source Physics | Physics/007-Capabilities.md, Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Full agent lifecycle from creation through retirement — state machine, transitions, tenure enforcement, and termination. This is the agent instance lifecycle (CREATED → ACTIVE → INACTIVE → RETIRED), distinct from the AGX evolution lifecycle (Nascent → Master). The instance lifecycle governs the operational state of an agent, while the evolution lifecycle governs capability maturity.

## Data Model

```typescript
enum AgentLifecycleState {
  Created = 'CREATED',
  Active = 'ACTIVE',
  Inactive = 'INACTIVE',
  Frozen = 'FROZEN',
  Retired = 'RETIRED',
  Archived = 'ARCHIVED',
}

interface LifecycleTransition {
  transitionId: string;
  agentId: string;
  fromState: AgentLifecycleState;
  toState: AgentLifecycleState;
  reason: string;
  authorizedBy: string;
  evidenceRef: string;
  transitionedAt: Timestamp;
  expiryDate: Timestamp | null;
}

interface TenurePolicy {
  policyId: string;
  name: string;
  maxTenure: Duration;
  warningPeriod: Duration;
  extensionLimit: number;
  extensionsUsed: number;
  actionsOnExpiry: 'retire' | 'freeze' | 'notify-only';
  exemptRoles: string[];
}

interface TerminationRecord {
  terminationId: string;
  agentId: string;
  terminationReason: 'natural' | 'policy' | 'failure' | 'manual';
  details: string;
  finalState: AgentLifecycleState;
  evidenceSealed: boolean;
  evidenceRef: string;
  genomeVersion: number;
  retentionUntil: Timestamp;
  terminatedAt: Timestamp;
  terminatedBy: string;
}
```

## Core Concepts / Operations

### State Machine (Created → Active → Inactive → Retired + Frozen → Archived)

```
     ┌──────────┐
     │ CREATED  │
     └────┬─────┘
          │ activate
     ┌────▼─────┐
     │  ACTIVE  │◄────────────┐
     └──┬───┬───┘             │
        │   │                 │
  deact.│   │ freeze          │
        │   │                 │
   ┌────▼───▼────┐      ┌────┴──────┐
   │  INACTIVE   │      │  FROZEN   │
   └────┬────────┘      └────┬──────┘
        │ thaw / reactivate──┘
        │ retire
   ┌────▼────────┐
   │   RETIRED   │
   └────┬────────┘
        │ archive
   ┌────▼────────┐
   │  ARCHIVED   │
   └─────────────┘
```

- **CREATED**: Agent assembled but not yet operational. Must be activated to begin work.
- **ACTIVE**: Agent is operational, accepting tasks, and generating evidence. The steady state.
- **INACTIVE**: Agent temporarily suspended. No tasks accepted. Can be reactivated to ACTIVE.
- **FROZEN**: Agent suspended for investigation (security incident, policy violation). Limited to evidence review only.
- **RETIRED**: Agent permanently decommissioned. Immutable state — cannot return to any prior state.
- **ARCHIVED**: Retired agent's evidence and genome metadata preserved for compliance. No runtime exists.

### Transition Authorization
State transitions require authorization based on the transition type:

| Transition | Authorized By |
|------------|---------------|
| Created → Active | Sou or OSYS |
| Active → Inactive | Sou, OSYS, or Self (graceful shutdown) |
| Inactive → Active | Sou or OSYS |
| Active → Frozen | Security Council only |
| Frozen → Inactive | Security Council only (investigation complete) |
| Any → Retired | Sou, OSYS, or Automatic (tenure expiry) |
| Retired → Archived | OSYS (automatic after retention period) |

### Tenure Enforcement (Law 10)
Every agent has a maximum tenure defined in its TenurePolicy. The system tracks time since agent creation and issues tenure warnings at configurable intervals before expiry. On tenure expiry, the configured action is executed (retire, freeze, or notify-only). Tenure extensions are limited and must be authorized by Sou.

### Termination Reasons
- **Natural**: Agent completed its mission and requested retirement.
- **Policy**: Agent violated policy or exceeded tenure (Law 10 enforcement).
- **Failure**: Agent unrecoverable failure (systemic errors, evidence corruption).
- **Manual**: Manual retirement by Sou or Security Council.

### Frozen State for Investigation
The FROZEN state halts all agent operations except evidence access. It is used when a security incident or policy violation requires investigation. Only the Security Council can freeze and unfreeze agents. Frozen agents cannot be retired until the investigation is complete.

### Retention Period After Retirement
After retirement, the agent enters a retention period defined in the TenurePolicy or system-wide default. During retention, the agent's evidence and genome history are preserved for audit and compliance. After retention expires, the agent transitions to ARCHIVED and only metadata (no evidence) is retained.

### Evidence Sealing on Termination
When an agent is terminated (retired), all evidence records are sealed. Sealed evidence is immutable and preserved for the retention period. The evidenceRef in the TerminationRecord points to the sealed evidence bundle. Sealing ensures that termination cannot destroy audit trails.

## Internal Interfaces

```typescript
interface LifecycleManager {
  getCurrentState(agentId: string): Promise<AgentLifecycleState>;
  transitionState(agentId: string, targetState: AgentLifecycleState, reason: string): Promise<LifecycleTransition>;
  freezeAgent(agentId: string, reason: string, authorizedBy: string): Promise<LifecycleTransition>;
  unfreezeAgent(agentId: string, reason: string, authorizedBy: string): Promise<LifecycleTransition>;
  retireAgent(agentId: string, reason: TerminationReason): Promise<TerminationRecord>;
  archiveAgent(agentId: string): Promise<void>;
}

interface TenureEnforcer {
  getTenurePolicy(agentId: string): Promise<TenurePolicy>;
  checkTenure(agentId: string): Promise<TenureStatus>;
  issueWarning(agentId: string): Promise<void>;
  enforceExpiry(agentId: string): Promise<TerminationRecord>;
  requestExtension(agentId: string, requestedBy: string): Promise<boolean>;
}

interface EvidenceSealer {
  sealEvidence(agentId: string, reason: string): Promise<string>;
  verifySeal(evidenceRef: string): Promise<boolean>;
  getRetentionPeriod(agentId: string): Promise<Duration>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| AGX.Lifecycle.AgentActivated | agentId, previousState, activatedAt | Agent transitioned to ACTIVE state |
| AGX.Lifecycle.AgentDeactivated | agentId, previousState, reason | Agent transitioned to INACTIVE state |
| AGX.Lifecycle.AgentFrozen | agentId, reason, authorizedBy | Agent frozen for investigation |
| AGX.Lifecycle.AgentRetired | agentId, reason, terminationId | Agent permanently retired |
| AGX.Lifecycle.AgentArchived | agentId, retentionPeriod, archivedAt | Agent evidence archived after retention |
| AGX.Lifecycle.TenureWarning | agentId, daysRemaining, policyId | Tenure warning issued |
| AGX.Lifecycle.TenureExpired | agentId, policyId, action | Tenure expired and action executed |
| AGX.Lifecycle.TerminationInitiated | agentId, reason, initiatedBy | Termination process started |
| AGX.Lifecycle.TerminationCompleted | agentId, terminationId, finalState | Termination process completed |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Invalid state transition requested | AGX_LCY_001 | Reject transition; report valid target states from current state |
| Unauthorized transition attempt | AGX_LCY_002 | Reject transition; log security event; notify Security Council |
| Agent frozen and cannot be retired before investigation complete | AGX_LCY_003 | Reject retirement; require unfreeze first |
| Tenure extension limit exceeded | AGX_LCY_004 | Reject extension; agent must be retired |
| Evidence sealing failed during termination | AGX_LCY_005 | Halt termination; roll back state; escalate to OSYS |
| Retention period not yet elapsed for archive | AGX_LCY_006 | Reject archive; report remaining retention duration |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AGX-LCY-001 | State transitions follow the defined state machine — no invalid transitions | Algorithmic — transition table is the authoritative map |
| AGX-LCY-002 | RETIRED is a terminal state — no transition out of RETIRED is permitted | Architectural — state machine has no outgoing edges from RETIRED |
| AGX-LCY-003 | Only the Security Council can freeze or unfreeze an agent | Algorithmic — authorization check enforced on every freeze/unfreeze |
| AGX-LCY-004 | No agent may exceed its tenure without explicit extension authorization | Algorithmic — TenureEnforcer blocks operations past expiry |
| AGX-LCY-005 | Every termination produces a sealed evidence record | Architectural — termination fails if evidence sealing fails |
| AGX-LCY-006 | Archived agents have no runtime — only metadata and evidence references persist | Architectural — runtime is deallocated on archive |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Lifecycle Manager owns agent instance states exclusively; AGX evolution lifecycle owns capability maturity; no overlap |
| R2 — Dependency Order | Lifecycle depends on EVS (evidence), IDS (authorization), OSYS (system operations); no circular dependencies |
| R3 — DRY | State machine is defined once in the transition table; all transitions are validated against it |
| R4 — Builder Pattern | TerminationRecord uses builder construction for evidence sealing and retention configuration |
| R9 — Deterministic | Given the same current state and transition request, the outcome is always deterministic |
| R10 — Simpler Over Complex | Six states with clearly defined transitions are simpler than a generic workflow engine |
| R13 — Design for Failure | Failed evidence sealing halts termination and preserves prior state; frozen state isolates without data loss |
| R14 — Paved Path | Standard path is CREATED → ACTIVE → RETIRED → ARCHIVED; Frozen and Inactive are exceptional paths |
| R15 — Open/Closed | New states can be added to the transition table without modifying existing transition logic |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/02-Core/Agents/000-Overview.md | AGX overview — Lifecycle is a sub-component of AGX |
| Bible/02-Core/Agents/001-Factory.md | Factory assigns the initial CREATED state; Lifecycle manages all subsequent transitions |
| Bible/02-Core/Agents/002-Templates.md | Templates may define default tenure policies |
| Bible/02-Core/Agents/003-Configuration.md | Configuration changes may trigger lifecycle transitions (restart-required) |
| Bible/02-Core/IDS/000-Overview.md | IDS provides authorization identity for transition requests |
| Bible/02-Core/SSM/000-Overview.md | SSM provides secrets for evidence sealing keys |
| Bible/05-Platform/004-EVS.md | EVS stores and seals evidence on termination |
| Bible/03-Institutions/ROS/000-Overview.md | ROS may trigger lifecycle transitions based on runtime health |
| Bible/03-Institutions/Works/000-Overview.md | Works manages agent work assignments during ACTIVE state |
| Bible/00-Foundations/008-Object-Lifecycle.md | Object Lifecycle is the foundational pattern for agent lifecycle states |
| Bible/04-Execution/Security/000-Overview.md | Security Council authorizes freeze/unfreeze transitions |
| Physics/007-Capabilities.md | Capability bounds limit transitions that require capability validation |
| Physics/006-Lifecycles.md | Lifecycle state machine invariants and transition rules |
