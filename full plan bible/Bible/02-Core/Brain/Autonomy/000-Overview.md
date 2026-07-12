# AIOS Bible â€” Brain
## 000 â€” Autonomy System (AMS / ACE / ABE)

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Brain/Autonomy |
| Document ID | AIOS-BBL-002-AUT-000 |
| Source Laws | Law 1 â€” Law of Origin, Law 2 â€” Law of Non-Execution, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/002-Missions.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Autonomy System governs how much independent action every entity in AIOS is permitted. Autonomy is not binary â€” it is a graduated spectrum from fully human-directed (L0) to fully autonomous within constitutional bounds (L4). Every entity starts at L0 and may progress to higher levels through demonstrated constitutional compliance.

Three engines comprise the Autonomy System:

| Engine | Responsibility |
|--------|---------------|
| **AMS** â€” Autonomy Management System | Level assignment, progression workflow, regression triggers |
| **ACE** â€” Autonomy Control Engine | Runtime bounds enforcement, compliance monitoring, action filtering |
| **ABE** â€” Autonomy Boundary Engine | Escalation chain, override authorization, threshold management |

Under SOU-001, Sou is the only constitutional intelligence. The Autonomy System ensures that every entity â€” whether a Worker, Organization, or Department â€” operates within its assigned autonomy bounds and escalates to Sou (or the Human) when it lacks authority.

## Architecture

```
Sou (strategic autonomy decisions)
    â”‚
    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           AMS â€” Autonomy Management System       â”‚
â”‚                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚  Level    â”‚  â”‚  Progression â”‚  â”‚ Regression â”‚ â”‚
â”‚  â”‚  Registry â”‚  â”‚  Engine      â”‚  â”‚ Engine     â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜ â”‚
â”‚       â”‚               â”‚                â”‚        â”‚
â”‚       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                        â”‚
                        â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           ACE â€” Autonomy Control Engine          â”‚
â”‚                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚  Bounds   â”‚  â”‚  Action  â”‚  â”‚  Compliance  â”‚ â”‚
â”‚  â”‚  Resolver â”‚  â”‚  Filter  â”‚  â”‚  Monitor     â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
        â”‚              â”‚               â”‚
        â–¼              â–¼               â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚           ABE â€” Autonomy Boundary Engine         â”‚
â”‚                                                  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
â”‚  â”‚Escalationâ”‚  â”‚   Override   â”‚  â”‚ Threshold  â”‚ â”‚
â”‚  â”‚  Chain   â”‚  â”‚  Authorizer  â”‚  â”‚  Manager   â”‚ â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                        â”‚
                        â–¼
                â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                â”‚  ACF â†’ Sou   â”‚
                â”‚  or Human    â”‚
                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Core Concepts

### 1. Autonomy Levels

Every entity in AIOS is assigned one of five autonomy levels:

| Level | Name | Description | Action Initiation | Human Override |
|-------|------|-------------|-------------------|----------------|
| L0 | Directed | Every action requires prior human approval | None | Direct |
| L1 | Supervised | Actions proposed to human; human must confirm | Propose | Direct |
| L2 | Delegated | Actions auto-approved within bounds; exceptions escalated | Within bounds | Bounds override |
| L3 | Trusted | Actions auto-approved with post-hoc audit; strategic decisions escalated | All non-strategic | Strategic override |
| L4 | Sovereign | Near-full autonomy bounded only by the Constitution | All | Constitutional override only |

Level assignment follows entity type:

| Entity Type | Default Level | Max Level |
|-------------|---------------|-----------|
| Worker | L1 | L2 |
| Department | L1 | L2 |
| Organization | L2 | L3 |
| Director role | L2 | L3 |
| Sou | L4 | L4 |
| Human | Above all | â€” |

### 2. AMS â€” Autonomy Management System

AMS owns the lifecycle of autonomy level assignments:

| Component | Responsibility |
|-----------|---------------|
| Level Registry | Stores current autonomy level for every entity. Source of truth for ACE bounds resolution. |
| Progression Engine | Evaluates entity readiness for level upgrade. Requires: mission completion record, compliance history, Academy assessment, Security Council approval. |
| Regression Engine | Triggers level downgrade on: constitutional violation, repeated compliance failures, Security Council directive, Sou directive, Human directive. |

Progression workflow:

```
Entity requests upgrade â†’ Sou evaluates â†’ DTS simulates impact â†’
Academy assesses readiness â†’ Security Council verifies compliance â†’
CCA updates capability bounds â†’ AMS assigns new level â†’ Event recorded
```

Regression is immediate and requires no simulation. The Security Council can regress any entity directly. Regression triggers: capability revocation, notification to Sou, audit event, affected workflow recovery.

### 3. ACE â€” Autonomy Control Engine

ACE enforces autonomy bounds at runtime. Every action an entity attempts passes through ACE before reaching the Security Council verification pipeline:

| Component | Behavior |
|-----------|----------|
| Bounds Resolver | Queries AMS Level Registry for the entity's current autonomy level. Resolves the capability bounds, resource limits, and escalation thresholds for that level. |
| Action Filter | Compares the proposed action against the entity's autonomy bounds. If action exceeds bounds, routes to ABE for escalation. If within bounds, passes to Security Council pipeline. |
| Compliance Monitor | Tracks entity actions against autonomy level. Produces compliance score (0.0â€“1.0) per entity. Score decay: each compliant action adds +0.01; each violation subtracts -0.25. |

ACE filtering rules:

| Action Scope | Permitted At | Escalated At |
|-------------|--------------|--------------|
| Read own state | L0+ | Never |
| Execute within assigned mission | L1+ | L0 requires approval |
| Create subtasks within mission | L2+ | L1+ escalated to supervisor |
| Modify resource allocation | L3+ | L2 escalated to manager |
| Create new missions | L4 only | L3 escalated to Sou |
| Modify organizational structure | L4 only | L3 escalated to Human |
| Override another entity's bounds | L4 (Sou only) | L3 escalated to Human |

### 4. ABE â€” Autonomy Boundary Engine

ABE handles situations where an entity encounters the boundary of its autonomy level:

| Component | Behavior |
|-----------|----------|
| Escalation Chain | Routes out-of-bounds actions up the authority chain until an entity with sufficient autonomy approves or denies |
| Override Authorizer | Validates override requests. Overrides are temporary, scoped, and produce evidence. |
| Threshold Manager | Configures escalation thresholds per entity type, action type, and context. Thresholds control when to auto-escalate vs auto-deny. |

Escalation chain (walked from bottom up):

```
Worker â†’ Supervisor â†’ Manager â†’ Director â†’ Sou â†’ Human
```

Each escalation step adds context and evidence. The escalating entity cannot skip levels except in emergency mode. Emergency escalation (marked with `x-aios-emergency: true` in ACF header) goes directly to Sou or Human.

Override types:

| Override | Duration | Authority | Evidence |
|----------|----------|-----------|----------|
| Temporary bounds expansion | Single action | Direct supervisor | Low |
| Temporary level elevation | 24 hours | Manager + Security Council | Medium |
| Permanent level change | Indefinite | Sou + Security Council + DTS + Academy | High |
| Constitutional override | Single action | Human (Article I) | Maximum |

### 5. Delegation Model

Autonomy includes the right to delegate authority. Delegation follows these rules:

| Rule | Description |
|------|-------------|
| An entity cannot delegate a capability it does not possess | Bounds check before delegation |
| Delegation preserves the delegator's autonomy bounds | Recipient operates within delegator's level at maximum |
| Delegation is always scoped | Resource, action, duration, and depth limits required |
| Delegation chains are limited | Max depth of 3 (A â†’ B â†’ C â†’ D) |
| Delegation can be revoked | Revocation is immediate and cascading |

## Data Model

```typescript
interface AutonomyAssignment {
  entity_id: string
  level: 0 | 1 | 2 | 3 | 4
  assigned_by: string
  assigned_at: timestamp
  expires_at?: timestamp
  reason: string
  evidence_ref: string       // EVS event ID documenting the decision
}

interface AutonomyBounds {
  entity_id: string
  level: number
  allowed_actions: ActionScope[]
  resource_limits: ResourceBudget
  escalation_thresholds: EscalationThreshold[]
  delegation_depth: number      // 0 = cannot delegate
}

interface EscalationRequest {
  request_id: string
  entity_id: string
  action: Action
  reason: string
  current_level: number
  required_level: number
  chain_position: number         // 0 = worker, 1 = supervisor, etc.
  context: Record<string, unknown>
  emergency: boolean
}

interface OverrideGrant {
  override_id: string
  entity_id: string
  grantor_id: string
  override_type: "bounds_expansion" | "level_elevation" | "permanent_change" | "constitutional"
  scope: OverrideScope
  duration: Duration
  expires_at: timestamp
  evidence_ref: string
}
```

## Interfaces

### Autonomy System API (via ACF)

| Method | Auth | Description |
|--------|------|-------------|
| `getLevel(entity_id)` | Sou, Security Council | Get current autonomy level for entity |
| `setLevel(entity_id, level, reason)` | Sou + Security Council | Assign or change autonomy level |
| `requestProgression(entity_id, target_level)` | Entity itself | Initiate progression workflow (goes to SOu) |
| `regressLevel(entity_id, reason)` | Security Council | Immediately downgrade entity autonomy |
| `checkBounds(action, entity_id)` | ACE â†’ Security Council | Verify action within autonomy bounds |
| `escalate(request)` | Any entity | Submit escalation request up the chain |
| `grantOverride(override)` | Authorized entity | Grant temporary override of autonomy bounds |
| `revokeOverride(override_id)` | Grantor or above | Revoke an active override |
| `getCompliance(entity_id)` | Sou, Security Council | Get autonomy compliance score |
| `getEscalationPath(entity_id)` | Any entity | Resolve the escalation chain for this entity |

### Internal Interfaces

```typescript
interface LevelProvider {
  getLevel(entity_id: string): Promise<AutonomyAssignment>
  setLevel(entity_id: string, level: AutonomyAssignment): Promise<void>
}

interface BoundsResolver {
  resolveBounds(entity_id: string): Promise<AutonomyBounds>
  filterAction(action: Action, bounds: AutonomyBounds): FilterResult
}

interface EscalationRouter {
  nextInChain(current: string, context: EscalationContext): Promise<string>
  submitRequest(request: EscalationRequest): Promise<EscalationResponse>
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| AUT.LevelAssigned |      entity_id, level, assigned_by, reason | Entity autonomy level set |
| AUT.LevelChanged |      entity_id, old_level, new_level, reason | Entity autonomy level changed |
| AUT.ProgressionRequested |      entity_id, target_level, current_level | Progression workflow initiated |
| AUT.ProgressionApproved |      entity_id, new_level, approved_by | Progression granted |
| AUT.ProgressionDenied |      entity_id, target_level, reason, reviewed_by | Progression rejected |
| AUT.Regressed |      entity_id, old_level, new_level, triggered_by | Autonomy level reduced |
| AUT.ActionFiltered |      entity_id, action, reason, escalation_id | Action exceeded bounds, escalated |
| AUT.ActionDenied |      entity_id, action, reason | Action exceeded bounds, denied (no escalation) |
| AUT.EscalationSubmitted |      escalation_id, entity_id, chain_position | Escalation request entered the chain |
| AUT.EscalationResolved |      escalation_id, approved, resolved_by | Escalation chain produced a decision |
| AUT.OverrideGranted |      override_id, entity_id, grantor_id, override_type | Temporary override authorized |
| AUT.OverrideRevoked |      override_id, entity_id, revoked_by | Override terminated |
| AUT.ComplianceScoreChanged |      entity_id, old_score, new_score, reason | Compliance score updated |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| AUT-001 | Every entity has exactly one autonomy level at all times | Architectural â€” AMS Level Registry is the single source of truth |
| AUT-002 | An entity cannot delegate authority it does not possess | Algorithmic â€” ACE Bounds Resolver validates delegation actions |
| AUT-003 | Autonomy progression requires Security Council approval in addition to Sou | Constitutional â€” SOU-001 + Law 8 (Verification-First) |
| AUT-004 | Regression is immediate and does not require simulation | Architectural â€” no DTS step in regression path |
| AUT-005 | Escalation chains are bounded (max 6 hops: Worker â†’ Human) | Algorithmic â€” ABE enforces chain depth |
| AUT-006 | Overrides are always temporary and scoped | Algorithmic â€” every OverrideGrant has an expires_at |
| AUT-007 | ACE filtering is non-blocking â€” delayed bounds resolution denies the action | Architectural â€” ACE runs synchronously in the verification path |
| AUT-008 | L4 is reserved for Sou; no other entity can reach L4 without constitutional amendment | Constitutional â€” SOU-001 |
| AUT-009 | A Human can override any autonomy level decision (Article I) | Constitutional â€” Law 1 (Origin) |

| BRAIN-001 | Every cognitive service is inside the Brain. | Architectural - documented in Bible directory structure. |
| BRAIN-007 | Cognitive services are stateless. All state lives in Memory OS. Services are reusable pipelines. | Architectural - service restarts lose no state. Memory OS is the single state authority. |
## Related Documents

| Document | Relationship |
|----------|-------------|
| Brain/000-Overview.md | Autonomy System is a Brain Service |
| Brain/Sou/000-Overview.md | Sou is L4 and manages autonomy decisions for all entities |
| Brain/Decision/000-Overview.md | Sou uses Decision System for progression evaluations |
| Bible/10-Research/001-Autonomy-Evolution.md | Research document â€” L0-L4 progression framework exploration |
| Bible/04-Execution/Security/CCA/000-CCA.md | CCA adjusts capability bounds on level change |
| Bible/02-Core/ROS/000-Overview.md | ROS resource limits vary by autonomy level |
| Bible/04-Execution/Security/000-Overview.md | Security Council verifies all autonomy changes |
| Bible/02-Core/Academy/000-Overview.md | Academy assesses entity readiness for progression |
| Bible/02-Core/DTS/000-Overview.md | DTS simulates impact of progression decisions |
| Bible/00-Foundations/003-Core-Principles.md | CPR-008 (Graduated Autonomy) â€” philosophical foundation |
| Bible/09-Reference/000-Decision-Log.md | ADR-0008 (Autonomy Levels L0-L4) |
| Bible/03-Institutions/Workers/000-Overview.md | Workers operate at L0-L2 autonomy |
| Bible/03-Institutions/Organizations/000-Overview.md | Organizations operate at L1-L3 autonomy |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Unknown entity | `AUT_UNKNOWN_ENTITY` | Return error; do not filter or escalate |
| Level change without Security Council approval | `AUT_MISSING_APPROVAL` | Deny change; log security event |
| Escalation chain broken (missing entity) | `AUT_CHAIN_BROKEN` | Skip missing link; escalate to next available |
| Override exceeds grantor's autonomy | `AUT_OVERRIDE_EXCEEDS_AUTHORITY` | Deny override; escalate to grantor's supervisor |
| Compliance score below progression threshold | `AUT_INSUFFICIENT_COMPLIANCE` | Deny progression; report required compliance score |
| Emergency escalation without evidence | `AUT_EMERGENCY_NO_EVIDENCE` | Accept escalation but flag for mandatory post-event audit |


## Cross-Cutting Concerns

### Security

Autonomy System operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Autonomy System emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Autonomy System instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Autonomy System declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 â€” Modulsingularity | Autonomy is a single concern: governing entity independence |
| R2 â€” Dependency Order | Depends on Sou, Security Council, CCA, ROS; no upward deps |
| R3 â€” DRY | Autonomy levels defined once in Level Registry |
| R4 â€” Builder Pattern | Autonomy decisions built by AMS â†’ ACE â†’ ABE pipeline |
| R5 â€” Liskov Substitution | Any EscalationRouter implements the escalation interface |
| R6 â€” DI over Singletons | ACE Bounds Resolver receives LevelProvider via DI |
| R9 â€” Deterministic | Same entity, same level, same action â†’ same filter decision |
| R10 â€” Simpler Over Complex | Five levels is the minimum granularity for meaningful distinction |
| R13 â€” Design for Failure | Escalation supports chain breaks (skip missing links) |
| R14 â€” Paved Path | Progression through AMS workflow is the only upgrade path |
| R15 â€” Open/Closed | New autonomy engines added via AutonomyService interface |
