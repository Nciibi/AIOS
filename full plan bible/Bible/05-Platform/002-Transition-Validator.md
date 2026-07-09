# AIOS Bible — Platform
## 002 — Transition Validator

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Platform |
| Document ID | AIOS-BBL-005-TV-000 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 8 — Law of Verification-First |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Rules engine for valid state transitions. The Transition Validator defines and enforces the validation rules that LMS uses to determine whether a transition is allowed. Every transition rule specifies authorization requirements, preconditions, postconditions, evidence requirements, and resource implications. The Transition Validator is the constitutional authority for transition rule definitions.

## Rule Structure

Every transition rule has the following structure:

```
TransitionRule {
  rule_id: string,
  from_state: string,
  to_state: string,
  authorized_entity_types: string[],
  preconditions: Condition[],
  postconditions: Condition[],
  evidence_required: EvidenceSpec[],
  resource_action: ResourceAction
}
```

### Rule Components

| Component | Description |
|-----------|-------------|
| **rule_id** | Unique identifier for the rule |
| **from_state** | The source state for this transition |
| **to_state** | The target state for this transition |
| **authorized_entity_types** | Entity types that may authorize this transition |
| **preconditions** | Conditions that must be true before transition |
| **postconditions** | Conditions that must be true after transition |
| **evidence_required** | Events that must be produced |
| **resource_action** | Budget freeze, release, or allocation |

## Transition Operations

```
defineRule(rule) → rule_id
updateRule(rule_id, updates) → rule
validateTransition(entity_id, to_state) → ValidationResult
getRulesForTransition(from, to) → TransitionRule[]
listRules() → TransitionRule[]
deleteRule(rule_id) → void
```

### Validation Flow

```
1. Receive transition request (entity_id, target_state, authorized_by)
2. Look up current state of entity
3. Find matching rule(s) for (current_state → target_state)
4. Verify authorized_by entity type matches rule.authorized_entity_types
5. Evaluate all preconditions:
   a. State preconditions — entity is in required state
   b. Resource preconditions — resources available
   c. Dependency preconditions — dependencies resolved
6. Validate evidence requirements — required Events exist
7. Return: { valid: bool, rule_applied: rule_id, reason: string, evidence: Event[] }
```

## Precondition and Postcondition Types

### Preconditions

| Type | Description | Example |
|------|-------------|---------|
| **StateCondition** | Entity must be in a specific state | `current == "Waiting"` |
| **ResourceCondition** | Resources must be available | `budget.tokens > 0` |
| **DependencyCondition** | Dependencies must be resolved | `parent.state == "Running"` |
| **TimeCondition** | Time-based constraint | `elapsed > 5min` |
| **EvidenceCondition** | Required evidence must exist | `event.type == "DependencyResolved"` |

### Postconditions

| Type | Description | Example |
|------|-------------|---------|
| **StateAssertion** | Entity must end in specific state | `next == "Running"` |
| **ResourceAssertion** | Resources must be allocated/released | `budget.frozen == true` |
| **EvidenceAssertion** | Required Events must be produced | `event.type == "StateChanged"` |

## Resource Actions

| Action | Effect | Used For |
|--------|--------|----------|
| **freeze** | Freeze resources for blocked/paused state | Running → Paused |
| **release** | Release resources to pool | Completed → Archived |
| **allocate** | Allocate resources for target state | Planned → Assigned |
| **hold** | Reserve resources without allowing draw | Running → Waiting |
| **noop** | No resource change | State changes that don't affect budget |

## Authorization Matrix

The Transition Validator maintains the canonical transition authorization matrix from Foundations/008-Object-Lifecycle.md:

| Transition | Authorized By | Auth Level |
|-----------|--------------|------------|
| Created → Planned | Creator entity | L2 |
| Planned → Assigned | Resource orchestrator | L3 |
| Assigned → Running | LMS (automatic) | L1 |
| Running → Waiting | Entity itself | L2 |
| Running → Paused | Supervisor or Security Council | L3 |
| Running → Blocked | Entity itself | L2 |
| Running → Review | Entity or policy trigger | L2 |
| Waiting → Running | LMS (automatic) | L1 |
| Paused → Running | Supervisor | L3 |
| Blocked → Running | Resolution by entity/supervisor | L3 |
| Blocked → Review | Entity or supervisor | L2 |
| Review → Running | Reviewer | L3 |
| Review → Completed | Reviewer | L3 |
| Completed → Archived | LMS (automatic) | L1 |

## Validation Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `TV.RuleDefined` | A new transition rule is created | rule_id, from_state, to_state, authorized_types |
| `TV.RuleUpdated` | An existing rule is modified | rule_id, changes, updated_by |
| `TV.RuleDeleted` | A rule is removed | rule_id, removed_by |
| `TV.ValidationPassed` | A transition passes validation | entity_id, from_state, to_state, rule_id, authorized_by |
| `TV.ValidationFailed` | A transition fails validation | entity_id, from_state, attempted_to, rule_id, reason, precondition_failed |

## Cross-Cutting Concerns

### Security

Transition rule definitions are protected. Only the Security Council may define or modify rules. Unauthorized rule changes are constitutional violations. Every rule change produces an auditable Event.

### Evidence

Every validation attempt produces a ValidationPassed or ValidationFailed Event. Validation Events include the rule applied and the authorization entity. Rule changes produce RuleDefined/RuleUpdated Events.

### Lifecycle

Transition rules themselves follow a lifecycle: Draft → Active → Suspended → Retired. Rules in Suspended state are not evaluated. Rules in Retired state are preserved for audit but never applied.

### Capability Bounds

The Transition Validator only evaluates rules. It does not execute transitions — that is LMS's responsibility. It does not store entity state — that is LMS's responsibility. It is a pure rules evaluation engine.

### Communication

The Transition Validator communicates through ACF. LMS sends validation requests via ACF. Validation results are returned via ACF response messages. All rule changes are published to ACF streams.

### Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Validator does one thing: validate transitions |
| R2 — Dependency Order | Validator depends on ACF; no upward dependencies |
| R3 — DRY | Transition rules are defined once per (from, to) pair |
| R4 — Builder Pattern | Rule objects are built by RuleBuilders with validation |
| R5 — Liskov | All rules implement the same TransitionRule interface |
| R6 — DI over Singletons | Validator receives ACF and Event Store as dependencies |
| R7 — Tests Exist | Every rule type has unit tests |
| R8 — Tests Fast | Rule evaluation completes in <1ms |
| R9 — Deterministic | Same inputs always produce same validation result |
| R10 — Simpler Over Complex | Rules are explicit condition lists; no complex inference |
| R11 — Refactor Over Rewrite | Rules evolve via versioned updates |
| R12 — Embrace Errors | Every validation failure has a unique error code |
| R13 — Design for Failure | Validator fails closed — unavailable = deny |
| R14 — Paved Path | Transition Validator is the only path for rule evaluation |
| R15 — Open/Closed | New rule types extend without modifying core |

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-LMS.md | LMS enforces the rules defined here |
| 001-State-Machine.md | State machine guards integrate with validation rules |
| Foundations/008-Object-Lifecycle.md | Source transition authorization matrix |
| Physics/006-Lifecycles.md | Lifecycle invariants — transitions must be authorized |
| Physics/008-Security.md | Authorization model for transition rules |
