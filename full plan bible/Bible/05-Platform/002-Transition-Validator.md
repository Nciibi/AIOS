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

| Component | Type | Description |
|-----------|------|-------------|
| rule_id | string | Unique identifier, format: `TV-{from}-{to}-{seq}` |
| from_state | string | Source state |
| to_state | string | Target state |
| authorized_entity_types | string[] | Entity types that may authorize (e.g., `["session", "org_supervisor", "security_council"]`) |
| preconditions | Condition[] | Conditions evaluated before transition |
| postconditions | Condition[] | Conditions verified after transition |
| evidence_required | EvidenceSpec[] | Events that must be produced |
| resource_action | ResourceAction | Budget freeze/release/allocate/hold/noop |

### Condition Structure

```
Condition {
  type: string,          // state, resource, dependency, time, evidence
  operator: string,      // eq, neq, gt, gte, lt, lte, exists, not_exists
  field: string,         // path to the value to check
  value: any,            // expected value
  description: string    // human-readable condition description
}
```

## Validation Flow

```
1. Receive transition request (entity_id, target_state, authorized_by)
2. Look up current state of entity via LMS
3. Find matching rule(s) for (current_state → target_state)
4. If no rule found, return InvalidTransition
5. If multiple rules, apply most specific rule (by entity type)
6. Verify authorized_by entity type matches rule.authorized_entity_types
7. Evaluate all preconditions:
   a. StateCondition — entity is in required state
   b. ResourceCondition — resources available
   c. DependencyCondition — dependencies resolved
   d. TimeCondition — time constraints met
   e. EvidenceCondition — required Events exist
8. Validate evidence requirements — required Events are present
9. Determine resource action (freeze, release, allocate, hold, noop)
10. Return ValidationResult
```

### ValidationResult

```
ValidationResult {
  valid: bool,
  rule_applied: string,           // rule_id that matched
  reason: string,                 // why valid or invalid
  failed_precondition: string?,   // first precondition that failed
  authorized_types: string[],     // who may authorize this
  resource_action: ResourceAction,
  evidence_required: EvidenceSpec[],
  evaluation_chain: EvaluationStep[]  // full evaluation trace
}

EvaluationStep {
  check: string,
  result: bool,
  details: string
}
```

## Rule Operations

```
defineRule(rule) → rule_id
updateRule(rule_id, updates) → rule
deleteRule(rule_id) → void
validateTransition(entity_id, to_state, authorized_by) → ValidationResult
getRulesForTransition(from, to) → TransitionRule[]
getRulesForState(state) → TransitionRule[]
listRules(filter?) → TransitionRule[]
testRule(rule_id, test_case) → TestResult
```

### defineRule

| Parameter | Description |
|-----------|-------------|
| rule | TransitionRule object |
| Validation | Rule must not duplicate existing (from, to) pair |
| Returns | rule_id |

Rules are immutable once created. To change a rule, create a new version or delete and recreate.

## Precondition and Postcondition Types

### Preconditions

| Type | Operator Examples | Description |
|------|------------------|-------------|
| StateCondition | eq, neq | Entity must be in a specific state |
| ResourceCondition | gte, lte | Resource availability check |
| DependencyCondition | exists, not_exists | Dependencies resolved |
| TimeCondition | gte, lte | Time-based constraint |
| EvidenceCondition | exists | Required evidence must exist |
| EntityCondition | eq | Entity attribute check |
| ParentCondition | eq, neq | Parent entity state check |

### Postconditions

| Type | Description |
|------|-------------|
| StateAssertion | Entity confirmed in target state |
| ResourceAssertion | Resource action completed |
| EvidenceAssertion | Required Events were produced |
| CascadeAssertion | Child transitions completed |

## Resource Actions

| Action | Effect on Budget | Transition Example |
|--------|-----------------|-------------------|
| **freeze** | Budget locked, not drawable | Running → Paused |
| **release** | Budget returned to pool | Completed → Archived |
| **allocate** | Budget assigned to entity | Planned → Assigned |
| **hold** | Budget reserved, not drawable | Running → Waiting |
| **noop** | No change | Review → Running |

## Authorization Matrix

The Transition Validator maintains the canonical transition authorization matrix from Foundations/008-Object-Lifecycle.md:

| Transition | Authorized By | Auth Level | Preconditions | Postconditions |
|-----------|--------------|------------|---------------|----------------|
| Created → Planned | Creator entity | L2 | Entity exists | Plan defined |
| Planned → Assigned | ROS | L3 | Resources available | Resources allocated |
| Assigned → Running | LMS (auto) | L1 | Ready check passed | Entity active |
| Running → Waiting | Entity itself | L2 | Dependency needed | Dependency logged |
| Running → Paused | Supervisor | L3 | Supervisor authorized | Resources frozen |
| Running → Blocked | Entity itself | L2 | Error detected | Error logged |
| Running → Review | Entity or policy | L2 | Review trigger | Review scheduled |
| Waiting → Running | LMS (auto) | L1 | Dependency resolved | Resource unfrozen |
| Paused → Running | Supervisor | L3 | Supervisor approves | Resource unfrozen |
| Blocked → Running | Resolver | L3 | Blocker resolved | Resolution logged |
| Blocked → Review | Entity/supervisor | L2 | Human assessment | Assessment created |
| Review → Running | Reviewer | L3 | Rework needed | Rework assigned |
| Review → Completed | Reviewer | L3 | Approved | Approval logged |
| Completed → Archived | LMS (auto) | L1 | Retention period met | Archive record created |

## Rule Lifecycle

```
Draft → Active → Suspended → Retired
```

| State | Description |
|-------|-------------|
| **Draft** | Rule defined, not enforced |
| **Active** | Rule is enforced by LMS |
| **Suspended** | Rule temporarily not enforced (audited override) |
| **Retired** | Rule permanently removed, kept for audit |

## Error Codes

| Code | Condition | Description |
|------|-----------|-------------|
| TV-001 | RuleNotFound | No rule for the specified (from, to) pair |
| TV-002 | DuplicateRule | A rule for this (from, to) pair already exists |
| TV-003 | InvalidCondition | Condition syntax or type is invalid |
| TV-004 | UnauthorizedEntityType | Entity type not in authorized list |
| TV-005 | PreconditionFailed | A precondition evaluated to false |
| TV-006 | EvidenceMissing | Required evidence Event not found |
| TV-007 | RuleSuspended | The matching rule is in Suspended state |
| TV-008 | CircularDependency | Rule creates circular dependency |

## Transition Validator Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `TV.RuleDefined` | A new transition rule is created | rule_id, from_state, to_state, authorized_types, precondition_count |
| `TV.RuleUpdated` | An existing rule is modified | rule_id, changes, updated_by, reason |
| `TV.RuleDeleted` | A rule is removed | rule_id, removed_by, reason |
| `TV.RuleSuspended` | A rule is suspended | rule_id, suspended_by, reason, duration |
| `TV.RuleReactivated` | A suspended rule is reactivated | rule_id, reactivated_by |
| `TV.ValidationPassed` | A transition passes validation | entity_id, from_state, to_state, rule_id, authorized_by, evaluation_time_ms |
| `TV.ValidationFailed` | A transition fails validation | entity_id, from_state, attempted_to, rule_id, failed_precondition, reason |

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| max_preconditions | 20 | Maximum preconditions per rule |
| max_postconditions | 10 | Maximum postconditions per rule |
| rule_cache_ttl_s | 300 | Rule cache time-to-live in seconds |
| evaluation_timeout_ms | 1000 | Max time for rule evaluation |

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
