# AIOS Bible — Authorization (AZS)
## 001 — Attribute-Based Access Control

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Authorization |
| Document ID | AIOS-BBL-AZS-001 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Attribute-Based Access Control (ABAC) extends the authorization model beyond static role membership by evaluating contextual attributes at authorization time. While RBAC (000-RBAC.md) answers "does the entity's role grant this permission?", ABAC answers "given the current context, should this permission be exercised?". ABAC is the second layer of the authorization stack, invoked after RBAC has identified a matching permission but before final authorization is granted.

ABAC evaluates attributes from four categories: subject attributes (entity identity, clearance level, department), resource attributes (sensitivity classification, data category, owner), action attributes (operation type, intensity, risk level), and environment attributes (time of day, system load, threat level, regulatory zone). A policy is a Boolean expression over these attributes. Only when all applicable policies evaluate to true does ABAC allow the action to proceed.

ABAC operates as a policy overlay on RBAC. A user may have the RBAC role `org.admin` which grants `write` on all org resources, but ABAC policies may restrict write access to resources classified below `confidential` when accessed outside business hours. Neither RBAC alone nor ABAC alone is sufficient — the combined result is the authorization decision.

## Attribute Model

### Subject Attributes

| Attribute | Source | Type | Example |
|-----------|--------|------|---------|
| `subject.id` | IDS | string | `aios:worker:prod:abc123` |
| `subject.type` | IDS | enum | `worker`, `session`, `engine`, `organization` |
| `subject.clearance` | IDS | enum | `unclassified`, `confidential`, `secret`, `top_secret` |
| `subject.org` | IDS | string | `org:engineering` |
| `subject.dept` | IDS | string | `dept:security` |
| `subject.roles` | AZS | string[] | `["org.admin", "auditor"]` |
| `subject.autonomy_level` | CCA | enum | `L0`, `L1`, `L2`, `L3`, `L4` |
| `subject.trust_score` | Trust | float | `0.0` to `1.0` |

### Resource Attributes

| Attribute | Source | Type | Example |
|-----------|--------|------|---------|
| `resource.id` | IDS | string | `aios:session:dev:456def` |
| `resource.type` | IDS | enum | `session`, `worker`, `policy`, `evidence` |
| `resource.classification` | LMS | enum | `public`, `internal`, `confidential`, `restricted`, `critical` |
| `resource.owner` | IDS | string | `aios:org:engineering` |
| `resource.domain` | IDS | string | `domain:security` |
| `resource.lifecycle_state` | LMS | enum | `active`, `suspended`, `archived` |

### Action Attributes

| Attribute | Source | Type | Example |
|-----------|--------|------|---------|
| `action.type` | Pipeline | enum | `read`, `write`, `execute`, `delete`, `delegate` |
| `action.risk_score` | Risk | float | `0.0` to `1.0` |
| `action.impact` | Risk | enum | `negligible`, `low`, `medium`, `high`, `critical` |
| `action.scope_depth` | Pipeline | int | Depth of delegation chain |

### Environment Attributes

| Attribute | Source | Type | Example |
|-----------|--------|------|---------|
| `env.time` | System | time | Current UTC time |
| `env.day_of_week` | System | int | `0` (Sunday) to `6` |
| `env.system_load` | ROS | float | `0.0` to `1.0` |
| `env.threat_level` | Security | enum | `normal`, `elevated`, `high`, `severe` |
| `env.regulatory_zone` | Policy | string | `gdpr`, `hipaa`, `pci`, `none` |

## Policy Model

### Policy Structure

```typescript
interface ABACPolicy {
  id: string;
  name: string;
  description: string;
  priority: number;           // Lower number = higher priority
  effect: "allow" | "deny";
  conditions: Condition[];    // All conditions must be true
  obligations?: Obligation[]; // Actions to perform if policy matches
}
```

### Condition Syntax

Each condition is a predicate over one or more attributes:

```
Condition ::= Attribute Operator Value [LogicalConnective Condition]
Operator  ::= "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not_in" | "contains" | "matches"
Value     ::= Literal | Attribute | Set
```

Example: `subject.clearance >= resource.classification AND env.time within business_hours`

### Policy Evaluation Order

1. Collect all ABAC policies applicable to the action and resource type
2. Sort by priority (ascending)
3. Evaluate each policy sequentially
4. If a `deny` policy's conditions are met → deny immediately
5. If an `allow` policy's conditions are met → mark as allowed, continue evaluation
6. If no policies match → fall back to RBAC decision
7. If both allow and deny match → deny wins (conservative)

### Policy Categories

| Category | Scope | Authority | Examples |
|----------|-------|-----------|----------|
| Constitutional | System-wide | Security Council | No entity may delete evidence records |
| Regulatory | Jurisdiction | Compliance Officer | GDPR data may not leave EU region |
| Organizational | Per-org | Org Admin | Org resources may not be read outside business hours |
| Mission | Per-mission | Mission Owner | Mission data may not be modified by non-contributors |
| Safety | System-wide | Safety Officer | No action with risk score >0.8 without MFA |

## Policy Administration

### Policy Lifecycle

```
Draft → Review → Active → Superseded → Archived
```

- **Draft**: Policy being authored. Not evaluated.
- **Review**: Under review by authorizing body. Not evaluated.
- **Active**: Policy is evaluated for every matching action.
- **Superseded**: Replaced by a newer version. Old version retained for audit.
- **Archived**: No longer evaluated. Retained for historical evidence.

### Change Management

- Policy modifications require authorization from the policy category's authority
- Policy changes are versioned. Every change produces an `AZS.PolicyChanged` event.
- Policy changes take effect within 5 seconds of approval (configurable per category)
- A policy may be emergency-suspended by the Security Council without review

### Conflict Detection

When a new policy is activated, the system detects conflicts with existing policies. A conflict exists when the same attribute set would match both an allow and a deny policy. Conflicts are reported to the policy author and must be resolved before the policy can move from Review to Active.

## ABAC + RBAC Integration

ABAC does not replace RBAC. The authorization decision is:

```
Authorized = RBAC_has_permission AND ABAC_conditions_met(allow) AND NOT ABAC_conditions_met(deny)
```

- If RBAC denies → deny (Stage 3 failure)
- If RBAC allows but ABAC denies → deny
- If RBAC allows and ABAC conditions allow → authorize

This layered approach ensures that static role assignments provide the baseline while contextual attributes fine-tune access under changing conditions.

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `AZS.AttributeResolved` | An attribute value is resolved for evaluation | entity_id, attribute_name, attribute_source, resolved_value |
| `AZS.PolicyEvaluated` | An ABAC policy is evaluated against a request | policy_id, entity_id, action, resource, conditions_evaluated, result |
| `AZS.PolicyCreated` | A new ABAC policy is defined | policy_id, policy_category, author, effect, conditions |
| `AZS.PolicyChanged` | An ABAC policy is modified | policy_id, old_version, new_version, changed_by |
| `AZS.PolicyActivated` | A policy transitions to Active | policy_id, effective_at |
| `AZS.PolicyConflict` | A conflict is detected between policies | policy_id_a, policy_id_b, conflict_conditions |
| `AZS.ABACOverride` | ABAC decision overrides RBAC decision | entity_id, action, rbac_result, abac_result, abac_policy_id |

## Cross-Cutting Concerns

### Security

- ABAC policies cannot override constitutional security invariants. An allow policy cannot authorize what Physics forbids.
- Attribute sources are verified: subject attributes are signed by IDS, resource attributes by LMS, environment attributes by ACF timestamp.
- Policy evaluation is sandboxed. A malformed policy cannot crash the authorization service.

### Evidence

- Every policy evaluation produces an `AZS.PolicyEvaluated` event with full condition results.
- Attribute resolution is logged for auditability. If a policy denied based on `subject.clearance`, the evidence must show what clearance was resolved.

### Lifecycle

- ABAC policies are lifecycle-managed. Draft policies are not evaluated. Archived policies are not evaluated.
- Entity lifecycle transitions (suspend, terminate) automatically trigger attribute changes that affect ABAC evaluation.

### Capability Bounds

- ABAC can read but never modify capability bounds. It makes access decisions within existing bounds.
- Capability verification (Stage 5) occurs after ABAC (Stage 3/4). A policy may allow an action that Stage 5 later denies due to resource exhaustion.

### Communication

- Attribute resolution requires ACF communication with IDS, LMS, CCA, and Trust services. Latency targets: <5ms per attribute.
- Policy changes are broadcast via ACF event streams to all pipeline instances.

### Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | ABAC does one thing: evaluate attribute conditions against policies |
| R2 — Dependency Order | Compliant | ABAC depends on attribute sources; no circular dependencies |
| R3 — DRY | Compliant | Attributes defined once per source, referenced by policy ID |
| R4 — Builder Pattern | Compliant | Policies constructed by PolicyBuilder, validated before activation |
| R5 — Liskov Substitution | Compliant | Any policy engine implementation conforms to the evaluation interface |
| R6 — DI over Singletons | Compliant | ABAC engine injected into authorization pipeline |
| R7 — Tests Exist | Compliant | Unit tests for condition evaluation, integration tests for ABAC+RBAC interaction |
| R8 — Tests Fast | Compliant | Policy evaluation target <5ms; test suite completes in <45s |
| R9 — Deterministic Tests | Compliant | Same attributes + same conditions always produce same evaluation result |
| R10 — Prefer Simpler | Compliant | Condition grammar has only 4 operators — no loops, no recursion |
| R11 — Refactor over Rewrite | Compliant | Policy evolution happens through versioned policy updates |
| R12 — Embrace Errors | Compliant | Each evaluation error has a unique code, condition reference, and attribute path |
| R13 — Design for Failure | Compliant | If attribute source unreachable, evaluation denies (fail closed) |
| R14 — Paved Path | Compliant | ABAC is always evaluated after RBAC in the paved pipeline path |
| R15 — Open/Closed | Compliant | New attribute types are added via new attribute sources, not policy engine changes |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 000-RBAC.md | Baseline authorization model that ABAC extends |
| 002-Capability.md | Delegated authorization model that complements ABAC |
| ../Execution-Auth/000-EAS.md | Pipeline Stage 3 that invokes ABAC evaluation |
| ../Policy-System/000-PS.md | ABAC policies are a subclass of the Policy System |
| ../Trust/000-TLM.md | Trust scores are ABAC subject attributes |
| Physics/007-Capabilities.md | Capability Bound invariants |
| Physics/008-Security.md | Security verification invariants |
