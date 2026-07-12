# AIOS Bible — Security
## 005 — Policy Compliance Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-005 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Verify that the requested action complies with all applicable policies — policy resolution, evaluation, and conflict detection.

## Architecture

```
Policy Compliance Request (entityId, action, resource, context)
        │
        ▼
┌────────────────────────┐
│ Policy Resolution      │──► Find all policies for entity + action
│ (Policy Engine)        │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ Policy Evaluation      │──► Evaluate each policy sequentially
│ ┌──────────────────┐   │
│ │ Allow / Deny /   │   │
│ │ Audit / Quota    │   │
│ └──────────────────┘   │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ Conflict Detection     │──► Detect overlapping allow/deny rules
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ Conditional Policy     │──► Evaluate time/context-based conditions
│ Evaluation             │
└───────────┬────────────┘
            │
            ▼
       Policy Result
    (passed / denied / audit)
```

## Data Model

```typescript
interface PolicyBinding {
  bindingId: string;
  policyId: string;
  entityId: string;
  action: string;
  resourcePattern: string;
  priority: number;
  enabled: boolean;
}

interface PolicyEvaluation {
  policyId: string;
  policyType: 'allow' | 'deny' | 'audit' | 'quota';
  effect: 'allow' | 'deny' | 'audit' | 'block';
  matched: boolean;
  conditionResult: boolean | null;
  evaluatedAt: Timestamp;
}

interface PolicyResult {
  passed: boolean;
  evaluations: PolicyEvaluation[];
  finalEffect: 'allow' | 'deny' | 'audit';
  conflicts: PolicyConflict[];
  errorCode: string | null;
  evidenceRef: string | null;
}

interface PolicyConflict {
  conflictId: string;
  policyIdA: string;
  policyIdB: string;
  description: string;
  resolved: boolean;
  resolutionEffect: 'allow' | 'deny';
}
```

## Core Concepts / Operations

- **Policy Resolution**: Find all applicable policies for the entity + action combination using PolicyBindings. Policies are collected from organizational, resource, and system levels.
- **Policy Evaluation**: Evaluate each resolved policy through the Policy Engine. Supports allow, deny, audit, and quota policy types.
- **Policy Types**: allow (explicit permission), deny (explicit prohibition), audit (log-only, no enforcement), quota (rate/resource limits).
- **Policy Conflict Detection**: Detect overlapping allow and deny rules for the same entity + action. Conflicting policies are flagged and resolved by priority.
- **Policy Precedence**: Explicit deny overrides allow. Higher-priority policies override lower-priority ones. Most-specific resource pattern wins.
- **Conditional Policy Evaluation**: Evaluate time-based (business hours only), context-based (location, device), and state-based conditions attached to policies.
- **Failure Modes**: Policy not found, conflicting policies, evaluation timeout.

## Internal Interfaces

```typescript
interface PolicyStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface PolicyResolver {
  resolve(entityId: string, action: string): Promise<PolicyBinding[]>;
  getPolicies(entityId: string): Promise<PolicyBinding[]>;
}

interface PolicyEngine {
  evaluate(policy: PolicyBinding, context: Record<string, unknown>): Promise<PolicyEvaluation>;
  evaluateAll(policies: PolicyBinding[], context: Record<string, unknown>): Promise<PolicyResult>;
}

interface PolicyConflictDetector {
  detect(evaluations: PolicyEvaluation[]): Promise<PolicyConflict[]>;
  resolve(conflict: PolicyConflict): Promise<string>;
}

interface ConditionEvaluator {
  evaluate(condition: string, context: Record<string, unknown>): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.Pol.PolicyResolutionStarted` | entityId, action | Policy resolution initiated |
| `FV.Pol.PolicyResolved` | entityId, policyCount | Applicable policies found |
| `FV.Pol.PolicyEvaluated` | policyId, effect | Individual policy evaluated |
| `FV.Pol.PolicyPassed` | entityId, action, finalEffect | All policies passed |
| `FV.Pol.PolicyDenied` | entityId, action, policyId | Policy evaluation denied action |
| `FV.Pol.PolicyConflictDetected` | conflictId, policyIdA, policyIdB | Conflicting policies found |
| `FV.Pol.PolicyEvaluationTimeout` | policyId, durationMs | Policy evaluation exceeded timeout |
| `FV.Pol.ConditionalPolicyTriggered` | policyId, condition | Conditional policy evaluated |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Policy not found | `FV_POL_001` | Stage failed; no applicable policy |
| Conflicting policies unresolved | `FV_POL_002` | Stage failed; manual resolution required |
| Policy evaluation timeout | `FV_POL_003` | Stage failed; mark inconclusive |
| Conditional evaluation error | `FV_POL_004` | Stage failed; condition malformed |
| Policy engine unavailable | `FV_POL_005` | Stage failed; dependency down |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-POL-001 | Every action is evaluated against all applicable policies — no policy is skipped | Algorithmic — exhaustive resolution |
| FV-POL-002 | Deny policies override allow policies at the same priority | Constitutional — deny precedence rule |
| FV-POL-003 | Policy conflicts are detected and resolved before final decision | Algorithmic — conflict detection before result |
| FV-POL-004 | Conditional policies are evaluated deterministically — same context = same result | Algorithmic — pure condition evaluation |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | Policy Stage owns compliance; Policy Engine owns evaluation logic |
| R2 — Dependency Order | Depends on Policy Engine, ConditionEvaluator; no cycles |
| R3 — DRY | Policies defined once in policy store; bindings reference, not duplicate |
| R4 — Builder Pattern | PolicyResult aggregates all evaluation results |
| R9 — Deterministic | Same policies + same context = same result |
| R10 — Simpler Over Complex | Allow/Deny/Audit/Quota as primitive types; complex policies via conditions |
| R13 — Design for Failure | Evaluation timeout treated as deny; conflicts block execution |
| R14 — Paved Path | Allow + Deny policies with audit logging; quota for rate-sensitive actions |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — policy compliance property |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — Policy is stage 4 |
| Bible/04-Execution/Security/Verification/004-AuthZ-Stage.md | AuthZ Stage — provides permission context for policy evaluation |
| Bible/04-Execution/Security/Verification/006-Capability-Stage.md | Capability Stage — next stage in pipeline |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for policy decisions |
