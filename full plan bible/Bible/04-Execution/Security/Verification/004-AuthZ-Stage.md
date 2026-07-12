# AIOS Bible — Security
## 004 — Authorization Stage

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Verification |
| Document ID | AIOS-BBL-004-FV-004 |
| Source Laws | Law 8 — Law of Verification-First, Law 4 — Law of Evidence |
| Source Physics | Physics/008-Security.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Authorize the authenticated entity to perform the requested action — permission check, role resolution, access control.

## Architecture

```
Authorization Request (entityId, action, resource)
        │
        ▼
┌────────────────────┐
│ Role Resolution    │──► RBAC hierarchy traversal
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Permission Check   │──► Does role have permission for action?
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ ACL Evaluation     │──► Resource-level access control entries
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Delegation Chain   │──► Verify chain of delegated authority
└────────┬───────────┘
         │
         ▼
    Authorization Result
    (passed / denied)
```

## Data Model

```typescript
interface AuthorizationRequest {
  entityId: string;
  action: string;
  resourceRef: string;
  context: Record<string, unknown>;
}

interface PermissionSet {
  permissions: string[];
  resourceScope: string;
  constraints: Record<string, unknown>;
}

interface RoleAssignment {
  entityId: string;
  roleId: string;
  roleName: string;
  scope: string;
  assignedAt: Timestamp;
  expiresAt: Timestamp | null;
}

interface AccessControlEntry {
  entryId: string;
  resourceRef: string;
  principal: string;
  effect: 'allow' | 'deny';
  action: string;
  priority: number;
  condition: string | null;
}

interface AuthorizationResult {
  passed: boolean;
  matchedRoles: RoleAssignment[];
  matchedPermissions: string[];
  aclDecision: 'allow' | 'deny' | 'not-applicable';
  delegationVerified: boolean;
  errorCode: string | null;
  evidenceRef: string | null;
}
```

## Core Concepts / Operations

- **Permission Check Against Declared Capabilities**: Verify the requested action is in the entity's declared permission set.
- **Role Resolution (RBAC Hierarchy)**: Resolve all roles assigned to the entity, including inherited roles from parent groups/orgs.
- **Access Control Entry Evaluation (ACL)**: Evaluate resource-level ACL entries. Deny entries take precedence over allow entries at the same level.
- **Resource-Level Authorization**: Match resource reference against ACL patterns (exact, prefix, wildcard).
- **Delegation Chain Verification**: Verify that delegated authority chains are valid — each delegation must be authorized by the original grantor.
- **Authorization Caching Strategy**: Cache resolved role assignments and permission sets with TTL based on role volatility.
- **Failure Modes**: Insufficient permissions, role not found, denied by ACL.

## Internal Interfaces

```typescript
interface AuthZStageHandler {
  execute(context: PipelineContext): Promise<StageResult>;
}

interface PermissionChecker {
  check(entityId: string, action: string): Promise<boolean>;
  getPermissions(entityId: string): Promise<PermissionSet>;
}

interface RoleResolver {
  resolve(entityId: string): Promise<RoleAssignment[]>;
  resolveHierarchy(roleId: string): Promise<string[]>;
}

interface ACLEvaluator {
  evaluate(resourceRef: string, principal: string, action: string): Promise<AccessControlEntry | null>;
  getEntries(resourceRef: string): Promise<AccessControlEntry[]>;
}

interface DelegationVerifier {
  verifyChain(entityId: string, action: string): Promise<boolean>;
}
```

## Events

| Event | Fields | Description |
|-------|--------|-------------|
| `FV.AuthZ.AuthorizationRequested` | entityId, action, resourceRef | Authorization check initiated |
| `FV.AuthZ.PermissionChecked` | entityId, action, permitted | Permission set evaluated |
| `FV.AuthZ.RoleResolved` | entityId, roleCount, roles | Entity roles resolved from hierarchy |
| `FV.AuthZ.ACLEvaluated` | resourceRef, effect, entryId | ACL entry matched and evaluated |
| `FV.AuthZ.AuthorizationPassed` | entityId, action | Authorization granted |
| `FV.AuthZ.AuthorizationDenied` | entityId, action, reason | Authorization denied |
| `FV.AuthZ.DelegationChainVerified` | entityId, chainLength | Delegation chain validated |

## Error Cases

| Condition | Error Code | Behavior |
|-----------|------------|----------|
| Insufficient permissions | `FV_AUTHZ_001` | Stage failed; deny access |
| Role not found | `FV_AUTHZ_002` | Stage failed; no roles assigned |
| Denied by ACL | `FV_AUTHZ_003` | Stage failed; ACL explicitly denies |
| Delegation chain broken | `FV_AUTHZ_004` | Stage failed; invalid delegation |
| Authorization cache stale | `FV_AUTHZ_005` | Refresh cache; retry resolution |

## Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| FV-AUTHZ-001 | Every authorization check evaluates roles, permissions, and ACLs — no single-factor decision | Architectural — three-factor check enforced by stage handler |
| FV-AUTHZ-002 | Deny ACL entries always override allow entries at the same scope | Algorithmic — priority-based ACL evaluation |
| FV-AUTHZ-003 | Delegation chain length is bounded and verifiable | Algorithmic — max depth enforced by DelegationVerifier |
| FV-AUTHZ-004 | Role hierarchy resolution is acyclic | Algorithmic — cycle detection in RBAC graph |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 — Modulsingularity | AuthZ Stage owns authorization rules; RBAC hierarchy is external data |
| R2 — Dependency Order | Depends on RoleResolver, ACLEvaluator, DelegationVerifier |
| R3 — DRY | Permission sets computed once per role, inherited by members |
| R4 — Builder Pattern | AuthorizationResult aggregates all sub-checks |
| R9 — Deterministic | Same entity + same action + same ACLs = same result |
| R10 — Simpler Over Complex | RBAC with ACL overrides; ABAC considered for future |
| R13 — Design for Failure | Deny-by-default; explicit allow required for access |
| R14 — Paved Path | Role-based access with resource-level ACL refinement |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Security/Verification/000-Overview.md | Formal Verification — non-bypassability property |
| Bible/04-Execution/Security/Verification/001-Pipeline-Stages.md | Pipeline Architecture — AuthZ is stage 3 |
| Bible/04-Execution/Security/Verification/003-AuthN-Stage.md | AuthN Stage — provides authenticated identity for authorization |
| Bible/04-Execution/Security/Verification/005-Policy-Stage.md | Policy Stage — next stage in pipeline |
| Bible/05-Platform/004-EVS.md | EVS — evidence logging for authorization decisions |
