# AIOS Bible — Authorization (AZS)
## 000 — Role-Based Access Control

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Security / Authorization |
| Document ID | AIOS-BBL-AZS-000 |
| Source Laws | Law 7 — Law of Capability Bounds, Law 8 — Law of Verification-First |
| Source Physics | Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Role-Based Access Control (RBAC) provides the foundational authorization model for AIOS. Under Law 8 (Verification-First), every action passes through authorization at Stage 3 of the verification pipeline. RBAC is the primary mechanism by which the system determines whether an authenticated entity is permitted to perform a requested action on a specific target resource.

RBAC models the AIOS organizational hierarchy as role sets. Each entity — Worker, Session, Engine, Organization — is assigned one or more roles. Each role carries a defined set of permissions. Authorization reduces to set membership: does the entity's role set include a role that grants the requested permission? This model aligns with the constitutional principle that authority flows from organizational position, not from individual identity.

RBAC does not stand alone. It is complemented by ABAC (001-ABAC.md) for fine-grained attribute-based decisions and Capability-Based Authorization (002-Capability.md) for delegation. The three systems operate in concert: RBAC provides baseline authorization, ABAC refines with contextual attributes, and capabilities enable scoped delegation. All three are invoked during Stage 3 of the verification pipeline.

## Role Hierarchy

### Role Types

| Role Type | Scope | Assignment Authority | Example |
|-----------|-------|---------------------|---------|
| System | Platform-wide | Security Council | `admin`, `auditor`, `operator` |
| Organization | Organization-scoped | Organization Admin | `org.admin`, `org.developer`, `org.viewer` |
| Mission | Mission-scoped | Mission Owner | `mission.lead`, `mission.contributor` |
| Department | Department-scoped | Department Head | `dept.manager`, `dept.analyst` |
| Session | Session-scoped | Session Creator | `session.owner`, `session.participant` |

### Inheritance

Roles form a hierarchy where senior roles inherit permissions from junior roles:

```
admin → operator → auditor → viewer
org.admin → org.developer → org.viewer
mission.lead → mission.contributor
```

Inheritance is monotonic: a role at level N possesses all permissions of levels N+1 through bottom. Cycles are forbidden by physics. The inheritance graph is validated at Role create time and any cycle causes creation to fail.

### Constraints

- An entity may hold multiple roles across different scopes
- Role assignment requires two-party authorization (assigner + entity consent) for high-privilege roles
- No entity may assign itself a role it does not already hold
- System roles may only be assigned by the Security Council

## Permission Model

### Permission Structure

```typescript
interface Permission {
  action: string;          // e.g., "read", "write", "execute", "delete"
  resourceType: string;    // e.g., "session", "worker", "policy", "organization"
  scope: string;           // e.g., "self", "org:*", "system:*"
  constraints?: string[];  // optional preconditions
}
```

### Permission Granularity

| Level | Scope | Example |
|-------|-------|---------|
| Global | `system:*` | `admin` can act on any resource system-wide |
| Organization | `org:{id}:*` | `org.admin` can act on any resource within their org |
| Department | `dept:{id}:*` | `dept.manager` can act on department-scoped resources |
| Self | `self` | Any entity can read its own identity record |

### Default Deny

All permissions are deny-by-default. A role carries only explicitly granted permissions. There is no implicit "everything else" permission. If a requested action does not match a Permission in the entity's role set, authorization fails with code `VERIFY_AUTHZ_001`.

## Role Assignment

### Assignment Lifecycle

```
Request → Validation → Approval → Binding → Active → Revocation
```

1. **Request**: Authorized entity submits role assignment request targeting a subject entity
2. **Validation**: System validates requestor authority, subject eligibility, and constraint compliance
3. **Approval**: Two-party approval required for roles above `viewer` level
4. **Binding**: Role is bound to subject identity — subject receives role credentials
5. **Active**: Role is active. Subject may exercise permissions.
6. **Revocation**: Role is revoked by assignor or automated policy. All derived authorizations invalidated.

### Temporal Assignments

Roles may be time-bound (`from`/`until`), session-bound (valid only while a specific session is active), or condition-bound (valid only when certain attributes are true). Temporal constraints are evaluated at authorization time. Expired or unsatisfied constraints cause the role to be treated as not assigned.

### Revocation

- Role revocation is immediate
- All cached authorization decisions relying on the revoked role are invalidated
- In-flight actions authorized under the revoked role are allowed to complete (grace period: 30s)
- Revocation produces an `AZS.RoleRevoked` event

## Role Resolution

### Resolution Algorithm

At Stage 3 of the verification pipeline, the Authorization service resolves the entity's effective permissions:

1. Collect all directly assigned roles for the entity
2. For each role, expand inherited permissions up the hierarchy
3. Merge all permission sets — deduplicate by `(action, resourceType, scope)`
4. Evaluate the requested action against the merged permission set
5. If no matching permission is found, evaluate ABAC policies for contextual override
6. If ABAC also denies, evaluate Capability grants for delegated authorization
7. Return authorization result

### Caching

Role resolution results are cached for 30 seconds. Cache entries are invalidated on any role assignment, revocation, or modification for the affected entity. The cache is an LRU map with a maximum of 10,000 entries.

### Conflict Resolution

When multiple roles grant conflicting permissions (one allows, one denies), the most specific scope wins. If scopes are identical, deny takes precedence over allow. This ensures conservative authorization.

## Events

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| `AZS.RoleCreated` | A new role is defined | role_id, role_name, parent_role_id, permissions, created_by |
| `AZS.RoleAssigned` | A role is assigned to an entity | entity_id, role_id, assignor_id, effective_from, effective_until, constraints |
| `AZS.RoleRevoked` | A role is revoked from an entity | entity_id, role_id, revoke_authority, reason |
| `AZS.AuthorizationCheck` | An authorization decision is made | entity_id, action, target, role_match, result, decision_time_ms |
| `AZS.PermissionDenied` | Authorization is denied | entity_id, action, target, reason_code, matched_roles |
| `AZS.RoleExpired` | A temporal role expires | entity_id, role_id, expiration_time |
| `AZS.InheritanceViolation` | A cycle is detected in role hierarchy | attempted_relationship, error_detail |

## Cross-Cutting Concerns

### Security

- RBAC follows the principle of least privilege. No role grants more permissions than necessary.
- Role definitions are immutable after creation. To change a role, create a new version and migrate assignments.
- The `admin` role is limited to platform operations — it cannot read session content or modify evidence records.
- All role assignment and revocation actions require authentication through Stage 2 and authorization through Stage 3.

### Evidence

- Every RBAC event listed above is recorded as immutable evidence in the Event Store.
- Role assignment evidence includes the full assignment chain (who assigned, on what authority, to whom).
- Authorization check results are recorded with the specific permissions matched and the role that granted them.
- Evidence retention follows Law 4 requirements — no authorization decision is invisible.

### Lifecycle

- Roles follow a lifecycle: Draft → Active → Deprecated → Retired. Deprecated roles remain functional but may not be assigned to new entities.
- Entity lifecycle transitions trigger role reassessment. A suspended entity's roles are suspended. A terminated entity's roles are revoked.
- Organizations undergoing dissolution trigger bulk role revocation for all members.

### Capability Bounds

- RBAC permissions define the upper bound of what a role may authorize. Capability verification (Stage 5) further constrains by resource budgets, autonomy level, and scope depth.
- A role may grant `write` permission, but if the entity's capability budget is exhausted, the write is denied at Stage 5.
- Role assignment cannot exceed the capability bounds of the assigning authority.

### Communication

- All authorization requests and responses flow through ACF. No direct authorization channel exists.
- ACF enforces that authorization requests carry verified identity and authentication tokens from Stages 1-2.
- Authorization events are published to ACF event streams for downstream consumers.

### Design DNA

| Rule | Assessment | Rationale |
|------|-----------|-----------|
| R1 — Modulsingularity | Compliant | RBAC does one thing: map roles to permissions |
| R2 — Dependency Order | Compliant | RBAC depends on IDS and ACF; nothing depends on RBAC for its own definition |
| R3 — DRY | Compliant | Permission definitions live in one place — the role definition |
| R4 — Builder Pattern | Compliant | Roles are constructed by RBAC Builder, not directly instantiated |
| R5 — Liskov Substitution | Compliant | Any Role implementation conforms to the Permission interface |
| R6 — DI over Singletons | Compliant | RBAC service is injected into the verification pipeline |
| R7 — Tests Exist | Compliant | Unit tests for role resolution, integration tests for pipeline integration |
| R8 — Tests Fast | Compliant | Authorization check targets <10ms; test suite completes in <30s |
| R9 — Deterministic Tests | Compliant | Same role set + same action always produces same authorization result |
| R10 — Prefer Simpler | Compliant | RBAC model is direct set membership — no inference, no rule engine |
| R11 — Refactor over Rewrite | Compliant | RBAC evolves through new role definitions, not pipeline rewrites |
| R12 — Embrace Errors | Compliant | Every denial has a unique error code, stage identifier, and human-readable message |
| R13 — Design for Failure | Compliant | If RBAC service is unreachable, pipeline denies (fail closed) |
| R14 — Paved Path | Compliant | The 7-stage pipeline is the only authorization path |
| R15 — Open/Closed | Compliant | New role types are added through extension, not by modifying existing role resolution |

## Related Documents

| Document | Relationship |
|----------|-------------|
| 001-ABAC.md | Complementary attribute-based authorization model |
| 002-Capability.md | Complementary capability-based delegation model |
| ../Execution-Auth/000-EAS.md | Stage 3 of verification pipeline consumes RBAC decisions |
| ../ATS/000-Auth-Methods.md | Authentication precedes authorization |
| Physics/007-Capabilities.md | Capability Bound invariants governing role scope |
| Physics/008-Security.md | Security verification invariants |
