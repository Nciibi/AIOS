# AIOS Bible — Core
## 006 — Resource Quota

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-ROS-006 |
| Source Laws | Law 7 — Law of Capability Bounds |
| Source Physics | Physics/007-Capabilities.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Quota enforces hard and soft limits on resource consumption across entities, organizations, missions, and the entire system. While Budget (005-Budget) defines per-entity entitlements, Quota defines system-wide and aggregate limits that prevent any single scope from consuming disproportionate resources.

## Hard Quota vs Soft Quota

| Aspect | Hard Quota | Soft Quota |
|--------|-----------|------------|
| Enforcement | Absolute maximum — cannot be exceeded | Warning threshold — can be exceeded temporarily |
| Consequence | Allocation denied | Event produced, warning logged |
| Override | Only by Security Council | Organization admin |
| Typical use | System-wide capacity, security limits | Alerting thresholds, planning triggers |

## Quota Types

### Per-Entity Quota

Limits resource consumption for a single entity. Applied in addition to the entity's budget.

| Field | Type | Description |
|-------|------|-------------|
| `scope_type` | Enum | entity |
| `scope_id` | UUID | Entity ID |
| `resource_type` | ResourceType | Resource limited |
| `hard_limit` | Quantity | Absolute maximum (cannot exceed) |
| `soft_limit` | Quantity | Warning threshold (can exceed temporarily) |
| `soft_limit_duration` | Duration | How long soft limit can be exceeded (default: 5 minutes) |

### Per-Organization Quota

Limits aggregate resource consumption across all entities in an Organization.

| Field | Type | Description |
|-------|------|-------------|
| `scope_type` | Enum | organization |
| `scope_id` | UUID | Organization ID |
| `resource_type` | ResourceType | Resource limited |
| `hard_limit` | Quantity | Organization-wide resource cap |
| `soft_limit` | Quantity | Organization warning threshold |

### Per-Mission Quota

Limits resource consumption for a specific Mission across all participating entities.

| Field | Type | Description |
|-------|------|-------------|
| `scope_type` | Enum | mission |
| `scope_id` | UUID | Mission ID |
| `resource_type` | ResourceType | Resource limited |
| `hard_limit` | Quantity | Mission resource cap |
| `soft_limit` | Quantity | Mission warning threshold |

### System-Wide Quota

Limits total resource consumption across the entire AIOS instance. Set by the Security Council.

| Field | Type | Description |
|-------|------|-------------|
| `scope_type` | Enum | system |
| `resource_type` | ResourceType | Resource limited |
| `hard_limit` | Quantity | Absolute system resource cap |
| `soft_limit` | Quantity | System warning threshold |

## Quota Operations

### setQuota

Creates or updates a quota for a scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, organization, mission, system |
| `scope_id` | UUID | Scope identifier |
| `resource_type` | ResourceType | Resource type |
| `hard_limit` | Quantity | Hard quota limit |
| `soft_limit` | Quantity (optional) | Soft quota limit |
| `soft_limit_duration` | Duration (optional) | Max duration for soft limit exceedance |

**Event produced**: `QuotaSet { quota_id, scope_type, scope_id, resource_type, hard_limit, soft_limit, timestamp }`

### checkQuota

Checks whether a given allocation request would violate any applicable quotas.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | UUID | Requesting entity |
| `resource_type` | ResourceType | Resource type |
| `requested_quantity` | Quantity | Amount requested |
| `scope_ids` | List<UUID> | Additional scopes to check (org, mission) |

**Process**:
1. Check entity quota: if entity_used + requested > entity_hard_limit → deny
2. Check organization quota: if org_used + requested > org_hard_limit → deny
3. Check mission quota: if mission_used + requested > mission_hard_limit → deny
4. Check system quota: if system_used + requested > system_hard_limit → deny
5. Check soft limits: if any soft limit exceeded, produce QuotaWarning Event
6. Return approval with warnings

**Returns**: `QuotaCheckResult { allowed: Boolean, warnings: List<QuotaWarning>, violations: List<QuotaViolation> }`

### getQuotaStatus

Returns the current quota status for a scope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_type` | Enum | entity, organization, mission, system |
| `scope_id` | UUID | Scope identifier |
| `resource_type` | ResourceType (optional) | Resource type filter |

**Returns**: Current usage and limits for all applicable quota levels.

## Quota Violation Escalation

| Violation Type | First Occurrence | Persistent (>3 checks) | Chronic (>24 hours) |
|----------------|------------------|----------------------|---------------------|
| Hard quota (entity) | Deny allocation, log warning | Escalate to org admin | Escalate to Security Council |
| Hard quota (org) | Deny allocation, notify org admin | Escalate to Security Council | Security Council intervention |
| Hard quota (system) | Deny allocation, alert Security Council | Security Council immediate action | System-wide review |
| Soft quota (any) | Produce QuotaWarning Event | Escalate to scope owner | Quota review recommended |

**Escalation Events**:

| Event | Trigger | Payload |
|-------|---------|---------|
| QuotaViolated | Hard quota exceeded | quota_id, scope_type, scope_id, resource_type, requested, limit, timestamp |
| QuotaWarning | Soft quota exceeded | quota_id, scope_type, scope_id, resource_type, usage, soft_limit, timestamp |
| QuotaEscalated | Persistent violation | quota_id, escalation_level, action_required, timestamp |

## Quota Enforcement Flow

```
Allocation Request
    │
    ▼
Check Entity Quota ──→ Hard limit exceeded? ──→ DENY
    │                      │
    │                      ▼ (no)
    ▼
Check Org Quota ─────→ Hard limit exceeded? ──→ DENY
    │                      │
    │                      ▼ (no)
    ▼
Check Mission Quota ──→ Hard limit exceeded? ──→ DENY
    │                      │
    │                      ▼ (no)
    ▼
Check System Quota ──→ Hard limit exceeded? ──→ DENY
    │                      │
    │                      ▼ (no)
    ▼
Check Soft Limits ───→ Any exceeded? ──→ ALLOW + Warning
    │
    ▼
ALLOW
```

## Events

| Event | Trigger | Payload |
|-------|---------|---------|
| QuotaSet | setQuota | quota_id, scope_type, scope_id, resource_type, hard_limit, soft_limit, timestamp |
| QuotaViolated | Hard quota exceeded | quota_id, scope_type, scope_id, resource_type, requested, limit, timestamp |
| QuotaWarning | Soft quota exceeded | quota_id, scope_type, scope_id, resource_type, usage, soft_limit, timestamp |
| QuotaEscalated | Persistent violation | quota_id, escalation_level, action_required, timestamp |
| QuotaReset | Quota period reset | quota_id, new_limit, timestamp |

## Cross-Cutting Concerns

### Security

Quota changes require elevated authorization. Only Security Council may set system-wide quotas. Organization admins may set organization quotas within system bounds.

### Evidence

All quota operations produce Events. Quota violation history is fully auditable for Security Council review.

### Lifecycle

Quotas are created when a scope is created and removed when the scope is destroyed. System-wide quotas persist across instance restarts.

### Capability Bounds

Quotas are bounded by the total capacity registered in the Registry. A system-wide quota cannot exceed total provider capacity.

### Communication

Quota checks are synchronous with allocation requests. Quota status queries use read replicas for scalability. Quota updates go through the active ROS node.

### Design DNA Compliance

| Rule | Compliance |
|------|------------|
| R1 — Modulsingularity | Quota handles only limit enforcement separate from budgeting. |
| R9 — Deterministic | Quota checks are deterministic — same inputs always produce same result. |
| R10 — Simpler Over Complex | Two limit types (hard/soft) cover all cases. Linear check hierarchy. |
| R12 — Embrace Errors | Every quota violation has a unique error code, actionable context, and escalation path. |
| R13 — Design for Failure | Quota enforcement in the Allocator prevents runaway consumption even if the Quota service is unavailable (fails closed). |
| R14 — Paved Path | The paved path is: Set Quota → Check Quota → Allocate or Deny → Escalate if Persistent. |

## Related Documents

| Document | Relationship |
|---------|-------------|
| ROS/003-Allocator.md | Allocator calls checkQuota before every allocation |
| ROS/005-Budget.md | Budget works alongside quota — budget for entitlement, quota for limits |
| ROS/007-RMP.md | RMP policies may override quota behavior |
| ROS/013-Observability.md | Quota violation alerting and monitoring |
| Physics/007-Capabilities.md | Quota bounds capability resource limits |
| Bible/03-Institutions/Security-Council | Escalation path for persistent violations |
