# AIOS Bible — Identity Service (IDS)
## 003 — Identity Lifecycle

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Security / Identity |
| Document ID | AIOS-BIBLE-IDS-003 |
| Source Laws | Law 5 — Law of Identity, Law/6 — Law of Lifecycle Compliance |
| Source Physics | Physics/001-Identity.md, Physics/006-Lifecycles.md |

## Lifecycle States

```
Created → Verified → Active → Suspended → Restored → Retired → Archived
```

| State | Description | Can Act? | Can Be Modified? | Transitions To |
|-------|-------------|--------|------------------|----------------|
| **Created** | Identity is assigned to a new entity. Entity may not act yet. | No | No | Verified |
| **Verified** | Identity binding to entity is confirmed by the authorizing entity (OSYS, LMS, AGS, etc.) | No | No | Active |
| **Active** | Entity may operate under this identity. | Yes | Metadata only | Suspended, Retired |
| **Suspended** | Identity is temporarily disabled. Entity may not act. | No | No | Restored, Retired |
| **Restored** | A suspended identity is reactivated. | Yes | Metadata only | Active |
| **Retired** | Entity has ceased operation. Identity remains for audit. | No | No | Archived |
| **Archived** | Identity record is preserved in evidence store. No longer resolvable for active queries. | No | No | (terminal) |

## Transition Diagram

```
┌──────────┐    verify()    ┌──────────┐    activate()    ┌────────┐
│ Created  │ ──────────────►│ Verified │ ────────────────►│ Active │
└──────────┘                └──────────┘                  └───┬────┘
                                                              │
                                        suspend()             │    retire()
                                    ┌─────────────────────────┘
                                    ▼
                              ┌───────────┐
                              │ Suspended │
                              └─────┬─────┘
                                      │
                              restore() │ ──────────────────► Active
                                      │
                              retire() │
                                      ▼
                              ┌──────────┐     archive()    ┌──────────┐
                              │ Retired  │ ────────────────► │ Archived │
                              └──────────┘                  └──────────┘
```

## Transition Authorization

| Transition | Authorizing Entity | Required Evidence |
|-----------|-------------------|-------------------|
| Created → Verified | Proving entity's creator (OSYS for Orgs, LMS for Sessions, IDS for Credentials) | Identity creation request, creator authorization |
| Verified → Active | Automatic after verification | No additional evidence |
| Active → Suspended | Security Council or parent entity (OSYS for Orgs) | Suspension reason, Security Council authorization |
| Suspended → Restored | Security Council | Restoration reason, authorization |
| Suspended → Retired | Security Council or parent entity | Retirement reason |
| Restored → Active | Automatic | No additional evidence |
| Active → Retired | Entity's creator or Security Council | Retirement reason, completion evidence |
| Retired → Archived | IDS (automatic after retention period) | Retention period expiry |

## Lifecycle Operations

### verifyIdentity(identity_id)

**Authorization**: Same as createIdentity — the entity's creator.

**Process**:
1. Load identity record
2. Validate status is `Created`
3. Set status to `Verified`, set `verified_at` timestamp
4. Produce Event: `IdentityVerified`
5. Return identity record with status `Verified`

### activateIdentity(identity_id)

**Authorization**: Automatic — called after verifyIdentity completes.

**Process**:
1. Load identity record
2. Validate status is `Verified`
3. Set status to `Active`
4. Produce Event: `IdentityActivated`
5. Return identity record with status `Active`

### suspendIdentity(identity_id, reason, authorizing_entity)

**Authorization**: Security Council or governing entity (OSYS, LMS, AGS).

**Process**:
1. Load identity record
2. Validate status is `Active`
3. Validate authorization
4. Set status to `Suspended`
5. Record reason and authorizing entity
6. Produce Event: `IdentitySuspended`
7. Notify affected entities through ACF
8. Return identity record with status `Suspended`

### restoreIdentity(identity_id, reason, authorizing_entity)

**Authorization**: Security Council.

**Process**:
1. Load identity record
2. Validate status is `Suspended`
3. Validate authorization
4. Set status to `Restored`
5. Record reason and authorizing entity
6. Produce Event: `IdentityRestored`
7. activateIdentity (automatic transition to Active)
8. Return identity record with status `Active`

### retireIdentity(identity_id, reason, authorizing_entity)

**Authorization**: Entity's creator or Security Council.

**Process**:
1. Load identity record
2. Validate status is `Active` or `Suspended`
3. Validate authorization
4. Set status to `Retired`
5. Record reason and authorizing entity
6. Record evidence hash (seal the entity's evidence chain)
7. Produce Event: `IdentityRetired`
8. Notify ACF to block routing for this identity
9. Return identity record with status `Retired`

## Lifecycle Events

| Event Type | Produced By | Fields |
|-----------|-------------|--------|
| `Identity.Created` | createIdentity | identity_id, entity_type, entity_id, provenance, timestamp |
| `Identity.Verified` | verifyIdentity | identity_id, verified_at, timestamp |
| `Identity.Activated` | activateIdentity | identity_id, timestamp |
| `Identity.Suspended` | suspendIdentity | identity_id, reason, authorizing_entity, timestamp |
| `Identity.Restored` | restoreIdentity | identity_id, reason, authorizing_entity, timestamp |
| `Identity.Retired` | retireIdentity | identity_id, reason, authorizing_entity, evidence_hash, timestamp |
| `Identity.Archived` | archiveIdentity | identity_id, timestamp |