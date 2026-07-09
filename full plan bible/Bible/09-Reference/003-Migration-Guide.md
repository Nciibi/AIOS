# AIOS Bible — Reference
## 003 — Migration Guide

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Reference |
| Document ID | REF-MIG-003 |
| Source Laws | Law 4 — Law of Evidence, Law 9 — Law of Constitutional Supremacy |
| Source Physics | Physics/006-Lifecycles.md, Physics/005-Events.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

This migration guide documents the paths between AIOS versions. It describes how to upgrade from one version to the next, what changes are required, what risks are involved, and how to verify a successful migration. Every migration path is evidenced and must be approved through the RFC process before execution.

## Migration Principles

### Principle 1 — Evidence-Driven Migration
Every migration step produces evidence. No migration operation is invisible. The Event Store records every state change, data transformation, and configuration update during migration.

### Principle 2 — Backward Compatibility
Within a MAJOR version, backward compatibility is preserved. Breaking changes are introduced only at MAJOR version boundaries and are documented in the breaking changes section of each migration path.

### Principle 3 — Phased Rollout
Migrations are executed in phases: Sandbox (testing) → Canary (limited production) → Rolling (gradual rollout) → Complete (full production). Each phase must complete verification before the next begins.

### Principle 4 — Rollback Capability
Every migration must have a verified rollback plan. If a migration fails verification at any phase, the system must be restored to the pre-migration state within the defined recovery time objective (RTO).

## Versioning Scheme

AIOS uses semantic versioning: MAJOR.MINOR.PATCH.

| Component | Version | Description |
|-----------|---------|-------------|
| MAJOR | 1+ | Breaking changes. New architecture, protocol changes, API incompatibility. |
| MINOR | 0+ | New features, non-breaking additions. |
| PATCH | 0+ | Bug fixes, security patches, performance improvements. |

Current version: **1.0.0** (Initial Release)

## Migration Paths

### Migration 1.0.0 → 1.1.0

| Property | Value |
|----------|-------|
| Type | Minor Upgrade |
| Risk | Low |
| Downtime | Rolling (no downtime) |
| Estimated Duration | 2 hours |
| Rollback Complexity | Low |

**Changes**:
- Introduction of the Academy learning pipeline (KCE, KEE, KMS)
- Expanded Event schema for knowledge events
- New ACF topics for Academy communication
- Additional SDK methods for knowledge queries

**Pre-Migration Requirements**:
1. All entities must be running 1.0.0 with no unresolved violations
2. Event Store must have at least 20% free capacity
3. Academy modules must be deployed but inactive
4. All current RFCs must be in Approved or Implemented state

**Migration Steps**:
```
1. Deploy KMS database schema (no downtime)
2. Deploy KCE and KEE modules (inactive)
3. Update ACF topic registry with Academy topics
4. Deploy updated SDKs
5. Activate KCE (starts processing Event backlog)
6. Activate KEE (starts evaluating knowledge)
7. Verify knowledge pipeline throughput
8. Enable Academy queries through SDK
```

**Verification**:
- KCE processes Events from the backlog within 24 hours
- KEE assigns confidence scores to all knowledge items
- No regression in existing entity operations
- ACF Academy topics are routable

**Rollback**:
```
1. Deactivate KEE and KCE
2. Remove Academy topics from ACF registry
3. Revert SDK to 1.0.0
4. Roll back KMS schema if modified
```

### Migration 1.1.0 → 1.2.0

| Property | Value |
|----------|-------|
| Type | Minor Upgrade |
| Risk | Low |
| Downtime | Rolling (no downtime) |
| Estimated Duration | 4 hours |
| Rollback Complexity | Low |

**Changes**:
- Plugin system introduction (foundation, not yet active plugins)
- Plugin SDK and sandbox infrastructure
- Plugin registry in CKR
- ADG-013 implementation

**Pre-Migration Requirements**:
1. All entities running 1.1.0
2. Plugin sandbox infrastructure deployed
3. Plugin SDK tested in sandbox environment

**Migration Steps**:
```
1. Deploy plugin sandbox infrastructure
2. Deploy Plugin SDK to all Runtimes
3. Initialize plugin registry in CKR
4. Deploy plugin verification pipeline (Security Kernel stage)
5. Verify plugin sandbox isolation
6. Enable plugin registration (no execution)
```

**Verification**:
- Plugin sandbox isolation verified (pentest)
- Plugin registry accepts registrations
- Security Kernel verifies plugin declarations
- No impact on non-plugin entity operations

### Migration 2.0.0 — Breaking Changes

| Property | Value |
|----------|-------|
| Type | Major Upgrade |
| Risk | High |
| Downtime | Required (scheduled) |
| Estimated Duration | 24 hours |
| Rollback Complexity | High |

**Breaking Changes**:
1. **ACF Protocol Version 2**: Message header format changed. New required fields for routing metadata.
2. **Event Schema Version 2**: All Event types adopt semantic versioning. Old schema (v1) deprecated.
3. **SDK API Changes**: Runtime SDK v2 removes deprecated methods. Provider SDK v2 requires new capability declaration.
4. **Worker Isolation Model**: Enhanced sandbox requirements. All Workers must be migrated to new isolation profiles.
5. **Knowledge Graph Schema**: KMS migrates from flat knowledge store to graph model.

**Pre-Migration Requirements**:
1. All RFCs for 1.x changes must be closed
2. All entities verified for 2.0 compatibility
3. Rollback infrastructure tested
4. Full Event Store backup completed
5. All Stakeholders notified
6. Migration window scheduled

**Migration Steps**:
```
Phase 1 — Preparation (Week -2 to Week 0)
1. Deploy compatibility layer for dual ACF protocol support
2. Migrate Event schema registrations to v2
3. Update all SDK consumers to v2
4. Run compatibility tests in sandbox
5. Document all entity compatibility status

Phase 2 — Canary (Hour 0-2)
1. Migrate 10% of Workers to new isolation profiles
2. Enable ACF v2 on canary nodes
3. Verify canary operations
4. If canary fails: rollback, diagnose, retry

Phase 3 — Rolling (Hour 2-12)
1. Migrate remaining Workers in batches of 20%
2. Verify each batch before proceeding
3. Monitor Event Store throughput
4. Monitor Security Kernel verification latency

Phase 4 — Completion (Hour 12-24)
1. Enable ACF v2 exclusively (disable v1 compatibility)
2. Migrate KMS to graph schema
3. Run full system verification
4. Archive pre-migration Event snapshots
```

**Verification**:
- All entities operational on 2.0
- Event Store ingesting at expected rate
- Security Pipeline latency within baseline + 10%
- Knowledge graph queries returning correct results
- No entities using deprecated v1 protocols

**Rollback**:
```
1. Restore Event Store from pre-migration backup
2. Re-enable ACF v1 compatibility layer
3. Roll back Worker isolation profiles to 1.x
4. Revert KMS to flat store schema
5. Run full system verification on 1.2.x
6. Investigate migration failure cause
```

### Migration 2.0.0 → 2.1.0

| Property | Value |
|----------|-------|
| Type | Minor Upgrade |
| Risk | Medium |
| Downtime | Rolling (no downtime) |
| Estimated Duration | 8 hours |
| Rollback Complexity | Medium |

**Changes**:
- Multi-instance federation foundation (IXP, CXP protocols)
- Cross-instance identity resolution (IXP)
- Cross-instance message exchange (CXP)
- Instance registry and discovery

**Pre-Migration Requirements**:
1. All instances running 2.0.0
2. Instance certificates provisioned
3. IXP and CXP tested in sandbox federation
4. Cross-instance governance policies defined

**Migration Steps**:
```
1. Deploy IXP module on all instances
2. Register instance certificates in cross-instance registry
3. Deploy CXP module for cross-instance messaging
4. Enable instance discovery via IXP
5. Verify cross-instance identity resolution
6. Enable cross-instance communication for L3+ entities
```

**Verification**:
- Cross-instance identity resolution successful
- CXP messages delivered and acknowledged
- Instance registry synchronized
- No degradation in intra-instance operations
- Cross-instance evidence chain verified

## Migration Tools and Automation

### Migration Scripts
Each migration path includes a set of idempotent migration scripts stored in the `tools/migrations/` directory. Scripts are:
- **Idempotent**: Running the same script multiple times produces the same result
- **Evidence-Producing**: Every script operation produces Events
- **Verifiable**: Each script outputs a verification hash

### Migration Verification Suite
Before and after each migration, the verification suite checks:
1. All entities are in valid lifecycle states
2. Event Store integrity (checksum verification)
3. Security Pipeline operational
4. ACF routing tables complete
5. SDK version compatibility
6. Knowledge graph integrity

### Dry-Run Mode
All migrations support dry-run mode:
```
migrate.sh --dry-run --target 2.0.0
```
Dry-run validates preconditions, checks compatibility, and produces a migration plan without executing any changes.

## Risk Classification

| Risk Level | Description | Approval Required | Rollback RTO |
|-----------|-------------|-------------------|--------------|
| Low | No entity impact. Configuration only. | Team Lead | 1 hour |
| Medium | Some entities affected. Non-breaking. | Security Council | 4 hours |
| High | All entities affected. Breaking changes. | Security Council + Sou | 24 hours |
| Critical | System-wide impact. Architecture change. | Security Council + Sou + Human | 48 hours |

## Cross-Cutting Concerns

### Security
Migrations must not introduce security regressions. All migration scripts are reviewed by the Security Council. Credentials and keys must never be exposed in migration scripts or logs. Cross-instance migrations require mTLS verification.

### Evidence
Every migration step produces Events in the migration audit trail. The complete migration history is stored in CKR. Failed migrations produce detailed error Events for post-mortem analysis. Migration verification results are stored as evidence artifacts.

### Lifecycle
Migrations follow their own lifecycle: Planned → Approved → Prepared → Executed → Verified → Completed. The system is in a special "Migration" lifecycle state during execution. If a migration fails verification, the system enters "Migration Rollback" state.

### Capability Bounds
Migrations may alter capability bounds for entities. Capability changes are documented in the migration path and require CCA re-certification for affected entities. Entities operating outside their new capability bounds during migration are denied.

### Design DNA Compliance
| Rule | Compliance |
|------|------------|
| R3 | Each migration path is documented once in this guide. |
| R10 | Migrations use the simplest path that achieves the target state. |
| R13 | Every migration has a rollback plan. |
| R14 | The documented migration paths are the only supported upgrade methods. |

### Interoperability
Cross-version interoperability is maintained within a MAJOR version. Mixed-version deployments are supported during rolling migrations but must be time-limited. Cross-instance migrations require both instances to be at compatible versions.

## Related Documents

| Document | Relationship |
|---------|-------------|
| 000-Decision-Log.md | ADRs that trigger migrations are referenced in migration paths |
| 01-Governance/003-CRP.md | RFCs proposing changes that require migration flow through CRP |
| 01-Governance/005-ADG.md | Architectural decisions that affect migration paths |
| 0007-Implementation-Roadmap.md | Version roadmap — which versions are planned and when |
| Physics/006-Lifecycles.md | Lifecycle framework — migration is an entity lifecycle transition |
| Physics/005-Events.md | Event schema — versioning affects migration Event handling |
| 10-Research/000-Phases-2-5.md | Research roadmap — future migration paths for Phases 2–5 |
