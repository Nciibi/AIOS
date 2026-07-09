# AIOS Bible — Core
## AGS 004 — Genome Versioning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core |
| Document ID | AIOS-BBL-002-AGS-004 |
| Source Laws | Law 6 — Law of Lifecycle Compliance, Law 8 — Law of Verification-First |
| Source Physics | Physics/006-Lifecycles.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Genome Versioning manages the evolution of Genomes over time. As AIOS capabilities evolve, Genomes must be updated, migrated, and eventually deprecated. Versioning ensures that changes are tracked, compatible, and auditable — and that existing Sessions can migrate between compatible versions.

## Version Scheme

Genome versions follow Semantic Versioning 2.0.0:

```
Major.Minor.Patch
```

| Component | Change Type | Description | Requires Re-validation? |
|-----------|-------------|-------------|------------------------|
| Major | Breaking | Changes capability set, removes capabilities, tightens bounds in incompatible ways | Full validation (all 5 stages) |
| Minor | Non-breaking | Adds optional capabilities, loosens bounds, adds policies | Full validation (all 5 stages) |
| Patch | Fix | Fixes documentation, corrects non-functional errors | Partial validation (stages 1, 3, 4) |

## Version Compatibility

AGS defines compatibility matrices between versions:

| From → To | Compatible? | Migration Required? |
|-----------|-------------|---------------------|
| v1.0.0 → v1.0.1 | Yes (patch) | No — automatic |
| v1.0.0 → v1.1.0 | Yes (minor) | No — new capabilities are optional |
| v1.0.0 → v2.0.0 | Conditional | Yes — explicit migration required |
| v2.0.0 → v1.0.0 | No | Downgrade not supported |
| v1.x.x → v1.y.y (y > x) | Yes | No — backward compatible |

## Version Lifecycle

Every Genome version follows a lifecycle:

```
Draft → Validated → Published → Active → Deprecated → Archived
```

| State | Description | Can Create Sessions? | Existing Sessions? |
|-------|-------------|---------------------|-------------------|
| Draft | Version spec being written | No | N/A |
| Validated | Passed all validation | No | N/A |
| Published | Available for use | Yes | N/A |
| Active | Currently the recommended version | Yes | Active |
| Deprecated | Still usable for existing sessions, no new sessions | No (new) | Yes (active, with deprecation notice) |
| Archived | Removed from all use | No | Must migrate before archive |

## Versioning Example

```
Genome: Worker (genome_id: wkr-001)

Version 1.0.0 (initial):
  capabilities: [communicate, execute, report]
  bounds: { max_concurrent: 5 }

Version 1.1.0 (minor — added optional capability):
  capabilities: [communicate, execute, report, preview]  // preview is optional
  bounds: { max_concurrent: 5 }
  ✓ Compatible — existing Sessions unaffected

Version 2.0.0 (major — capability removed):
  capabilities: [communicate, execute]  // report capability removed
  bounds: { max_concurrent: 5 }
  ✗ Breaking — Sessions using report must migrate or lose capability
  Migration: Sessions using report must be notified and reassigned
```

## Migration Process

When a breaking version change occurs, Sessions must migrate:

```
1. Version 2.0.0 released (breaking change)
2. AGS identifies all Sessions using version 1.x.x
3. AGS notifies affected Sessions and their parent Organizations
4. Each Session has a migration window (configurable, default 30 days)
5. Within the window, Session may:
   a. Request migration to new version
   b. Request exemption (requires Security Council approval)
   c. Accept deprecation (capabilities removed)
6. After window expires, Sessions that have not migrated are:
   a. If compatible downgrade exists → auto-migrated
   b. If no downgrade exists → capability revoked, Security Council notified
```

## Version Operations

### createVersion(genome_id, version_delta, change_description)

```
Input:  genome_id, version_delta (major | minor | patch), change_description
Process:
  1. Clone current version
  2. Apply changes
  3. Validate changes
  4. Create new version record
Output: GenomeVersion { genome_id, version, state: Draft }
Event: AGS.GenomeVersionCreated
```

### deprecateVersion(genome_id, version, reason)

```
Input:  genome_id, version, deprecation_reason
Process:
  1. Verify no critical dependencies on this version
  2. Set state to Deprecated
  3. Notify all entities using this version
Output: DeprecationResult { genome_id, version, deprecation_date }
Event: AGS.GenomeDeprecated
```

### archiveVersion(genome_id, version)

```
Input:  genome_id, version
Process:
  1. Verify all Sessions migrated away from this version
  2. Set state to Archived
  3. Remove from active query results
Output: ArchiveResult { genome_id, version, archived_at }
Event: AGS.GenomeArchived
```

### getCurrentVersion(genome_id)

```
Input:  genome_id
Process: query Registry for the highest Active version
Output: GenomeVersion { genome_id, version, state: Active }
```

### getVersionHistory(genome_id)

```
Input:  genome_id
Process: query Registry for all versions
Output: VersionHistory { genome_id, versions: [{ version, state, created_at }] }
```

### migrateSession(session_id, target_genome_id, target_version)

```
Input:  session_id, target_genome_id, target_version
Process:
  1. Verify compatibility between current and target versions
  2. Validate Session can accept the new Genome
  3. Perform migration
  4. Update Session record
Output: MigrationResult { session_id, from_version, to_version, success }
Event: AGS.SessionMigrated
```

## Versioning Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `AGS.GenomeVersionCreated` | A new version is created | genome_id, version, change_summary |
| `AGS.GenomePublished` | A version transitions to Published | genome_id, version |
| `AGS.GenomeDeprecated` | A version is deprecated | genome_id, version, deprecation_reason |
| `AGS.GenomeArchived` | A version is archived | genome_id, version, archived_at |
| `AGS.SessionMigrated` | A Session migrates between versions | session_id, from_version, to_version |
| `AGS.MigrationFailed` | A migration attempt fails | session_id, from_version, to_version, reason |

## Error Codes (R12)

| Code | Description |
|------|-------------|
| AGS_VER_001 | Version already exists — increment is invalid |
| AGS_VER_002 | Cannot deprecate last Active version without replacement |
| AGS_VER_003 | Cannot archive version with active Sessions |
| AGS_VER_004 | Incompatible migration path — from_version → to_version |
| AGS_VER_005 | Version not found in Registry |
| AGS_VER_006 | Cannot modify Archived version |

## Edge Cases — Versioning

| Scenario | Handling |
|----------|----------|
| Session migration fails mid-transition | Full rollback to original version. Session state is preserved. Error event produced. |
| Breaking change announced but no Sessions can migrate | Extension granted by Security Council. Manual migration path created. |
| Version is deprecated but critical bug found | Emergency patch release on deprecated version. Bugfix increments patch regardless of deprecation state. |
| Two versions published simultaneously (race condition) | Last write wins. Version with higher semver precedence is authoritative. |
| Session requests migration to incompatible version | Rejected with AGS_VER_004. Compatibility matrix must allow the migration. |
| Genome is archived but referenced by historical Events | Archive preserves the Genome record as read-only. Events can still reference it. |
| Patch version contains breaking change (incorrect classification) | Correction: new minor version created. Patch version marked as erroneous (not retracted). |

## Cross-Cutting Concerns

### Security

Version changes are constitutional operations. Every version change produces an Event and requires authorization. Deprecation of a Genome affects all Sessions using it — notification is mandatory. (Physics/008-Security.md)

### Evidence

Every versioning operation produces an Event. The complete version history of every Genome is recorded in the Event Store. Version audits are traceable. (PHI-008)

### Lifecycle

Genome versions follow a defined lifecycle (Draft → Validated → Published → Active → Deprecated → Archived). This is managed by AGS in coordination with LMS. (Physics/006-Lifecycles.md)

### Capability Bounds

A Major version change that tightens capability bounds may require existing Sessions to narrow their capabilities. This is a constitutional event requiring Security Council notification. (Physics/007-Capabilities.md)

### Communication

Version deprecation notifications are sent through ACF to all affected entities. Migration guidance is communicated via ACF. (Law 3 — Communication)

### Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Versioning focused solely on Genome version lifecycle |
| R3 (DRY) | Version schemas and migration logic are shared, not duplicated per version |
| R10 (Simpler Over Complex) | SemVer with clear compatibility rules — no complex migration graphs |
| R12 (Embrace Errors) | All errors have unique codes (AGS_VER_001–006) |
| R13 (Design for Failure) | Failed migration rolls back to previous version — Session is not left in inconsistent state |
| R15 (Open/Closed) | New version types added without modifying existing version logic |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Physics/006-Lifecycles.md | Lifecycles — version lifecycle mirrors entity lifecycle |
| Bible/02-Core/AGS/000-Overview.md | AGS overview — versioning is a core AGS operation |
| Bible/02-Core/AGS/001-Composition.md | Composition — each version is a distinct composition target |
| Bible/02-Core/AGS/003-Validation.md | Validation — each new version must be validated |
| Bible/02-Core/AGS/005-Signing.md | Signing — each version is independently signed |
| Bible/00-Foundations/009-Versioning.md | Versioning — Foundations versioning conventions |
| Bible/04-Execution/Security/ATS | ATS — Sessions authenticate using their Genome version |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001–010 — philosophical grounding |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001–010 — core principles |
