# AIOS Bible — Core
## Academy — 008: Knowledge Versioning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-008 |
| Source Laws | Law 9 — Deterministic |
| Source Physics | Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Knowledge Versioning defines how knowledge artifacts change over time. Every accepted knowledge artifact has a version chain that records its evolution. Versioning ensures traceability, enables rollback, and provides consumers with clear semantics about the impact of each change.

Versioning follows SemVer (Semantic Versioning) principles adapted for knowledge artifacts.

## Version Scheme: Major.Minor.Patch

```
Major.Minor.Patch
  │      │      └── Patch: correction, clarification (no semantic change)
  │      └── Minor: non-breaking addition or refinement
  └── Major: breaking change (supersedes previous version)
```

### Major Version Increment

A Major version increment indicates the knowledge artifact has changed in a way that makes it semantically different from the previous version. Consumers relying on the previous version may need to update their understanding or implementation.

| Trigger | Example |
|---------|---------|
| Knowledge claim changes | "Authentication requires 2 factors" → "Authentication requires 3 factors" |
| Knowledge scope changes | "Applies to L2+ entities" → "Applies to L3+ entities" |
| Knowledge supersedes another | Artifact now supersedes an additional artifact |
| Constitutional impact | Knowledge interpretation of a Law changes |

### Minor Version Increment

A Minor version increment indicates the knowledge artifact has been extended or refined without invalidating the previous version.

| Trigger | Example |
|---------|---------|
| Additional supporting evidence | New Events reinforce the existing claim |
| Refined context | More detailed examples added |
| Extended applicability | Additional scenarios covered |
| New metadata | Additional tags, cross-references added |

### Patch Version Increment

A Patch version increment indicates a correction or clarification that does not change the knowledge's semantic meaning.

| Trigger | Example |
|---------|---------|
| Typographical correction | Fixed spelling in title or description |
| Clarification | Improved wording without changing meaning |
| Metadata correction | Fixed incorrect tag or reference |
| Formatting | Content structure improved without semantic change |

## Version Graph

Knowledge artifacts can have branches for alternative knowledge claims that are resolved on acceptance:

```
v1.0.0 ─────── v1.1.0 ─────── v1.2.0 ─────── v2.0.0
  │                                                │
  │         ┌── v1.1.0 (experimental branch)       │
  │         │                                      │
  └─────────┴── v1.1.0 (resolved on acceptance) ──┘
```

| Concept | Description |
|---------|-------------|
| **Main branch** | The canonical version chain of accepted knowledge |
| **Branch** | Alternative version of the same artifact, typically exploratory |
| **Merge** | Branch is resolved and merged into main on acceptance |
| **Fork point** | Version at which the branch diverges |

### Branch Rules

| Rule | Description |
|------|-------------|
| Branches are temporary | Branches exist only during review; resolved on acceptance |
| No permanent forks | All knowledge converges to a single version chain |
| Branch naming | Named by entity ID that created it |
| Branch visibility | Only visible to the creating entity and reviewers |
| Merge authority | Reviewer or Security Council can approve merge |

## Version Lifecycle

Individual versions within an artifact's chain have their own lifecycle:

```
Active → Superseded → Deprecated → Archived
```

| State | Description | Published? | Searchable? |
|-------|-------------|------------|-------------|
| **Active** | Current version in use | Yes | Yes |
| **Superseded** | Replaced by a newer version | Yes (with warning) | Yes |
| **Deprecated** | Marked as deprecated | Yes (with warning) | Yes |
| **Archived** | Preserved for audit | No | No (audit only) |

## Deprecation Policy

### Deprecation Triggers

| Trigger | Description |
|---------|-------------|
| Superseded by Major version | Knowledge is replaced by a breaking change |
| Evidence invalidation | Source Events are found to be invalid or incorrect |
| Constitutional change | A constitutional amendment makes the knowledge obsolete |
| Security Council order | Security Council orders deprecation |
| Organizational change | The owning organization is restructured or dissolved |

### Deprecation Process

```
1. Deprecation proposed (by Reviewer, Security Council, or automated)
2. Deprecation reason recorded
3. Superseded_by link established (if applicable)
4. Artifact status set to Deprecated
5. Consumers notified via ACF topic
6. Retention timer starts (configurable per type, default 90 days)
7. After retention: artifact transitions to Archived
```

### Deprecated Knowledge Access

| Access Type | Behavior |
|-------------|----------|
| Direct query (by ID) | Returns artifact with deprecation warning |
| Search results | Excluded from default results; included if `include_deprecated=true` |
| Distribution push | Deprecated artifacts are not pushed to subscribers |
| Graph traversal | Deprecated nodes are flagged but visible |
| Provenance chain | Deprecated artifacts remain in provenance chains |

## Version Operations

### createVersion

Create a new version of an existing artifact.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Existing artifact ID |
| `version_type` | Yes | Major, Minor, or Patch |
| `content` | Yes | Updated content |
| `reason` | Yes | Human-readable reason for version change |
| `authorized_by` | Yes | Entity authorizing the change |

**Response**: `{ artifact_id, old_version: "x.y.z", new_version: "x.y.z1" }`

### getVersion

Retrieve specific version of an artifact.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Artifact ID |
| `version` | Yes | Version string (e.g., "1.2.0") |
| `include_deprecated` | No | Allow access to deprecated versions |

**Response**: Full artifact at specified version.

### listVersions

List all versions of an artifact.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Artifact ID |
| `include_branches` | No | Include branch versions (default: false) |
| `status_filter` | No | Filter by version status |

**Response**: `{ versions: [{ version, status, timestamp, authored_by }] }`

### compareVersions

Compare two versions of an artifact.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Artifact ID |
| `version_a` | Yes | First version |
| `version_b` | Yes | Second version |

**Response**: `{ diff: { added, removed, changed, unchanged }, impact: "Major"|"Minor"|"Patch" }`

## Version Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Versioning.VersionCreated` | New version is created | artifact_id, version, version_type, reason |
| `Versioning.VersionSuperseded` | Version is superseded | artifact_id, version, superseded_by |
| `Versioning.VersionDeprecated` | Version is deprecated | artifact_id, version, reason |
| `Versioning.VersionArchived` | Version is archived | artifact_id, version, retention_period |
| `Versioning.BranchCreated` | Branch is forked from main | artifact_id, branch_name, fork_version |
| `Versioning.BranchMerged` | Branch is merged into main | artifact_id, branch_name, merge_version |
| `Versioning.VersionCompared` | Two versions are compared | artifact_id, version_a, version_b, impact |

## Cross-Cutting Concerns

### Security

Version operations require authorization. Only entities with `knowledge.version.create` capability can create new versions. Deprecation requires `knowledge.deprecate` capability. Version history is immutable — versions cannot be deleted or reordered (CPR-004).

### Evidence

Every version event is recorded in the KMS event log. The complete version history of every artifact is reconstructable. Version events include the authorizing entity ID and reason.

### Lifecycle

Versioning is orthogonal to the AKM lifecycle. An artifact in Accepted state can have multiple versions (active, superseded). The AKM lifecycle applies to the artifact as a whole; versioning applies to its content evolution.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| Create Major version | `knowledge.version.major` |
| Create Minor version | `knowledge.version.minor` |
| Create Patch version | `knowledge.version.patch` |
| Deprecate version | `knowledge.deprecate` |
| Archive version | `knowledge.archive` |
| Compare versions | `knowledge.query` |

### Communication

Version operations are accessed through ACF. The KMS (002) manages version storage. The Distribution service (009) propagates version changes to subscribers.

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Versioning is a KMS sub-function — does not exist as separate service |
| R3 | Version chain is the single source of truth for artifact history |
| R9 | Version comparison produces deterministic diffs |
| R10 | Version scheme is simple SemVer — no custom version formats |
| R12 | Every version operation error has a unique code |
| R13 | Version database fails closed on storage failure |
| R14 | Paved path: createVersion → validate → store → notify |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Version events recorded in event log |
| Governance/006-AKM.md | AKM lifecycle operates alongside versioning |
| Foundations/001-AIOS-Philosophy.md | PHI-006 — lifecycle compliance for versions |
| Foundations/002-Design-DNA.md | R1, R3, R9, R10, R12, R13, R14 |
| Foundations/009-Versioning.md | General versioning framework for all AIOS objects |
| 002-KMS.md | KMS stores version chains |
| 009-Knowledge-Distribution.md | Distribution propagates version changes |
| 011-Knowledge-Provenance.md | Provenance chains reference specific versions |
