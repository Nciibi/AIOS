# AIOS Bible — Core
## Academy — 004: Knowledge Registry

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Core / Academy |
| Document ID | AIOS-BBL-002-ACD-004 |
| Source Laws | Law 4 — Evidence, Law 5 — Identity |
| Source Physics | Physics/005-Events.md |
| Source Governance | Governance/006-AKM.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Knowledge Registry is the authoritative index of all knowledge the Academy knows. Every accepted knowledge artifact has exactly one entry in the Registry. The Registry answers: "What does AIOS know?" It is the source of truth for knowledge existence, status, and provenance.

The Registry is to knowledge what the Identity Registry (IDS) is to entities — the canonical, queryable index of all constitutional knowledge artifacts.

## Registry Entry Structure

Each entry in the Registry represents one accepted knowledge artifact:

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `id` | UUIDv7 | Registry entry ID (same as artifact ID) | Yes |
| `type` | Enum | Knowledge type (operational, domain, constitutional, strategic, experimental) | Yes |
| `status` | Enum | Current lifecycle state from AKM | Yes |
| `version` | SemVer | Latest accepted version | Yes |
| `provenance_hash` | SHA-256 | Hash of the full provenance chain | Yes |
| `evidence_hash` | SHA-256 | Hash of concatenated source Event payloads | Yes |
| `signature` | Signature | Cryptographic signature from the accepting authority | Yes |
| `accepted_at` | DateTime | When the artifact was accepted | Yes |
| `accepted_by` | UUID | Entity ID that accepted (Reviewer or Security Council) | Yes |
| `organization_id` | UUID | Organization that owns this knowledge | Yes |
| `supersedes` | UUID[] | IDs of artifacts this entry supersedes | No |
| `superseded_by`| UUID | ID of artifact that supersedes this entry | No |
| `tags` | String[] | Searchable tags | No |
| `constitutional_hash` | SHA-256 | Hash of constitution snapshot at acceptance time | Yes |

### Entry States

| State | Description | Queries Include? |
|-------|-------------|-----------------|
| `Registered` | Entry is active and current | Yes |
| `Superseded` | Entry has been replaced by newer version | Yes (with warning) |
| `Deprecated` | Entry is deprecated but not yet archived | Yes (with warning) |
| `Archived` | Entry is preserved for audit only | No (audit only) |

## Registry Operations

### register

Registers a new knowledge artifact in the Registry. This is the terminal step of the validation pipeline — only artifacts that passed Validator (005), Verifier (006), and Review (007, if required) may be registered.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Artifact ID from KMS |
| `validation_proof` | Yes | Proof of successful validation/verification |
| `review_proof` | Conditional | Proof of review (if required by type) |
| `accepted_by` | Yes | Authorized accepting entity |

**Preconditions**:
- Artifact exists in KMS with status `Validated` or `Reviewed`
- Artifact passes constitutional validation at registration time
- Accepting entity has `knowledge.accept` capability

**Response**: `{ registry_id, status: "Registered", accepted_at }`

### query

Query the Registry for entries matching criteria.

| Parameter | Description |
|-----------|-------------|
| `type` | Filter by knowledge type |
| `status` | Filter by Registry status |
| `organization_id` | Filter by owning organization |
| `tags` | Filter by tags (AND logic) |
| `timerange` | Filter by acceptance time range |
| `include_superseded` | Include superseded entries (default: false) |
| `include_deprecated` | Include deprecated entries (default: false) |

**Response**: `{ entries: [], total_count, page, page_size }`

### list

List all entries with pagination. Supports same filters as query.

| Parameter | Description |
|-----------|-------------|
| `page` | Page number (1-indexed) |
| `page_size` | Items per page (max 100) |
| `sort_by` | Field to sort by (accepted_at, type, version) |
| `sort_order` | Ascending or descending |

**Response**: `{ entries: [], total_count, page, page_size }`

### resolve

Resolve an artifact ID to its Registry entry, following the superse­des chain to find the current active entry.

| Parameter | Description |
|-----------|-------------|
| `artifact_id` | Artifact ID to resolve |
| `follow_supersedes` | Follow chain to most current (default: true) |

**Response**: `{ current_entry, chain: [predecessor_entries] }`

### deprecate

Mark a Registry entry as deprecated. Requires authorized reviewer.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `artifact_id` | Yes | Entry to deprecate |
| `superseded_by` | No | Replacement artifact ID |
| `reason` | Yes | Deprecation reason |
| `authorized_by` | Yes | Authorizing entity |

**Response**: `{ registry_id, status: "Deprecated", superseded_by }`

## Constitutional Validation at Registration

When an artifact is registered, the Registry performs a final constitutional validation check:

| Check | Description | On Failure |
|-------|-------------|------------|
| Constitution consistency | Artifact does not contradict current constitution | Reject registration |
| Evidence provenance | Source events exist and are accessible | Reject registration |
| Non-contradiction | Artifact does not contradict accepted knowledge | Flag for review |
| Privacy compliance | Artifact does not expose evidence beyond org bounds | Reject registration |
| Signature validity | Artifact signature is valid | Reject registration |
| Authorization | Registering entity has `knowledge.accept` capability | Reject registration |

This is the last gate before knowledge becomes authoritative.

## Registry Index

The Registry maintains the following indexes for query performance:

| Index | Key | Query Types |
|-------|-----|-------------|
| Primary | `id` | getKnowledge, resolve |
| Type-status | `(type, status)` | listByType, listByStatus |
| Organization | `organization_id` | listByOrganization |
| Temporal | `accepted_at` | time-range queries |
| Supersedes | `supersedes[]` | resolve, chain traversal |
| Tag | `tags[]` | tag-based filtering |

## Registry Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| `Registry.ArtifactRegistered` | New artifact registered | registry_id, type, version, accepted_by |
| `Registry.ArtifactSuperseded` | Entry is superseded | registry_id, superseded_by, timestamp |
| `Registry.ArtifactDeprecated` | Entry deprecated | registry_id, reason, authorized_by |
| `Registry.ArtifactArchived` | Entry archived | registry_id, retention_period |
| `Registry.ValidationFailed` | Registration validation failed | artifact_id, reason, failed_check |
| `Registry.QueryExecuted` | Query/List executed | query_type, filter_count, result_count |

## Cross-Cutting Concerns

### Security

The Registry is append-only after registration. Entries may be deprecated but never deleted. Tampering with Registry entries is a constitutional violation (CPR-004). All mutations require cryptographic signature from authorized entities.

### Evidence

Every Registry operation produces an Event. The Registry Event log is the authoritative record of what knowledge AIOS has accepted and when. The log can be replayed to reconstruct Registry state at any point in time.

### Lifecycle

Registry state is a subset of the AKM knowledge lifecycle. Only artifacts in `Validated` or `Reviewed` state may be registered. Registration transitions the artifact to `Accepted` state in KMS.

### Capability Bounds

| Operation | Required Capability |
|-----------|---------------------|
| register | `knowledge.accept` |
| query/list | `knowledge.query` |
| resolve | `knowledge.query` |
| deprecate | `knowledge.deprecate` |
| archive | `knowledge.archive` |

Capabilities are scoped by organization and knowledge type (Physics/007-Capabilities.md).

### Communication

Registry operations are accessed through ACF. The Registry subscribes to Validator and Verifier events to know when artifacts are ready for registration. External consumers query through Knowledge API (016).

### Design DNA

| Rule | Application |
|------|-------------|
| R1 | Registry does indexing and registration — does not store artifact content |
| R3 | Registry is the single authoritative index (no duplicate indexing) |
| R4 | Registry entries are built by the acceptance process, not constructed directly |
| R9 | Registry queries are deterministic |
| R13 | Registry fails closed on storage failure |
| R14 | Paved path for registration: Validated → Reviewed → Registered |
| R15 | New index types added without modifying Registry core |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Physics/005-Events.md | Registry events are source events for knowledge lifecycle |
| Governance/006-AKM.md | AKM lifecycle defines Registry entry states |
| Foundations/001-AIOS-Philosophy.md | PHI-008 (Evidence Over Opinion) — all knowledge is registered |
| Foundations/003-Core-Principles.md | CPR-004 (Evidence Is Immutable) — Registry is append-only |
| Foundations/002-Design-DNA.md | R1, R3, R4, R9, R13, R14, R15 |
| 002-KMS.md | KMS stores artifact content; Registry indexes it |
| 003-Knowledge-Graph.md | Graph connects what Registry indexes |
| 005-Knowledge-Validator.md | Registry consumes validation results |
| 007-Knowledge-Review.md | Registry consumes review results |
| 016-Knowledge-API.md | Registry operations exposed through API |
